// Package snapshot creates disposable, analysis-safe copies of local working
// trees. It intentionally does not use git so staged, modified, and untracked
// files are copied exactly as they exist on disk.
package snapshot

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const (
	defaultPrefix      = "repo-snapshot-"
	markerName         = ".snapshot-marker"
	markerMagic        = "springmaster-snapshot-v1"
	manifestHashFormat = "springmaster-snapshot-manifest-v1"

	// Defaults are also hard ceilings. Callers may lower them, but cannot make
	// an unbounded or unexpectedly large snapshot.
	DefaultMaxFiles      = 50_000
	DefaultMaxFileBytes  = int64(64 << 20)
	DefaultMaxTotalBytes = int64(1 << 30)
	DefaultMaxDepth      = 64
)

// DefaultExcludedNames are skipped anywhere in a source tree. They are build
// products, dependency caches, or repository metadata rather than source input.
var DefaultExcludedNames = []string{
	".git",
	"build",
	"target",
	"node_modules",
	".gradle",
	".springmaster",
	"dist",
	".idea",
	".vscode",
}

// Keep Create's safety policy independent from callers mutating the exported
// convenience slice. A snapshot must always exclude these names.
var defaultExcludedNames = []string{
	".git",
	"build",
	"target",
	"node_modules",
	".gradle",
	".springmaster",
	"dist",
	".idea",
	".vscode",
}

var (
	// ErrDestinationRequired prevents snapshots from silently using a global temp
	// directory. The caller chooses the parent directory explicitly.
	ErrDestinationRequired = errors.New("snapshot destination directory is required")

	// ErrSnapshotUntrusted means Cleanup could not prove that its target is the
	// directory originally created by Create. Cleanup leaves it untouched.
	ErrSnapshotUntrusted = errors.New("snapshot cleanup target is not trusted")

	// ErrDestinationInsideSource prevents a new snapshot directory from being
	// discovered as part of its own source walk.
	ErrDestinationInsideSource = errors.New("snapshot destination directory is inside source")

	// ErrLimitExceeded means the source exceeded a configured hard safety bound.
	ErrLimitExceeded = errors.New("snapshot safety limit exceeded")

	// ErrSourceChanged means Create could not prove that copied bytes came from
	// one stable source-tree state.
	ErrSourceChanged = errors.New("snapshot source changed while copying")

	// ErrSecureTraversalUnsupported rejects snapshots on platforms where the
	// package cannot provide descriptor-relative, no-follow source traversal.
	ErrSecureTraversalUnsupported = errors.New("secure snapshot traversal is unsupported on this platform")
)

// Options controls how a snapshot is made.
type Options struct {
	// DestinationDir is an existing directory under which Create makes a unique
	// MkdirTemp-style directory. It must be set explicitly by the caller.
	DestinationDir string

	// Prefix is passed to os.MkdirTemp after validation. An empty prefix uses
	// "repo-snapshot-".
	Prefix string

	// ExcludeNames are additional base names to skip anywhere in the tree.
	// DefaultExcludedNames always apply.
	ExcludeNames []string

	// Zero uses the safe default. Positive values may lower, never raise, the
	// package hard ceilings. MaxFiles counts all copied filesystem entries.
	MaxFiles      int
	MaxFileBytes  int64
	MaxTotalBytes int64
	MaxDepth      int
}

// ContentOptions controls an exact source-tree content fingerprint. Its
// exclusions and safety limits have the same meaning and hard ceilings as
// Options. ContentDigest does not need or create a destination directory.
type ContentOptions struct {
	// ExcludeNames are additional base names to skip anywhere in the tree.
	// DefaultExcludedNames always apply.
	ExcludeNames []string

	// Zero uses the safe default. Positive values may lower, never raise, the
	// package hard ceilings. MaxFiles counts all inspected filesystem entries.
	MaxFiles      int
	MaxFileBytes  int64
	MaxTotalBytes int64
	MaxDepth      int
}

// ContentFingerprint identifies exact source-tree contents without creating a
// snapshot destination. ContentHash uses the same manifest format as
// Snapshot.ContentHash, including regular-file bytes and safely rewritten
// symlink targets.
type ContentFingerprint struct {
	ContentHash string
	FileCount   int
	TotalBytes  int64
}

// ManifestEntry describes one entry actually created in the snapshot. SHA256
// is set for regular-file bytes and symlink target text; directories use an
// empty hash. Paths are sorted, root-relative, and slash-separated.
type ManifestEntry struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256,omitempty"`
}

// Diagnostic records a non-fatal entry skipped during a snapshot. Path is
// source-root relative and slash-separated, so diagnostics are deterministic
// across host operating systems.
type Diagnostic struct {
	Path   string
	Reason string
}

// Snapshot is an independently removable copy of a source tree.
//
// Root is absolute. Cleanup does not trust this exported field: it uses an
// immutable internal path and an ownership marker created with the snapshot.
type Snapshot struct {
	Root        string
	Diagnostics []Diagnostic
	Manifest    []ManifestEntry
	ContentHash string
	FileCount   int
	TotalBytes  int64

	directory      string
	parent         string
	marker         string
	markerContents string
	createdInfo    os.FileInfo

	mu      sync.Mutex
	cleaned bool
}

// ContentDigest securely walks source and hashes exact regular-file bytes
// without writing a destination tree. Exclusions, limits, symlink handling,
// and source-mutation checks match Create. For the same stable source and
// options, ContentHash, FileCount, and TotalBytes equal Create's results.
func ContentDigest(ctx context.Context, source string, options ContentOptions) (ContentFingerprint, error) {
	if err := contextError(ctx); err != nil {
		return ContentFingerprint{}, err
	}

	sourceRoot, err := canonicalDirectory(source, "source")
	if err != nil {
		return ContentFingerprint{}, err
	}
	excluded, err := excludedNames(options.ExcludeNames)
	if err != nil {
		return ContentFingerprint{}, err
	}
	limits, err := normalizeLimits(Options{
		MaxFiles:      options.MaxFiles,
		MaxFileBytes:  options.MaxFileBytes,
		MaxTotalBytes: options.MaxTotalBytes,
		MaxDepth:      options.MaxDepth,
	})
	if err != nil {
		return ContentFingerprint{}, err
	}

	state := copyState{limits: limits}
	if err := secureContentTree(ctx, sourceRoot, excluded, &state); err != nil {
		return ContentFingerprint{}, err
	}
	sort.Slice(state.manifest, func(i, j int) bool {
		if state.manifest[i].Path == state.manifest[j].Path {
			return state.manifest[i].Kind < state.manifest[j].Kind
		}
		return state.manifest[i].Path < state.manifest[j].Path
	})
	return ContentFingerprint{
		ContentHash: manifestHash(state.manifest),
		FileCount:   state.entries,
		TotalBytes:  state.totalBytes,
	}, nil
}

// Create copies source into a fresh directory below options.DestinationDir.
// It copies regular files, preserves regular-file permissions, does not invoke
// git, and therefore includes dirty and untracked working-tree content.
//
// Symlinks are never followed while walking. A symlink whose final target is
// inside source is recreated to point to the equivalent target in the snapshot.
// Broken, excluded-target, and escaping links are skipped with a diagnostic.
func Create(ctx context.Context, source string, options Options) (*Snapshot, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}

	sourceRoot, err := canonicalDirectory(source, "source")
	if err != nil {
		return nil, err
	}
	parent, err := canonicalDirectory(options.DestinationDir, "destination")
	if err != nil {
		return nil, err
	}
	if _, insideSource := relativeWithin(sourceRoot, parent); insideSource {
		return nil, ErrDestinationInsideSource
	}

	prefix := options.Prefix
	if prefix == "" {
		prefix = defaultPrefix
	}
	if err := validateName(prefix); err != nil {
		return nil, fmt.Errorf("invalid snapshot prefix %q: %w", prefix, err)
	}
	excluded, err := excludedNames(options.ExcludeNames)
	if err != nil {
		return nil, err
	}
	limits, err := normalizeLimits(options)
	if err != nil {
		return nil, err
	}

	directory, err := os.MkdirTemp(parent, prefix)
	if err != nil {
		return nil, fmt.Errorf("create snapshot directory: %w", err)
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		_ = os.RemoveAll(directory)
		return nil, fmt.Errorf("make snapshot path absolute: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.RemoveAll(directory)
		return nil, fmt.Errorf("make snapshot directory private: %w", err)
	}
	if _, ok := relativeWithin(parent, directory); !ok {
		_ = os.RemoveAll(directory)
		return nil, fmt.Errorf("create snapshot directory: %w", ErrSnapshotUntrusted)
	}
	createdInfo, err := os.Stat(directory)
	if err != nil {
		_ = os.RemoveAll(directory)
		return nil, fmt.Errorf("stat snapshot directory: %w", err)
	}

	markerContents, err := newMarkerContents()
	if err != nil {
		_ = os.RemoveAll(directory)
		return nil, err
	}
	marker := filepath.Join(directory, markerName+"-"+markerToken(markerContents))
	if err := writeMarker(marker, markerContents); err != nil {
		_ = os.RemoveAll(directory)
		return nil, err
	}

	snapshot := &Snapshot{
		Root:           directory,
		directory:      directory,
		parent:         parent,
		marker:         marker,
		markerContents: markerContents,
		createdInfo:    createdInfo,
	}
	state := copyState{limits: limits}
	if err := secureCopyTree(ctx, sourceRoot, directory, excluded, &snapshot.Diagnostics, &state); err != nil {
		_ = snapshot.Cleanup()
		return nil, err
	}
	sort.Slice(state.manifest, func(i, j int) bool {
		if state.manifest[i].Path == state.manifest[j].Path {
			return state.manifest[i].Kind < state.manifest[j].Kind
		}
		return state.manifest[i].Path < state.manifest[j].Path
	})
	snapshot.Manifest = append([]ManifestEntry(nil), state.manifest...)
	snapshot.ContentHash = manifestHash(snapshot.Manifest)
	snapshot.FileCount = state.entries
	snapshot.TotalBytes = state.totalBytes
	return snapshot, nil
}

// Cleanup removes only this exact snapshot. Before removing anything it checks
// that the path is still directly below the requested destination, refers to
// the directory Create made, and contains its private regular-file marker.
// Repeated successful calls are no-ops.
func (s *Snapshot) Cleanup() error {
	if s == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cleaned {
		return nil
	}

	missing, err := s.validateCleanupTarget()
	if err != nil {
		return err
	}
	if missing {
		s.cleaned = true
		return nil
	}
	if err := os.RemoveAll(s.directory); err != nil {
		return fmt.Errorf("remove snapshot directory: %w", err)
	}
	s.cleaned = true
	return nil
}

func (s *Snapshot) validateCleanupTarget() (missing bool, err error) {
	if s.directory == "" || s.parent == "" || s.marker == "" || s.createdInfo == nil {
		return false, ErrSnapshotUntrusted
	}
	if !filepath.IsAbs(s.directory) || !filepath.IsAbs(s.parent) {
		return false, ErrSnapshotUntrusted
	}
	if _, ok := relativeWithin(s.parent, s.directory); !ok {
		return false, ErrSnapshotUntrusted
	}
	if filepath.Dir(s.marker) != s.directory || !strings.HasPrefix(filepath.Base(s.marker), markerName+"-") {
		return false, ErrSnapshotUntrusted
	}

	info, statErr := os.Lstat(s.directory)
	if errors.Is(statErr, os.ErrNotExist) {
		return true, nil
	}
	if statErr != nil {
		return false, fmt.Errorf("inspect snapshot directory: %w", statErr)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(s.createdInfo, info) {
		return false, ErrSnapshotUntrusted
	}

	markerInfo, markerErr := os.Lstat(s.marker)
	if markerErr != nil {
		if errors.Is(markerErr, os.ErrNotExist) {
			return false, ErrSnapshotUntrusted
		}
		return false, fmt.Errorf("inspect snapshot marker: %w", markerErr)
	}
	if !markerInfo.Mode().IsRegular() || markerInfo.Mode()&os.ModeSymlink != 0 {
		return false, ErrSnapshotUntrusted
	}
	contents, markerErr := os.ReadFile(s.marker)
	if markerErr != nil {
		return false, fmt.Errorf("read snapshot marker: %w", markerErr)
	}
	if string(contents) != s.markerContents {
		return false, ErrSnapshotUntrusted
	}
	return false, nil
}

func canonicalDirectory(path, kind string) (string, error) {
	if path == "" {
		if kind == "destination" {
			return "", ErrDestinationRequired
		}
		return "", fmt.Errorf("%s directory is required", kind)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("make %s path absolute: %w", kind, err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolve %s directory: %w", kind, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("stat %s directory: %w", kind, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s path is not a directory", kind)
	}
	return filepath.Clean(resolved), nil
}

func excludedNames(extra []string) (map[string]struct{}, error) {
	excluded := make(map[string]struct{}, len(defaultExcludedNames)+len(extra))
	for _, name := range append(append([]string(nil), defaultExcludedNames...), extra...) {
		if err := validateName(name); err != nil {
			return nil, fmt.Errorf("invalid excluded name %q: %w", name, err)
		}
		excluded[name] = struct{}{}
	}
	return excluded, nil
}

type limits struct {
	maxFiles      int
	maxFileBytes  int64
	maxTotalBytes int64
	maxDepth      int
}

type copyState struct {
	limits      limits
	seenEntries int
	entries     int
	totalBytes  int64
	manifest    []ManifestEntry
}

func normalizeLimits(options Options) (limits, error) {
	result := limits{
		maxFiles:      DefaultMaxFiles,
		maxFileBytes:  DefaultMaxFileBytes,
		maxTotalBytes: DefaultMaxTotalBytes,
		maxDepth:      DefaultMaxDepth,
	}
	if options.MaxFiles < 0 || options.MaxFileBytes < 0 || options.MaxTotalBytes < 0 || options.MaxDepth < 0 {
		return limits{}, errors.New("snapshot limits cannot be negative")
	}
	if options.MaxFiles > DefaultMaxFiles || options.MaxFileBytes > DefaultMaxFileBytes || options.MaxTotalBytes > DefaultMaxTotalBytes || options.MaxDepth > DefaultMaxDepth {
		return limits{}, fmt.Errorf("%w: options exceed package hard maximum", ErrLimitExceeded)
	}
	if options.MaxFiles > 0 {
		result.maxFiles = options.MaxFiles
	}
	if options.MaxFileBytes > 0 {
		result.maxFileBytes = options.MaxFileBytes
	}
	if options.MaxTotalBytes > 0 {
		result.maxTotalBytes = options.MaxTotalBytes
	}
	if options.MaxDepth > 0 {
		result.maxDepth = options.MaxDepth
	}
	return result, nil
}

func (state *copyState) addEntry(relative string, depth int) error {
	if depth > state.limits.maxDepth {
		return fmt.Errorf("%w: path depth exceeds %d at %q", ErrLimitExceeded, state.limits.maxDepth, filepath.ToSlash(relative))
	}
	state.seenEntries++
	if state.seenEntries > state.limits.maxFiles {
		return fmt.Errorf("%w: entry count exceeds %d", ErrLimitExceeded, state.limits.maxFiles)
	}
	return nil
}

func (state *copyState) addBytes(relative string, fileBytes, amount int64) error {
	if amount < 0 || fileBytes > state.limits.maxFileBytes-amount {
		return fmt.Errorf("%w: file exceeds %d bytes at %q", ErrLimitExceeded, state.limits.maxFileBytes, filepath.ToSlash(relative))
	}
	if state.totalBytes > state.limits.maxTotalBytes-amount {
		return fmt.Errorf("%w: total copied bytes exceed %d", ErrLimitExceeded, state.limits.maxTotalBytes)
	}
	state.totalBytes += amount
	return nil
}

func manifestHash(entries []ManifestEntry) string {
	digest := sha256.New()
	writeManifestField(digest, "format", manifestHashFormat)
	for _, entry := range entries {
		writeManifestField(digest, "path", entry.Path)
		writeManifestField(digest, "kind", entry.Kind)
		writeManifestField(digest, "mode", fmt.Sprintf("%#o", entry.Mode))
		writeManifestField(digest, "size", fmt.Sprintf("%d", entry.Size))
		writeManifestField(digest, "sha256", entry.SHA256)
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func writeManifestField(writer io.Writer, name, value string) {
	_, _ = fmt.Fprintf(writer, "%s:%d:", name, len(value))
	_, _ = io.WriteString(writer, value)
	_, _ = io.WriteString(writer, "\n")
}

func validateName(name string) error {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsRune(name, filepath.Separator) {
		return errors.New("must be one path component")
	}
	return nil
}

func newMarkerContents() (string, error) {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", fmt.Errorf("create snapshot marker token: %w", err)
	}
	return markerMagic + "\n" + hex.EncodeToString(token[:]) + "\n", nil
}

func markerToken(contents string) string {
	parts := strings.Split(strings.TrimSuffix(contents, "\n"), "\n")
	return parts[len(parts)-1]
}

func writeMarker(path, contents string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create snapshot marker: %w", err)
	}
	_, writeErr := io.WriteString(file, contents)
	closeErr := file.Close()
	if writeErr != nil {
		_ = os.Remove(path)
		return fmt.Errorf("write snapshot marker: %w", writeErr)
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close snapshot marker: %w", closeErr)
	}
	return nil
}

func sameStableEntry(before, after os.FileInfo) bool {
	return before != nil && after != nil &&
		os.SameFile(before, after) &&
		before.Mode() == after.Mode() &&
		before.Size() == after.Size() &&
		before.ModTime().Equal(after.ModTime())
}

func writeAll(file *os.File, data []byte) error {
	for len(data) > 0 {
		written, err := file.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func safeDestinationPath(root, relative string) (string, error) {
	if relative == "." {
		return root, nil
	}
	if relative == "" || filepath.IsAbs(relative) {
		return "", fmt.Errorf("unsafe destination-relative path %q", relative)
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if err := validateName(component); err != nil {
			return "", fmt.Errorf("unsafe destination-relative path %q: %w", relative, err)
		}
	}
	destination := filepath.Join(root, relative)
	if _, ok := relativeWithin(root, destination); !ok {
		return "", fmt.Errorf("destination path escapes snapshot root: %q", relative)
	}
	return destination, nil
}

func relativeWithin(root, path string) (string, bool) {
	relative, err := filepath.Rel(root, path)
	if err != nil || filepath.IsAbs(relative) {
		return "", false
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", false
	}
	return relative, true
}

func pathHasExcludedComponent(relative string, excluded map[string]struct{}) bool {
	if relative == "." {
		return false
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if _, found := excluded[component]; found {
			return true
		}
	}
	return false
}

func addDiagnostic(diagnostics *[]Diagnostic, path, reason string) {
	*diagnostics = append(*diagnostics, Diagnostic{Path: filepath.ToSlash(path), Reason: reason})
}

func displayPath(root, path string) string {
	return filepath.ToSlash(mustRelative(root, path))
}

func mustRelative(root, path string) string {
	relative, ok := relativeWithin(root, path)
	if !ok {
		return path
	}
	return relative
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("snapshot context is nil")
	}
	return ctx.Err()
}

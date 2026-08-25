// Package semantic materializes a bounded, source-only dependency context for
// static analysis. It never evaluates build files, executes code, or uses a
// network connection.
package semantic

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

	"github.com/gudcks0305/springmaster/internal/graph"
)

const (
	// ReservedDirectory is the only target-root directory owned by this package.
	ReservedDirectory = "_springmaster_deps"

	defaultMaxEntries    = 100_000
	defaultMaxFiles      = 20_000
	defaultMaxFileBytes  = int64(16 << 20)
	defaultMaxTotalBytes = int64(256 << 20)
	defaultMaxDepth      = 64

	maxEntries    = 200_000
	maxFiles      = 50_000
	maxFileBytes  = int64(64 << 20)
	maxTotalBytes = int64(512 << 20)
	maxDepth      = 128

	manifestFormat = "springmaster-semantic-context-v1"
	markerName     = ".springmaster-semantic-context-marker"
	markerMagic    = "springmaster-semantic-context-v1"
)

var (
	// ErrInvalidInput means a graph, target, or prepared snapshot root is not
	// suitable for safe context materialization.
	ErrInvalidInput = errors.New("invalid semantic context input")
	// ErrLimitExceeded means a fixed source-context safety bound was exceeded.
	ErrLimitExceeded = errors.New("semantic context safety limit exceeded")
	// ErrReservedPathExists prevents overwriting a source-controlled directory.
	ErrReservedPathExists = errors.New("semantic context reserved path already exists")
	// ErrContextUntrusted makes Cleanup leave a modified overlay untouched.
	ErrContextUntrusted = errors.New("semantic context cleanup target is untrusted")
	// ErrSourceChanged means a prepared source snapshot changed while copying.
	ErrSourceChanged = errors.New("semantic context source changed while copying")
)

// SnapshotRoot identifies one prepared, local repository snapshot. Root must
// be a directory; RepositoryID must match the graph's repository ID.
type SnapshotRoot struct {
	RepositoryID string
	Root         string
}

// CopyMode controls regular-file materialization. Auto first attempts a hard
// link, then makes a byte copy if the filesystem rejects the link. Copy never
// hard-links; HardLink requires one.
type CopyMode string

const (
	CopyModeAuto     CopyMode = "auto"
	CopyModeCopy     CopyMode = "copy"
	CopyModeHardLink CopyMode = "hardlink"
)

// Options bounds every materialization. Zero values use safe defaults; callers
// may lower, never raise, package hard ceilings.
type Options struct {
	Mode          CopyMode
	MaxEntries    int
	MaxFiles      int
	MaxFileBytes  int64
	MaxTotalBytes int64
	MaxDepth      int
}

// ManifestEntry describes one Java source file placed under Context.Path.
// Path is context-root relative, slash-separated, and begins with RepositoryID.
type ManifestEntry struct {
	RepositoryID string `json:"repositoryId"`
	Path         string `json:"path"`
	Mode         uint32 `json:"mode"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
}

// Diagnostic records a skipped non-regular entry without copying source paths
// outside its owning dependency subtree.
type Diagnostic struct {
	RepositoryID string `json:"repositoryId"`
	Path         string `json:"path"`
	Reason       string `json:"reason"`
}

// Context is a removable dependency-source overlay inside a target snapshot.
// Path is targetRoot/_springmaster_deps. Cleanup verifies its private marker and
// only removes this exact directory.
type Context struct {
	Path               string          `json:"path"`
	TargetRepositoryID string          `json:"targetRepositoryId"`
	DependencyIDs      []string        `json:"dependencyIds"`
	Manifest           []ManifestEntry `json:"manifest"`
	Diagnostics        []Diagnostic    `json:"diagnostics"`
	ContentHash        string          `json:"contentHash"`
	FileCount          int             `json:"fileCount"`
	TotalBytes         int64           `json:"totalBytes"`

	targetRoot     string
	overlayRoot    string
	marker         string
	markerContents string
	createdInfo    os.FileInfo

	mu      sync.Mutex
	cleaned bool
}

// DependencyClosure returns local, transitive dependency repository IDs for a
// target. The result is dependency-first according to graph.Order, with a
// lexical fallback for malformed/incomplete orders. Target itself is excluded.
func DependencyClosure(dependencyGraph *graph.Graph, targetRepositoryID string) ([]string, error) {
	if dependencyGraph == nil || strings.TrimSpace(targetRepositoryID) == "" {
		return nil, fmt.Errorf("%w: graph and target repository ID are required", ErrInvalidInput)
	}
	known := make(map[string]struct{}, len(dependencyGraph.Repositories))
	for _, repository := range dependencyGraph.Repositories {
		known[repository.ID] = struct{}{}
	}
	if _, found := known[targetRepositoryID]; !found {
		return nil, fmt.Errorf("%w: target repository %q is not in graph", ErrInvalidInput, targetRepositoryID)
	}
	dependencies := make(map[string]map[string]struct{}, len(known))
	for _, dependency := range dependencyGraph.Dependencies {
		if dependency.Resolution != graph.ResolutionLocal || dependency.SourceRepositoryID == dependency.TargetRepositoryID || dependency.TargetRepositoryID == "" {
			continue
		}
		if _, sourceKnown := known[dependency.SourceRepositoryID]; !sourceKnown {
			continue
		}
		if _, targetKnown := known[dependency.TargetRepositoryID]; !targetKnown {
			continue
		}
		if dependencies[dependency.SourceRepositoryID] == nil {
			dependencies[dependency.SourceRepositoryID] = make(map[string]struct{})
		}
		dependencies[dependency.SourceRepositoryID][dependency.TargetRepositoryID] = struct{}{}
	}

	closure := make(map[string]struct{})
	visited := map[string]struct{}{targetRepositoryID: {}}
	queue := []string{targetRepositoryID}
	for len(queue) > 0 {
		source := queue[0]
		queue = queue[1:]
		targets := sortedStringSet(dependencies[source])
		for _, target := range targets {
			if _, seen := visited[target]; seen {
				continue
			}
			visited[target] = struct{}{}
			closure[target] = struct{}{}
			queue = append(queue, target)
		}
	}
	result := make([]string, 0, len(closure))
	for _, repositoryID := range dependencyGraph.Order {
		if _, found := closure[repositoryID]; found {
			result = append(result, repositoryID)
			delete(closure, repositoryID)
		}
	}
	for _, repositoryID := range sortedStringSet(closure) {
		result = append(result, repositoryID)
	}
	return result, nil
}

// Materialize creates a Java-source-only dependency overlay for targetRepositoryID.
// Source snapshots remain untouched. After this function returns successfully,
// dependency snapshots can be cleaned once no other target needs them; Context
// owns only the target overlay and is removed by Cleanup.
func Materialize(ctx context.Context, dependencyGraph *graph.Graph, targetRepositoryID string, snapshots []SnapshotRoot, options Options) (*Context, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is required", ErrInvalidInput)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	limits, err := normalizeOptions(options)
	if err != nil {
		return nil, err
	}
	dependencies, err := DependencyClosure(dependencyGraph, targetRepositoryID)
	if err != nil {
		return nil, err
	}
	roots, err := normalizeRoots(snapshots)
	if err != nil {
		return nil, err
	}
	target, found := roots[targetRepositoryID]
	if !found {
		return nil, fmt.Errorf("%w: target snapshot %q is missing", ErrInvalidInput, targetRepositoryID)
	}
	for _, repositoryID := range append([]string{targetRepositoryID}, dependencies...) {
		if err := validateRepositoryID(repositoryID); err != nil {
			return nil, err
		}
		if _, found := roots[repositoryID]; !found {
			return nil, fmt.Errorf("%w: dependency snapshot %q is missing", ErrInvalidInput, repositoryID)
		}
	}
	for _, dependencyID := range dependencies {
		if rootsOverlap(target, roots[dependencyID]) {
			return nil, fmt.Errorf("%w: target and dependency snapshots overlap", ErrInvalidInput)
		}
	}

	result, err := createContext(target, targetRepositoryID, dependencies)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = result.Cleanup()
		}
	}()

	state := materializationState{limits: limits}
	for _, dependencyID := range dependencies {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := materializeRepository(ctx, roots[dependencyID], result.targetRoot, dependencyID, limits.mode, &state, &result.Diagnostics); err != nil {
			return nil, err
		}
	}
	sort.Slice(state.manifest, func(left, right int) bool {
		leftEntry, rightEntry := state.manifest[left], state.manifest[right]
		if leftEntry.RepositoryID == rightEntry.RepositoryID {
			return leftEntry.Path < rightEntry.Path
		}
		return leftEntry.RepositoryID < rightEntry.RepositoryID
	})
	sort.Slice(result.Diagnostics, func(left, right int) bool {
		leftDiagnostic, rightDiagnostic := result.Diagnostics[left], result.Diagnostics[right]
		if leftDiagnostic.RepositoryID == rightDiagnostic.RepositoryID {
			if leftDiagnostic.Path == rightDiagnostic.Path {
				return leftDiagnostic.Reason < rightDiagnostic.Reason
			}
			return leftDiagnostic.Path < rightDiagnostic.Path
		}
		return leftDiagnostic.RepositoryID < rightDiagnostic.RepositoryID
	})
	result.Manifest = append([]ManifestEntry(nil), state.manifest...)
	result.ContentHash = manifestHash(result.DependencyIDs, result.Manifest)
	result.FileCount = state.files
	result.TotalBytes = state.bytes
	keep = true
	return result, nil
}

// Cleanup removes this Context's exact reserved overlay. It is safe to call
// repeatedly and never deletes a path that fails ownership validation.
func (context *Context) Cleanup() error {
	if context == nil {
		return nil
	}
	context.mu.Lock()
	defer context.mu.Unlock()
	if context.cleaned {
		return nil
	}
	missing, err := context.validateCleanupTarget()
	if err != nil {
		return err
	}
	if missing {
		context.cleaned = true
		return nil
	}
	if err := os.RemoveAll(context.overlayRoot); err != nil {
		return fmt.Errorf("remove semantic context: %w", err)
	}
	context.cleaned = true
	return nil
}

func createContext(targetRoot, targetRepositoryID string, dependencies []string) (*Context, error) {
	overlayRoot := filepath.Join(targetRoot, ReservedDirectory)
	if info, err := os.Lstat(overlayRoot); err == nil {
		_ = info
		return nil, ErrReservedPathExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect semantic context destination: %w", err)
	}
	if err := os.Mkdir(overlayRoot, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, ErrReservedPathExists
		}
		return nil, fmt.Errorf("create semantic context destination: %w", err)
	}
	createdInfo, err := os.Stat(overlayRoot)
	if err != nil {
		_ = os.RemoveAll(overlayRoot)
		return nil, fmt.Errorf("inspect semantic context destination: %w", err)
	}
	markerContents, err := newMarkerContents()
	if err != nil {
		_ = os.RemoveAll(overlayRoot)
		return nil, err
	}
	marker := filepath.Join(overlayRoot, markerName)
	if err := writeMarker(marker, markerContents); err != nil {
		_ = os.RemoveAll(overlayRoot)
		return nil, err
	}
	return &Context{
		Path:               overlayRoot,
		TargetRepositoryID: targetRepositoryID,
		DependencyIDs:      append([]string(nil), dependencies...),
		Manifest:           make([]ManifestEntry, 0),
		Diagnostics:        make([]Diagnostic, 0),
		targetRoot:         targetRoot,
		overlayRoot:        overlayRoot,
		marker:             marker,
		markerContents:     markerContents,
		createdInfo:        createdInfo,
	}, nil
}

func (context *Context) validateCleanupTarget() (missing bool, err error) {
	if context.targetRoot == "" || context.overlayRoot == "" || context.marker == "" || context.createdInfo == nil {
		return false, ErrContextUntrusted
	}
	relative, inside := relativeWithin(context.targetRoot, context.overlayRoot)
	if !inside || relative != ReservedDirectory || filepath.Dir(context.marker) != context.overlayRoot {
		return false, ErrContextUntrusted
	}
	info, statErr := os.Lstat(context.overlayRoot)
	if errors.Is(statErr, os.ErrNotExist) {
		return true, nil
	}
	if statErr != nil {
		return false, fmt.Errorf("inspect semantic context: %w", statErr)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(context.createdInfo, info) {
		return false, ErrContextUntrusted
	}
	markerInfo, markerErr := os.Lstat(context.marker)
	if markerErr != nil {
		return false, ErrContextUntrusted
	}
	if !markerInfo.Mode().IsRegular() || markerInfo.Mode()&os.ModeSymlink != 0 {
		return false, ErrContextUntrusted
	}
	contents, markerErr := os.ReadFile(context.marker)
	if markerErr != nil || string(contents) != context.markerContents {
		return false, ErrContextUntrusted
	}
	return false, nil
}

type normalizedOptions struct {
	mode          CopyMode
	maxEntries    int
	maxFiles      int
	maxFileBytes  int64
	maxTotalBytes int64
	maxDepth      int
}

func normalizeOptions(options Options) (normalizedOptions, error) {
	if options.Mode == "" {
		options.Mode = CopyModeAuto
	}
	if options.Mode != CopyModeAuto && options.Mode != CopyModeCopy && options.Mode != CopyModeHardLink {
		return normalizedOptions{}, fmt.Errorf("%w: unknown copy mode %q", ErrInvalidInput, options.Mode)
	}
	result := normalizedOptions{mode: options.Mode, maxEntries: defaultMaxEntries, maxFiles: defaultMaxFiles, maxFileBytes: defaultMaxFileBytes, maxTotalBytes: defaultMaxTotalBytes, maxDepth: defaultMaxDepth}
	if options.MaxEntries < 0 || options.MaxFiles < 0 || options.MaxFileBytes < 0 || options.MaxTotalBytes < 0 || options.MaxDepth < 0 {
		return normalizedOptions{}, fmt.Errorf("%w: limits cannot be negative", ErrInvalidInput)
	}
	if options.MaxEntries > maxEntries || options.MaxFiles > maxFiles || options.MaxFileBytes > maxFileBytes || options.MaxTotalBytes > maxTotalBytes || options.MaxDepth > maxDepth {
		return normalizedOptions{}, fmt.Errorf("%w: options exceed package hard maximum", ErrLimitExceeded)
	}
	if options.MaxEntries > 0 {
		result.maxEntries = options.MaxEntries
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

func normalizeRoots(roots []SnapshotRoot) (map[string]string, error) {
	result := make(map[string]string, len(roots))
	for _, root := range roots {
		if err := validateRepositoryID(root.RepositoryID); err != nil {
			return nil, err
		}
		if _, duplicate := result[root.RepositoryID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate snapshot ID %q", ErrInvalidInput, root.RepositoryID)
		}
		absolute, err := filepath.Abs(root.Root)
		if err != nil {
			return nil, fmt.Errorf("%w: resolve snapshot root: %v", ErrInvalidInput, err)
		}
		resolved, err := filepath.EvalSymlinks(absolute)
		if err != nil {
			return nil, fmt.Errorf("%w: resolve snapshot root: %v", ErrInvalidInput, err)
		}
		info, err := os.Lstat(resolved)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			if err != nil {
				return nil, fmt.Errorf("%w: inspect snapshot root: %v", ErrInvalidInput, err)
			}
			return nil, fmt.Errorf("%w: snapshot root is not a regular directory", ErrInvalidInput)
		}
		result[root.RepositoryID] = filepath.Clean(resolved)
	}
	return result, nil
}

func validateRepositoryID(repositoryID string) error {
	repositoryID = strings.TrimSpace(repositoryID)
	if repositoryID == "" || repositoryID == "." || repositoryID == ".." || filepath.Base(repositoryID) != repositoryID || strings.ContainsAny(repositoryID, `/\\`) {
		return fmt.Errorf("%w: repository ID %q is not one safe path component", ErrInvalidInput, repositoryID)
	}
	return nil
}

func rootsOverlap(first, second string) bool {
	if first == second {
		return true
	}
	_, firstInsideSecond := relativeWithin(second, first)
	_, secondInsideFirst := relativeWithin(first, second)
	return firstInsideSecond || secondInsideFirst
}

func relativeWithin(root, candidate string) (string, bool) {
	relative, err := filepath.Rel(root, candidate)
	if err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", false
	}
	return relative, true
}

func newMarkerContents() (string, error) {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", fmt.Errorf("create semantic context marker: %w", err)
	}
	return markerMagic + "\n" + hex.EncodeToString(token[:]) + "\n", nil
}

func writeMarker(name, contents string) error {
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create semantic context marker: %w", err)
	}
	_, writeErr := io.WriteString(file, contents)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(name)
		if writeErr != nil {
			return fmt.Errorf("write semantic context marker: %w", writeErr)
		}
		return fmt.Errorf("close semantic context marker: %w", closeErr)
	}
	return nil
}

func manifestHash(dependencies []string, entries []ManifestEntry) string {
	digest := sha256.New()
	writeManifestField(digest, "format", manifestFormat)
	for _, dependency := range dependencies {
		writeManifestField(digest, "dependency", dependency)
	}
	for _, entry := range entries {
		writeManifestField(digest, "repository", entry.RepositoryID)
		writeManifestField(digest, "path", entry.Path)
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

func sortedStringSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

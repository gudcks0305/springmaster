// Package workspace discovers local Spring repositories and captures the Git
// state needed to safely address an analysis request.
package workspace

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maxGitOutputBytes    = 4 << 20
	maxSpringFiles       = 20_000
	maxSpringFileRead    = 256 << 10
	maxRelevantFileBytes = 64 << 20
	maxRelevantFileCount = 50_000
	contentHashVersion   = "springmaster-workspace-content-v1"
	repositoryIDPrefix   = "repo_"
)

var errOutputLimit = errors.New("git output exceeds configured limit")

// Options controls repository discovery. MaxDepth is counted from root; zero
// means no depth limit. Include and Exclude use slash-separated glob patterns.
// A pattern without a slash also matches the repository directory name.
type Options struct {
	MaxDepth     int
	Include      []string
	Exclude      []string
	OnDiagnostic func(Diagnostic)
}

// Diagnostic reports a repository-scoped discovery problem that made a
// candidate incomplete or unsafe to classify. Discovery continues with sibling
// repositories; callers may surface these diagnostics in their own report.
type Diagnostic struct {
	Path    string
	Code    string
	Message string
}

// Repository is the immutable Git state passed to an analyzer worker.
type Repository struct {
	ID          string
	Path        string
	Branch      string
	Head        string
	RemoteURL   string
	ContentHash string
	Dirty       bool
	Untracked   bool
}

// Discover recursively finds Spring Git repositories below root. It never
// traverses .git metadata directories, but it can discover a nested worktree.
func Discover(ctx context.Context, root string, options Options) ([]Repository, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve workspace root: %w", err)
	}
	absRoot = filepath.Clean(absRoot)
	info, err := os.Stat(absRoot)
	if err != nil {
		return nil, fmt.Errorf("stat workspace root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("workspace root is not a directory: %s", absRoot)
	}

	runner := gitRunner{outputLimit: maxGitOutputBytes}
	repositories := make([]Repository, 0)
	seen := make(map[string]struct{})
	err = filepath.WalkDir(absRoot, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}

		rel, err := filepath.Rel(absRoot, current)
		if err != nil {
			return fmt.Errorf("calculate workspace relative path: %w", err)
		}
		rel = normalizeRelativePath(rel)
		if entry.IsDir() && entry.Name() == ".git" {
			return filepath.SkipDir
		}
		if current != absRoot && matchesAny(options.Exclude, rel) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.IsDir() {
			return nil
		}
		if options.MaxDepth > 0 && relativeDepth(rel) > options.MaxDepth {
			return filepath.SkipDir
		}
		if !hasGitMarker(current) || !matchesInclude(options.Include, rel) {
			return nil
		}
		if _, duplicate := seen[current]; duplicate {
			return nil
		}
		isSpring, err := springRepository(ctx, current)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			if options.OnDiagnostic != nil {
				options.OnDiagnostic(Diagnostic{
					Path:    current,
					Code:    "spring_prefilter_incomplete",
					Message: err.Error(),
				})
			}
			return filepath.SkipDir
		}
		if !isSpring {
			return nil
		}

		repository, err := inspectRepository(ctx, runner, current)
		if err != nil {
			return err
		}
		seen[current] = struct{}{}
		repositories = append(repositories, repository)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("discover repositories below %s: %w", absRoot, err)
	}
	sort.Slice(repositories, func(i, j int) bool { return repositories[i].Path < repositories[j].Path })
	return repositories, nil
}

func inspectRepository(ctx context.Context, runner gitRunner, root string) (Repository, error) {
	inside, err := runner.run(ctx, root, "rev-parse", "--is-inside-work-tree")
	if err != nil {
		return Repository{}, fmt.Errorf("verify Git repository %s: %w", root, err)
	}
	if strings.TrimSpace(inside) != "true" {
		return Repository{}, fmt.Errorf("Git marker is not a work tree: %s", root)
	}

	head, err := runner.run(ctx, root, "rev-parse", "--verify", "HEAD")
	if err != nil {
		if !hasExitCode(err, 128) {
			return Repository{}, fmt.Errorf("read Git HEAD for %s: %w", root, err)
		}
		head = ""
	}
	branch, err := runner.run(ctx, root, "symbolic-ref", "--quiet", "--short", "HEAD")
	if err != nil {
		if !hasExitCode(err, 1) {
			return Repository{}, fmt.Errorf("read Git branch for %s: %w", root, err)
		}
		branch = "HEAD"
	}
	remoteURL, err := runner.run(ctx, root, "config", "--get", "remote.origin.url")
	if err != nil {
		if !hasExitCode(err, 1) {
			return Repository{}, fmt.Errorf("read Git remote for %s: %w", root, err)
		}
		remoteURL = ""
	}
	remoteURL = sanitizeRemoteURL(remoteURL)
	statusOutput, err := runner.run(ctx, root, "--no-optional-locks", "status", "--porcelain=v1", "-z", "--no-renames", "--untracked-files=all", "--ignore-submodules=none")
	if err != nil {
		return Repository{}, fmt.Errorf("read Git status for %s: %w", root, err)
	}
	changes, err := parseStatus([]byte(statusOutput))
	if err != nil {
		return Repository{}, fmt.Errorf("parse Git status for %s: %w", root, err)
	}
	contentHash, err := hashRepositoryContent(ctx, runner, root, strings.TrimSpace(head), changes)
	if err != nil {
		return Repository{}, fmt.Errorf("hash repository content for %s: %w", root, err)
	}

	return Repository{
		ID:          repositoryID(root, remoteURL),
		Path:        root,
		Branch:      strings.TrimSpace(branch),
		Head:        strings.TrimSpace(head),
		RemoteURL:   remoteURL,
		ContentHash: contentHash,
		Dirty:       len(changes) > 0,
		Untracked:   anyUntracked(changes),
	}, nil
}

func springRepository(ctx context.Context, root string) (bool, error) {
	var buildFileFound, springMarkerFound bool
	filesChecked := 0
	err := filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			if current != root && ignoredContentPath(filepath.Base(current)) {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}

		filesChecked++
		if filesChecked > maxSpringFiles {
			return fmt.Errorf("Spring prefilter exceeded %d files", maxSpringFiles)
		}
		name := entry.Name()
		isBuildFile := name == "pom.xml" || name == "build.gradle" || name == "build.gradle.kts"
		if !isBuildFile && !springMarkerCandidate(name) {
			return nil
		}
		if isBuildFile {
			buildFileFound = true
		}
		containsMarker, err := fileContainsMarker(current, maxSpringFileRead)
		if err != nil {
			return err
		}
		if containsMarker {
			springMarkerFound = true
		}
		if buildFileFound && springMarkerFound {
			return fs.SkipAll
		}
		return nil
	})
	if errors.Is(err, fs.SkipAll) {
		err = nil
	}
	if err != nil {
		return false, err
	}
	return buildFileFound && springMarkerFound, nil
}

func fileContainsMarker(fileName string, limit int64) (bool, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return false, err
	}
	defer file.Close()

	contents, err := io.ReadAll(io.LimitReader(file, limit))
	if err != nil {
		return false, err
	}
	text := strings.ToLower(string(contents))
	return strings.Contains(text, "org.springframework") ||
		strings.Contains(text, "spring-boot") ||
		strings.Contains(text, "springframework") ||
		strings.Contains(text, "@springbootapplication") ||
		strings.Contains(text, "spring.application"), nil
}

func hasGitMarker(directory string) bool {
	info, err := os.Lstat(filepath.Join(directory, ".git"))
	if err != nil {
		return false
	}
	return info.IsDir() || info.Mode().IsRegular()
}

func springMarkerCandidate(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".java", ".kt", ".groovy", ".properties", ".yml", ".yaml":
		return true
	default:
		return false
	}
}

func hashRepositoryContent(ctx context.Context, runner gitRunner, root, head string, changes []statusEntry) (string, error) {
	digest := sha256.New()
	writeHashField(digest, "version", contentHashVersion)
	writeHashField(digest, "head", head)

	relevant := make([]statusEntry, 0, len(changes))
	for _, change := range changes {
		if relevantRepositoryPath(change.path) {
			relevant = append(relevant, change)
		}
	}
	if len(relevant) > maxRelevantFileCount {
		return "", fmt.Errorf("relevant change count exceeds %d", maxRelevantFileCount)
	}
	sort.Slice(relevant, func(i, j int) bool { return relevant[i].sortKey() < relevant[j].sortKey() })
	for _, change := range relevant {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		writeHashField(digest, "status", change.status)
		writeHashField(digest, "path", change.path)
		writeHashField(digest, "from", change.from)
		if err := hashWorkingPath(ctx, digest, runner, root, change.path); err != nil {
			return "", err
		}
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

func hashWorkingPath(ctx context.Context, digest hash.Hash, runner gitRunner, root, relativePath string) error {
	if !relevantRepositoryPath(relativePath) {
		writeHashField(digest, "kind", "excluded")
		return nil
	}
	fullPath, err := repositoryPath(root, relativePath)
	if err != nil {
		return err
	}
	info, err := os.Lstat(fullPath)
	if errors.Is(err, os.ErrNotExist) {
		writeHashField(digest, "kind", "missing")
		return nil
	}
	if err != nil {
		return err
	}

	switch {
	case info.Mode().IsRegular():
		writeHashField(digest, "kind", "file")
		return hashRegularFile(ctx, digest, fullPath, info.Size())
	case info.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(fullPath)
		if err != nil {
			return err
		}
		writeHashField(digest, "kind", "symlink")
		writeHashField(digest, "target", target)
		return nil
	case info.IsDir():
		writeHashField(digest, "kind", "directory")
		if hasGitMarker(fullPath) {
			head, err := runner.run(ctx, fullPath, "rev-parse", "--verify", "HEAD")
			if err == nil {
				statusOutput, statusErr := runner.run(ctx, fullPath, "--no-optional-locks", "status", "--porcelain=v1", "-z", "--no-renames", "--untracked-files=all", "--ignore-submodules=none")
				if statusErr != nil {
					return statusErr
				}
				changes, parseErr := parseStatus([]byte(statusOutput))
				if parseErr != nil {
					return parseErr
				}
				submoduleHash, hashErr := hashRepositoryContent(ctx, runner, fullPath, strings.TrimSpace(head), changes)
				if hashErr != nil {
					return hashErr
				}
				writeHashField(digest, "submodule-content", submoduleHash)
				return nil
			}
			if !hasExitCode(err, 128) {
				return err
			}
		}
		return nil
	default:
		writeHashField(digest, "kind", info.Mode().String())
		return nil
	}
}

func hashRegularFile(ctx context.Context, digest hash.Hash, fileName string, size int64) error {
	if size > maxRelevantFileBytes {
		return fmt.Errorf("file exceeds %d byte hash limit: %s", maxRelevantFileBytes, fileName)
	}
	writeHashField(digest, "size", fmt.Sprintf("%d", size))
	file, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() || before.Size() != size {
		return fmt.Errorf("file changed while hashing: %s", fileName)
	}

	buffer := make([]byte, 32<<10)
	var copied int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		read, readErr := file.Read(buffer)
		if read > 0 {
			copied += int64(read)
			if copied > maxRelevantFileBytes {
				return fmt.Errorf("file exceeds %d byte hash limit: %s", maxRelevantFileBytes, fileName)
			}
			_, _ = digest.Write(buffer[:read])
		}
		if errors.Is(readErr, io.EOF) {
			after, statErr := file.Stat()
			if statErr != nil {
				return statErr
			}
			if !os.SameFile(before, after) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || copied != before.Size() {
				return fmt.Errorf("file changed while hashing: %s", fileName)
			}
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

type statusEntry struct {
	status string
	path   string
	from   string
}

func (entry statusEntry) sortKey() string {
	return entry.path + "\x00" + entry.from + "\x00" + entry.status
}

func parseStatus(data []byte) ([]statusEntry, error) {
	if len(data) == 0 {
		return nil, nil
	}
	parts := bytes.Split(data, []byte{0})
	entries := make([]statusEntry, 0, len(parts))
	for index := 0; index < len(parts); index++ {
		part := parts[index]
		if len(part) == 0 {
			continue
		}
		if len(part) < 4 || part[2] != ' ' {
			return nil, fmt.Errorf("unexpected porcelain record %q", string(part))
		}
		entry := statusEntry{status: string(part[:2]), path: string(part[3:])}
		if entry.path == "" {
			return nil, errors.New("empty porcelain path")
		}
		if strings.ContainsAny(entry.status, "RC") {
			index++
			if index >= len(parts) || len(parts[index]) == 0 {
				return nil, errors.New("rename porcelain record missing source path")
			}
			entry.from = string(parts[index])
		}
		if !validRelativeRepositoryPath(entry.path) || (entry.from != "" && !validRelativeRepositoryPath(entry.from)) {
			return nil, errors.New("porcelain path escapes repository")
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func anyUntracked(entries []statusEntry) bool {
	for _, entry := range entries {
		if entry.status == "??" {
			return true
		}
	}
	return false
}

func repositoryID(repositoryPath, remoteURL string) string {
	canonicalPath := canonicalRepositoryPath(repositoryPath)
	identity := "path\x00" + canonicalPath + "\x00remote\x00" + sanitizeRemoteURL(remoteURL)
	digest := sha256.Sum256([]byte(identity))
	return repositoryIDPrefix + hex.EncodeToString(digest[:])
}

func canonicalRepositoryPath(repositoryPath string) string {
	absolute, err := filepath.Abs(repositoryPath)
	if err != nil {
		return filepath.Clean(repositoryPath)
	}
	absolute = filepath.Clean(absolute)
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return absolute
	}
	return filepath.Clean(resolved)
}

// sanitizeRemoteURL removes credentials and URL-only secret-bearing components
// before a remote is stored, logged, or incorporated into a repository ID.
// Git's SCP-like SSH syntax (user@host:path) is handled without turning the
// repository path into an opaque URL.
func sanitizeRemoteURL(raw string) string {
	remote := stripRemoteSuffix(strings.TrimSpace(raw))
	if remote == "" {
		return ""
	}
	if !strings.Contains(remote, "://") && strings.ContainsRune(remote, '@') {
		if separator := scpSeparator(remote); separator > 0 {
			host := remote[:separator]
			if at := strings.LastIndexByte(host, '@'); at >= 0 {
				host = host[at+1:]
			}
			return host + ":" + remote[separator+1:]
		}
	}
	if parsed, err := url.Parse(remote); err == nil && (parsed.Scheme != "" || parsed.Host != "") {
		parsed.User = nil
		parsed.RawQuery = ""
		parsed.ForceQuery = false
		parsed.Fragment = ""
		return parsed.String()
	}

	if schemeEnd := strings.Index(remote, "://"); schemeEnd > 0 {
		authorityStart := schemeEnd + 3
		authorityEnd := len(remote)
		if separator := strings.IndexAny(remote[authorityStart:], `/\\`); separator >= 0 {
			authorityEnd = authorityStart + separator
		}
		authority := remote[authorityStart:authorityEnd]
		if at := strings.LastIndexByte(authority, '@'); at >= 0 {
			authority = authority[at+1:]
		}
		return remote[:authorityStart] + authority + remote[authorityEnd:]
	}
	separator := scpSeparator(remote)
	if separator <= 0 {
		return remote
	}
	host := remote[:separator]
	if strings.ContainsAny(host, `/\\`) {
		return remote
	}
	if at := strings.LastIndexByte(host, '@'); at >= 0 {
		host = host[at+1:]
	}
	if host == "" {
		return remote[separator+1:]
	}
	return host + ":" + remote[separator+1:]
}

func stripRemoteSuffix(remote string) string {
	if index := strings.IndexAny(remote, "?#"); index >= 0 {
		return remote[:index]
	}
	return remote
}

func scpSeparator(remote string) int {
	if strings.HasPrefix(remote, "[") {
		if closing := strings.IndexByte(remote, ']'); closing >= 0 && closing+1 < len(remote) && remote[closing+1] == ':' {
			return closing + 1
		}
	}
	if at := strings.LastIndexByte(remote, '@'); at >= 0 {
		if colon := strings.IndexByte(remote[at+1:], ':'); colon >= 0 {
			return at + 1 + colon
		}
	}
	return strings.IndexByte(remote, ':')
}

func repositoryPath(root, relativePath string) (string, error) {
	if !validRelativeRepositoryPath(relativePath) {
		return "", fmt.Errorf("invalid repository-relative path: %q", relativePath)
	}
	fullPath := filepath.Join(root, filepath.FromSlash(relativePath))
	relative, err := filepath.Rel(root, fullPath)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("repository-relative path escapes root: %q", relativePath)
	}
	return fullPath, nil
}

func relevantRepositoryPath(relativePath string) bool {
	if !validRelativeRepositoryPath(relativePath) {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(relativePath), "/") {
		if ignoredContentPath(part) {
			return false
		}
	}
	return true
}

func ignoredContentPath(part string) bool {
	switch part {
	case ".git", "build", "target", "node_modules":
		return true
	default:
		return false
	}
}

func validRelativeRepositoryPath(relativePath string) bool {
	if relativePath == "" || filepath.IsAbs(relativePath) {
		return false
	}
	clean := filepath.Clean(filepath.FromSlash(relativePath))
	return clean != "." && clean != ".." && !strings.HasPrefix(clean, ".."+string(filepath.Separator))
}

func writeHashField(digest hash.Hash, name, value string) {
	_, _ = fmt.Fprintf(digest, "%s:%d:", name, len(value))
	_, _ = io.WriteString(digest, value)
	_, _ = io.WriteString(digest, "\n")
}

func normalizeRelativePath(relativePath string) string {
	if relativePath == "." {
		return "."
	}
	return filepath.ToSlash(relativePath)
}

func relativeDepth(relativePath string) int {
	if relativePath == "." || relativePath == "" {
		return 0
	}
	return strings.Count(relativePath, "/") + 1
}

func matchesInclude(patterns []string, relativePath string) bool {
	return len(patterns) == 0 || matchesAny(patterns, relativePath)
}

func matchesAny(patterns []string, relativePath string) bool {
	for _, pattern := range patterns {
		if matchesPattern(pattern, relativePath) {
			return true
		}
	}
	return false
}

func matchesPattern(pattern, relativePath string) bool {
	pattern = strings.TrimPrefix(filepath.ToSlash(filepath.Clean(pattern)), "./")
	if pattern == "." {
		return relativePath == "."
	}
	if ok, err := path.Match(pattern, relativePath); err == nil && ok {
		return true
	}
	if !strings.Contains(pattern, "/") {
		if ok, err := path.Match(pattern, path.Base(relativePath)); err == nil && ok {
			return true
		}
	}
	return globStarMatch(strings.Split(pattern, "/"), strings.Split(relativePath, "/"))
}

func globStarMatch(pattern, target []string) bool {
	if len(pattern) == 0 {
		return len(target) == 0
	}
	if pattern[0] == "**" {
		for index := 0; index <= len(target); index++ {
			if globStarMatch(pattern[1:], target[index:]) {
				return true
			}
		}
		return false
	}
	if len(target) == 0 {
		return false
	}
	ok, err := path.Match(pattern[0], target[0])
	return err == nil && ok && globStarMatch(pattern[1:], target[1:])
}

type gitRunner struct {
	outputLimit int
}

func (runner gitRunner) run(ctx context.Context, directory string, arguments ...string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	commandArguments := append([]string{"-C", directory}, arguments...)
	command := exec.CommandContext(ctx, "git", commandArguments...)
	stdout := &limitedBuffer{limit: runner.outputLimit}
	stderr := &limitedBuffer{limit: runner.outputLimit}
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	if stdout.exceeded || stderr.exceeded {
		return "", errOutputLimit
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		return "", &gitCommandError{err: err, stderr: stderr.String()}
	}
	return stdout.String(), nil
}

type limitedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (buffer *limitedBuffer) Write(data []byte) (int, error) {
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining <= 0 {
		buffer.exceeded = true
		return len(data), nil
	}
	if len(data) > remaining {
		_, _ = buffer.buffer.Write(data[:remaining])
		buffer.exceeded = true
		return len(data), nil
	}
	_, _ = buffer.buffer.Write(data)
	return len(data), nil
}

func (buffer *limitedBuffer) String() string { return buffer.buffer.String() }

type gitCommandError struct {
	err    error
	stderr string
}

func (err *gitCommandError) Error() string {
	message := strings.TrimSpace(err.stderr)
	if message == "" {
		return err.err.Error()
	}
	return err.err.Error() + ": " + message
}

func (err *gitCommandError) Unwrap() error { return err.err }

func hasExitCode(err error, code int) bool {
	var exitError *exec.ExitError
	return errors.As(err, &exitError) && exitError.ExitCode() == code
}

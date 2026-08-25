package semantic

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const maxDiagnostics = 1_024

type materializationState struct {
	limits  normalizedOptions
	entries int
	files   int
	bytes   int64

	manifest []ManifestEntry
}

func materializeRepository(ctx context.Context, sourceRoot, targetRoot, repositoryID string, mode CopyMode, state *materializationState, diagnostics *[]Diagnostic) error {
	source, err := os.OpenRoot(sourceRoot)
	if err != nil {
		return fmt.Errorf("open dependency snapshot root: %w", err)
	}
	defer source.Close()
	target, err := os.OpenRoot(targetRoot)
	if err != nil {
		return fmt.Errorf("open target snapshot root: %w", err)
	}
	defer target.Close()

	return fs.WalkDir(source.FS(), ".", func(relative string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk dependency source: %w", walkErr)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		depth := sourceDepth(relative)
		if err := state.addEntry(relative, depth); err != nil {
			return err
		}
		if entry.IsDir() {
			if excludedSourceDirectory(filepath.Base(filepath.FromSlash(relative))) {
				return fs.SkipDir
			}
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			appendDiagnostic(diagnostics, Diagnostic{RepositoryID: repositoryID, Path: filepath.ToSlash(relative), Reason: "symbolic link skipped"})
			return nil
		}
		relativeOS := filepath.FromSlash(relative)
		info, err := source.Lstat(relativeOS)
		if err != nil {
			return fmt.Errorf("inspect dependency source: %w", err)
		}
		if !info.Mode().IsRegular() {
			appendDiagnostic(diagnostics, Diagnostic{RepositoryID: repositoryID, Path: filepath.ToSlash(relative), Reason: "non-regular file skipped"})
			return nil
		}
		if !strings.HasSuffix(relative, ".java") {
			return nil
		}
		if err := state.addFile(relative, info.Size()); err != nil {
			return err
		}
		destinationRelative, err := contextDestinationRelative(repositoryID, relativeOS)
		if err != nil {
			return err
		}
		if err := target.MkdirAll(filepath.Dir(destinationRelative), 0o700); err != nil {
			return fmt.Errorf("create dependency context directory: %w", err)
		}
		sourceAbsolute := filepath.Join(sourceRoot, relativeOS)
		destinationAbsolute := filepath.Join(targetRoot, destinationRelative)
		if _, inside := relativeWithin(sourceRoot, sourceAbsolute); !inside {
			return fmt.Errorf("%w: dependency source path escapes root", ErrInvalidInput)
		}
		if _, inside := relativeWithin(filepath.Join(targetRoot, ReservedDirectory), destinationAbsolute); !inside {
			return fmt.Errorf("%w: dependency context path escapes reserved root", ErrInvalidInput)
		}
		sha256sum, err := materializeRegularFile(ctx, source, target, sourceAbsolute, destinationAbsolute, relativeOS, destinationRelative, info, mode)
		if err != nil {
			return err
		}
		state.manifest = append(state.manifest, ManifestEntry{
			RepositoryID: repositoryID,
			Path:         filepath.ToSlash(filepath.Join(repositoryID, relativeOS)),
			Mode:         uint32(info.Mode().Perm()),
			Size:         info.Size(),
			SHA256:       sha256sum,
		})
		return nil
	})
}

func (state *materializationState) addEntry(relative string, depth int) error {
	if depth > state.limits.maxDepth {
		return fmt.Errorf("%w: path depth exceeds %d at %q", ErrLimitExceeded, state.limits.maxDepth, filepath.ToSlash(relative))
	}
	state.entries++
	if state.entries > state.limits.maxEntries {
		return fmt.Errorf("%w: entry count exceeds %d", ErrLimitExceeded, state.limits.maxEntries)
	}
	return nil
}

func (state *materializationState) addFile(relative string, size int64) error {
	if size < 0 || size > state.limits.maxFileBytes {
		return fmt.Errorf("%w: Java source exceeds %d bytes at %q", ErrLimitExceeded, state.limits.maxFileBytes, filepath.ToSlash(relative))
	}
	if state.files >= state.limits.maxFiles {
		return fmt.Errorf("%w: Java source count exceeds %d", ErrLimitExceeded, state.limits.maxFiles)
	}
	if state.bytes > state.limits.maxTotalBytes-size {
		return fmt.Errorf("%w: total Java source bytes exceed %d", ErrLimitExceeded, state.limits.maxTotalBytes)
	}
	state.files++
	state.bytes += size
	return nil
}

func materializeRegularFile(ctx context.Context, source, target *os.Root, sourceAbsolute, destinationAbsolute, sourceRelative, destinationRelative string, before os.FileInfo, mode CopyMode) (string, error) {
	if mode == CopyModeCopy {
		return copyRegularFile(ctx, source, target, sourceRelative, destinationRelative, before)
	}
	hash, err := hashRegularFile(ctx, source, sourceRelative, before)
	if err != nil {
		return "", err
	}
	if err := os.Link(sourceAbsolute, destinationAbsolute); err == nil {
		destinationInfo, destinationErr := target.Lstat(destinationRelative)
		sourceAfter, sourceErr := source.Lstat(sourceRelative)
		if destinationErr != nil || sourceErr != nil || !destinationInfo.Mode().IsRegular() || !os.SameFile(before, destinationInfo) || !sameStableFile(before, sourceAfter) {
			_ = target.Remove(destinationRelative)
			return "", fmt.Errorf("%w: dependency source changed while hard-linking", ErrSourceChanged)
		}
		return hash, nil
	} else if mode == CopyModeHardLink {
		return "", fmt.Errorf("hard-link dependency source: %w", err)
	}
	// A failed Link may leave a destination on unusual filesystems. Never
	// overwrite one; otherwise a byte copy is the safe portable fallback.
	if _, statErr := target.Lstat(destinationRelative); statErr == nil {
		return "", fmt.Errorf("materialize dependency source: destination already exists")
	} else if !os.IsNotExist(statErr) {
		return "", fmt.Errorf("inspect failed hard-link destination: %w", statErr)
	}
	return copyRegularFile(ctx, source, target, sourceRelative, destinationRelative, before)
}

func hashRegularFile(ctx context.Context, source *os.Root, relative string, before os.FileInfo) (string, error) {
	file, err := source.Open(relative)
	if err != nil {
		return "", fmt.Errorf("open dependency source: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !sameStableFile(before, opened) {
		return "", fmt.Errorf("%w: dependency source changed before reading", ErrSourceChanged)
	}
	digest := sha256.New()
	copied, err := copyWithContext(ctx, digest, file)
	if err != nil {
		return "", err
	}
	after, err := file.Stat()
	if err != nil || copied != before.Size() || !sameStableFile(before, after) {
		return "", fmt.Errorf("%w: dependency source changed while reading", ErrSourceChanged)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func copyRegularFile(ctx context.Context, source, target *os.Root, sourceRelative, destinationRelative string, before os.FileInfo) (result string, err error) {
	input, err := source.Open(sourceRelative)
	if err != nil {
		return "", fmt.Errorf("open dependency source: %w", err)
	}
	defer input.Close()
	opened, err := input.Stat()
	if err != nil || !sameStableFile(before, opened) {
		return "", fmt.Errorf("%w: dependency source changed before copying", ErrSourceChanged)
	}
	output, err := target.OpenFile(destinationRelative, os.O_WRONLY|os.O_CREATE|os.O_EXCL, before.Mode().Perm())
	if err != nil {
		return "", fmt.Errorf("create dependency context source: %w", err)
	}
	completed := false
	defer func() {
		closeErr := output.Close()
		if err == nil && closeErr != nil {
			err = fmt.Errorf("close dependency context source: %w", closeErr)
		}
		if !completed || err != nil {
			_ = target.Remove(destinationRelative)
		}
	}()
	digest := sha256.New()
	copied, err := copyWithContext(ctx, io.MultiWriter(output, digest), input)
	if err != nil {
		return "", err
	}
	after, statErr := input.Stat()
	if statErr != nil || copied != before.Size() || !sameStableFile(before, after) {
		return "", fmt.Errorf("%w: dependency source changed while copying", ErrSourceChanged)
	}
	if chmodErr := output.Chmod(before.Mode().Perm()); chmodErr != nil {
		return "", fmt.Errorf("set dependency context source mode: %w", chmodErr)
	}
	completed = true
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func copyWithContext(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	buffer := make([]byte, 64<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		read, readErr := source.Read(buffer)
		if read > 0 {
			written, writeErr := destination.Write(buffer[:read])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != read {
				return total, io.ErrShortWrite
			}
		}
		if readErr == io.EOF {
			return total, nil
		}
		if readErr != nil {
			return total, readErr
		}
	}
}

func contextDestinationRelative(repositoryID, sourceRelative string) (string, error) {
	if sourceRelative == "" || filepath.IsAbs(sourceRelative) || !filepath.IsLocal(sourceRelative) {
		return "", fmt.Errorf("%w: unsafe dependency source path", ErrInvalidInput)
	}
	for _, component := range strings.Split(sourceRelative, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return "", fmt.Errorf("%w: unsafe dependency source path", ErrInvalidInput)
		}
	}
	return filepath.Join(ReservedDirectory, repositoryID, sourceRelative), nil
}

func sourceDepth(relative string) int {
	if relative == "." || relative == "" {
		return 0
	}
	return strings.Count(relative, "/") + 1
}

func excludedSourceDirectory(name string) bool {
	switch name {
	case ".git", ".gradle", ".springmaster", "build", "target", "node_modules", "dist", ".idea", ".vscode", ReservedDirectory:
		return true
	default:
		return false
	}
}

func sameStableFile(before, after os.FileInfo) bool {
	return before != nil && after != nil && os.SameFile(before, after) && before.Mode() == after.Mode() && before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
}

func appendDiagnostic(diagnostics *[]Diagnostic, diagnostic Diagnostic) {
	if len(*diagnostics) >= maxDiagnostics {
		return
	}
	*diagnostics = append(*diagnostics, diagnostic)
}

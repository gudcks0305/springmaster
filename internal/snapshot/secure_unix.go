//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package snapshot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"
)

func secureCopyTree(ctx context.Context, sourceRoot, destinationRoot string, excluded map[string]struct{}, diagnostics *[]Diagnostic, state *copyState) error {
	expected, err := os.Lstat(sourceRoot)
	if err != nil || !expected.IsDir() || expected.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: inspect source root", ErrSourceChanged)
	}
	fd, err := unix.Open(sourceRoot, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open source root without following links: %w", err)
	}
	root := os.NewFile(uintptr(fd), sourceRoot)
	if root == nil {
		_ = unix.Close(fd)
		return errors.New("wrap source root descriptor")
	}
	defer root.Close()
	opened, err := root.Stat()
	if err != nil || !sameStableEntry(expected, opened) {
		return fmt.Errorf("%w: source root replaced before descriptor open", ErrSourceChanged)
	}
	return secureCopyDirectory(ctx, root, sourceRoot, destinationRoot, ".", destinationRoot, excluded, diagnostics, state, 0)
}

func secureContentTree(ctx context.Context, sourceRoot string, excluded map[string]struct{}, state *copyState) error {
	expected, err := os.Lstat(sourceRoot)
	if err != nil || !expected.IsDir() || expected.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: inspect source root", ErrSourceChanged)
	}
	fd, err := unix.Open(sourceRoot, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open source root without following links: %w", err)
	}
	root := os.NewFile(uintptr(fd), sourceRoot)
	if root == nil {
		_ = unix.Close(fd)
		return errors.New("wrap source root descriptor")
	}
	defer root.Close()
	opened, err := root.Stat()
	if err != nil || !sameStableEntry(expected, opened) {
		return fmt.Errorf("%w: source root replaced before descriptor open", ErrSourceChanged)
	}
	var diagnostics []Diagnostic
	return secureContentDirectory(ctx, root, sourceRoot, ".", excluded, &diagnostics, state, 0)
}

func secureContentDirectory(ctx context.Context, sourceDirectory *os.File, sourceRoot, relativeDirectory string, excluded map[string]struct{}, diagnostics *[]Diagnostic, state *copyState, depth int) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	directoryBefore, err := sourceDirectory.Stat()
	if err != nil || !directoryBefore.IsDir() {
		return fmt.Errorf("%w: inspect directory %q", ErrSourceChanged, filepath.ToSlash(relativeDirectory))
	}
	entries, err := sourceDirectory.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("read source directory %q: %w", filepath.ToSlash(relativeDirectory), err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, entry := range entries {
		if err := contextError(ctx); err != nil {
			return err
		}
		name := entry.Name()
		if err := validateName(name); err != nil {
			return fmt.Errorf("unsafe source entry name %q: %w", name, err)
		}
		if _, skip := excluded[name]; skip {
			continue
		}
		relative := name
		if relativeDirectory != "." {
			relative = filepath.Join(relativeDirectory, name)
		}
		entryDepth := depth + 1
		if err := state.addEntry(relative, entryDepth); err != nil {
			return err
		}

		var expected unix.Stat_t
		if err := unix.Fstatat(int(sourceDirectory.Fd()), name, &expected, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("%w: inspect entry %q: %v", ErrSourceChanged, filepath.ToSlash(relative), err)
		}
		switch expected.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			child, err := openDirectoryAt(int(sourceDirectory.Fd()), name, expected)
			if err != nil {
				return fmt.Errorf("%w at %q", err, filepath.ToSlash(relative))
			}
			walkErr := secureContentDirectory(ctx, child, sourceRoot, relative, excluded, diagnostics, state, entryDepth)
			closeErr := child.Close()
			if walkErr != nil {
				return walkErr
			}
			if closeErr != nil {
				return fmt.Errorf("close source directory %q: %w", filepath.ToSlash(relative), closeErr)
			}
			if err := verifyEntryAt(int(sourceDirectory.Fd()), name, expected); err != nil {
				return fmt.Errorf("%w at %q", err, filepath.ToSlash(relative))
			}
			state.manifest = append(state.manifest, ManifestEntry{
				Path: filepath.ToSlash(relative), Kind: "directory", Mode: uint32(expected.Mode & 0o777),
			})
			state.entries++
		case unix.S_IFREG:
			input, err := openRegularAt(int(sourceDirectory.Fd()), name, expected)
			if err != nil {
				return fmt.Errorf("%w at %q", err, filepath.ToSlash(relative))
			}
			manifestEntry, inspectErr := digestOpenedRegularFile(ctx, input, relative, state)
			closeErr := input.Close()
			if inspectErr != nil {
				return inspectErr
			}
			if closeErr != nil {
				return fmt.Errorf("close source file %q: %w", filepath.ToSlash(relative), closeErr)
			}
			if err := verifyEntryAt(int(sourceDirectory.Fd()), name, expected); err != nil {
				return fmt.Errorf("%w at %q", err, filepath.ToSlash(relative))
			}
			state.manifest = append(state.manifest, manifestEntry)
			state.entries++
		case unix.S_IFLNK:
			manifestEntry, newTarget, included, err := inspectSecureSymlink(sourceDirectory, name, expected, sourceRoot, relative, excluded, diagnostics)
			if err != nil {
				return err
			}
			if included {
				targetDigest := sha256.Sum256([]byte(newTarget))
				manifestEntry.SHA256 = hex.EncodeToString(targetDigest[:])
				state.manifest = append(state.manifest, manifestEntry)
				state.entries++
			}
		default:
			addDiagnostic(diagnostics, relative, "non-regular file skipped")
		}
	}
	directoryAfter, err := sourceDirectory.Stat()
	if err != nil || !sameStableEntry(directoryBefore, directoryAfter) {
		return fmt.Errorf("%w: directory mutated at %q", ErrSourceChanged, filepath.ToSlash(relativeDirectory))
	}
	return nil
}

func secureCopyDirectory(ctx context.Context, sourceDirectory *os.File, sourceRoot, destinationRoot, relativeDirectory, destinationDirectory string, excluded map[string]struct{}, diagnostics *[]Diagnostic, state *copyState, depth int) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	directoryBefore, err := sourceDirectory.Stat()
	if err != nil || !directoryBefore.IsDir() {
		return fmt.Errorf("%w: inspect directory %q", ErrSourceChanged, filepath.ToSlash(relativeDirectory))
	}
	entries, err := sourceDirectory.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("read source directory %q: %w", filepath.ToSlash(relativeDirectory), err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, entry := range entries {
		if err := contextError(ctx); err != nil {
			return err
		}
		name := entry.Name()
		if err := validateName(name); err != nil {
			return fmt.Errorf("unsafe source entry name %q: %w", name, err)
		}
		if _, skip := excluded[name]; skip {
			continue
		}
		relative := name
		if relativeDirectory != "." {
			relative = filepath.Join(relativeDirectory, name)
		}
		entryDepth := depth + 1
		if err := state.addEntry(relative, entryDepth); err != nil {
			return err
		}
		destinationPath, err := safeDestinationPath(destinationRoot, relative)
		if err != nil {
			return err
		}

		var expected unix.Stat_t
		if err := unix.Fstatat(int(sourceDirectory.Fd()), name, &expected, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("%w: inspect entry %q: %v", ErrSourceChanged, filepath.ToSlash(relative), err)
		}
		switch expected.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			child, err := openDirectoryAt(int(sourceDirectory.Fd()), name, expected)
			if err != nil {
				return fmt.Errorf("%w at %q", err, filepath.ToSlash(relative))
			}
			if err := os.Mkdir(destinationPath, 0o700); err != nil {
				child.Close()
				return fmt.Errorf("create snapshot directory %q: %w", filepath.ToSlash(relative), err)
			}
			copyErr := secureCopyDirectory(ctx, child, sourceRoot, destinationRoot, relative, destinationPath, excluded, diagnostics, state, entryDepth)
			closeErr := child.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return fmt.Errorf("close source directory %q: %w", filepath.ToSlash(relative), closeErr)
			}
			if err := verifyEntryAt(int(sourceDirectory.Fd()), name, expected); err != nil {
				return fmt.Errorf("%w at %q", err, filepath.ToSlash(relative))
			}
			mode := os.FileMode(expected.Mode & 0o777)
			if err := os.Chmod(destinationPath, mode); err != nil {
				return fmt.Errorf("preserve directory mode for %q: %w", filepath.ToSlash(relative), err)
			}
			state.manifest = append(state.manifest, ManifestEntry{Path: filepath.ToSlash(relative), Kind: "directory", Mode: uint32(mode)})
			state.entries++
		case unix.S_IFREG:
			input, err := openRegularAt(int(sourceDirectory.Fd()), name, expected)
			if err != nil {
				return fmt.Errorf("%w at %q", err, filepath.ToSlash(relative))
			}
			manifestEntry, copyErr := copyOpenedRegularFile(ctx, input, destinationPath, relative, state)
			closeErr := input.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return fmt.Errorf("close source file %q: %w", filepath.ToSlash(relative), closeErr)
			}
			if err := verifyEntryAt(int(sourceDirectory.Fd()), name, expected); err != nil {
				return fmt.Errorf("%w at %q", err, filepath.ToSlash(relative))
			}
			state.manifest = append(state.manifest, manifestEntry)
			state.entries++
		case unix.S_IFLNK:
			manifestEntry, copied, err := copySecureSymlink(sourceDirectory, name, expected, sourceRoot, relative, destinationPath, excluded, diagnostics)
			if err != nil {
				return err
			}
			if copied {
				state.manifest = append(state.manifest, manifestEntry)
				state.entries++
			}
		default:
			addDiagnostic(diagnostics, relative, "non-regular file skipped")
		}
	}
	directoryAfter, err := sourceDirectory.Stat()
	if err != nil || !sameStableEntry(directoryBefore, directoryAfter) {
		return fmt.Errorf("%w: directory mutated at %q", ErrSourceChanged, filepath.ToSlash(relativeDirectory))
	}
	return nil
}

func openDirectoryAt(parentFD int, name string, expected unix.Stat_t) (*os.File, error) {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open directory without following links: %v", ErrSourceChanged, err)
	}
	if err := verifyOpenedFD(fd, expected, unix.S_IFDIR); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("wrap source directory descriptor")
	}
	return file, nil
}

func openRegularAt(parentFD int, name string, expected unix.Stat_t) (*os.File, error) {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open file without following links: %v", ErrSourceChanged, err)
	}
	if err := verifyOpenedFD(fd, expected, unix.S_IFREG); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("wrap source file descriptor")
	}
	return file, nil
}

func verifyOpenedFD(fd int, expected unix.Stat_t, kind uint32) error {
	var actual unix.Stat_t
	if err := unix.Fstat(fd, &actual); err != nil {
		return fmt.Errorf("%w: stat opened source entry: %v", ErrSourceChanged, err)
	}
	if uint32(actual.Mode)&uint32(unix.S_IFMT) != kind || !sameUnixEntry(expected, actual) {
		return fmt.Errorf("%w: source entry replaced before open", ErrSourceChanged)
	}
	return nil
}

func verifyEntryAt(parentFD int, name string, expected unix.Stat_t) error {
	var actual unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &actual, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("%w: source entry disappeared: %v", ErrSourceChanged, err)
	}
	if !sameUnixEntry(expected, actual) {
		return fmt.Errorf("%w: source entry replaced", ErrSourceChanged)
	}
	return nil
}

func sameUnixEntry(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode && left.Size == right.Size
}

func copyOpenedRegularFile(ctx context.Context, input *os.File, destination, relative string, state *copyState) (manifest ManifestEntry, resultErr error) {
	before, err := input.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return ManifestEntry{}, fmt.Errorf("%w: stat opened file %q", ErrSourceChanged, filepath.ToSlash(relative))
	}
	if before.Size() > state.limits.maxFileBytes {
		return ManifestEntry{}, fmt.Errorf("%w: file exceeds %d bytes at %q", ErrLimitExceeded, state.limits.maxFileBytes, filepath.ToSlash(relative))
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, before.Mode().Perm())
	if err != nil {
		return ManifestEntry{}, fmt.Errorf("create snapshot file %q: %w", filepath.ToSlash(relative), err)
	}
	succeeded := false
	defer func() {
		if closeErr := output.Close(); resultErr == nil && closeErr != nil {
			resultErr = fmt.Errorf("close snapshot file %q: %w", filepath.ToSlash(relative), closeErr)
		}
		if !succeeded || resultErr != nil {
			_ = os.Remove(destination)
		}
	}()

	digest := sha256.New()
	buffer := make([]byte, 64*1024)
	var copied int64
	for {
		if err := contextError(ctx); err != nil {
			return ManifestEntry{}, err
		}
		count, readErr := input.Read(buffer)
		if count > 0 {
			if err := state.addBytes(relative, copied, int64(count)); err != nil {
				return ManifestEntry{}, err
			}
			if err := writeAll(output, buffer[:count]); err != nil {
				return ManifestEntry{}, fmt.Errorf("write snapshot file %q: %w", filepath.ToSlash(relative), err)
			}
			_, _ = digest.Write(buffer[:count])
			copied += int64(count)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return ManifestEntry{}, fmt.Errorf("read source file %q: %w", filepath.ToSlash(relative), readErr)
		}
	}
	after, err := input.Stat()
	if err != nil || !sameStableEntry(before, after) || copied != before.Size() {
		return ManifestEntry{}, fmt.Errorf("%w: file mutated at %q", ErrSourceChanged, filepath.ToSlash(relative))
	}
	if err := output.Chmod(before.Mode().Perm()); err != nil {
		return ManifestEntry{}, fmt.Errorf("preserve file mode for %q: %w", filepath.ToSlash(relative), err)
	}
	succeeded = true
	return ManifestEntry{Path: filepath.ToSlash(relative), Kind: "file", Mode: uint32(before.Mode().Perm()), Size: copied, SHA256: hex.EncodeToString(digest.Sum(nil))}, nil
}

func digestOpenedRegularFile(ctx context.Context, input *os.File, relative string, state *copyState) (ManifestEntry, error) {
	before, err := input.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return ManifestEntry{}, fmt.Errorf("%w: stat opened file %q", ErrSourceChanged, filepath.ToSlash(relative))
	}
	if before.Size() > state.limits.maxFileBytes {
		return ManifestEntry{}, fmt.Errorf("%w: file exceeds %d bytes at %q", ErrLimitExceeded, state.limits.maxFileBytes, filepath.ToSlash(relative))
	}

	digest := sha256.New()
	buffer := make([]byte, 64*1024)
	var read int64
	for {
		if err := contextError(ctx); err != nil {
			return ManifestEntry{}, err
		}
		count, readErr := input.Read(buffer)
		if count > 0 {
			if err := state.addBytes(relative, read, int64(count)); err != nil {
				return ManifestEntry{}, err
			}
			_, _ = digest.Write(buffer[:count])
			read += int64(count)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return ManifestEntry{}, fmt.Errorf("read source file %q: %w", filepath.ToSlash(relative), readErr)
		}
	}
	after, err := input.Stat()
	if err != nil || !sameStableEntry(before, after) || read != before.Size() {
		return ManifestEntry{}, fmt.Errorf("%w: file mutated at %q", ErrSourceChanged, filepath.ToSlash(relative))
	}
	return ManifestEntry{
		Path: filepath.ToSlash(relative), Kind: "file", Mode: uint32(before.Mode().Perm()), Size: read, SHA256: hex.EncodeToString(digest.Sum(nil)),
	}, nil
}

func copySecureSymlink(parent *os.File, name string, expected unix.Stat_t, sourceRoot, relative, destination string, excluded map[string]struct{}, diagnostics *[]Diagnostic) (ManifestEntry, bool, error) {
	manifestEntry, newTarget, included, err := inspectSecureSymlink(parent, name, expected, sourceRoot, relative, excluded, diagnostics)
	if err != nil || !included {
		return ManifestEntry{}, included, err
	}
	if err := os.Symlink(newTarget, destination); err != nil {
		return ManifestEntry{}, false, fmt.Errorf("create snapshot symlink %q: %w", filepath.ToSlash(relative), err)
	}
	targetDigest := sha256.Sum256([]byte(newTarget))
	manifestEntry.SHA256 = hex.EncodeToString(targetDigest[:])
	return manifestEntry, true, nil
}

func inspectSecureSymlink(parent *os.File, name string, expected unix.Stat_t, sourceRoot, relative string, excluded map[string]struct{}, diagnostics *[]Diagnostic) (ManifestEntry, string, bool, error) {
	target, err := readlinkAt(int(parent.Fd()), name)
	if err != nil {
		return ManifestEntry{}, "", false, fmt.Errorf("%w: read symlink %q: %v", ErrSourceChanged, filepath.ToSlash(relative), err)
	}
	verifyUnchanged := func() error {
		afterTarget, linkErr := readlinkAt(int(parent.Fd()), name)
		if linkErr != nil || afterTarget != target || verifyEntryAt(int(parent.Fd()), name, expected) != nil {
			return fmt.Errorf("%w: symlink mutated at %q", ErrSourceChanged, filepath.ToSlash(relative))
		}
		return nil
	}
	if err := verifyUnchanged(); err != nil {
		return ManifestEntry{}, "", false, err
	}
	sourcePath := filepath.Join(sourceRoot, relative)
	targetPath := target
	if !filepath.IsAbs(targetPath) {
		targetPath = filepath.Join(filepath.Dir(sourcePath), targetPath)
	}
	resolved, err := filepath.EvalSymlinks(targetPath)
	if err != nil {
		if verifyErr := verifyUnchanged(); verifyErr != nil {
			return ManifestEntry{}, "", false, verifyErr
		}
		addDiagnostic(diagnostics, relative, "broken symlink skipped")
		return ManifestEntry{}, "", false, nil
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return ManifestEntry{}, "", false, fmt.Errorf("make symlink target absolute: %w", err)
	}
	targetRelative, inside := relativeWithin(sourceRoot, resolved)
	if !inside {
		if verifyErr := verifyUnchanged(); verifyErr != nil {
			return ManifestEntry{}, "", false, verifyErr
		}
		addDiagnostic(diagnostics, relative, "symlink escapes source root and was skipped")
		return ManifestEntry{}, "", false, nil
	}
	if pathHasExcludedComponent(targetRelative, excluded) {
		if verifyErr := verifyUnchanged(); verifyErr != nil {
			return ManifestEntry{}, "", false, verifyErr
		}
		addDiagnostic(diagnostics, relative, "symlink target is excluded and was skipped")
		return ManifestEntry{}, "", false, nil
	}
	newTarget, err := filepath.Rel(filepath.Dir(relative), targetRelative)
	if err != nil {
		return ManifestEntry{}, "", false, fmt.Errorf("make snapshot symlink target relative: %w", err)
	}
	if err := verifyUnchanged(); err != nil {
		return ManifestEntry{}, "", false, err
	}
	return ManifestEntry{Path: filepath.ToSlash(relative), Kind: "symlink", Size: int64(len(newTarget))}, newTarget, true, nil
}

func readlinkAt(parentFD int, name string) (string, error) {
	buffer := make([]byte, 256)
	for len(buffer) <= 64<<10 {
		count, err := unix.Readlinkat(parentFD, name, buffer)
		if err != nil {
			return "", err
		}
		if count < len(buffer) {
			return string(buffer[:count]), nil
		}
		buffer = make([]byte, len(buffer)*2)
	}
	return "", errors.New("symlink target exceeds 65536 bytes")
}

//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package snapshot

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestContentDigestMatchesCreateAndDoesNotWriteDestination(t *testing.T) {
	parent := t.TempDir()
	source := filepath.Join(parent, "source")
	if err := os.Mkdir(source, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(source, "src", "App.java"), "class App {}\n")
	writeTestFile(t, filepath.Join(source, "application.yml"), "spring:\n  application:\n    name: test\n")
	if err := os.Mkdir(filepath.Join(source, "empty"), 0o750); err != nil {
		t.Fatal(err)
	}
	makeSymlink(t, filepath.Join("src", "App.java"), filepath.Join(source, "app-link"))
	writeTestFile(t, filepath.Join(source, ".git", "ignored"), "ignored")
	writeTestFile(t, filepath.Join(source, "generated", "ignored"), "ignored")
	contentOptions := ContentOptions{ExcludeNames: []string{"generated"}}

	before := directoryEntryNames(t, parent)
	fingerprint, err := ContentDigest(context.Background(), source, contentOptions)
	if err != nil {
		t.Fatalf("ContentDigest() error = %v", err)
	}
	after := directoryEntryNames(t, parent)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("parent entries changed from %v to %v; ContentDigest wrote destination data", before, after)
	}

	snapshot, err := Create(context.Background(), source, Options{DestinationDir: t.TempDir(), ExcludeNames: contentOptions.ExcludeNames})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	t.Cleanup(func() { _ = snapshot.Cleanup() })
	if fingerprint.ContentHash != snapshot.ContentHash ||
		fingerprint.FileCount != snapshot.FileCount ||
		fingerprint.TotalBytes != snapshot.TotalBytes {
		t.Fatalf("ContentDigest() = %#v, Create() = hash %q files %d bytes %d", fingerprint, snapshot.ContentHash, snapshot.FileCount, snapshot.TotalBytes)
	}
}

func TestContentDigestDetectsSameSizeByteChange(t *testing.T) {
	source := t.TempDir()
	file := filepath.Join(source, "same-size.txt")
	writeTestFile(t, file, "first")
	original, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	first := contentFingerprint(t, source, ContentOptions{})

	writeTestFile(t, file, "other")
	if err := os.Chtimes(file, original.ModTime(), original.ModTime()); err != nil {
		t.Fatal(err)
	}
	second := contentFingerprint(t, source, ContentOptions{})
	if first.ContentHash == second.ContentHash {
		t.Fatalf("same-size byte change retained content hash %q", first.ContentHash)
	}
	if first.FileCount != second.FileCount || first.TotalBytes != second.TotalBytes {
		t.Fatalf("same-size byte change altered counts: %#v then %#v", first, second)
	}
}

func TestContentDigestRejectsConcurrentSourceMutation(t *testing.T) {
	source := t.TempDir()
	fileName := filepath.Join(source, "changing.bin")
	contents := make([]byte, 32<<20)
	if err := os.WriteFile(fileName, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		file, err := os.OpenFile(fileName, os.O_WRONLY, 0)
		if err != nil {
			return
		}
		defer file.Close()
		close(started)
		value := byte(1)
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = file.WriteAt([]byte{value}, 0)
				value++
			}
		}
	}()
	<-started
	time.Sleep(time.Millisecond)
	_, err := ContentDigest(context.Background(), source, ContentOptions{})
	close(stop)
	<-done
	if !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("ContentDigest() error = %v, want ErrSourceChanged", err)
	}
}

func TestContentDigestEnforcesLimits(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*testing.T, string)
		options ContentOptions
	}{
		{
			name: "file count",
			prepare: func(t *testing.T, source string) {
				writeTestFile(t, filepath.Join(source, "one"), "1")
				writeTestFile(t, filepath.Join(source, "two"), "2")
			},
			options: ContentOptions{MaxFiles: 1},
		},
		{
			name: "per file bytes",
			prepare: func(t *testing.T, source string) {
				writeTestFile(t, filepath.Join(source, "large"), "1234")
			},
			options: ContentOptions{MaxFileBytes: 3},
		},
		{
			name: "total bytes",
			prepare: func(t *testing.T, source string) {
				writeTestFile(t, filepath.Join(source, "one"), "123")
				writeTestFile(t, filepath.Join(source, "two"), "456")
			},
			options: ContentOptions{MaxTotalBytes: 5},
		},
		{
			name: "depth",
			prepare: func(t *testing.T, source string) {
				writeTestFile(t, filepath.Join(source, "one", "two", "file"), "x")
			},
			options: ContentOptions{MaxDepth: 1},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := t.TempDir()
			test.prepare(t, source)
			_, err := ContentDigest(context.Background(), source, test.options)
			if !errors.Is(err, ErrLimitExceeded) {
				t.Fatalf("ContentDigest() error = %v, want ErrLimitExceeded", err)
			}
		})
	}

	source := t.TempDir()
	writeTestFile(t, filepath.Join(source, "keep"), "x")
	writeTestFile(t, filepath.Join(source, ".springmaster", "ignored"), "too large")
	fingerprint := contentFingerprint(t, source, ContentOptions{MaxFiles: 1, MaxFileBytes: 1, MaxTotalBytes: 1})
	if fingerprint.FileCount != 1 || fingerprint.TotalBytes != 1 {
		t.Fatalf("excluded tree consumed budget: %#v", fingerprint)
	}

	_, err := ContentDigest(context.Background(), source, ContentOptions{MaxFiles: DefaultMaxFiles + 1})
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("raised hard limit error = %v, want ErrLimitExceeded", err)
	}
}

func TestContentDigestRejectsInvalidInputAndCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ContentDigest(ctx, t.TempDir(), ContentOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ContentDigest() error = %v, want context.Canceled", err)
	}
	if _, err := ContentDigest(nil, t.TempDir(), ContentOptions{}); err == nil {
		t.Fatal("ContentDigest() accepted nil context")
	}
	if _, err := ContentDigest(context.Background(), t.TempDir(), ContentOptions{ExcludeNames: []string{"bad/name"}}); err == nil {
		t.Fatal("ContentDigest() accepted invalid exclusion")
	}
}

func TestOpenRegularAtRejectsRenameToSymlinkRace(t *testing.T) {
	parent := t.TempDir()
	writeTestFile(t, filepath.Join(parent, "source.txt"), "source")
	writeTestFile(t, filepath.Join(parent, "outside.txt"), "outside")

	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(parentFD)
	var expected unix.Stat_t
	if err := unix.Fstatat(parentFD, "source.txt", &expected, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(parent, "source.txt"), filepath.Join(parent, "original.txt")); err != nil {
		t.Fatal(err)
	}
	makeSymlink(t, "outside.txt", filepath.Join(parent, "source.txt"))

	opened, err := openRegularAt(parentFD, "source.txt", expected)
	if opened != nil {
		opened.Close()
		t.Fatal("openRegularAt() followed replacement symlink")
	}
	if !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("openRegularAt() error = %v, want ErrSourceChanged", err)
	}
}

func TestInspectSecureSymlinkRejectsReplacement(t *testing.T) {
	source := t.TempDir()
	writeTestFile(t, filepath.Join(source, "one.txt"), "one")
	writeTestFile(t, filepath.Join(source, "second-target.txt"), "two")
	makeSymlink(t, "one.txt", filepath.Join(source, "current"))

	parentFD, err := unix.Open(source, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent := os.NewFile(uintptr(parentFD), source)
	if parent == nil {
		_ = unix.Close(parentFD)
		t.Fatal("wrap source descriptor")
	}
	defer parent.Close()
	var expected unix.Stat_t
	if err := unix.Fstatat(parentFD, "current", &expected, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(source, "current")); err != nil {
		t.Fatal(err)
	}
	makeSymlink(t, "second-target.txt", filepath.Join(source, "current"))

	_, _, _, err = inspectSecureSymlink(parent, "current", expected, source, "current", map[string]struct{}{}, &[]Diagnostic{})
	if !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("inspectSecureSymlink() error = %v, want ErrSourceChanged", err)
	}
}

func contentFingerprint(t *testing.T, source string, options ContentOptions) ContentFingerprint {
	t.Helper()
	fingerprint, err := ContentDigest(context.Background(), source, options)
	if err != nil {
		t.Fatalf("ContentDigest() error = %v", err)
	}
	return fingerprint
}

func directoryEntryNames(t *testing.T, path string) []string {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func TestOpenDirectoryAtRejectsRenameToSymlinkRace(t *testing.T) {
	parent := t.TempDir()
	original := filepath.Join(parent, "module")
	outside := t.TempDir()
	writeTestFile(t, filepath.Join(original, "inside.txt"), "inside")
	writeTestFile(t, filepath.Join(outside, "secret.txt"), "outside-secret")

	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(parentFD)
	var expected unix.Stat_t
	if err := unix.Fstatat(parentFD, "module", &expected, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(parent, "module-original")
	if err := os.Rename(original, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, original); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	opened, err := openDirectoryAt(parentFD, "module", expected)
	if opened != nil {
		opened.Close()
		t.Fatal("openDirectoryAt() followed replacement symlink")
	}
	if !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("openDirectoryAt() error = %v, want ErrSourceChanged", err)
	}
}

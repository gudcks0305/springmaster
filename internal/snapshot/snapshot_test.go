package snapshot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCreateCopiesWorkingTreeAndExcludesNames(t *testing.T) {
	source := t.TempDir()
	destinationParent := t.TempDir()

	writeTestFile(t, filepath.Join(source, "tracked.txt"), "tracked")
	writeTestFile(t, filepath.Join(source, "dirty.txt"), "dirty working-tree bytes")
	writeTestFile(t, filepath.Join(source, "untracked", "new.txt"), "untracked")
	executable := filepath.Join(source, "bin", "run.sh")
	writeTestFile(t, executable, "#!/bin/sh\n")
	if err := os.Chmod(executable, 0o751); err != nil {
		t.Fatal(err)
	}
	for _, name := range append(append([]string(nil), DefaultExcludedNames...), "generated") {
		writeTestFile(t, filepath.Join(source, name, "ignored.txt"), name)
	}

	snapshot, err := Create(context.Background(), source, Options{
		DestinationDir: destinationParent,
		ExcludeNames:   []string{"generated"},
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !filepath.IsAbs(snapshot.Root) {
		t.Fatalf("snapshot root is not absolute: %q", snapshot.Root)
	}
	canonicalParent, err := canonicalDirectory(destinationParent, "destination")
	if err != nil {
		t.Fatal(err)
	}
	if relative, inside := relativeWithin(canonicalParent, snapshot.Root); !inside || relative == "." {
		t.Fatalf("snapshot root %q escaped destination %q", snapshot.Root, canonicalParent)
	}

	assertFileContent(t, filepath.Join(snapshot.Root, "tracked.txt"), "tracked")
	assertFileContent(t, filepath.Join(snapshot.Root, "dirty.txt"), "dirty working-tree bytes")
	assertFileContent(t, filepath.Join(snapshot.Root, "untracked", "new.txt"), "untracked")
	info, err := os.Stat(filepath.Join(snapshot.Root, "bin", "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o751); got != want {
		t.Errorf("copied mode = %o, want %o", got, want)
	}
	for _, name := range append(append([]string(nil), DefaultExcludedNames...), "generated") {
		if _, err := os.Lstat(filepath.Join(snapshot.Root, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("excluded %q exists or has unexpected error: %v", name, err)
		}
	}

	if err := snapshot.Cleanup(); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if _, err := os.Lstat(snapshot.directory); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("snapshot still exists after cleanup: %v", err)
	}
	if err := snapshot.Cleanup(); err != nil {
		t.Fatalf("second Cleanup() error = %v", err)
	}
}

func TestCreatePreservesOnlySafeInternalSymlinks(t *testing.T) {
	source := t.TempDir()
	destinationParent := t.TempDir()
	external := t.TempDir()
	writeTestFile(t, filepath.Join(source, "inner", "target.txt"), "inside")
	writeTestFile(t, filepath.Join(source, ".git", "config"), "metadata")
	writeTestFile(t, filepath.Join(external, "secret.txt"), "outside")

	makeSymlink(t, filepath.Join("inner", "target.txt"), filepath.Join(source, "c-inside"))
	makeSymlink(t, ".", filepath.Join(source, "d-root"))
	makeSymlink(t, filepath.Join(external, "secret.txt"), filepath.Join(source, "a-escape"))
	makeSymlink(t, filepath.Join(".git", "config"), filepath.Join(source, "b-excluded-target"))
	makeSymlink(t, "missing.txt", filepath.Join(source, "e-broken"))

	snapshot, err := Create(context.Background(), source, Options{DestinationDir: destinationParent})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	t.Cleanup(func() { _ = snapshot.Cleanup() })

	inside := filepath.Join(snapshot.Root, "c-inside")
	info, err := os.Lstat(inside)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("safe link mode = %v, want symlink", info.Mode())
	}
	resolved, err := filepath.EvalSymlinks(inside)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(snapshot.Root, "inner", "target.txt"); resolved != want {
		t.Errorf("safe link resolved to %q, want %q", resolved, want)
	}
	rootResolved, err := filepath.EvalSymlinks(filepath.Join(snapshot.Root, "d-root"))
	if err != nil {
		t.Fatal(err)
	}
	if rootResolved != snapshot.Root {
		t.Errorf("root symlink resolved to %q, want %q", rootResolved, snapshot.Root)
	}

	for _, name := range []string{"a-escape", "b-excluded-target", "e-broken"} {
		if _, err := os.Lstat(filepath.Join(snapshot.Root, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("unsafe link %q exists or has unexpected error: %v", name, err)
		}
	}
	wantDiagnostics := []Diagnostic{
		{Path: "a-escape", Reason: "symlink escapes source root and was skipped"},
		{Path: "b-excluded-target", Reason: "symlink target is excluded and was skipped"},
		{Path: "e-broken", Reason: "broken symlink skipped"},
	}
	if !reflect.DeepEqual(snapshot.Diagnostics, wantDiagnostics) {
		t.Errorf("diagnostics = %#v, want %#v", snapshot.Diagnostics, wantDiagnostics)
	}
}

func TestCreateRejectsInvalidDestinationControls(t *testing.T) {
	source := t.TempDir()
	destinationParent := t.TempDir()

	if _, err := Create(context.Background(), source, Options{}); !errors.Is(err, ErrDestinationRequired) {
		t.Errorf("missing destination error = %v, want ErrDestinationRequired", err)
	}
	if _, err := Create(context.Background(), source, Options{DestinationDir: destinationParent, Prefix: "../escape"}); err == nil {
		t.Error("Create() accepted traversal prefix")
	}
	if _, err := Create(context.Background(), source, Options{DestinationDir: destinationParent, ExcludeNames: []string{"nested/name"}}); err == nil {
		t.Error("Create() accepted non-name exclusion")
	}
	nestedDestination := filepath.Join(source, "snapshots")
	if err := os.Mkdir(nestedDestination, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(context.Background(), source, Options{DestinationDir: nestedDestination}); !errors.Is(err, ErrDestinationInsideSource) {
		t.Errorf("nested destination error = %v, want ErrDestinationInsideSource", err)
	}
}

func TestCreateHonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Create(ctx, t.TempDir(), Options{DestinationDir: t.TempDir()})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Create() error = %v, want context.Canceled", err)
	}
}

func TestCreateEnforcesHardLimitsAndIgnoresExcludedTrees(t *testing.T) {
	t.Run("file count", func(t *testing.T) {
		source := t.TempDir()
		writeTestFile(t, filepath.Join(source, "one.txt"), "1")
		writeTestFile(t, filepath.Join(source, "two.txt"), "2")
		_, err := Create(context.Background(), source, Options{DestinationDir: t.TempDir(), MaxFiles: 1})
		if !errors.Is(err, ErrLimitExceeded) {
			t.Fatalf("Create() error = %v, want ErrLimitExceeded", err)
		}
	})

	t.Run("per file", func(t *testing.T) {
		source := t.TempDir()
		writeTestFile(t, filepath.Join(source, "large.txt"), "1234")
		_, err := Create(context.Background(), source, Options{DestinationDir: t.TempDir(), MaxFileBytes: 3})
		if !errors.Is(err, ErrLimitExceeded) {
			t.Fatalf("Create() error = %v, want ErrLimitExceeded", err)
		}
	})

	t.Run("actual total bytes", func(t *testing.T) {
		source := t.TempDir()
		writeTestFile(t, filepath.Join(source, "one.txt"), "123")
		writeTestFile(t, filepath.Join(source, "two.txt"), "456")
		_, err := Create(context.Background(), source, Options{DestinationDir: t.TempDir(), MaxTotalBytes: 5})
		if !errors.Is(err, ErrLimitExceeded) {
			t.Fatalf("Create() error = %v, want ErrLimitExceeded", err)
		}
	})

	t.Run("depth", func(t *testing.T) {
		source := t.TempDir()
		writeTestFile(t, filepath.Join(source, "one", "two", "file.txt"), "data")
		_, err := Create(context.Background(), source, Options{DestinationDir: t.TempDir(), MaxDepth: 1})
		if !errors.Is(err, ErrLimitExceeded) {
			t.Fatalf("Create() error = %v, want ErrLimitExceeded", err)
		}
	})

	t.Run("excluded entries do not consume budget", func(t *testing.T) {
		source := t.TempDir()
		writeTestFile(t, filepath.Join(source, "keep.txt"), "x")
		for index := range 20 {
			writeTestFile(t, filepath.Join(source, ".springmaster", "nested", string(rune('a'+index)), "ignored.txt"), "ignored")
		}
		snapshot, err := Create(context.Background(), source, Options{DestinationDir: t.TempDir(), MaxFiles: 1, MaxTotalBytes: 1})
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		t.Cleanup(func() { _ = snapshot.Cleanup() })
		if snapshot.FileCount != 1 || snapshot.TotalBytes != 1 {
			t.Fatalf("snapshot counts = (%d, %d), want (1, 1)", snapshot.FileCount, snapshot.TotalBytes)
		}
	})

	_, err := Create(context.Background(), t.TempDir(), Options{DestinationDir: t.TempDir(), MaxFiles: DefaultMaxFiles + 1})
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("raised hard limit error = %v, want ErrLimitExceeded", err)
	}
}

func TestCreateManifestHashesExactCopiedBytesDeterministically(t *testing.T) {
	source := t.TempDir()
	writeTestFile(t, filepath.Join(source, "src", "App.java"), "class App {}\n")
	writeTestFile(t, filepath.Join(source, "application.yml"), "spring:\n  application:\n    name: test\n")

	first, err := Create(context.Background(), source, Options{DestinationDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Cleanup() })
	second, err := Create(context.Background(), source, Options{DestinationDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Cleanup() })
	if first.ContentHash == "" || first.ContentHash != second.ContentHash {
		t.Fatalf("content hashes = %q and %q, want same non-empty hash", first.ContentHash, second.ContentHash)
	}
	if !reflect.DeepEqual(first.Manifest, second.Manifest) {
		t.Fatalf("manifests differ: %#v != %#v", first.Manifest, second.Manifest)
	}
	if first.TotalBytes != int64(len("class App {}\n")+len("spring:\n  application:\n    name: test\n")) {
		t.Fatalf("TotalBytes = %d", first.TotalBytes)
	}

	contents := []byte("class App {}\n")
	wantFileDigest := sha256.Sum256(contents)
	var appEntry *ManifestEntry
	for index := range first.Manifest {
		if first.Manifest[index].Path == "src/App.java" {
			appEntry = &first.Manifest[index]
			break
		}
	}
	if appEntry == nil || appEntry.SHA256 != hex.EncodeToString(wantFileDigest[:]) || appEntry.Size != int64(len(contents)) {
		t.Fatalf("App.java manifest = %#v", appEntry)
	}
	copied, err := os.ReadFile(filepath.Join(first.Root, "src", "App.java"))
	if err != nil || !reflect.DeepEqual(copied, contents) {
		t.Fatalf("copied bytes = %q, error = %v", copied, err)
	}

	writeTestFile(t, filepath.Join(source, "src", "App.java"), "class Changed {}\n")
	changed, err := Create(context.Background(), source, Options{DestinationDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = changed.Cleanup() })
	if changed.ContentHash == first.ContentHash {
		t.Fatalf("changed copied bytes retained hash %q", changed.ContentHash)
	}
}

func TestCreateRejectsConcurrentSourceMutation(t *testing.T) {
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
	_, err := Create(context.Background(), source, Options{DestinationDir: t.TempDir()})
	close(stop)
	<-done
	if !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("Create() error = %v, want ErrSourceChanged", err)
	}
}

func TestCleanupUsesPrivatePathAndRefusesTamperedMarker(t *testing.T) {
	source := t.TempDir()
	destinationParent := t.TempDir()
	writeTestFile(t, filepath.Join(source, "file.txt"), "data")

	snapshot, err := Create(context.Background(), source, Options{DestinationDir: destinationParent})
	if err != nil {
		t.Fatal(err)
	}
	actualRoot := snapshot.directory
	unrelated := t.TempDir()
	snapshot.Root = unrelated // Cleanup must not trust public, caller-mutable field.
	if err := snapshot.Cleanup(); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if _, err := os.Lstat(actualRoot); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("actual snapshot root still exists: %v", err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Errorf("unrelated path was removed: %v", err)
	}

	snapshot, err = Create(context.Background(), source, Options{DestinationDir: destinationParent})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(snapshot.marker); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Cleanup(); !errors.Is(err, ErrSnapshotUntrusted) {
		t.Errorf("tampered marker Cleanup() error = %v, want ErrSnapshotUntrusted", err)
	}
	if _, err := os.Stat(snapshot.directory); err != nil {
		t.Errorf("untrusted cleanup removed snapshot: %v", err)
	}
}

func TestCleanupIsConcurrentAndIdempotent(t *testing.T) {
	source := t.TempDir()
	destinationParent := t.TempDir()
	writeTestFile(t, filepath.Join(source, "file.txt"), "data")
	snapshot, err := Create(context.Background(), source, Options{DestinationDir: destinationParent})
	if err != nil {
		t.Fatal(err)
	}

	const callers = 12
	errCh := make(chan error, callers)
	for range callers {
		go func() { errCh <- snapshot.Cleanup() }()
	}
	for range callers {
		if err := <-errCh; err != nil {
			t.Errorf("Cleanup() error = %v", err)
		}
	}
	if _, err := os.Lstat(snapshot.directory); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("snapshot still exists after concurrent cleanup: %v", err)
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(contents); got != want {
		t.Errorf("file %q = %q, want %q", path, got, want)
	}
}

func makeSymlink(t *testing.T, target, path string) {
	t.Helper()
	if err := os.Symlink(target, path); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not permitted") {
			t.Skipf("symlink creation unavailable: %v", err)
		}
		t.Fatal(err)
	}
}

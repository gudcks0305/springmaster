//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package snapshot

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

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

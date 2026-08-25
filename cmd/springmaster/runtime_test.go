package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLocateBundledAnalyzerJarBesideResolvedExecutable(t *testing.T) {
	installRoot := t.TempDir()
	realDirectory := filepath.Join(installRoot, "share", "springmaster")
	binDirectory := filepath.Join(installRoot, "bin")
	if err := os.MkdirAll(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(binDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(realDirectory, "springmaster")
	jar := filepath.Join(realDirectory, "analyzer.jar")
	if err := os.WriteFile(binary, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jar, []byte("jar"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(binDirectory, "springmaster")
	if err := os.Symlink(binary, link); err != nil {
		t.Fatal(err)
	}

	resolved, err := locateBundledAnalyzerJar("", func() (string, error) { return link, nil })
	if err != nil {
		t.Fatalf("locateBundledAnalyzerJar() error = %v", err)
	}
	want, err := filepath.EvalSymlinks(jar)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != want {
		t.Fatalf("locateBundledAnalyzerJar() = %q, want %q", resolved, want)
	}
}

func TestLocateBundledAnalyzerJarHonorsExplicitEnvironmentPath(t *testing.T) {
	jar := filepath.Join(t.TempDir(), "analyzer.jar")
	if err := os.WriteFile(jar, []byte("jar"), 0o600); err != nil {
		t.Fatal(err)
	}

	resolved, err := locateBundledAnalyzerJar(jar, func() (string, error) {
		t.Fatal("executable lookup must not run for an explicit analyzer path")
		return "", nil
	})
	if err != nil {
		t.Fatalf("locateBundledAnalyzerJar() error = %v", err)
	}
	want, err := filepath.EvalSymlinks(jar)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != want {
		t.Fatalf("locateBundledAnalyzerJar() = %q, want %q", resolved, want)
	}
}

func TestLocateBundledAnalyzerJarRejectsMissingPair(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "springmaster")
	if err := os.WriteFile(binary, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}

	_, err := locateBundledAnalyzerJar("", func() (string, error) { return binary, nil })
	if err == nil || !strings.Contains(err.Error(), "analyzer.jar not found") {
		t.Fatalf("locateBundledAnalyzerJar() error = %v", err)
	}
}

func TestResolveWorkerCommandPreservesExplicitOverride(t *testing.T) {
	command, err := resolveWorkerCommand(`custom-worker --flag "two words"`)
	if err != nil {
		t.Fatalf("resolveWorkerCommand() error = %v", err)
	}
	want := []string{"custom-worker", "--flag", "two words"}
	if !reflect.DeepEqual(command, want) {
		t.Fatalf("resolveWorkerCommand() = %#v, want %#v", command, want)
	}
}

package semantic

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gudcks0305/springmaster/internal/graph"
)

func TestMaterializeAppSharedLibraryContextAndChange(t *testing.T) {
	root := t.TempDir()
	shared := writeFixture(t, root, "shared", map[string]string{
		"pom.xml": `<project><modelVersion>4.0.0</modelVersion><groupId>example</groupId><artifactId>shared-lib</artifactId><version>1.0.0</version></project>`,
		"src/main/java/example/shared/Shared.java": `package example.shared; public final class Shared { public static String value() { return "one"; } }`,
		"src/main/resources/application.yml":       "must-not-copy: true\n",
	})
	app := writeFixture(t, root, "app", map[string]string{
		"pom.xml":                            `<project><modelVersion>4.0.0</modelVersion><groupId>example</groupId><artifactId>app</artifactId><version>1.0.0</version><dependencies><dependency><groupId>example</groupId><artifactId>shared-lib</artifactId><version>1.0.0</version></dependency></dependencies></project>`,
		"src/main/java/example/app/App.java": `package example.app; public final class App { }`,
	})
	dependencyGraph, err := graph.Build(context.Background(), []graph.Repository{
		{ID: "app", Path: app, ContentHash: "app-v1"},
		{ID: "shared", Path: shared, ContentHash: "shared-v1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := Materialize(context.Background(), dependencyGraph, "app", []SnapshotRoot{
		{RepositoryID: "app", Root: app},
		{RepositoryID: "shared", Root: shared},
	}, Options{Mode: CopyModeCopy})
	if err != nil {
		t.Fatal(err)
	}
	expected := filepath.Join(app, ReservedDirectory, "shared", "src", "main", "java", "example", "shared", "Shared.java")
	contents, err := os.ReadFile(expected)
	if err != nil || !strings.Contains(string(contents), `"one"`) {
		t.Fatalf("materialized source = %q, %v", contents, err)
	}
	if _, err := os.Lstat(filepath.Join(app, ReservedDirectory, "shared", "pom.xml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dependency build script leaked into context: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(app, ReservedDirectory, "shared", "src", "main", "resources", "application.yml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dependency resource leaked into context: %v", err)
	}
	if got, want := first.DependencyIDs, []string{"shared"}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("DependencyIDs = %#v, want %#v", got, want)
	}
	if first.FileCount != 1 || len(first.Manifest) != 1 || first.ContentHash == "" {
		t.Fatalf("context metadata = %#v", first)
	}
	firstHash := first.ContentHash
	if err := first.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(app, ReservedDirectory)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("context still exists after cleanup: %v", err)
	}
	if err := first.Cleanup(); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(shared, "src", "main", "java", "example", "shared", "Shared.java"), []byte(`package example.shared; public final class Shared { public static String value() { return "two"; } }`), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := Materialize(context.Background(), dependencyGraph, "app", []SnapshotRoot{
		{RepositoryID: "shared", Root: shared},
		{RepositoryID: "app", Root: app},
	}, Options{Mode: CopyModeCopy})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Cleanup() })
	changed, err := os.ReadFile(expected)
	if err != nil || !strings.Contains(string(changed), `"two"`) {
		t.Fatalf("changed materialized source = %q, %v", changed, err)
	}
	if second.ContentHash == firstHash {
		t.Fatal("dependency source change did not change context manifest hash")
	}
}

func TestMaterializeSkipsSymlinkAndEnforcesBounds(t *testing.T) {
	root := t.TempDir()
	shared := writeFixture(t, root, "shared", map[string]string{
		"pom.xml": `<project><groupId>example</groupId><artifactId>shared</artifactId><version>1</version></project>`,
		"src/main/java/example/shared/Shared.java": "package example.shared; class Shared {}",
	})
	app := writeFixture(t, root, "app", map[string]string{
		"pom.xml": `<project><groupId>example</groupId><artifactId>app</artifactId><version>1</version><dependencies><dependency><groupId>example</groupId><artifactId>shared</artifactId><version>1</version></dependency></dependencies></project>`,
	})
	outside := filepath.Join(root, "outside.java")
	if err := os.WriteFile(outside, []byte("class Outside {}"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(shared, "src", "main", "java", "example", "shared", "Escape.java")
	if err := os.Symlink(outside, symlink); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	dependencyGraph := fixtureGraph(t, app, shared)
	contextOverlay, err := Materialize(context.Background(), dependencyGraph, "app", []SnapshotRoot{{RepositoryID: "app", Root: app}, {RepositoryID: "shared", Root: shared}}, Options{Mode: CopyModeAuto})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDiagnostic(contextOverlay.Diagnostics, "symbolic link skipped") {
		t.Fatalf("symlink diagnostic missing: %#v", contextOverlay.Diagnostics)
	}
	if _, err := os.Lstat(filepath.Join(contextOverlay.Path, "shared", "src", "main", "java", "example", "shared", "Escape.java")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlink escaped into context: %v", err)
	}
	if err := contextOverlay.Cleanup(); err != nil {
		t.Fatal(err)
	}
	_, err = Materialize(context.Background(), dependencyGraph, "app", []SnapshotRoot{{RepositoryID: "app", Root: app}, {RepositoryID: "shared", Root: shared}}, Options{MaxFileBytes: 1})
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("Materialize() bounded error = %v, want ErrLimitExceeded", err)
	}
	if _, statErr := os.Lstat(filepath.Join(app, ReservedDirectory)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed materialization retained overlay: %v", statErr)
	}
}

func TestDependencyClosureRejectsUnknownTarget(t *testing.T) {
	if _, err := DependencyClosure(&graph.Graph{}, "missing"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("DependencyClosure() error = %v, want ErrInvalidInput", err)
	}
}

func TestCleanupRefusesTamperedOverlay(t *testing.T) {
	root := t.TempDir()
	shared := writeFixture(t, root, "shared", map[string]string{
		"pom.xml": `<project><groupId>example</groupId><artifactId>shared</artifactId><version>1</version></project>`,
		"src/main/java/example/shared/Shared.java": "package example.shared; class Shared {}",
	})
	app := writeFixture(t, root, "app", map[string]string{
		"pom.xml": `<project><groupId>example</groupId><artifactId>app</artifactId><version>1</version><dependencies><dependency><groupId>example</groupId><artifactId>shared</artifactId><version>1</version></dependency></dependencies></project>`,
	})
	overlay, err := Materialize(context.Background(), fixtureGraph(t, app, shared), "app", []SnapshotRoot{{RepositoryID: "app", Root: app}, {RepositoryID: "shared", Root: shared}}, Options{Mode: CopyModeCopy})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(overlay.Path, markerName)); err != nil {
		t.Fatal(err)
	}
	if err := overlay.Cleanup(); !errors.Is(err, ErrContextUntrusted) {
		t.Fatalf("Cleanup() error = %v, want ErrContextUntrusted", err)
	}
	if _, err := os.Lstat(overlay.Path); err != nil {
		t.Fatalf("untrusted cleanup removed overlay: %v", err)
	}
}

func fixtureGraph(t *testing.T, app, shared string) *graph.Graph {
	t.Helper()
	dependencyGraph, err := graph.Build(context.Background(), []graph.Repository{{ID: "app", Path: app, ContentHash: "app"}, {ID: "shared", Path: shared, ContentHash: "shared"}})
	if err != nil {
		t.Fatal(err)
	}
	return dependencyGraph
}

func hasDiagnostic(diagnostics []Diagnostic, reason string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Reason == reason {
			return true
		}
	}
	return false
}

func writeFixture(t *testing.T, root, name string, files map[string]string) string {
	t.Helper()
	directory := filepath.Join(root, name)
	for relative, contents := range files {
		file := filepath.Join(directory, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return directory
}

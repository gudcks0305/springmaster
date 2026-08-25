package graph

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestBuildMavenCrossRepositoryOrderImpactAndEffectiveHash(t *testing.T) {
	root := t.TempDir()
	library := writeGraphFiles(t, root, "library", map[string]string{
		"pom.xml": `<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId><artifactId>shared</artifactId>
  <version>${revision}</version><properties><revision>1.2.3</revision></properties>
</project>`,
	})
	service := writeGraphFiles(t, root, "service", map[string]string{
		"pom.xml": `<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId><artifactId>service</artifactId><version>1.0.0</version>
  <properties><shared.version>1.2.3</shared.version></properties>
  <dependencies><dependency><groupId>com.example</groupId><artifactId>shared</artifactId><version>${shared.version}</version></dependency></dependencies>
</project>`,
	})
	consumer := writeGraphFiles(t, root, "consumer", map[string]string{
		"pom.xml": `<project><groupId>com.example</groupId><artifactId>consumer</artifactId><version>1.0.0</version><dependencies><dependency><groupId>com.example</groupId><artifactId>service</artifactId><version>1.0.0</version></dependency></dependencies></project>`,
	})
	input := []Repository{{ID: "consumer", Path: consumer, ContentHash: "consumer-v1"}, {ID: "service", Path: service, ContentHash: "service-v1"}, {ID: "library", Path: library, ContentHash: "library-v1"}}
	graph, err := Build(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := graph.Order, []string{"library", "service", "consumer"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Order = %#v, want %#v", got, want)
	}
	dependency := localDependency(t, graph, "service", "library")
	if dependency.Kind != DependencyMaven || dependency.Coordinate.String() != "com.example:shared:1.2.3" {
		t.Fatalf("dependency = %#v", dependency)
	}
	if got, want := graph.Impact([]string{"library"}), (Impact{Changed: []string{"library"}, Direct: []string{"service"}, Transitive: []string{"consumer"}, All: []string{"consumer", "service"}}); !reflect.DeepEqual(got, want) {
		t.Fatalf("Impact = %#v, want %#v", got, want)
	}
	first := graph.EffectiveHash("service")
	changedInput := append([]Repository(nil), input...)
	for index := range changedInput {
		if changedInput[index].ID == "library" {
			changedInput[index].ContentHash = "library-v2"
		}
	}
	changed, err := Build(context.Background(), changedInput)
	if err != nil {
		t.Fatal(err)
	}
	if changed.EffectiveHash("library") == graph.EffectiveHash("library") || changed.EffectiveHash("service") == first {
		t.Fatalf("dependency effective hashes did not propagate: before=%s after=%s", first, changed.EffectiveHash("service"))
	}
}

func TestBuildPrefersMatchingBuildSystemForDualBuildRepository(t *testing.T) {
	root := t.TempDir()
	library := writeGraphFiles(t, root, "library", map[string]string{
		"pom.xml":          `<project><groupId>com.example</groupId><artifactId>shared</artifactId><version>1</version></project>`,
		"build.gradle.kts": `group = "com.example"\nversion = "1"`,
	})
	service := writeGraphFiles(t, root, "service", map[string]string{
		"pom.xml": `<project><groupId>com.example</groupId><artifactId>service</artifactId><version>1</version><dependencies><dependency><groupId>com.example</groupId><artifactId>shared</artifactId><version>1</version></dependency></dependencies></project>`,
	})
	result, err := Build(t.Context(), []Repository{
		{ID: "service", Path: service, ContentHash: "service"},
		{ID: "library", Path: library, ContentHash: "library"},
	})
	if err != nil {
		t.Fatal(err)
	}
	dependency := localDependency(t, result, "service", "library")
	if target := moduleByTestID(result.Modules, dependency.TargetModuleID); target.BuildSystem != BuildSystemMaven {
		t.Fatalf("Maven dependency resolved to %#v", target)
	}
	if got := result.Impact([]string{"library"}).All; !reflect.DeepEqual(got, []string{"service"}) {
		t.Fatalf("impact = %v", got)
	}
}

func TestBuildGradleProjectsAndVersionCatalog(t *testing.T) {
	root := t.TempDir()
	library := writeGraphFiles(t, root, "library", map[string]string{
		"settings.gradle.kts": `rootProject.name = "shared"`,
		"build.gradle.kts":    "group = \"com.example\"\nversion = \"1.2.3\"",
	})
	service := writeGraphFiles(t, root, "service", map[string]string{
		"settings.gradle.kts": `rootProject.name = "service"
include(":core", ":api")`,
		"build.gradle.kts": `allprojects {
  group = "com.example"
  version = "1.0.0"
}`,
		"core/build.gradle.kts": "",
		"api/build.gradle.kts": `dependencies {
  implementation(project(":core"))
  implementation(libs.shared.lib)
  implementation("com.example:shared:+")
}`,
		"gradle/libs.versions.toml": `[versions]
shared = "1.2.3"
[libraries]
shared-lib = { module = "com.example:shared", version.ref = "shared" }
`,
	})
	graph, err := Build(context.Background(), []Repository{
		{ID: "service", Path: service, ContentHash: "service-v1"},
		{ID: "library", Path: library, ContentHash: "library-v1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := graph.Order, []string{"library", "service"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Order = %#v, want %#v", got, want)
	}
	if len(graph.Modules) != 4 { // library root plus service root/core/api
		t.Fatalf("Modules = %#v", graph.Modules)
	}
	if dependency := localDependency(t, graph, "service", "library"); dependency.Kind != DependencyGradleAlias || dependency.Coordinate.String() != "com.example:shared:1.2.3" {
		t.Fatalf("catalog dependency = %#v", dependency)
	}
	var projectDependency *Dependency
	for index := range graph.Dependencies {
		dependency := &graph.Dependencies[index]
		if dependency.Kind == DependencyGradleProj && dependency.Resolution == ResolutionLocal {
			projectDependency = dependency
			break
		}
	}
	if projectDependency == nil || projectDependency.SourceRepositoryID != "service" || projectDependency.TargetRepositoryID != "service" {
		t.Fatalf("Gradle project dependency = %#v", projectDependency)
	}
	dynamicFound := false
	for _, dependency := range graph.Dependencies {
		if dependency.Kind == DependencyGradle && dependency.TargetRepositoryID == "library" && dependency.Dynamic {
			dynamicFound = true
		}
	}
	if !dynamicFound {
		t.Fatalf("dynamic Gradle dependency was not clearly retained: %#v", graph.Dependencies)
	}
}

func TestBuildReportsCycleAndDynamicDependencyDeterministically(t *testing.T) {
	root := t.TempDir()
	a := writeGraphFiles(t, root, "a", map[string]string{
		"pom.xml": `<project><groupId>example</groupId><artifactId>a</artifactId><version>1</version><dependencies><dependency><groupId>example</groupId><artifactId>b</artifactId><version>1</version></dependency></dependencies></project>`,
	})
	b := writeGraphFiles(t, root, "b", map[string]string{
		"pom.xml": `<project><groupId>example</groupId><artifactId>b</artifactId><version>1</version><dependencies><dependency><groupId>example</groupId><artifactId>a</artifactId><version>1</version></dependency></dependencies></project>`,
	})
	graph, err := Build(context.Background(), []Repository{{ID: "b", Path: b, ContentHash: "b"}, {ID: "a", Path: a, ContentHash: "a"}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := graph.Order, []string{"a", "b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("cycle order = %#v, want %#v", got, want)
	}
	if len(graph.Cycles) != 1 || !reflect.DeepEqual(graph.Cycles[0].RepositoryIDs, []string{"a", "b"}) {
		t.Fatalf("Cycles = %#v", graph.Cycles)
	}
	if graph.EffectiveHash("a") == "" || graph.EffectiveHash("b") == "" {
		t.Fatalf("cycle hashes missing: %#v", graph.EffectiveHashes)
	}
	if impact := graph.Impact([]string{"a"}); !reflect.DeepEqual(impact.All, []string{"b"}) {
		t.Fatalf("cycle impact = %#v", impact)
	}
}

func TestBuildHonorsCanceledContextAndFileBound(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Build(ctx, []Repository{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Build() error = %v, want context cancellation", err)
	}
	root := t.TempDir()
	repository := writeGraphFiles(t, root, "large", map[string]string{"pom.xml": "<project>" + string(make([]byte, 2048)) + "</project>"})
	graph, err := BuildWithOptions(context.Background(), []Repository{{ID: "large", Path: repository, ContentHash: "v1"}}, Options{MaxFiles: 2, MaxFileBytes: 64, MaxTotalBytes: 128})
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Modules) != 0 || !hasDiagnostic(graph.Diagnostics, "descriptor_file_too_large") {
		t.Fatalf("bounded result = %#v", graph)
	}
}

func TestEffectiveHashIsStableWithMultipleLocalDependencies(t *testing.T) {
	repositories := []Repository{
		{ID: "app", ContentHash: "app-content"},
		{ID: "alpha", ContentHash: "alpha-content"},
		{ID: "beta", ContentHash: "beta-content"},
		{ID: "gamma", ContentHash: "gamma-content"},
	}
	modules := []Module{
		{ID: "app", RepositoryID: "app"},
		{ID: "alpha", RepositoryID: "alpha"},
		{ID: "beta", RepositoryID: "beta"},
		{ID: "gamma", RepositoryID: "gamma"},
	}
	dependencies := []Dependency{
		{SourceModuleID: "app", SourceRepositoryID: "app", TargetModuleID: "alpha", TargetRepositoryID: "alpha", Resolution: ResolutionLocal},
		{SourceModuleID: "app", SourceRepositoryID: "app", TargetModuleID: "beta", TargetRepositoryID: "beta", Resolution: ResolutionLocal},
		{SourceModuleID: "app", SourceRepositoryID: "app", TargetModuleID: "gamma", TargetRepositoryID: "gamma", Resolution: ResolutionLocal},
	}

	_, baseline := calculateEffectiveHashes(repositories, modules, dependencies)
	for iteration := 0; iteration < 200; iteration++ {
		_, got := calculateEffectiveHashes(repositories, modules, dependencies)
		if got["app"] != baseline["app"] {
			t.Fatalf("iteration %d effective hash = %q, want stable %q", iteration, got["app"], baseline["app"])
		}
	}
}

func localDependency(t *testing.T, graph *Graph, source, target string) Dependency {
	t.Helper()
	for _, dependency := range graph.Dependencies {
		if dependency.SourceRepositoryID == source && dependency.TargetRepositoryID == target && dependency.Resolution == ResolutionLocal {
			return dependency
		}
	}
	t.Fatalf("no local dependency %s -> %s in %#v", source, target, graph.Dependencies)
	return Dependency{}
}

func moduleByTestID(modules []Module, id string) Module {
	for _, module := range modules {
		if module.ID == id {
			return module
		}
	}
	return Module{}
}

func hasDiagnostic(diagnostics []Diagnostic, code string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return true
		}
	}
	return false
}

func writeGraphFiles(t *testing.T, root, name string, files map[string]string) string {
	t.Helper()
	directory := filepath.Join(root, name)
	keys := make([]string, 0, len(files))
	for key := range files {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, file := range keys {
		path := filepath.Join(directory, filepath.FromSlash(file))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(files[file]), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return directory
}

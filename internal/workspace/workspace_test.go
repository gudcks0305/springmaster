package workspace

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverFiltersSpringRepositoriesAndHashesWorkingState(t *testing.T) {
	root := t.TempDir()
	first := makeRepository(t, root, "spring-one", map[string]string{
		"pom.xml":      "<project><artifactId>spring-boot-starter-web</artifactId></project>",
		"src/App.java": "import org.springframework.boot.SpringApplication; class App {}",
	})
	if err := os.MkdirAll(filepath.Join(first, ".git", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(first, ".git", "nested", ".git"), []byte("must never be walked"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, first, "remote", "add", "origin", "https://example.test/acme/spring-one.git")
	second := makeRepository(t, root, "group/spring-two", map[string]string{
		"build.gradle.kts": "plugins { id(\"org.springframework.boot\") version \"3.5.0\" }",
		"src/App.kt":       "import org.springframework.boot.autoconfigure.SpringBootApplication",
	})
	_ = second
	makeRepository(t, root, "ignored/spring-three", map[string]string{
		"build.gradle": "plugins { id 'org.springframework.boot' }",
		"src/App.java": "import org.springframework.context.ApplicationContext; class App {}",
	})
	makeRepository(t, root, "plain", map[string]string{
		"pom.xml":      "<project><artifactId>plain</artifactId></project>",
		"src/App.java": "class App {}",
	})

	repositories, err := Discover(context.Background(), root, Options{MaxDepth: 2, Exclude: []string{"ignored"}})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(repositories) != 2 {
		t.Fatalf("Discover() found %d repositories, want 2: %#v", len(repositories), repositories)
	}
	firstRepository := findRepository(t, repositories, first)
	if firstRepository.ID == "" || !strings.HasPrefix(firstRepository.ID, repositoryIDPrefix) {
		t.Errorf("ID = %q, want stable repository ID", firstRepository.ID)
	}
	if firstRepository.Branch != "main" || len(firstRepository.Head) != 40 {
		t.Errorf("Git state = branch %q, head %q", firstRepository.Branch, firstRepository.Head)
	}
	if firstRepository.RemoteURL != "https://example.test/acme/spring-one.git" {
		t.Errorf("RemoteURL = %q", firstRepository.RemoteURL)
	}
	if firstRepository.Dirty || firstRepository.Untracked || !strings.HasPrefix(firstRepository.ContentHash, "sha256:") {
		t.Errorf("clean state = %#v", firstRepository)
	}

	if err := os.MkdirAll(filepath.Join(first, "build"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(first, "build", "generated.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	withIgnoredBuildChange, err := Discover(context.Background(), root, Options{MaxDepth: 2, Exclude: []string{"ignored"}})
	if err != nil {
		t.Fatalf("Discover() with build output error = %v", err)
	}
	ignoredChange := findRepository(t, withIgnoredBuildChange, first)
	if !ignoredChange.Dirty || !ignoredChange.Untracked {
		t.Errorf("ignored build change state = %#v, want dirty and untracked", ignoredChange)
	}
	if ignoredChange.ContentHash != firstRepository.ContentHash {
		t.Errorf("excluded build content changed hash: before %s after %s", firstRepository.ContentHash, ignoredChange.ContentHash)
	}

	if err := os.WriteFile(filepath.Join(first, "src", "App.java"), []byte("import org.springframework.boot.SpringApplication; class ChangedApp {}"), 0o600); err != nil {
		t.Fatal(err)
	}
	withTrackedChange, err := Discover(context.Background(), root, Options{MaxDepth: 2, Exclude: []string{"ignored"}})
	if err != nil {
		t.Fatalf("Discover() with tracked change error = %v", err)
	}
	if changed := findRepository(t, withTrackedChange, first); changed.ContentHash == firstRepository.ContentHash || !changed.Dirty || changed.Untracked != true {
		t.Errorf("tracked change state = %#v, want changed dirty hash", changed)
	}

	if err := os.WriteFile(filepath.Join(first, "new-source.txt"), []byte("relevant"), 0o600); err != nil {
		t.Fatal(err)
	}
	withRelevantChange, err := Discover(context.Background(), root, Options{MaxDepth: 2, Exclude: []string{"ignored"}})
	if err != nil {
		t.Fatalf("Discover() with relevant output error = %v", err)
	}
	if changed := findRepository(t, withRelevantChange, first); changed.ContentHash == firstRepository.ContentHash {
		t.Error("relevant untracked content did not change content hash")
	}
}

func TestDiscoverHonorsIncludeAndDepth(t *testing.T) {
	root := t.TempDir()
	first := makeRepository(t, root, "one", map[string]string{
		"pom.xml":      "<project>spring-boot</project>",
		"src/App.java": "import org.springframework.context.ApplicationContext; class App {}",
	})
	second := makeRepository(t, root, "group/two", map[string]string{
		"build.gradle": "plugins { id 'org.springframework.boot' }",
		"src/App.java": "import org.springframework.context.ApplicationContext; class App {}",
	})

	depthLimited, err := Discover(context.Background(), root, Options{MaxDepth: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(depthLimited) != 1 || depthLimited[0].Path != first {
		t.Fatalf("MaxDepth result = %#v, want only %s", depthLimited, first)
	}
	included, err := Discover(context.Background(), root, Options{Include: []string{"group/**"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(included) != 1 || included[0].Path != second {
		t.Fatalf("Include result = %#v, want only %s", included, second)
	}
}

func TestDiscoverHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Discover(ctx, t.TempDir(), Options{}); err == nil {
		t.Fatal("Discover() error = nil, want cancellation")
	}
}

func TestDiscoverContinuesAfterRepositoryPrefilterLimit(t *testing.T) {
	root := t.TempDir()
	oversized := filepath.Join(root, "a-oversized")
	if err := os.MkdirAll(filepath.Join(oversized, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < maxSpringFiles; index++ {
		name := filepath.Join(oversized, "files", fmt.Sprintf("file-%05d.txt", index))
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(oversized, "pom.xml"), []byte("<project>plain</project>"), 0o600); err != nil {
		t.Fatal(err)
	}
	valid := makeRepository(t, root, "z-valid", map[string]string{
		"pom.xml":      "<project>spring-boot</project>",
		"src/App.java": "import org.springframework.context.ApplicationContext; class App {}",
	})
	diagnostics := make([]Diagnostic, 0)
	repositories, err := Discover(context.Background(), root, Options{OnDiagnostic: func(diagnostic Diagnostic) {
		diagnostics = append(diagnostics, diagnostic)
	}})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(repositories) != 1 || repositories[0].Path != valid {
		t.Fatalf("repositories = %#v, want valid sibling %q", repositories, valid)
	}
	if len(diagnostics) != 1 || diagnostics[0].Path != oversized || diagnostics[0].Code != "spring_prefilter_incomplete" || !strings.Contains(diagnostics[0].Message, "exceeded") {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
}

func TestDiscoverSanitizesRemoteAndDisambiguatesCheckouts(t *testing.T) {
	root := t.TempDir()
	first := makeRepository(t, root, "first", map[string]string{
		"pom.xml":      "<project>spring-boot</project>",
		"src/App.java": "import org.springframework.context.ApplicationContext; class App {}",
	})
	second := makeRepository(t, root, "second", map[string]string{
		"pom.xml":      "<project>spring-boot</project>",
		"src/App.java": "import org.springframework.context.ApplicationContext; class App {}",
	})
	secretRemote := "https://agent:top-secret@example.test/acme/service.git?token=also-secret#fragment"
	git(t, first, "remote", "add", "origin", secretRemote)
	git(t, second, "remote", "add", "origin", secretRemote)

	repositories, err := Discover(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	firstRepository := findRepository(t, repositories, first)
	secondRepository := findRepository(t, repositories, second)
	if got, want := firstRepository.RemoteURL, "https://example.test/acme/service.git"; got != want {
		t.Fatalf("sanitized remote = %q, want %q", got, want)
	}
	if strings.Contains(firstRepository.RemoteURL, "secret") || strings.Contains(firstRepository.RemoteURL, "token") {
		t.Fatalf("sanitized remote leaked credential material: %q", firstRepository.RemoteURL)
	}
	if firstRepository.ID == secondRepository.ID {
		t.Fatalf("distinct checkouts with same remote share ID %q", firstRepository.ID)
	}

	alias := filepath.Join(root, "first-alias")
	if err := os.Symlink(first, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if got, want := repositoryID(alias, secretRemote), repositoryID(first, secretRemote); got != want {
		t.Errorf("canonical path ID = %q, want %q", got, want)
	}
}

func TestSanitizeRemoteURLHandlesSCPLikeSSH(t *testing.T) {
	for input, want := range map[string]string{
		"deploy@example.test:team/service.git?token=secret#fragment":              "example.test:team/service.git",
		"deploy:secret@example.test:team/service.git?token=secret#fragment":       "example.test:team/service.git",
		"ssh://deploy:secret@example.test/team/service.git?token=secret#fragment": "ssh://example.test/team/service.git",
		"https://agent:secret@example.test/team/%ZZ?token=secret#fragment":        "https://example.test/team/%ZZ",
		"deploy@[2001:db8::1]:team/service.git#fragment":                          "[2001:db8::1]:team/service.git",
	} {
		if got := sanitizeRemoteURL(input); got != want {
			t.Errorf("sanitizeRemoteURL(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestDiscoverHashesDirtyNestedGitRepositoryContent(t *testing.T) {
	root := t.TempDir()
	parent := makeRepository(t, root, "parent", map[string]string{
		"pom.xml":      "<project>spring-boot</project>",
		"src/App.java": "import org.springframework.context.ApplicationContext; class App {}",
	})
	nested := makeRepository(t, parent, "vendor/shared", map[string]string{
		"pom.xml":         "<project><artifactId>shared</artifactId></project>",
		"src/Shared.java": "class Shared { int value = 1; }",
	})
	before, err := Discover(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	beforeHash := findRepository(t, before, parent).ContentHash
	if err := os.WriteFile(filepath.Join(nested, "src", "Shared.java"), []byte("class Shared { int value = 2; }"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := Discover(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if afterHash := findRepository(t, after, parent).ContentHash; afterHash == beforeHash {
		t.Fatalf("dirty nested Git content aliased parent hash %q", afterHash)
	}
}

func findRepository(t *testing.T, repositories []Repository, path string) Repository {
	t.Helper()
	for _, repository := range repositories {
		if repository.Path == path {
			return repository
		}
	}
	t.Fatalf("repository %s not found in %#v", path, repositories)
	return Repository{}
}

func makeRepository(t *testing.T, root, relativePath string, files map[string]string) string {
	t.Helper()
	repository := filepath.Join(root, relativePath)
	for name, contents := range files {
		fileName := filepath.Join(repository, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(fileName), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fileName, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	git(t, repository, "init", "-b", "main")
	git(t, repository, "config", "user.email", "test@example.test")
	git(t, repository, "config", "user.name", "Spring Master Test")
	git(t, repository, "add", ".")
	git(t, repository, "commit", "-m", "initial")
	return repository
}

func git(t *testing.T, directory string, arguments ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", directory}, arguments...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", arguments, err, output)
	}
}

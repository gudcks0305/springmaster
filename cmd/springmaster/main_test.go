package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gudcks0305/springmaster/internal/graph"
	"github.com/gudcks0305/springmaster/internal/report"
	"github.com/gudcks0305/springmaster/internal/workspace"
)

func TestSplitCommandDoesNotUseShell(t *testing.T) {
	got, err := splitCommand(`java -jar "worker with spaces.jar" '--flag=value'`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"java", "-jar", "worker with spaces.jar", "--flag=value"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("splitCommand = %#v, want %#v", got, want)
	}
	if _, err := splitCommand("worker '"); err == nil {
		t.Fatal("expected unterminated quote error")
	}
}

func TestCommandIdentityIncludesArtifactContents(t *testing.T) {
	artifact := filepath.Join(t.TempDir(), "analyzer.jar")
	if err := os.WriteFile(artifact, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := commandIdentity([]string{os.Args[0], "-jar", artifact})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := commandIdentity([]string{os.Args[0], "-jar", artifact})
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("command identity did not change with analyzer artifact contents")
	}
}

func TestResultConfigurationFingerprintInvalidatesRuleConfigAndEnvironment(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("ANALYZER_TEST_FINGERPRINT", "one")
	command := []string{os.Args[0]}
	missing, err := resultConfigurationFingerprint(command, "STATIC_ONLY")
	if err != nil {
		t.Fatal(err)
	}
	configDirectory := filepath.Join(home, ".spring-boot-analyzer")
	if err := os.MkdirAll(configDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(configDirectory, "rule-config.json")
	if err := os.WriteFile(configPath, []byte(`{"disabledRuleIds":["RULE_A"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	configured, err := resultConfigurationFingerprint(command, "STATIC_ONLY")
	if err != nil {
		t.Fatal(err)
	}
	if missing == configured {
		t.Fatal("missing and present rule config produced same fingerprint")
	}
	prepared := preparedRepository{repository: workspace.Repository{ID: "repo"}, contentHash: "content"}
	options := scanOptions{mode: "STATIC_ONLY"}
	if analysisCacheKey("worker", missing, options, prepared) == analysisCacheKey("worker", configured, options, prepared) {
		t.Fatal("rule config change did not invalidate cache key")
	}
	t.Setenv("ANALYZER_TEST_FINGERPRINT", "two")
	environmentChanged, err := resultConfigurationFingerprint(command, "STATIC_ONLY")
	if err != nil {
		t.Fatal(err)
	}
	if configured == environmentChanged {
		t.Fatal("result-affecting environment change did not invalidate fingerprint")
	}
}

func TestResultAffectingEnvironmentScope(t *testing.T) {
	environment := []string{
		"UNRELATED=value",
		"ANALYZER_GRADLE_ENABLED=false",
		"SPRING_PROFILES_ACTIVE=test",
		"JAVA_TOOL_OPTIONS=-Duser.language=ko",
	}
	static := resultAffectingEnvironment("STATIC_ONLY", environment)
	if strings.Contains(strings.Join(static, "\n"), "UNRELATED") || len(static) != 3 {
		t.Fatalf("STATIC_ONLY environment scope = %#v", static)
	}
	extended := resultAffectingEnvironment("EXTENDED", environment)
	if len(extended) != len(environment) {
		t.Fatalf("EXTENDED must fingerprint all inherited environment: %#v", extended)
	}
}

func TestRunSnapshotBudgetAggregatesFilesAndBytes(t *testing.T) {
	budget := runSnapshotBudget{maxFiles: 5, maxBytes: 10}
	if err := budget.add(3, 4); err != nil {
		t.Fatal(err)
	}
	if err := budget.add(2, 6); err != nil {
		t.Fatal(err)
	}
	if err := budget.add(1, 0); err == nil {
		t.Fatal("expected aggregate file budget rejection")
	}
	if err := (&runSnapshotBudget{maxFiles: 5, maxBytes: 10}).add(1, 11); err == nil {
		t.Fatal("expected aggregate byte budget rejection")
	}
}

func TestOrderByDependenciesPropagatesEffectiveHash(t *testing.T) {
	root := t.TempDir()
	library := filepath.Join(root, "library")
	service := filepath.Join(root, "service")
	for _, directory := range []string{library, service} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(library, "pom.xml"), []byte(
		`<project><groupId>example</groupId><artifactId>library</artifactId><version>1</version></project>`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(service, "pom.xml"), []byte(
		`<project><groupId>example</groupId><artifactId>service</artifactId><version>1</version><dependencies><dependency><groupId>example</groupId><artifactId>library</artifactId><version>1</version></dependency></dependencies></project>`), 0o600); err != nil {
		t.Fatal(err)
	}
	repositories := []workspace.Repository{
		{ID: "service", Path: service, ContentHash: "service-content"},
		{ID: "library", Path: library, ContentHash: "library-content"},
	}
	ordered, dependencyGraph, err := orderByDependencies(t.Context(), repositories)
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{ordered[0].ID, ordered[1].ID}; !reflect.DeepEqual(got, []string{"library", "service"}) {
		t.Fatalf("dependency order = %v", got)
	}
	if dependencyGraph.EffectiveHash("service") == "" || dependencyGraph.EffectiveHash("service") == "service-content" {
		t.Fatal("dependent effective hash does not include local dependency state")
	}
}

func TestRunScanAnalyzesMultiModuleRepositoryRootOnce(t *testing.T) {
	t.Setenv("SPRINGMASTER_TEST_WORKER", "1")
	master := t.TempDir()
	root := filepath.Join(master, "multi")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("git", "init", "--quiet", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	for _, module := range []string{"library", "application"} {
		if err := os.MkdirAll(filepath.Join(root, module, "src", "main", "java"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "pom.xml"), []byte(
		`<project><groupId>example</groupId><artifactId>root</artifactId><version>1</version><packaging>pom</packaging><modules><module>library</module><module>application</module></modules></project>`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "library", "pom.xml"), []byte(
		`<project><parent><groupId>example</groupId><artifactId>root</artifactId><version>1</version></parent><artifactId>library</artifactId></project>`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "application", "pom.xml"), []byte(
		`<project><parent><groupId>example</groupId><artifactId>root</artifactId><version>1</version></parent><artifactId>application</artifactId><dependencies><dependency><groupId>example</groupId><artifactId>library</artifactId><version>1</version></dependency></dependencies></project>`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "application", "src", "main", "java", "App.java"), []byte("@SpringBootApplication class App {}"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{
		"scan", master,
		"--worker-command", testWorkerCommand(),
		"--format", "json",
		"--no-cache",
		"--fail-on", "none",
	}, &stdout, &stderr)
	if code != exitClean {
		t.Fatalf("code = %d, stderr=%s", code, stderr.String())
	}
	var output struct {
		Repositories []struct {
			Path string `json:"path"`
		} `json:"repositories"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("decode report: %v\n%s", err, stdout.String())
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(output.Repositories) != 1 || filepath.Clean(output.Repositories[0].Path) != filepath.Clean(canonicalRoot) {
		t.Fatalf("repository root must be analyzed once: %s", stdout.String())
	}
}

func TestRunScanMaterializesCrossRepositoryDependencyContext(t *testing.T) {
	t.Setenv("SPRINGMASTER_TEST_WORKER", "1")
	t.Setenv("SPRINGMASTER_TEST_REQUIRE_DEPENDENCY_SOURCE", "1")
	t.Setenv("HOME", t.TempDir())
	master := t.TempDir()
	library := makeSpringRepository(t, master, "library", false)
	service := makeSpringRepository(t, master, "service", false)
	if err := os.WriteFile(filepath.Join(library, "pom.xml"), []byte(
		`<project><groupId>example</groupId><artifactId>library</artifactId><version>1</version><dependency>spring-boot</dependency></project>`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(library, "src", "main", "java", "Shared.java"), []byte("class Shared {}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(service, "pom.xml"), []byte(
		`<project><groupId>example</groupId><artifactId>service</artifactId><version>1</version><dependency>spring-boot</dependency><dependencies><dependency><groupId>example</groupId><artifactId>library</artifactId><version>1</version></dependency></dependencies></project>`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(service, "src", "main", "java", "Service.java"), []byte("class Service extends Shared {}"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, repository := range []string{library, service} {
		gitCommand(t, repository, "config", "user.email", "test@example.test")
		gitCommand(t, repository, "config", "user.name", "Springmaster Test")
		gitCommand(t, repository, "add", ".")
		gitCommand(t, repository, "commit", "-m", "dependency-replay")
	}

	state := t.TempDir()
	arguments := []string{
		"scan", master,
		"--worker-command", testWorkerCommand(),
		"--cache-dir", filepath.Join(state, "cache"),
		"--fail-on", "none",
	}
	var stdout, stderr bytes.Buffer
	code := run(t.Context(), arguments, &stdout, &stderr)
	if code != exitClean {
		t.Fatalf("code=%d stderr=%s report=%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "2 (completed: 2, failed: 0)") || !strings.Contains(stdout.String(), "Findings: 2 ") {
		t.Fatalf("cross-repository report incomplete: %s", stdout.String())
	}
	if strings.Contains(stdout.String(), "Shared.java") {
		t.Fatalf("dependency overlay finding leaked into owner report: %s", stdout.String())
	}

	t.Setenv("SPRINGMASTER_TEST_WORKER_FAIL_ALL", "1")
	stdout.Reset()
	stderr.Reset()
	if code := run(t.Context(), arguments, &stdout, &stderr); code != exitClean {
		t.Fatalf("dependency replay code=%d stderr=%s report=%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stderr.String(), "cache replay: reused exact results for 2 repositories") ||
		strings.Contains(stdout.String(), "Shared.java") ||
		!strings.Contains(stdout.String(), "Findings: 2 ") {
		t.Fatalf("dependency replay/filtering wrong: stderr=%s report=%s", stderr.String(), stdout.String())
	}
	t.Setenv("SPRINGMASTER_TEST_WORKER_FAIL_ALL", "0")

	// The dependency is now a cache hit, while the changed dependent is a miss.
	// Its already-materialized overlay must survive prompt dependency snapshot cleanup.
	if err := os.WriteFile(filepath.Join(service, "src", "main", "java", "Service.java"), []byte("class Service extends Shared { int changed; }"), 0o600); err != nil {
		t.Fatal(err)
	}
	countFile := filepath.Join(state, "snapshot-count")
	t.Setenv("SPRINGMASTER_TEST_SNAPSHOT_COUNT_FILE", countFile)
	stdout.Reset()
	stderr.Reset()
	if code := run(t.Context(), arguments, &stdout, &stderr); code != exitClean {
		t.Fatalf("warm dependent code=%d stderr=%s report=%s", code, stderr.String(), stdout.String())
	}
	if counts, err := os.ReadFile(countFile); err != nil || strings.TrimSpace(string(counts)) != "1" {
		t.Fatalf("cache-hit dependency snapshot not promptly cleaned: %v %q", err, counts)
	}
	if strings.Contains(stdout.String(), "Shared.java") || !strings.Contains(stdout.String(), "Findings: 2 ") {
		t.Fatalf("warm dependency context filtering wrong: %s", stdout.String())
	}

	// A dependency source change invalidates both its own cache entry and every
	// dependent effective hash.
	if err := os.WriteFile(filepath.Join(library, "src", "main", "java", "Shared.java"), []byte("class Shared { int changed; }"), 0o600); err != nil {
		t.Fatal(err)
	}
	requestCountFile := filepath.Join(state, "request-count")
	t.Setenv("SPRINGMASTER_TEST_REQUEST_COUNT_FILE", requestCountFile)
	stdout.Reset()
	stderr.Reset()
	if code := run(t.Context(), arguments, &stdout, &stderr); code != exitClean {
		t.Fatalf("dependency change code=%d stderr=%s report=%s", code, stderr.String(), stdout.String())
	}
	if requests, err := os.ReadFile(requestCountFile); err != nil || strings.Count(string(requests), "request\n") != 2 {
		t.Fatalf("dependency change did not invalidate dependent cache: %v %q", err, requests)
	}
	if strings.Contains(stdout.String(), "Shared.java") || !strings.Contains(stdout.String(), "Findings: 2 ") {
		t.Fatalf("dependency-change filtering wrong: %s", stdout.String())
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), []string{"wat"}, &stdout, &stderr); code != exitInvalidArgs {
		t.Fatalf("code = %d, want %d", code, exitInvalidArgs)
	}
	if stdout.Len() != 0 || stderr.Len() == 0 {
		t.Fatalf("unexpected output stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunShowsHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), []string{"scan", "--help"}, &stdout, &stderr); code != exitClean {
		t.Fatalf("code = %d, want %d", code, exitClean)
	}
	if stdout.Len() == 0 || stderr.Len() != 0 {
		t.Fatalf("unexpected output stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunShowsShortHelp(t *testing.T) {
	for _, arguments := range [][]string{{"-h"}, {"scan", "-h"}} {
		var stdout, stderr bytes.Buffer
		if code := run(t.Context(), arguments, &stdout, &stderr); code != exitClean {
			t.Fatalf("run(%q) code = %d, want %d", arguments, code, exitClean)
		}
		if stdout.Len() == 0 || stderr.Len() != 0 {
			t.Fatalf("run(%q) stdout=%q stderr=%q", arguments, stdout.String(), stderr.String())
		}
	}
}

func TestRunScanEmptyRootDoesNotStartWorker(t *testing.T) {
	root := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{
		"scan", root,
		"--worker-command", filepath.Join(root, "worker-does-not-exist"),
		"--format", "json",
	}, &stdout, &stderr)
	if code != exitClean {
		t.Fatalf("code = %d, want %d; stderr=%s", code, exitClean, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"repositories": 0`) || !strings.Contains(stdout.String(), `"repositories": []`) {
		t.Fatalf("empty report missing: %s", stdout.String())
	}
}

func TestRunScanRepositoryRootDoesNotWriteSource(t *testing.T) {
	t.Setenv("SPRINGMASTER_TEST_WORKER", "1")
	t.Setenv("HOME", t.TempDir())
	master := t.TempDir()
	repository := makeSpringRepository(t, master, "root", false)

	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{
		"scan", repository,
		"--worker-command", testWorkerCommand(),
		"--format", "json",
		"--fail-on", "none",
	}, &stdout, &stderr)
	if code != exitClean {
		t.Fatalf("code = %d, stderr=%s", code, stderr.String())
	}
	if _, err := os.Lstat(filepath.Join(repository, ".springmaster")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source repository mutated, .springmaster stat error = %v", err)
	}
}

func TestRunScanCapsWorkerProcessesAtMisses(t *testing.T) {
	t.Setenv("SPRINGMASTER_TEST_WORKER", "1")
	countFile := filepath.Join(t.TempDir(), "worker-count")
	t.Setenv("SPRINGMASTER_TEST_WORKER_COUNT_FILE", countFile)
	root := t.TempDir()
	makeSpringRepository(t, root, "alpha", false)
	makeSpringRepository(t, root, "beta", false)

	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{
		"scan", root,
		"--worker-command", testWorkerCommand(),
		"--workers", "8",
		"--no-cache",
		"--fail-on", "none",
	}, &stdout, &stderr)
	if code != exitClean {
		t.Fatalf("code = %d, stderr=%s", code, stderr.String())
	}
	contents, err := os.ReadFile(countFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(contents), "worker\n"); got != 2 {
		t.Fatalf("worker processes = %d, want 2; contents=%q", got, contents)
	}
}

func TestRunScanUsesAndCleansPrivateMarkedSnapshotRoot(t *testing.T) {
	t.Setenv("SPRINGMASTER_TEST_WORKER", "1")
	allowedRootLog := filepath.Join(t.TempDir(), "allowed-root")
	t.Setenv("SPRINGMASTER_TEST_ALLOWED_ROOT_LOG", allowedRootLog)
	master := t.TempDir()
	makeSpringRepository(t, master, "repo", false)

	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{
		"scan", master,
		"--worker-command", testWorkerCommand(),
		"--no-cache",
		"--fail-on", "none",
	}, &stdout, &stderr)
	if code != exitClean {
		t.Fatalf("code = %d, stderr=%s", code, stderr.String())
	}
	contents, err := os.ReadFile(allowedRootLog)
	if err != nil {
		t.Fatal(err)
	}
	allowedRoot := strings.TrimSpace(string(contents))
	if allowedRoot == "" {
		t.Fatal("worker allowed root was empty")
	}
	if _, err := os.Lstat(allowedRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private snapshot root was not cleaned: %s: %v", allowedRoot, err)
	}
}

func TestRunScanExtendedRequiresTrustAndWarns(t *testing.T) {
	t.Setenv("SPRINGMASTER_TEST_WORKER", "1")
	root := t.TempDir()
	makeSpringRepository(t, root, "trusted", false)

	var rejectedOut, rejectedErr bytes.Buffer
	if code := run(t.Context(), []string{
		"scan", root,
		"--worker-command", testWorkerCommand(),
		"--mode", "EXTENDED",
	}, &rejectedOut, &rejectedErr); code != exitInvalidArgs {
		t.Fatalf("untrusted EXTENDED code = %d, want %d", code, exitInvalidArgs)
	}

	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{
		"scan", root,
		"--worker-command", testWorkerCommand(),
		"--mode", "EXTENDED",
		"--trust-extended",
		"--no-cache",
		"--fail-on", "none",
	}, &stdout, &stderr)
	if code != exitClean {
		t.Fatalf("trusted EXTENDED code = %d, stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "WARNING:") || !strings.Contains(stderr.String(), "not a sandbox") {
		t.Fatalf("EXTENDED warning missing: %q", stderr.String())
	}
}

func TestRunScanExtendedRejectsMultipleRepositories(t *testing.T) {
	root := t.TempDir()
	makeSpringRepository(t, root, "one", false)
	makeSpringRepository(t, root, "two", false)
	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{
		"scan", root,
		"--worker-command", filepath.Join(root, "unused-worker"),
		"--mode", "EXTENDED",
		"--trust-extended",
	}, &stdout, &stderr)
	if code != exitInvalidArgs || !strings.Contains(stderr.String(), "exactly one discovered repository") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestConfigureStoragePathsRejectsSourceWrites(t *testing.T) {
	repository := t.TempDir()
	options := scanOptions{noCache: true, output: filepath.Join(repository, "report.json")}
	if err := configureStoragePaths(&options, []workspace.Repository{{Path: repository}}); err == nil {
		t.Fatal("expected source output rejection")
	}
	options.allowSourceWrite = true
	if err := configureStoragePaths(&options, []workspace.Repository{{Path: repository}}); err != nil {
		t.Fatalf("explicit source write opt-in rejected: %v", err)
	}
}

func TestConfigureStoragePathsRejectsBroadCacheTargets(t *testing.T) {
	repository := t.TempDir()
	ancestor := filepath.Dir(repository)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, cacheDirectory := range []string{
		filepath.Clean(filepath.VolumeName(repository) + string(filepath.Separator)),
		home,
		os.TempDir(),
		ancestor,
	} {
		options := scanOptions{cacheDir: cacheDirectory, allowSourceWrite: true}
		if err := configureStoragePaths(&options, []workspace.Repository{{Path: repository}}); err == nil {
			t.Fatalf("broad cache target accepted: %s", cacheDirectory)
		}
	}
}

func TestWriteReportFileIsAtomicPrivateAndRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	output := filepath.Join(directory, "report.json")
	if err := os.WriteFile(output, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	options := scanOptions{output: output, format: "json"}
	if err := writeReport(options, io.Discard, report.Aggregate(nil)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("report mode = %o, want 600", got)
	}
	contents, err := os.ReadFile(output)
	if err != nil || !json.Valid(contents) {
		t.Fatalf("report contents invalid: %v %q", err, contents)
	}

	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "link.json")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	options.output = link
	if err := writeReport(options, io.Discard, report.Aggregate(nil)); err == nil {
		t.Fatal("expected symlink destination rejection")
	}
	if contents, err := os.ReadFile(target); err != nil || string(contents) != "keep" {
		t.Fatalf("symlink target changed: %v %q", err, contents)
	}
}

func TestWriteGraphDiagnosticsGroupsDuplicates(t *testing.T) {
	var output bytes.Buffer
	writeGraphDiagnostics(&output, []graph.Diagnostic{
		{RepositoryID: "repo", Code: "DYNAMIC", Message: "unresolved"},
		{RepositoryID: "repo-2", Code: "DYNAMIC", Message: "unresolved"},
	})
	if got := output.String(); strings.Count(got, "DYNAMIC") != 1 || !strings.Contains(got, "[repo,repo-2]") || !strings.Contains(got, "(x2)") {
		t.Fatalf("diagnostics not grouped: %q", got)
	}
}

func TestWriteWorkspaceDiagnosticsGroupsAndEscapes(t *testing.T) {
	var output bytes.Buffer
	writeWorkspaceDiagnostics(&output, []workspace.Diagnostic{
		{Path: "bad\npath", Code: "spring_prefilter_incomplete", Message: "limit"},
		{Path: "other", Code: "spring_prefilter_incomplete", Message: "limit"},
	})
	if got := output.String(); strings.Count(got, "spring_prefilter_incomplete") != 1 || !strings.Contains(got, "2 paths") || strings.Contains(got, "bad\npath") {
		t.Fatalf("workspace diagnostics not grouped/escaped: %q", got)
	}
}

func TestRunScanAggregatesWorkerResults(t *testing.T) {
	t.Setenv("SPRINGMASTER_TEST_WORKER", "1")
	root := t.TempDir()
	makeSpringRepository(t, root, "alpha", false)
	makeSpringRepository(t, root, "zeta", false)

	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{
		"scan", root,
		"--worker-command", testWorkerCommand(),
		"--workers", "2",
		"--format", "json",
		"--no-cache",
	}, &stdout, &stderr)
	if code != exitFindings {
		t.Fatalf("code = %d, want %d; stderr=%s", code, exitFindings, stderr.String())
	}
	var output struct {
		Repositories []struct {
			Path     string `json:"path"`
			Status   string `json:"status"`
			Findings []struct {
				Severity string `json:"severity"`
				Rule     string `json:"rule"`
				Path     string `json:"path"`
			} `json:"findings"`
		} `json:"repositories"`
		Summary struct {
			Completed int `json:"completed"`
			Failed    int `json:"failed"`
			Findings  struct {
				Errors int `json:"errors"`
			} `json:"findings"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout.String())
	}
	if len(output.Repositories) != 2 || output.Summary.Completed != 2 || output.Summary.Failed != 0 || output.Summary.Findings.Errors != 2 {
		t.Fatalf("unexpected report: %s", stdout.String())
	}
	if !strings.Contains(output.Repositories[0].Path, "alpha") || output.Repositories[0].Status != "completed" {
		t.Fatalf("repositories not stable/completed: %s", stdout.String())
	}
	first := output.Repositories[0].Findings[0]
	if first.Severity != "ERROR" || first.Rule != "TEST_RULE" || first.Path != "src/main/java/App.java" {
		t.Fatalf("finding extraction wrong: %#v", first)
	}
}

func TestRunScanIsolatesRepositoryFailure(t *testing.T) {
	t.Setenv("SPRINGMASTER_TEST_WORKER", "1")
	root := t.TempDir()
	makeSpringRepository(t, root, "ok", false)
	makeSpringRepository(t, root, "failed", true)

	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{
		"scan", root,
		"--worker-command", testWorkerCommand(),
		"--format", "json",
		"--no-cache",
		"--fail-on", "none",
	}, &stdout, &stderr)
	if code != exitOperational {
		t.Fatalf("code = %d, want %d; stderr=%s", code, exitOperational, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"completed": 1`) || !strings.Contains(stdout.String(), `"failed": 1`) || !strings.Contains(stdout.String(), "TEST_FAILURE") {
		t.Fatalf("isolated failure missing from report:\n%s", stdout.String())
	}
}

func TestRunScanUsesCompletedResultCacheUnlessDisabled(t *testing.T) {
	t.Setenv("SPRINGMASTER_TEST_WORKER", "1")
	root := t.TempDir()
	makeSpringRepository(t, root, "cached", false)
	state := t.TempDir()
	countFile := filepath.Join(state, "worker-count")
	t.Setenv("SPRINGMASTER_TEST_WORKER_COUNT_FILE", countFile)
	arguments := []string{
		"scan", root,
		"--worker-command", testWorkerCommand(),
		"--format", "json",
		"--fail-on", "none",
		"--cache-dir", filepath.Join(state, "cache"),
	}

	var firstOutput, firstError bytes.Buffer
	if code := run(t.Context(), arguments, &firstOutput, &firstError); code != exitClean {
		t.Fatalf("first code = %d, want %d; stderr=%s", code, exitClean, firstError.String())
	}
	if contents, err := os.ReadFile(countFile); err != nil || strings.Count(string(contents), "worker\n") != 1 {
		t.Fatalf("first scan worker count: %v %q", err, contents)
	}

	// A second worker would return a request failure. A successful second scan
	// proves it used the valid completed raw result stored by the first scan.
	if err := os.WriteFile(countFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SPRINGMASTER_TEST_WORKER_FAIL_ALL", "1")
	var secondOutput, secondError bytes.Buffer
	if code := run(t.Context(), arguments, &secondOutput, &secondError); code != exitClean {
		t.Fatalf("cached code = %d, want %d; stderr=%s\nreport=%s", code, exitClean, secondError.String(), secondOutput.String())
	}
	if strings.Contains(secondOutput.String(), "TEST_FAILURE") || !strings.Contains(secondOutput.String(), `"completed": 1`) {
		t.Fatalf("cache result wrong:\n%s", secondOutput.String())
	}
	if contents, err := os.ReadFile(countFile); err != nil || len(contents) != 0 {
		t.Fatalf("cache hit started worker: %v %q", err, contents)
	}

	var bypassOutput, bypassError bytes.Buffer
	if code := run(t.Context(), append(append([]string(nil), arguments...), "--no-cache"), &bypassOutput, &bypassError); code != exitOperational {
		t.Fatalf("no-cache code = %d, want %d; stderr=%s\nreport=%s", code, exitOperational, bypassError.String(), bypassOutput.String())
	}
	if !strings.Contains(bypassOutput.String(), "TEST_FAILURE") {
		t.Fatalf("no-cache did not call worker:\n%s", bypassOutput.String())
	}
}

func TestRunScanReplaysExactResultsAcrossBranchRoundTrip(t *testing.T) {
	t.Setenv("SPRINGMASTER_TEST_WORKER", "1")
	t.Setenv("HOME", t.TempDir())
	master := t.TempDir()
	repository := makeSpringRepository(t, master, "branch-replay", false)
	gitCommand(t, repository, "config", "user.email", "test@example.test")
	gitCommand(t, repository, "config", "user.name", "Springmaster Test")
	gitCommand(t, repository, "add", ".")
	gitCommand(t, repository, "commit", "-m", "branch-a")
	mainBranch := strings.TrimSpace(gitCommand(t, repository, "branch", "--show-current"))

	state := t.TempDir()
	countFile := filepath.Join(state, "worker-count")
	snapshotCountFile := filepath.Join(state, "snapshot-root-count")
	t.Setenv("SPRINGMASTER_TEST_WORKER_COUNT_FILE", countFile)
	t.Setenv("SPRINGMASTER_TEST_RUN_SNAPSHOT_COUNT_FILE", snapshotCountFile)
	arguments := []string{
		"scan", master,
		"--worker-command", testWorkerCommand(),
		"--format", "json",
		"--fail-on", "none",
		"--cache-dir", filepath.Join(state, "cache"),
	}
	runScanForTest(t, arguments, exitClean)
	assertWorkerStarts(t, countFile, 1)
	assertMarkerCount(t, snapshotCountFile, "snapshot-root\n", 1)

	gitCommand(t, repository, "switch", "-c", "same-content")
	t.Setenv("SPRINGMASTER_TEST_WORKER_FAIL_ALL", "1")
	_, aliasError := runScanForTest(t, arguments, exitClean)
	if !strings.Contains(aliasError, "cache replay: reused exact results") {
		t.Fatalf("same-content branch did not replay exact result: %s", aliasError)
	}
	assertWorkerStarts(t, countFile, 1)
	assertMarkerCount(t, snapshotCountFile, "snapshot-root\n", 1)

	t.Setenv("SPRINGMASTER_TEST_WORKER_FAIL_ALL", "0")
	if err := os.WriteFile(
		filepath.Join(repository, "src", "main", "java", "App.java"),
		[]byte("@SpringBootApplication class BranchB {}"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	gitCommand(t, repository, "add", ".")
	gitCommand(t, repository, "commit", "-m", "branch-b")
	runScanForTest(t, arguments, exitClean)
	assertWorkerStarts(t, countFile, 2)
	assertMarkerCount(t, snapshotCountFile, "snapshot-root\n", 2)

	gitCommand(t, repository, "switch", mainBranch)
	t.Setenv("SPRINGMASTER_TEST_WORKER_FAIL_ALL", "1")
	_, roundTripError := runScanForTest(t, arguments, exitClean)
	if !strings.Contains(roundTripError, "cache replay: reused exact results") {
		t.Fatalf("A-B-A branch return did not replay exact result: %s", roundTripError)
	}
	assertWorkerStarts(t, countFile, 2)
	assertMarkerCount(t, snapshotCountFile, "snapshot-root\n", 2)
}

func TestRunScanDoesNotReplayDirtyWorkspace(t *testing.T) {
	t.Setenv("SPRINGMASTER_TEST_WORKER", "1")
	t.Setenv("HOME", t.TempDir())
	master := t.TempDir()
	repository := makeSpringRepository(t, master, "dirty-replay", false)
	gitCommand(t, repository, "config", "user.email", "test@example.test")
	gitCommand(t, repository, "config", "user.name", "Springmaster Test")
	gitCommand(t, repository, "add", ".")
	gitCommand(t, repository, "commit", "-m", "clean")

	state := t.TempDir()
	countFile := filepath.Join(state, "worker-count")
	t.Setenv("SPRINGMASTER_TEST_WORKER_COUNT_FILE", countFile)
	arguments := []string{
		"scan", master,
		"--worker-command", testWorkerCommand(),
		"--format", "json",
		"--fail-on", "none",
		"--cache-dir", filepath.Join(state, "cache"),
	}
	runScanForTest(t, arguments, exitClean)
	if err := os.WriteFile(
		filepath.Join(repository, "src", "main", "java", "App.java"),
		[]byte("@SpringBootApplication class Dirty {}"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SPRINGMASTER_TEST_WORKER_FAIL_ALL", "1")
	stdout, stderr := runScanForTest(t, arguments, exitOperational)
	if strings.Contains(stderr, "cache replay: reused exact results") ||
		!strings.Contains(stdout, "TEST_FAILURE") {
		t.Fatalf("dirty workspace reused replay: stderr=%s report=%s", stderr, stdout)
	}
	assertWorkerStarts(t, countFile, 2)
}

func TestRunScanRejectsValidJSONResultCacheCorruption(t *testing.T) {
	t.Setenv("SPRINGMASTER_TEST_WORKER", "1")
	t.Setenv("HOME", t.TempDir())
	master := t.TempDir()
	repository := makeSpringRepository(t, master, "corrupt-replay", false)
	gitCommand(t, repository, "config", "user.email", "test@example.test")
	gitCommand(t, repository, "config", "user.name", "Springmaster Test")
	gitCommand(t, repository, "add", ".")
	gitCommand(t, repository, "commit", "-m", "clean")

	state := t.TempDir()
	cacheDirectory := filepath.Join(state, "cache")
	countFile := filepath.Join(state, "worker-count")
	snapshotCountFile := filepath.Join(state, "snapshot-root-count")
	t.Setenv("SPRINGMASTER_TEST_WORKER_COUNT_FILE", countFile)
	t.Setenv("SPRINGMASTER_TEST_RUN_SNAPSHOT_COUNT_FILE", snapshotCountFile)
	arguments := []string{
		"scan", master,
		"--worker-command", testWorkerCommand(),
		"--format", "json",
		"--fail-on", "none",
		"--cache-dir", cacheDirectory,
	}
	runScanForTest(t, arguments, exitClean)
	corruptCachedAnalysisResult(t, cacheDirectory)

	t.Setenv("SPRINGMASTER_TEST_WORKER_FAIL_ALL", "1")
	stdout, stderr := runScanForTest(t, arguments, exitOperational)
	if strings.Contains(stderr, "cache replay: reused exact results") {
		t.Fatalf("corrupt cached result was replayed: %s", stderr)
	}
	if !strings.Contains(stdout, "TEST_FAILURE") {
		t.Fatalf("corrupt cached result did not force worker recomputation: %s", stdout)
	}
	assertWorkerStarts(t, countFile, 2)
	assertMarkerCount(t, snapshotCountFile, "snapshot-root\n", 2)
}

func TestRunScanResultConfigurationChangesBypassCache(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*testing.T, string)
	}{
		{
			name: "rule config",
			change: func(t *testing.T, home string) {
				directory := filepath.Join(home, ".spring-boot-analyzer")
				if err := os.MkdirAll(directory, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(directory, "rule-config.json"), []byte(`{"disabledRuleIds":["RULE"]}`), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "analyzer environment",
			change: func(t *testing.T, _ string) {
				t.Setenv("ANALYZER_TEST_CACHE_IDENTITY", "changed")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("SPRINGMASTER_TEST_WORKER", "1")
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("ANALYZER_TEST_CACHE_IDENTITY", "initial")
			master := t.TempDir()
			makeSpringRepository(t, master, "repo", false)
			state := t.TempDir()
			countFile := filepath.Join(state, "worker-count")
			t.Setenv("SPRINGMASTER_TEST_WORKER_COUNT_FILE", countFile)
			arguments := []string{
				"scan", master,
				"--worker-command", testWorkerCommand(),
				"--cache-dir", filepath.Join(state, "cache"),
				"--fail-on", "none",
			}
			var stdout, stderr bytes.Buffer
			if code := run(t.Context(), arguments, &stdout, &stderr); code != exitClean {
				t.Fatalf("prime code=%d stderr=%s", code, stderr.String())
			}
			if err := os.WriteFile(countFile, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			test.change(t, home)
			t.Setenv("SPRINGMASTER_TEST_WORKER_FAIL_ALL", "1")
			stdout.Reset()
			stderr.Reset()
			if code := run(t.Context(), arguments, &stdout, &stderr); code != exitOperational {
				t.Fatalf("changed config reused stale cache: code=%d stderr=%s report=%s", code, stderr.String(), stdout.String())
			}
			if contents, err := os.ReadFile(countFile); err != nil || strings.Count(string(contents), "worker\n") != 1 {
				t.Fatalf("changed config worker count: %v %q", err, contents)
			}
		})
	}
}

func TestRunScanCleansCacheHitSnapshotBeforeAnalyzingMiss(t *testing.T) {
	t.Setenv("SPRINGMASTER_TEST_WORKER", "1")
	t.Setenv("HOME", t.TempDir())
	master := t.TempDir()
	makeSpringRepository(t, master, "alpha", false)
	beta := makeSpringRepository(t, master, "beta", false)
	state := t.TempDir()
	arguments := []string{
		"scan", master,
		"--worker-command", testWorkerCommand(),
		"--cache-dir", filepath.Join(state, "cache"),
		"--fail-on", "none",
	}
	var firstOutput, firstError bytes.Buffer
	if code := run(t.Context(), arguments, &firstOutput, &firstError); code != exitClean {
		t.Fatalf("prime code=%d stderr=%s", code, firstError.String())
	}
	if err := os.WriteFile(filepath.Join(beta, "src", "main", "java", "App.java"), []byte("@SpringBootApplication class Changed {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	countFile := filepath.Join(state, "snapshot-count")
	t.Setenv("SPRINGMASTER_TEST_SNAPSHOT_COUNT_FILE", countFile)
	var secondOutput, secondError bytes.Buffer
	if code := run(t.Context(), arguments, &secondOutput, &secondError); code != exitClean {
		t.Fatalf("second code=%d stderr=%s", code, secondError.String())
	}
	contents, err := os.ReadFile(countFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(contents)) != "1" {
		t.Fatalf("live snapshot count at miss analysis = %q, want 1", contents)
	}
}

func TestRunScanCacheWriteFailureDoesNotDiscardAnalysis(t *testing.T) {
	t.Setenv("SPRINGMASTER_TEST_WORKER", "1")
	t.Setenv("HOME", t.TempDir())
	master := t.TempDir()
	makeSpringRepository(t, master, "repo", false)
	cacheDirectory := filepath.Join(t.TempDir(), "cache")
	t.Setenv("SPRINGMASTER_TEST_BREAK_CACHE_DIR", cacheDirectory)
	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{
		"scan", master,
		"--worker-command", testWorkerCommand(),
		"--cache-dir", cacheDirectory,
		"--fail-on", "none",
	}, &stdout, &stderr)
	if code != exitClean {
		t.Fatalf("cache failure discarded analysis: code=%d stderr=%s report=%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "completed: 1, failed: 0") || !strings.Contains(stderr.String(), "completed result was not cached") {
		t.Fatalf("cache failure diagnostic/result missing: stderr=%s report=%s", stderr.String(), stdout.String())
	}
}

func TestWorkerProcess(t *testing.T) {
	if os.Getenv("SPRINGMASTER_TEST_WORKER") != "1" {
		return
	}
	if countFile := os.Getenv("SPRINGMASTER_TEST_WORKER_COUNT_FILE"); countFile != "" {
		file, err := os.OpenFile(countFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			os.Exit(12)
		}
		_, _ = file.WriteString("worker\n")
		_ = file.Close()
	}
	allowedRoot := os.Getenv("SPRINGMASTER_WORKER_ALLOWED_ROOT")
	if allowedRoot == "" || os.Getenv("SPRINGMASTER_WORKER_REQUIRE_SNAPSHOT_MARKER") != "true" {
		os.Exit(13)
	}
	if logFile := os.Getenv("SPRINGMASTER_TEST_ALLOWED_ROOT_LOG"); logFile != "" {
		if err := os.WriteFile(logFile, []byte(allowedRoot+"\n"), 0o600); err != nil {
			os.Exit(14)
		}
	}
	scanner := bufio.NewScanner(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var request struct {
			SchemaVersion  int    `json:"schemaVersion"`
			RequestID      string `json:"requestId"`
			RepositoryPath string `json:"repositoryPath"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			os.Exit(11)
		}
		if countFile := os.Getenv("SPRINGMASTER_TEST_REQUEST_COUNT_FILE"); countFile != "" {
			file, err := os.OpenFile(countFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
			if err != nil {
				os.Exit(20)
			}
			_, _ = file.WriteString("request\n")
			_ = file.Close()
		}
		if !pathWithin(allowedRoot, request.RepositoryPath) {
			os.Exit(15)
		}
		markers, err := filepath.Glob(filepath.Join(request.RepositoryPath, ".snapshot-marker-*"))
		if err != nil || len(markers) != 1 {
			os.Exit(16)
		}
		if os.Getenv("SPRINGMASTER_TEST_REQUIRE_DEPENDENCY_SOURCE") == "1" {
			if _, err := os.Stat(filepath.Join(request.RepositoryPath, "src", "main", "java", "Service.java")); err == nil {
				matches, globErr := filepath.Glob(filepath.Join(request.RepositoryPath, "_springmaster_deps", "*", "src", "main", "java", "Shared.java"))
				if globErr != nil || len(matches) != 1 {
					os.Exit(19)
				}
			}
		}
		if cacheDirectory := os.Getenv("SPRINGMASTER_TEST_BREAK_CACHE_DIR"); cacheDirectory != "" {
			if err := os.Chmod(cacheDirectory, 0o755); err != nil {
				os.Exit(21)
			}
		}
		if countFile := os.Getenv("SPRINGMASTER_TEST_SNAPSHOT_COUNT_FILE"); countFile != "" {
			entries, err := os.ReadDir(allowedRoot)
			if err != nil {
				os.Exit(17)
			}
			live := 0
			for _, entry := range entries {
				if entry.IsDir() && strings.HasPrefix(entry.Name(), "springmaster-") {
					live++
				}
			}
			file, err := os.OpenFile(countFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
			if err != nil {
				os.Exit(18)
			}
			_, _ = fmt.Fprintf(file, "%d\n", live)
			_ = file.Close()
		}
		if os.Getenv("SPRINGMASTER_TEST_WORKER_FAIL_ALL") == "1" {
			_ = encoder.Encode(map[string]any{
				"schemaVersion": request.SchemaVersion,
				"requestId":     request.RequestID,
				"status":        "failed",
				"error":         map[string]string{"code": "TEST_FAILURE", "message": "forced"},
			})
			continue
		}
		if _, err := os.Stat(filepath.Join(request.RepositoryPath, "FAIL_WORKER")); err == nil {
			_ = encoder.Encode(map[string]any{
				"schemaVersion": request.SchemaVersion,
				"requestId":     request.RequestID,
				"status":        "failed",
				"error":         map[string]string{"code": "TEST_FAILURE", "message": "isolated"},
			})
			continue
		}
		findings := []map[string]any{{
			"severity":   "ERROR",
			"ruleId":     "TEST_RULE",
			"sourceFile": "src/main/java/App.java",
		}}
		if os.Getenv("SPRINGMASTER_TEST_REQUIRE_DEPENDENCY_SOURCE") == "1" {
			if _, err := os.Stat(filepath.Join(request.RepositoryPath, "src", "main", "java", "Service.java")); err == nil {
				dependencyFiles, _ := filepath.Glob(filepath.Join(request.RepositoryPath, "_springmaster_deps", "*", "src", "main", "java", "Shared.java"))
				if len(dependencyFiles) == 1 {
					findings[0]["sourceFile"] = "src/main/java/Service.java"
					findings = append(findings, map[string]any{
						"severity":   "ERROR",
						"ruleId":     "DEPENDENCY_CONTEXT_ONLY",
						"sourceFile": dependencyFiles[0],
					})
				}
			}
		}
		_ = encoder.Encode(map[string]any{
			"schemaVersion": request.SchemaVersion,
			"requestId":     request.RequestID,
			"status":        "completed",
			"result": map[string]any{
				"findings": findings,
			},
		})
	}
	os.Exit(0)
}

func makeSpringRepository(t *testing.T, root, name string, workerFailure bool) string {
	t.Helper()
	repository := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Join(repository, "src", "main", "java"), 0o755); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("git", "init", "--quiet", repository).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := os.WriteFile(filepath.Join(repository, "pom.xml"), []byte("<project><dependency>spring-boot</dependency></project>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "src", "main", "java", "App.java"), []byte("@SpringBootApplication class App {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if workerFailure {
		if err := os.WriteFile(filepath.Join(repository, "FAIL_WORKER"), []byte("1"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return repository
}

func testWorkerCommand() string {
	return fmt.Sprintf("%q -test.run=^TestWorkerProcess$", os.Args[0])
}

func gitCommand(t *testing.T, directory string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", directory}, arguments...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", arguments, err, output)
	}
	return string(output)
}

func runScanForTest(t *testing.T, arguments []string, wantCode int) (string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), arguments, &stdout, &stderr); code != wantCode {
		t.Fatalf(
			"scan code=%d, want %d; stderr=%s\nreport=%s",
			code,
			wantCode,
			stderr.String(),
			stdout.String(),
		)
	}
	return stdout.String(), stderr.String()
}

func assertWorkerStarts(t *testing.T, countFile string, want int) {
	t.Helper()
	assertMarkerCount(t, countFile, "worker\n", want)
}

func assertMarkerCount(t *testing.T, countFile, marker string, want int) {
	t.Helper()
	contents, err := os.ReadFile(countFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(contents), marker); got != want {
		t.Fatalf("marker %q count=%d, want %d; contents=%q", marker, got, want, contents)
	}
}

func corruptCachedAnalysisResult(t *testing.T, cacheDirectory string) {
	t.Helper()
	entries, err := filepath.Glob(filepath.Join(cacheDirectory, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		contents, err := os.ReadFile(entry)
		if err != nil {
			t.Fatal(err)
		}
		var envelope map[string]any
		if json.Unmarshal(contents, &envelope) != nil {
			continue
		}
		value, ok := envelope["value"].(map[string]any)
		if !ok || value["findings"] == nil {
			continue
		}
		envelope["value"] = map[string]any{"findings": []any{}}
		corrupted, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(entry, corrupted, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatal("analysis result cache entry not found")
}

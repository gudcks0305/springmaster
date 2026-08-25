package analyzer

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	helperProcessEnv  = "ANALYZER_WORKER_HELPER_PROCESS"
	helperScenarioEnv = "ANALYZER_WORKER_HELPER_SCENARIO"
	helperMarkerEnv   = "ANALYZER_WORKER_HELPER_MARKER"
)

func TestWorkerPoolHelperProcess(t *testing.T) {
	if os.Getenv(helperProcessEnv) != "1" {
		return
	}

	scenario := os.Getenv(helperScenarioEnv)
	marker := os.Getenv(helperMarkerEnv)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024), 2<<20)
	for scanner.Scan() {
		var request Request
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			os.Exit(2)
		}

		switch scenario {
		case "crash-once":
			if firstHelperAttempt(marker) {
				os.Exit(23)
			}
			writeHelperCompleted(request, map[string]any{"retried": true})
		case "cancel-once":
			if firstHelperAttempt(marker) {
				time.Sleep(5 * time.Second)
			}
			writeHelperCompleted(request, map[string]any{"restarted": true})
		case "stderr":
			fmt.Fprintln(os.Stderr, "worker diagnostic")
			writeHelperCompleted(request, map[string]any{"ok": true})
		case "long-response":
			fmt.Fprintf(
				os.Stdout,
				`{"schemaVersion":1,"requestId":%q,"status":"completed","result":{"payload":%q}}`+"\n",
				request.RequestID,
				strings.Repeat("x", 4096),
			)
		case "large-response":
			writeHelperCompleted(request, map[string]any{"payload": strings.Repeat("x", 2<<20)})
		case "framed-large-response":
			writeHelperFramedCompleted(
				request,
				map[string]any{"payload": strings.Repeat("x", 20<<20)},
				helperFrameOptions{},
			)
		case "framed-corrupt-checksum":
			writeHelperFramedCompleted(
				request,
				map[string]any{"payload": "checksum"},
				helperFrameOptions{corruptChecksum: true},
			)
		case "framed-out-of-order":
			writeHelperFramedCompleted(
				request,
				map[string]any{"payload": strings.Repeat("x", responseFrameRawChunkBytes+1)},
				helperFrameOptions{outOfOrder: true},
			)
		case "framed-wrong-request":
			writeHelperFramedCompleted(
				request,
				map[string]any{"payload": "wrong request"},
				helperFrameOptions{requestID: "different-request"},
			)
		case "framed-overlong-frame":
			writeHelperOverlongFrame(request)
		case "spawn-child":
			startHelperDescendant(marker)
		case "slow":
			time.Sleep(150 * time.Millisecond)
			writeHelperCompleted(request, map[string]any{"pid": os.Getpid()})
		case "failed":
			fmt.Fprintf(
				os.Stdout,
				`{"schemaVersion":1,"requestId":%q,"status":"failed","error":{"code":"ANALYSIS_FAILED","message":"request failed"}}`+"\n",
				request.RequestID,
			)
		default:
			writeHelperCompleted(request, map[string]any{"pid": os.Getpid()})
		}
	}
	os.Exit(0)
}

func startHelperDescendant(marker string) {
	if marker == "" {
		os.Exit(3)
	}
	// This is intentionally a real descendant rather than another Go routine:
	// Unix process-group teardown must kill it when the worker is cancelled or
	// closed. It is only exercised by Unix-specific tests.
	child := exec.Command(
		"/bin/sh",
		"-c",
		"exec sleep 30",
	)
	if err := child.Start(); err != nil {
		os.Exit(4)
	}
	if err := os.WriteFile(marker, []byte(strconv.Itoa(child.Process.Pid)+"\n"), 0o600); err != nil {
		_ = child.Process.Kill()
		os.Exit(5)
	}
	_ = child.Wait()
	os.Exit(0)
}

func firstHelperAttempt(marker string) bool {
	if marker == "" {
		return false
	}
	if _, err := os.Stat(marker); err == nil {
		return false
	}
	if err := os.WriteFile(marker, []byte("attempted"), 0o600); err != nil {
		os.Exit(3)
	}
	return true
}

func writeHelperCompleted(request Request, result any) {
	encoded, err := json.Marshal(Response{
		SchemaVersion: protocolSchemaVersion,
		RequestID:     request.RequestID,
		Status:        StatusCompleted,
		Result:        mustMarshalRaw(result),
	})
	if err != nil {
		os.Exit(4)
	}
	_, _ = os.Stdout.Write(append(encoded, '\n'))
}

func mustMarshalRaw(value any) json.RawMessage {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}

func TestPoolAnalyzeGeneratesProtocolFields(t *testing.T) {
	pool := newTestPool(t, "success", Config{})
	t.Cleanup(func() { _ = pool.Close() })

	response, err := pool.Analyze(context.Background(), testRequest(t))
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if response.SchemaVersion != protocolSchemaVersion {
		t.Fatalf("SchemaVersion = %d, want %d", response.SchemaVersion, protocolSchemaVersion)
	}
	if response.RequestID == "" {
		t.Fatal("Analyze() did not generate RequestID")
	}
	if response.Status != StatusCompleted {
		t.Fatalf("Status = %q, want %q", response.Status, StatusCompleted)
	}
	if pool.WorkerCount() != 1 {
		t.Fatalf("WorkerCount() = %d, want 1", pool.WorkerCount())
	}
}

func TestPoolReusesPersistentWorkerProcess(t *testing.T) {
	pool := newTestPool(t, "success", Config{})
	t.Cleanup(func() { _ = pool.Close() })

	first, err := pool.Analyze(context.Background(), testRequest(t))
	if err != nil {
		t.Fatalf("first Analyze() error = %v", err)
	}
	second, err := pool.Analyze(context.Background(), testRequest(t))
	if err != nil {
		t.Fatalf("second Analyze() error = %v", err)
	}
	if helperPID(t, first) != helperPID(t, second) {
		t.Fatal("sequential requests did not reuse one persistent worker process")
	}
}

func TestPoolDispatchesConcurrentRequestsAcrossWorkers(t *testing.T) {
	pool := newTestPool(t, "slow", Config{Workers: 2})
	t.Cleanup(func() { _ = pool.Close() })

	start := make(chan struct{})
	responses := make(chan Response, 2)
	errors := make(chan error, 2)
	requests := make([]Request, 2)
	for index := range requests {
		requests[index] = testRequest(t)
		requests[index].RepositoryID = fmt.Sprintf("repo-%d", index)
	}
	var group sync.WaitGroup
	for index := 0; index < 2; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			<-start
			response, err := pool.Analyze(context.Background(), requests[index])
			if err != nil {
				errors <- err
				return
			}
			responses <- response
		}(index)
	}
	close(start)
	group.Wait()
	close(errors)
	close(responses)
	for err := range errors {
		t.Fatalf("Analyze() error = %v", err)
	}

	pids := map[int]struct{}{}
	for response := range responses {
		pids[helperPID(t, response)] = struct{}{}
	}
	if len(pids) != 2 {
		t.Fatalf("requests used %d processes, want 2", len(pids))
	}
}

func helperPID(t *testing.T, response Response) int {
	t.Helper()
	var result struct {
		PID int `json:"pid"`
	}
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatalf("decode response result: %v", err)
	}
	return result.PID
}

func TestPoolRestartsAndRetriesOneCrash(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "first-attempt")
	pool := newTestPool(t, "crash-once", Config{RetryLimit: 1}, marker)
	t.Cleanup(func() { _ = pool.Close() })

	response, err := pool.Analyze(context.Background(), testRequest(t))
	if err != nil {
		t.Fatalf("Analyze() error after one crash = %v", err)
	}
	var result struct {
		Retried bool `json:"retried"`
	}
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatalf("decode response result: %v", err)
	}
	if !result.Retried {
		t.Fatalf("retry result = %#v, want retried=true", result)
	}
}

func TestPoolCancellationRetiresWorkerBeforeNextRequest(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "first-attempt")
	pool := newTestPool(t, "cancel-once", Config{}, marker)
	t.Cleanup(func() { _ = pool.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := pool.Analyze(ctx, testRequest(t))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Analyze() error = %v, want deadline exceeded", err)
	}

	response, err := pool.Analyze(context.Background(), testRequest(t))
	if err != nil {
		t.Fatalf("Analyze() after cancellation error = %v", err)
	}
	var result struct {
		Restarted bool `json:"restarted"`
	}
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatalf("decode response result: %v", err)
	}
	if !result.Restarted {
		t.Fatalf("restart result = %#v, want restarted=true", result)
	}
}

func TestPoolBoundsOversizedResponse(t *testing.T) {
	pool := newTestPool(t, "long-response", Config{MaxLineBytes: 512})
	t.Cleanup(func() { _ = pool.Close() })

	_, err := pool.Analyze(context.Background(), testRequest(t))
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("Analyze() error = %v, want ErrProtocol", err)
	}
}

func TestPoolAcceptsResponseLargerThanOneMiBByDefault(t *testing.T) {
	pool := newTestPool(t, "large-response", Config{})
	t.Cleanup(func() { _ = pool.Close() })

	response, err := pool.Analyze(context.Background(), testRequest(t))
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if len(response.Result) <= 1<<20 {
		t.Fatalf("response size = %d, want > 1 MiB", len(response.Result))
	}
}

func TestPoolReassemblesFramedResponseOverLegacyLineLimit(t *testing.T) {
	pool := newTestPool(t, "framed-large-response", Config{})
	t.Cleanup(func() { _ = pool.Close() })

	response, err := pool.Analyze(context.Background(), testRequest(t))
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if len(response.Result) <= defaultMaxLineBytes {
		t.Fatalf("framed result size = %d, want > legacy line limit %d", len(response.Result), defaultMaxLineBytes)
	}
}

func TestPoolRejectsFramedResponseOverConfiguredTotalLimit(t *testing.T) {
	pool := newTestPool(t, "framed-large-response", Config{MaxResponseBytes: 16 << 20})
	t.Cleanup(func() { _ = pool.Close() })

	_, err := pool.Analyze(context.Background(), testRequest(t))
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("Analyze() error = %v, want ErrProtocol", err)
	}
}

func TestPoolRejectsFramedChecksumOrderingAndCorrelationFailures(t *testing.T) {
	for _, scenario := range []string{
		"framed-corrupt-checksum",
		"framed-out-of-order",
		"framed-wrong-request",
		"framed-overlong-frame",
	} {
		t.Run(scenario, func(t *testing.T) {
			pool := newTestPool(t, scenario, Config{})
			t.Cleanup(func() { _ = pool.Close() })

			_, err := pool.Analyze(context.Background(), testRequest(t))
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("Analyze() error = %v, want ErrProtocol", err)
			}
		})
	}
}

func TestPoolProtocolLimitsDefaultAndOverride(t *testing.T) {
	defaults, err := normalizeConfig(Config{Command: []string{"worker"}})
	if err != nil {
		t.Fatalf("normalize default config: %v", err)
	}
	if defaults.maxLineBytes != 16<<20 {
		t.Fatalf("default MaxLineBytes = %d, want 16 MiB", defaults.maxLineBytes)
	}
	if defaults.maxResponseBytes != 64<<20 {
		t.Fatalf("default MaxResponseBytes = %d, want 64 MiB", defaults.maxResponseBytes)
	}

	override, err := normalizeConfig(Config{
		Command:          []string{"worker"},
		MaxLineBytes:     24 << 20,
		MaxResponseBytes: 96 << 20,
	})
	if err != nil {
		t.Fatalf("normalize overridden config: %v", err)
	}
	if override.maxLineBytes != 24<<20 {
		t.Fatalf("overridden MaxLineBytes = %d, want 24 MiB", override.maxLineBytes)
	}
	if override.maxResponseBytes != 96<<20 {
		t.Fatalf("overridden MaxResponseBytes = %d, want 96 MiB", override.maxResponseBytes)
	}

	if _, err := normalizeConfig(Config{Command: []string{"worker"}, MaxLineBytes: 32<<20 + 1}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("normalize over-cache-boundary config error = %v, want ErrInvalidConfig", err)
	}
	if _, err := normalizeConfig(Config{Command: []string{"worker"}, MaxResponseBytes: 256<<20 + 1}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("normalize over-total-bound config error = %v, want ErrInvalidConfig", err)
	}
}

func TestPoolConfigExportsCanonicalWorkerRoot(t *testing.T) {
	root := t.TempDir()
	config, err := normalizeConfig(Config{
		Command:               []string{"worker"},
		AllowedRoot:           root,
		RequireSnapshotMarker: true,
	})
	if err != nil {
		t.Fatalf("normalize allowed-root config: %v", err)
	}
	if config.allowedRoot == "" || !filepath.IsAbs(config.allowedRoot) {
		t.Fatalf("canonical allowed root = %q, want absolute directory", config.allowedRoot)
	}
	environment := workerEnvironment(config)
	if !containsEnvironment(environment, "SPRINGMASTER_WORKER_ALLOWED_ROOT="+config.allowedRoot) {
		t.Fatalf("worker environment does not contain canonical allowed root")
	}
	if !containsEnvironment(environment, "SPRINGMASTER_WORKER_REQUIRE_SNAPSHOT_MARKER=true") {
		t.Fatalf("worker environment does not require snapshot marker")
	}
	if !containsEnvironment(environment, "SPRINGMASTER_WORKER_MAX_RESPONSE_BYTES=67108864") {
		t.Fatalf("worker environment does not contain default response limit")
	}

	if _, err := normalizeConfig(Config{
		Command:               []string{"worker"},
		RequireSnapshotMarker: true,
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("marker without allowed root error = %v, want ErrInvalidConfig", err)
	}
}

func containsEnvironment(environment []string, wanted string) bool {
	for _, entry := range environment {
		if entry == wanted {
			return true
		}
	}
	return false
}

func TestPoolForwardsBoundedStderrToHook(t *testing.T) {
	pool := newTestPool(t, "stderr", Config{})
	t.Cleanup(func() { _ = pool.Close() })

	lines := make(chan string, 1)
	pool.SetStderrHook(func(_ int, line string) {
		lines <- line
	})
	if _, err := pool.Analyze(context.Background(), testRequest(t)); err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	select {
	case line := <-lines:
		if line != "worker diagnostic" {
			t.Fatalf("stderr hook line = %q", line)
		}
	case <-time.After(time.Second):
		t.Fatal("stderr hook did not receive worker line")
	}
}

func TestPoolKeepsRequestScopedFailuresInResponse(t *testing.T) {
	pool := newTestPool(t, "failed", Config{})
	t.Cleanup(func() { _ = pool.Close() })

	response, err := pool.Analyze(context.Background(), testRequest(t))
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if response.Status != StatusFailed || response.Error == nil || response.Error.Code != "ANALYSIS_FAILED" {
		t.Fatalf("response = %#v, want request-scoped failure", response)
	}
}

func TestPoolCloseRejectsNewRequests(t *testing.T) {
	pool := newTestPool(t, "success", Config{})
	if err := pool.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	_, err := pool.Analyze(context.Background(), testRequest(t))
	if !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("Analyze() after Close error = %v, want ErrPoolClosed", err)
	}
}

func TestPoolStartErrorDoesNotExposeCommand(t *testing.T) {
	const secret = "definitely-not-a-command-secret"
	_, err := NewPool(Config{Command: []string{secret}})
	if !errors.Is(err, ErrWorkerStart) {
		t.Fatalf("NewPool() error = %v, want ErrWorkerStart", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("NewPool() leaked command in error %q", err)
	}
}

func newTestPool(t *testing.T, scenario string, override Config, marker ...string) *Pool {
	t.Helper()
	t.Setenv(helperProcessEnv, "1")
	t.Setenv(helperScenarioEnv, scenario)
	if len(marker) > 0 {
		t.Setenv(helperMarkerEnv, marker[0])
	}
	config := Config{
		Command:          []string{os.Args[0], "-test.run=^TestWorkerPoolHelperProcess$"},
		Workers:          override.Workers,
		MaxLineBytes:     override.MaxLineBytes,
		MaxResponseBytes: override.MaxResponseBytes,
		StderrLimitBytes: override.StderrLimitBytes,
		RetryLimit:       override.RetryLimit,
	}
	pool, err := NewPool(config)
	if err != nil {
		t.Fatalf("NewPool() error = %v", err)
	}
	return pool
}

func testRequest(t *testing.T) Request {
	t.Helper()
	return Request{
		RepositoryPath: t.TempDir(),
		RepositoryID:   "repo",
		ContentHash:    "sha256:test",
		Mode:           ModeStaticOnly,
	}
}

// Package analyzer manages persistent JSONL analyzer worker processes.
package analyzer

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	protocolSchemaVersion = 1

	defaultMaxLineBytes        = 16 << 20
	defaultStderrLimitBytes    = 64 << 10
	defaultMaxResponseBytes    = 64 << 20
	maxConfiguredWorkers       = 256
	maxConfiguredLineBytes     = 32 << 20
	maxConfiguredResponseBytes = 256 << 20
	maxStderrCaptureBytes      = 1 << 20

	workerExitDrainTimeout = 100 * time.Millisecond
)

const (
	// ModeStaticOnly never asks the Java analyzer to execute repository build code.
	ModeStaticOnly = "STATIC_ONLY"
	// ModeExtended permits the Java analyzer's optional extended analysis.
	ModeExtended = "EXTENDED"

	// StatusCompleted is returned when a request completed successfully.
	StatusCompleted = "completed"
	// StatusFailed is returned when the Java analyzer rejected one request.
	StatusFailed = "failed"
)

var (
	// ErrInvalidConfig means Config is incomplete or exceeds a fixed safety bound.
	ErrInvalidConfig = errors.New("invalid analyzer worker pool configuration")
	// ErrInvalidRequest means Request does not satisfy WORKER_PROTOCOL.md.
	ErrInvalidRequest = errors.New("invalid analyzer worker request")
	// ErrPoolClosed means the pool no longer accepts work.
	ErrPoolClosed = errors.New("analyzer worker pool is closed")
	// ErrWorkerStart means a Java worker process could not be started.
	ErrWorkerStart = errors.New("analyzer worker failed to start")
	// ErrWorkerCrashed means a worker exited before returning its response.
	ErrWorkerCrashed = errors.New("analyzer worker exited unexpectedly")
	// ErrProtocol means a worker returned malformed or mismatched JSONL.
	ErrProtocol = errors.New("invalid analyzer worker protocol response")
)

// Config controls a pool of persistent Java analyzer worker processes.
//
// Command is argv: Command[0] is the executable and remaining values are its
// arguments. It is passed to os/exec without a shell.
//
// Zero values for Workers, MaxLineBytes, MaxResponseBytes, StderrLimitBytes,
// and RetryLimit use safe defaults of 1, 16 MiB, 64 MiB, 64 KiB, and one retry
// respectively. MaxLineBytes protects one legacy response or one protocol
// frame; MaxResponseBytes protects the reconstructed framed payload and is
// capped at 256 MiB. Workers are capped at 256 and RetryLimit at one, so
// configuration cannot create an unbounded process set or replay one request
// repeatedly after a crash.
//
// AllowedRoot is optional for compatibility with standalone worker users. When
// set, it is canonicalized before workers start and exported to each worker as
// SPRINGMASTER_WORKER_ALLOWED_ROOT. Java workers must reject any repositoryPath
// outside it. RequireSnapshotMarker additionally exports
// SPRINGMASTER_WORKER_REQUIRE_SNAPSHOT_MARKER=true; it requires AllowedRoot and
// tells a compatible Java worker to accept only springmaster-created snapshots.
// This is the parent/worker contract used by a future CLI wiring step; it does
// not modify arbitrary Command argv values.
type Config struct {
	Command               []string
	Workers               int
	MaxLineBytes          int
	MaxResponseBytes      int
	StderrLimitBytes      int
	RetryLimit            int
	AllowedRoot           string
	RequireSnapshotMarker bool
}

// Request is one WORKER_PROTOCOL.md request. RepositoryURL and Branch are
// optional. Analyze fills SchemaVersion and RequestID when they are empty.
type Request struct {
	SchemaVersion  int    `json:"schemaVersion"`
	RequestID      string `json:"requestId"`
	RepositoryPath string `json:"repositoryPath"`
	RepositoryID   string `json:"repositoryId"`
	RepositoryURL  string `json:"repositoryUrl,omitempty"`
	Branch         string `json:"branch,omitempty"`
	ContentHash    string `json:"contentHash"`
	Mode           string `json:"mode"`
}

// Response is one WORKER_PROTOCOL.md response. Result remains raw JSON so the
// caller can decode the analyzer's existing response contract itself.
type Response struct {
	SchemaVersion int             `json:"schemaVersion"`
	RequestID     string          `json:"requestId"`
	Status        string          `json:"status"`
	Result        json.RawMessage `json:"result,omitempty"`
	Error         *ResponseError  `json:"error,omitempty"`
}

// ResponseError is a request-scoped Java analyzer failure response.
// A StatusFailed response is valid protocol output and Analyze returns it with
// a nil Go error; transport and protocol errors use the sentinel errors above.
type ResponseError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type normalizedConfig struct {
	command               []string
	workers               int
	maxLineBytes          int
	maxResponseBytes      int
	stderrLimitBytes      int
	retryLimit            int
	allowedRoot           string
	requireSnapshotMarker bool
}

// Pool dispatches requests across persistent workers. A worker handles only
// one request at a time; separate workers can process requests concurrently.
type Pool struct {
	cfg normalizedConfig

	workers   []*worker
	available chan *worker
	done      chan struct{}

	stateMu   sync.Mutex
	closed    atomic.Bool
	closeOnce sync.Once
	calls     sync.WaitGroup

	requestSeq atomic.Uint64

	hookMu       sync.RWMutex
	stderrHook   func(worker int, line string)
	stderrEvents chan stderrEvent
	forwardWG    sync.WaitGroup
}

type stderrEvent struct {
	worker int
	line   string
}

// NewPool starts Config.Workers persistent Java worker processes.
func NewPool(config Config) (*Pool, error) {
	cfg, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}

	pool := &Pool{
		cfg:          cfg,
		available:    make(chan *worker, cfg.workers),
		done:         make(chan struct{}),
		stderrEvents: make(chan stderrEvent, cfg.workers*4),
	}
	pool.forwardWG.Add(1)
	go pool.forwardStderr()

	for index := 0; index < cfg.workers; index++ {
		process, startErr := startWorkerProcess(pool, index)
		if startErr != nil {
			_ = pool.Close()
			return nil, ErrWorkerStart
		}
		current := &worker{
			pool:    pool,
			index:   index,
			process: process,
		}
		pool.workers = append(pool.workers, current)
		pool.available <- current
	}

	return pool, nil
}

// Analyze sends one request to an available worker. Context cancellation or a
// deadline stops the in-flight worker so a late response can never be confused
// with a later request; the worker slot is then restarted for future work.
func (pool *Pool) Analyze(ctx context.Context, request Request) (Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}

	prepared, err := pool.prepareRequest(request)
	if err != nil {
		return Response{}, err
	}
	if !pool.beginCall() {
		return Response{}, ErrPoolClosed
	}
	defer pool.calls.Done()

	select {
	case <-pool.done:
		return Response{}, ErrPoolClosed
	default:
	}

	var current *worker
	select {
	case <-pool.done:
		return Response{}, ErrPoolClosed
	case <-ctx.Done():
		return Response{}, ctx.Err()
	case current = <-pool.available:
	}
	defer pool.release(current)

	if pool.closed.Load() {
		return Response{}, ErrPoolClosed
	}
	return current.analyze(ctx, prepared)
}

// Close stops every worker and waits for active requests and owned goroutines
// to finish. It is safe to call more than once.
func (pool *Pool) Close() error {
	pool.closeOnce.Do(func() {
		pool.stateMu.Lock()
		pool.closed.Store(true)
		close(pool.done)
		pool.stateMu.Unlock()

		for _, current := range pool.workers {
			current.stop()
		}
		pool.calls.Wait()
		for _, current := range pool.workers {
			current.close()
		}
		pool.forwardWG.Wait()
	})
	return nil
}

// WorkerCount returns configured worker-process capacity. It never exposes the
// mutable worker slice or process handles.
func (pool *Pool) WorkerCount() int {
	return len(pool.workers)
}

// SetStderrHook installs an optional observer for bounded stderr lines. The
// hook runs asynchronously from workers and must return promptly. Stderr is
// never added to returned errors, so worker logs cannot leak through normal
// request failures. Passing nil disables forwarding.
func (pool *Pool) SetStderrHook(hook func(worker int, line string)) {
	pool.hookMu.Lock()
	pool.stderrHook = hook
	pool.hookMu.Unlock()
}

func normalizeConfig(config Config) (normalizedConfig, error) {
	if len(config.Command) == 0 || config.Command[0] == "" || config.Workers < 0 ||
		config.Workers > maxConfiguredWorkers ||
		config.MaxLineBytes < 0 || config.MaxResponseBytes < 0 ||
		config.StderrLimitBytes < 0 || config.RetryLimit < 0 ||
		config.RetryLimit > 1 || (config.RequireSnapshotMarker && config.AllowedRoot == "") {
		return normalizedConfig{}, ErrInvalidConfig
	}

	cfg := normalizedConfig{
		command:               append([]string(nil), config.Command...),
		workers:               config.Workers,
		maxLineBytes:          config.MaxLineBytes,
		maxResponseBytes:      config.MaxResponseBytes,
		stderrLimitBytes:      config.StderrLimitBytes,
		retryLimit:            config.RetryLimit,
		requireSnapshotMarker: config.RequireSnapshotMarker,
	}
	if config.AllowedRoot != "" {
		allowedRoot, err := canonicalDirectory(config.AllowedRoot)
		if err != nil {
			return normalizedConfig{}, ErrInvalidConfig
		}
		cfg.allowedRoot = allowedRoot
	}
	if cfg.workers == 0 {
		cfg.workers = 1
	}
	if cfg.maxLineBytes == 0 {
		cfg.maxLineBytes = defaultMaxLineBytes
	}
	if cfg.maxLineBytes > maxConfiguredLineBytes {
		return normalizedConfig{}, ErrInvalidConfig
	}
	if cfg.maxResponseBytes == 0 {
		cfg.maxResponseBytes = defaultMaxResponseBytes
	}
	if cfg.maxResponseBytes > maxConfiguredResponseBytes {
		return normalizedConfig{}, ErrInvalidConfig
	}
	if cfg.stderrLimitBytes == 0 {
		cfg.stderrLimitBytes = defaultStderrLimitBytes
	}
	if cfg.stderrLimitBytes > maxStderrCaptureBytes {
		return normalizedConfig{}, ErrInvalidConfig
	}
	if cfg.retryLimit == 0 {
		cfg.retryLimit = 1
	}
	return cfg, nil
}

func canonicalDirectory(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	realPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(realPath)
	if err != nil || !info.IsDir() {
		if err == nil {
			err = errors.New("path is not a directory")
		}
		return "", err
	}
	return filepath.Clean(realPath), nil
}

func (pool *Pool) prepareRequest(request Request) (Request, error) {
	if request.SchemaVersion == 0 {
		request.SchemaVersion = protocolSchemaVersion
	}
	if request.RequestID == "" {
		request.RequestID = pool.nextRequestID()
	}
	if request.SchemaVersion != protocolSchemaVersion || request.RequestID == "" ||
		request.RepositoryPath == "" || !filepath.IsAbs(request.RepositoryPath) ||
		request.RepositoryID == "" || request.ContentHash == "" ||
		(request.Mode != ModeStaticOnly && request.Mode != ModeExtended) {
		return Request{}, ErrInvalidRequest
	}
	return request, nil
}

func (pool *Pool) nextRequestID() string {
	sequence := pool.requestSeq.Add(1)
	return "analysis-" + strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + strconv.FormatUint(sequence, 10)
}

func (pool *Pool) beginCall() bool {
	pool.stateMu.Lock()
	defer pool.stateMu.Unlock()
	if pool.closed.Load() {
		return false
	}
	pool.calls.Add(1)
	return true
}

func (pool *Pool) release(current *worker) {
	if current == nil || pool.closed.Load() {
		return
	}
	select {
	case pool.available <- current:
	case <-pool.done:
	}
}

func (pool *Pool) forwardStderr() {
	defer pool.forwardWG.Done()
	for {
		select {
		case <-pool.done:
			return
		default:
		}
		select {
		case <-pool.done:
			return
		case event := <-pool.stderrEvents:
			pool.hookMu.RLock()
			hook := pool.stderrHook
			pool.hookMu.RUnlock()
			if hook != nil {
				invokeStderrHook(hook, event)
			}
		}
	}
}

func invokeStderrHook(hook func(worker int, line string), event stderrEvent) {
	defer func() {
		// A log observer must not take down the worker pool.
		_ = recover()
	}()
	hook(event.worker, event.line)
}

func (pool *Pool) emitStderr(worker int, line string) {
	select {
	case <-pool.done:
		return
	default:
	}
	select {
	case pool.stderrEvents <- stderrEvent{worker: worker, line: line}:
	default:
		// A slow observer cannot block a Java process's stderr drain.
	}
}

type worker struct {
	pool  *Pool
	index int

	workMu  sync.Mutex
	procMu  sync.RWMutex
	process *workerProcess
}

func (worker *worker) analyze(ctx context.Context, request Request) (Response, error) {
	worker.workMu.Lock()
	defer worker.workMu.Unlock()

	payload, err := json.Marshal(request)
	if err != nil || len(payload)+1 > worker.pool.cfg.maxLineBytes {
		return Response{}, ErrInvalidRequest
	}
	payload = append(payload, '\n')

	retries := 0
	for {
		process := worker.currentProcess()
		if process == nil {
			return Response{}, ErrWorkerStart
		}

		response, roundTripErr := process.roundTrip(
			ctx,
			payload,
			request.RequestID,
			worker.pool.cfg.maxResponseBytes,
		)
		if roundTripErr == nil {
			return response, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			_ = worker.restart()
			return Response{}, ctxErr
		}
		if worker.pool.closed.Load() {
			return Response{}, ErrPoolClosed
		}

		if errors.Is(roundTripErr, ErrWorkerCrashed) && retries < worker.pool.cfg.retryLimit {
			if restartErr := worker.restart(); restartErr != nil {
				return Response{}, restartErr
			}
			retries++
			continue
		}

		// A malformed response also poisons this process, but is not replayed:
		// it may already represent a completed request with an unknown result.
		_ = worker.restart()
		if worker.pool.closed.Load() {
			return Response{}, ErrPoolClosed
		}
		return Response{}, roundTripErr
	}
}

func (worker *worker) currentProcess() *workerProcess {
	worker.procMu.RLock()
	defer worker.procMu.RUnlock()
	return worker.process
}

func (worker *worker) restart() error {
	old := worker.currentProcess()
	if old != nil {
		old.stop()
		<-old.done
		<-old.stderrDone
	}
	if worker.pool.closed.Load() {
		return ErrPoolClosed
	}

	replacement, err := startWorkerProcess(worker.pool, worker.index)
	if err != nil {
		return ErrWorkerStart
	}

	worker.procMu.Lock()
	if worker.pool.closed.Load() {
		worker.procMu.Unlock()
		replacement.stop()
		<-replacement.done
		<-replacement.stderrDone
		return ErrPoolClosed
	}
	worker.process = replacement
	worker.procMu.Unlock()
	return nil
}

func (worker *worker) stop() {
	if process := worker.currentProcess(); process != nil {
		process.stop()
	}
}

func (worker *worker) close() {
	process := worker.currentProcess()
	if process == nil {
		return
	}
	process.stop()
	<-process.done
	<-process.stderrDone
}

type workerProcess struct {
	cmd *exec.Cmd

	stdin  *os.File
	stdout *os.File
	stderr *os.File

	stdoutScanner *bufio.Scanner
	stderrTail    boundedTail

	done       chan struct{}
	stderrDone chan struct{}
	exited     atomic.Bool

	stdinCloseOnce  sync.Once
	stdoutCloseOnce sync.Once
	stderrCloseOnce sync.Once
	stopOnce        sync.Once
}

func startWorkerProcess(pool *Pool, index int) (*workerProcess, error) {
	stdinReader, stdinWriter, err := os.Pipe()
	if err != nil {
		return nil, ErrWorkerStart
	}
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		closeFiles(stdinReader, stdinWriter)
		return nil, ErrWorkerStart
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		closeFiles(stdinReader, stdinWriter, stdoutReader, stdoutWriter)
		return nil, ErrWorkerStart
	}

	command := exec.Command(pool.cfg.command[0], pool.cfg.command[1:]...)
	command.Env = workerEnvironment(pool.cfg)
	configureWorkerProcessGroup(command)
	command.Stdin = stdinReader
	command.Stdout = stdoutWriter
	command.Stderr = stderrWriter
	if err := command.Start(); err != nil {
		closeFiles(stdinReader, stdinWriter, stdoutReader, stdoutWriter, stderrReader, stderrWriter)
		return nil, ErrWorkerStart
	}

	// The child received duplicates at Start. Keep only the parent ends.
	closeFiles(stdinReader, stdoutWriter, stderrWriter)
	process := &workerProcess{
		cmd:           command,
		stdin:         stdinWriter,
		stdout:        stdoutReader,
		stderr:        stderrReader,
		stdoutScanner: newBoundedScanner(stdoutReader, pool.cfg.maxLineBytes),
		stderrTail:    boundedTail{maxBytes: pool.cfg.stderrLimitBytes},
		done:          make(chan struct{}),
		stderrDone:    make(chan struct{}),
	}
	go process.waitForExit()
	go process.drainStderr(pool, index, pool.cfg.stderrLimitBytes)
	return process, nil
}

func workerEnvironment(cfg normalizedConfig) []string {
	overrides := map[string]string{
		"SPRINGMASTER_WORKER_MAX_RESPONSE_BYTES": strconv.Itoa(cfg.maxResponseBytes),
	}
	if cfg.allowedRoot != "" {
		overrides["SPRINGMASTER_WORKER_ALLOWED_ROOT"] = cfg.allowedRoot
		overrides["SPRINGMASTER_WORKER_REQUIRE_SNAPSHOT_MARKER"] = strconv.FormatBool(cfg.requireSnapshotMarker)
	}

	environment := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		key, _, found := strings.Cut(entry, "=")
		if found {
			if _, overridden := overrides[key]; overridden {
				continue
			}
		}
		environment = append(environment, entry)
	}
	// Keep this deterministic for process inspection and tests.
	environment = append(
		environment,
		"SPRINGMASTER_WORKER_MAX_RESPONSE_BYTES="+strconv.Itoa(cfg.maxResponseBytes),
	)
	if cfg.allowedRoot != "" {
		environment = append(environment, "SPRINGMASTER_WORKER_ALLOWED_ROOT="+cfg.allowedRoot)
		environment = append(
			environment,
			"SPRINGMASTER_WORKER_REQUIRE_SNAPSHOT_MARKER="+strconv.FormatBool(cfg.requireSnapshotMarker),
		)
	}
	return environment
}

func closeFiles(files ...*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}

func newBoundedScanner(reader io.Reader, maxLineBytes int) *bufio.Scanner {
	scanner := bufio.NewScanner(reader)
	initial := 64 << 10
	if maxLineBytes < initial {
		initial = maxLineBytes
	}
	if initial < 1 {
		initial = 1
	}
	scanner.Buffer(make([]byte, initial), maxLineBytes)
	return scanner
}

func (process *workerProcess) waitForExit() {
	_ = process.cmd.Wait()
	process.exited.Store(true)
	process.closeStdin()
	close(process.done)
}

func (process *workerProcess) drainStderr(pool *Pool, index, maxLineBytes int) {
	defer close(process.stderrDone)
	scanner := newBoundedScanner(process.stderr, maxLineBytes)
	for scanner.Scan() {
		line := scanner.Text()
		process.stderrTail.appendLine(line)
		pool.emitStderr(index, line)
	}
	if scanner.Err() != nil {
		const boundedMessage = "[analyzer worker stderr line exceeded configured limit]"
		process.stderrTail.appendLine(boundedMessage)
		pool.emitStderr(index, boundedMessage)
		_, _ = io.Copy(io.Discard, process.stderr)
	}
}

func (process *workerProcess) roundTrip(
	ctx context.Context,
	payload []byte,
	requestID string,
	maxResponseBytes int,
) (Response, error) {
	if process.exited.Load() {
		return Response{}, ErrWorkerCrashed
	}
	if err := process.write(ctx, payload); err != nil {
		return Response{}, err
	}

	return process.readResponse(ctx, requestID, maxResponseBytes)
}

func (process *workerProcess) write(ctx context.Context, payload []byte) error {
	written := make(chan error, 1)
	go func() {
		written <- writeAll(process.stdin, payload)
	}()

	select {
	case err := <-written:
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return ErrWorkerCrashed
		}
		return nil
	case <-ctx.Done():
		process.stop()
		<-written
		return ctx.Err()
	case <-process.done:
		<-written
		return ErrWorkerCrashed
	}
}

func writeAll(file *os.File, payload []byte) error {
	for len(payload) > 0 {
		written, err := file.Write(payload)
		if written > 0 {
			payload = payload[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

type scanResult struct {
	line []byte
	ok   bool
	err  error
}

func (process *workerProcess) readLine(ctx context.Context) ([]byte, error) {
	read := make(chan scanResult, 1)
	go func() {
		if process.stdoutScanner.Scan() {
			line := append([]byte(nil), process.stdoutScanner.Bytes()...)
			read <- scanResult{line: line, ok: true}
			return
		}
		read <- scanResult{err: process.stdoutScanner.Err()}
	}()

	select {
	case result := <-read:
		return process.classifyScan(result)
	case <-ctx.Done():
		process.stop()
		<-read
		return nil, ctx.Err()
	case <-process.done:
		select {
		case result := <-read:
			return process.classifyScan(result)
		default:
		}

		timer := time.NewTimer(workerExitDrainTimeout)
		defer timer.Stop()
		select {
		case result := <-read:
			return process.classifyScan(result)
		case <-timer.C:
			process.closeStdout()
			result := <-read
			return process.classifyScan(result)
		}
	}
}

func (process *workerProcess) classifyScan(result scanResult) ([]byte, error) {
	if result.ok {
		return result.line, nil
	}
	if result.err != nil {
		return nil, ErrProtocol
	}
	if process.exited.Load() {
		return nil, ErrWorkerCrashed
	}

	// EOF can arrive immediately after the child exits, just before its Wait
	// goroutine records the exit. Give Wait a bounded chance to classify that
	// race as a crash instead of a malformed response.
	timer := time.NewTimer(workerExitDrainTimeout)
	defer timer.Stop()
	select {
	case <-process.done:
		return nil, ErrWorkerCrashed
	case <-timer.C:
	}
	return nil, ErrProtocol
}

func parseResponse(line []byte, requestID string) (Response, error) {
	var response Response
	if err := json.Unmarshal(line, &response); err != nil {
		return Response{}, ErrProtocol
	}
	if response.SchemaVersion != protocolSchemaVersion || response.RequestID != requestID {
		return Response{}, ErrProtocol
	}
	switch response.Status {
	case StatusCompleted:
		if len(response.Result) == 0 || response.Error != nil {
			return Response{}, ErrProtocol
		}
	case StatusFailed:
		if response.Error == nil {
			return Response{}, ErrProtocol
		}
	default:
		return Response{}, ErrProtocol
	}
	return response, nil
}

func (process *workerProcess) stop() {
	process.stopOnce.Do(func() {
		// A JVM can leave Gradle or other descendants alive. On Unix the worker
		// starts in its own process group, so this kills the full tree. Other
		// platforms fall back to terminating the direct worker process.
		killWorkerProcessTree(process.cmd)
		process.closeStdin()
		process.closeStdout()
		process.closeStderr()
	})
}

func (process *workerProcess) closeStdin() {
	process.stdinCloseOnce.Do(func() {
		_ = process.stdin.Close()
	})
}

func (process *workerProcess) closeStdout() {
	process.stdoutCloseOnce.Do(func() {
		_ = process.stdout.Close()
	})
}

func (process *workerProcess) closeStderr() {
	process.stderrCloseOnce.Do(func() {
		_ = process.stderr.Close()
	})
}

type boundedTail struct {
	mu       sync.Mutex
	maxBytes int
	data     []byte
}

func (tail *boundedTail) appendLine(line string) {
	if tail.maxBytes <= 0 {
		return
	}
	entry := append([]byte(line), '\n')
	tail.mu.Lock()
	defer tail.mu.Unlock()

	if len(entry) >= tail.maxBytes {
		tail.data = append(tail.data[:0], entry[len(entry)-tail.maxBytes:]...)
		return
	}
	overflow := len(tail.data) + len(entry) - tail.maxBytes
	if overflow > 0 {
		copy(tail.data, tail.data[overflow:])
		tail.data = tail.data[:len(tail.data)-overflow]
	}
	tail.data = append(tail.data, entry...)
}

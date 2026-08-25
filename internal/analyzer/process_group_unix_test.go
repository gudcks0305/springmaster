//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package analyzer

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPoolCancellationKillsWorkerProcessGroup(t *testing.T) {
	marker := t.TempDir() + "/descendant-pid"
	pool := newTestPool(t, "spawn-child", Config{}, marker)
	t.Cleanup(func() { _ = pool.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	request := testRequest(t)
	go func() {
		_, err := pool.Analyze(ctx, request)
		result <- err
	}()

	pid := waitForDescendantPID(t, marker, result)
	t.Cleanup(func() { killProcessForTest(pid) })
	cancel()

	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Analyze() after cancellation error = %v, want context canceled", err)
	}
	waitForProcessExit(t, pid)
}

func TestPoolCloseKillsWorkerProcessGroup(t *testing.T) {
	marker := t.TempDir() + "/descendant-pid"
	pool := newTestPool(t, "spawn-child", Config{}, marker)

	result := make(chan error, 1)
	request := testRequest(t)
	go func() {
		_, err := pool.Analyze(context.Background(), request)
		result <- err
	}()

	pid := waitForDescendantPID(t, marker, result)
	t.Cleanup(func() { killProcessForTest(pid) })
	if err := pool.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := <-result; !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("Analyze() after Close error = %v, want ErrPoolClosed", err)
	}
	waitForProcessExit(t, pid)
}

func waitForDescendantPID(t *testing.T, marker string, result <-chan error) int {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		contents, err := os.ReadFile(marker)
		if err == nil {
			pid, parseErr := strconv.Atoi(strings.TrimSpace(string(contents)))
			if parseErr == nil && pid > 0 {
				return pid
			}
		}
		select {
		case analysisErr := <-result:
			markerContents, _ := os.ReadFile(marker)
			t.Fatalf(
				"worker exited before descendant PID marker: %v (marker=%q)",
				analysisErr,
				markerContents,
			)
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatalf("worker did not create descendant PID marker %q", marker)
	return 0
}

func waitForProcessExit(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("descendant process %d survived worker teardown", pid)
}

func killProcessForTest(pid int) {
	if pid > 0 {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

package main

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/gudcks0305/springmaster/internal/report"
)

func TestParseScanArgsAllowsRootBeforeFlags(t *testing.T) {
	options, err := parseScanArgs([]string{
		"/repos", "--worker-command=java -jar worker.jar", "--workers", "3",
		"--mode", "extended", "--trust-extended", "--format=json", "--fail-on", "warning",
		"--include", "service/**,api/**", "--exclude", ".git/**", "--max-depth", "2",
		"--timeout", "30s", "--cache-dir", "/tmp/springmaster-cache", "--no-cache",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.root != "/repos" || options.workerCommand != "java -jar worker.jar" || options.workers != 3 || options.mode != "EXTENDED" || !options.trustExtended || options.format != "json" || options.failOn != report.SeverityWarning || options.maxDepth != 2 || options.timeout != 30*time.Second || options.cacheDir != "/tmp/springmaster-cache" || !options.noCache {
		t.Fatalf("unexpected options: %#v", options)
	}
	if got, want := options.include, []string{"service/**", "api/**"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("include = %#v, want %#v", got, want)
	}
}

func TestParseScanArgsRejectsInvalidArguments(t *testing.T) {
	for _, arguments := range [][]string{
		{"/repos", "--worker-command", "worker", "--format", "sarif"},
		{"/repos", "--worker-command", "worker", "--workers", "0"},
		{"/repos", "--worker-command", "worker", "--timeout", "0s"},
		{"/repos", "--worker-command", "worker", "--unknown"},
		{"/repos", "--worker-command", "worker", "--mode", "EXTENDED"},
		{"/repos", "--worker-command", "worker", "--trust-extended"},
	} {
		if _, err := parseScanArgs(arguments); err == nil {
			t.Fatalf("parseScanArgs(%q) unexpectedly succeeded", arguments)
		}
	}
}

func TestParseScanArgsAllowsBundledWorker(t *testing.T) {
	options, err := parseScanArgs([]string{"/repos", "--format", "json"})
	if err != nil {
		t.Fatal(err)
	}
	if options.workerCommand != "" {
		t.Fatalf("workerCommand = %q, want bundled default", options.workerCommand)
	}
}

func TestParseScanArgsHelp(t *testing.T) {
	for _, arguments := range [][]string{{"--help"}, {"-h"}} {
		_, err := parseScanArgs(arguments)
		if !errors.Is(err, errHelp) {
			t.Fatalf("parseScanArgs(%q) error = %v, want errHelp", arguments, err)
		}
	}
}

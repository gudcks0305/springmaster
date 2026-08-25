package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gudcks0305/springmaster/internal/report"
)

var errHelp = errors.New("help requested")

const (
	exitClean       = 0
	exitFindings    = 1
	exitOperational = 2
	exitInvalidArgs = 4
)

type scanOptions struct {
	root             string
	workerCommand    string
	workers          int
	mode             string
	format           string
	output           string
	cacheDir         string
	failOn           report.Severity
	include          []string
	exclude          []string
	maxDepth         int
	timeout          time.Duration
	noCache          bool
	trustExtended    bool
	allowSourceWrite bool
}

func parseScanArgs(arguments []string) (scanOptions, error) {
	options := scanOptions{
		workers:  1,
		mode:     "STATIC_ONLY",
		format:   "text",
		failOn:   report.SeverityError,
		maxDepth: 0,
		timeout:  5 * time.Minute,
	}

	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if argument == "--" {
			if options.root != "" || index+2 != len(arguments) {
				return scanOptions{}, fmt.Errorf("scan requires exactly one ROOT")
			}
			options.root = arguments[index+1]
			break
		}
		if argument == "-h" {
			return scanOptions{}, errHelp
		}
		if !strings.HasPrefix(argument, "--") {
			if options.root != "" {
				return scanOptions{}, fmt.Errorf("scan requires exactly one ROOT")
			}
			options.root = argument
			continue
		}

		name, value, hasValue := strings.Cut(strings.TrimPrefix(argument, "--"), "=")
		if name == "help" || name == "h" {
			return scanOptions{}, errHelp
		}
		if name == "no-cache" {
			if hasValue {
				parsed, err := strconv.ParseBool(value)
				if err != nil {
					return scanOptions{}, fmt.Errorf("--no-cache: %w", err)
				}
				options.noCache = parsed
			} else {
				options.noCache = true
			}
			continue
		}
		if name == "trust-extended" || name == "allow-source-write" {
			parsed := true
			if hasValue {
				var err error
				parsed, err = strconv.ParseBool(value)
				if err != nil {
					return scanOptions{}, fmt.Errorf("--%s: %w", name, err)
				}
			}
			if name == "trust-extended" {
				options.trustExtended = parsed
			} else {
				options.allowSourceWrite = parsed
			}
			continue
		}

		if !hasValue {
			if index+1 >= len(arguments) {
				return scanOptions{}, fmt.Errorf("--%s requires a value", name)
			}
			index++
			value = arguments[index]
		}

		switch name {
		case "worker-command":
			options.workerCommand = value
		case "workers":
			workers, err := strconv.Atoi(value)
			if err != nil || workers < 1 {
				return scanOptions{}, fmt.Errorf("--workers must be a positive integer")
			}
			options.workers = workers
		case "mode":
			mode := strings.ToUpper(strings.TrimSpace(value))
			if mode != "STATIC_ONLY" && mode != "EXTENDED" {
				return scanOptions{}, fmt.Errorf("--mode must be STATIC_ONLY or EXTENDED")
			}
			options.mode = mode
		case "format":
			format := strings.ToLower(strings.TrimSpace(value))
			if format != "text" && format != "json" {
				return scanOptions{}, fmt.Errorf("--format must be text or json")
			}
			options.format = format
		case "output":
			if value == "" {
				return scanOptions{}, fmt.Errorf("--output must not be empty")
			}
			options.output = value
		case "cache-dir":
			if value == "" {
				return scanOptions{}, fmt.Errorf("--cache-dir must not be empty")
			}
			options.cacheDir = value
		case "fail-on":
			severity, err := report.ParseSeverity(value)
			if err != nil {
				return scanOptions{}, fmt.Errorf("--fail-on: %w", err)
			}
			options.failOn = severity
		case "include":
			options.include = appendPatterns(options.include, value)
		case "exclude":
			options.exclude = appendPatterns(options.exclude, value)
		case "max-depth":
			maxDepth, err := strconv.Atoi(value)
			if err != nil || maxDepth < 0 {
				return scanOptions{}, fmt.Errorf("--max-depth must be a non-negative integer")
			}
			options.maxDepth = maxDepth
		case "timeout":
			timeout, err := time.ParseDuration(value)
			if err != nil || timeout <= 0 {
				return scanOptions{}, fmt.Errorf("--timeout must be a positive duration")
			}
			options.timeout = timeout
		default:
			return scanOptions{}, fmt.Errorf("unknown flag --%s", name)
		}
	}

	if options.root == "" {
		return scanOptions{}, fmt.Errorf("scan requires ROOT")
	}
	if strings.TrimSpace(options.workerCommand) == "" {
		return scanOptions{}, fmt.Errorf("--worker-command is required")
	}
	if options.mode == "EXTENDED" && !options.trustExtended {
		return scanOptions{}, fmt.Errorf("--mode EXTENDED requires explicit --trust-extended")
	}
	if options.mode != "EXTENDED" && options.trustExtended {
		return scanOptions{}, fmt.Errorf("--trust-extended requires --mode EXTENDED")
	}
	return options, nil
}

func appendPatterns(patterns []string, value string) []string {
	for _, pattern := range strings.Split(value, ",") {
		if pattern = strings.TrimSpace(pattern); pattern != "" {
			patterns = append(patterns, pattern)
		}
	}
	return patterns
}

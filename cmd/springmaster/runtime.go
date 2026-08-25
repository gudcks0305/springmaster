package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const analyzerJarEnvironment = "SPRINGMASTER_ANALYZER_JAR"

func resolveWorkerCommand(configured string) ([]string, error) {
	if strings.TrimSpace(configured) != "" {
		command, err := splitCommand(configured)
		if err != nil {
			return nil, fmt.Errorf("invalid --worker-command: %w", err)
		}
		return command, nil
	}

	jar, err := locateBundledAnalyzerJar(os.Getenv(analyzerJarEnvironment), os.Executable)
	if err != nil {
		return nil, err
	}
	java, err := exec.LookPath("java")
	if err != nil {
		return nil, fmt.Errorf("locate java for bundled analyzer: %w", err)
	}
	return []string{java, "-jar", jar, "--worker"}, nil
}

func locateBundledAnalyzerJar(
	configured string,
	executable func() (string, error),
) (string, error) {
	if strings.TrimSpace(configured) != "" {
		jar, err := canonicalRegularFile(configured)
		if err != nil {
			return "", fmt.Errorf("%s: %w", analyzerJarEnvironment, err)
		}
		return jar, nil
	}

	binary, err := executable()
	if err != nil {
		return "", fmt.Errorf("locate springmaster executable: %w", err)
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return "", fmt.Errorf("resolve springmaster executable: %w", err)
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		return "", fmt.Errorf("resolve springmaster executable symlink: %w", err)
	}
	jarCandidate := filepath.Join(filepath.Dir(binary), "analyzer.jar")
	jar, err := canonicalRegularFile(jarCandidate)
	if err != nil {
		return "", fmt.Errorf(
			"bundled analyzer.jar not found beside springmaster (%s); rebuild/install the paired package or set %s: %w",
			jarCandidate,
			analyzerJarEnvironment,
			err,
		)
	}
	return jar, nil
}

func canonicalRegularFile(candidate string) (string, error) {
	if !filepath.IsAbs(candidate) {
		return "", errors.New("path must be absolute")
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("path must be a regular file")
	}
	return resolved, nil
}

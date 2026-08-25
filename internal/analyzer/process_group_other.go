//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package analyzer

import "os/exec"

// Process groups are not exposed portably by os/exec on every supported
// platform. Keep the worker boundary safe there by terminating the direct
// process; platform-specific Job Object support can replace this fallback.
func configureWorkerProcessGroup(_ *exec.Cmd) {}

func killWorkerProcessTree(command *exec.Cmd) {
	if command != nil && command.Process != nil {
		_ = command.Process.Kill()
	}
}

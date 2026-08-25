//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package analyzer

import (
	"errors"
	"os/exec"
	"syscall"
)

// configureWorkerProcessGroup isolates a worker and all descendants it starts
// from springmaster's own process group. This must run before Cmd.Start.
func configureWorkerProcessGroup(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killWorkerProcessTree terminates the worker's entire process group. A
// negative PID targets the group whose leader is the worker. The direct-process
// fallback covers a process that exited between inspection and signal delivery.
func killWorkerProcessTree(command *exec.Cmd) {
	if command == nil || command.Process == nil || command.Process.Pid <= 0 {
		return
	}

	if err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL); err == nil || errors.Is(err, syscall.ESRCH) {
		return
	}
	_ = command.Process.Kill()
}

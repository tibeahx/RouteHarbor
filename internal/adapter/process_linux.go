//go:build linux

package adapter

import (
	"os/exec"
	"syscall"
)

// Engines run as the API service user and never change credentials. Terminate
// them when their controller dies so a restart can safely reserve its own ports.
func superviseEngine(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

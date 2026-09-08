//go:build !linux

package adapter

import "os/exec"

func superviseEngine(cmd *exec.Cmd) {}

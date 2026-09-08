package helper

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

// ProcessWatchdog starts a detached helper process, never a goroutine tied to the
// API or privileged server. Arm waits for readiness before any network mutation.
type ProcessWatchdog struct {
	Binary   string
	StateDir string
}

func (w ProcessWatchdog) Arm(id string) error {
	if runtime.GOOS != "linux" {
		return errors.New("watchdog_unavailable: independent privileged watchdog requires Linux")
	}
	if !validTransactionID(id) || !filepath.IsAbs(w.Binary) || !filepath.IsAbs(w.StateDir) {
		return errors.New("watchdog_unavailable: invalid watchdog configuration")
	}
	info, err := os.Lstat(w.Binary)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || !ownedByCurrentUID(info) {
		return errors.New("watchdog_unavailable: helper executable must be a trusted regular file")
	}
	read, write, err := os.Pipe()
	if err != nil {
		return err
	}
	defer func() { _ = read.Close() }()
	cmd := exec.Command(
		w.Binary,
		"watchdog",
		"--state-dir",
		w.StateDir,
		"--transaction",
		id,
		"--ready-fd",
		"3",
	)
	cmd.ExtraFiles = []*os.File{write}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err = cmd.Start(); err != nil {
		_ = write.Close()
		return err
	}
	_ = write.Close()
	go func() { _ = cmd.Wait() }()
	_ = read.SetReadDeadline(time.Now().Add(5 * time.Second))
	data := make([]byte, 6)
	_, err = io.ReadFull(read, data)
	if err != nil || string(data) != "ready\n" {
		_ = cmd.Process.Kill()
		return errors.New("watchdog_unavailable: detached process did not become ready")
	}
	return nil
}

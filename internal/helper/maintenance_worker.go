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

// MaintenanceWorker survives API/procd controller restarts. Its executable is the
// retained guard helper, which is never one of the supported update targets.
type MaintenanceWorker struct{ Binary, StateDir, RoutingDir string }

func (w MaintenanceWorker) Arm(id string) error {
	if runtime.GOOS != "linux" || !validTransactionID(id) || !filepath.IsAbs(w.Binary) ||
		!filepath.IsAbs(w.StateDir) ||
		!filepath.IsAbs(w.RoutingDir) {
		return errors.New("maintenance_worker_configuration_invalid")
	}
	info, err := os.Lstat(w.Binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 ||
		!ownedByCurrentUID(info) {
		return errors.New("maintenance_worker_binary_untrusted")
	}
	read, write, err := os.Pipe()
	if err != nil {
		return err
	}
	defer func() { _ = read.Close() }()
	cmd := exec.Command(
		w.Binary,
		"maintenance-worker",
		"--state-dir",
		w.StateDir,
		"--routing-state-dir",
		w.RoutingDir,
		"--operation",
		id,
		"--ready-fd",
		"3",
	)
	cmd.ExtraFiles = []*os.File{write}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err = cmd.Start(); err != nil {
		_ = write.Close()
		return err
	}
	_ = write.Close()
	go func() { _ = cmd.Wait() }()
	_ = read.SetReadDeadline(time.Now().Add(5 * time.Second))
	var message [6]byte
	if _, err = io.ReadFull(read, message[:]); err != nil || string(message[:]) != "ready\n" {
		_ = cmd.Process.Kill()
		return errors.New("maintenance_worker_not_ready")
	}
	return nil
}

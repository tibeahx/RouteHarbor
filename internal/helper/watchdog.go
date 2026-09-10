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

type watchdogLease struct{ file *os.File }

func (l *watchdogLease) Close() error {
	if l.file == nil {
		return nil
	}
	f := l.file
	l.file = nil
	// Unlink while still owning the lease, after the monitor loop has ended.
	// A replacement may then claim a new inode without overlapping any work.
	if current, err := os.Lstat(f.Name()); err == nil {
		if held, err := f.Stat(); err == nil && os.SameFile(current, held) {
			_ = os.Remove(f.Name())
		}
	}
	return f.Close()
}

// WatchdogLease is claimed before readiness, independently of the journal lock
// held by the parent. Modes are separate so apply can replace a prepared monitor.
// Duplicate service restarts reuse the already-live monitor instead of leaking
// persistent detached processes for the same transaction and mode.
func (m *Manager) WatchdogLease(id string, prepared bool) (io.Closer, bool, error) {
	if !validTransactionID(id) {
		return nil, false, errors.New("invalid_transaction_identity")
	}
	mode := "active"
	if prepared {
		mode = "prepared"
	}
	path := filepath.Join(m.dir, ".watchdog-"+id+"-"+mode+".lock")
	for attempt := 0; attempt < 4; attempt++ {
		file, err := openPrivate(path, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, false, err
		}
		owned, err := lockCurrentWatchdogFile(file)
		if err == nil && owned {
			return &watchdogLease{file: file}, true, nil
		}
		_ = file.Close()
		if errors.Is(err, errWatchdogLeaseReplaced) {
			continue
		}
		return nil, false, err
	}
	return nil, false, errWatchdogLeaseReplaced
}

var errWatchdogLeaseReplaced = errors.New("watchdog_unavailable: lease file replaced")

func lockCurrentWatchdogFile(file *os.File) (bool, error) {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	busy := errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN)
	if err != nil && !busy {
		return false, err
	}
	// Close unlinks a completed owner's inode. A contender may already have
	// opened it, so even successful flock is insufficient: only the current
	// pathname's inode may acknowledge readiness and perform monitor work.
	held, err := file.Stat()
	if err != nil {
		return false, err
	}
	current, err := os.Lstat(file.Name())
	if errors.Is(err, os.ErrNotExist) {
		return false, errWatchdogLeaseReplaced
	}
	if err != nil {
		return false, err
	}
	if !os.SameFile(current, held) {
		return false, errWatchdogLeaseReplaced
	}
	return !busy, nil
}

func (w ProcessWatchdog) Arm(id string) error {
	return w.arm(id, "watchdog")
}

// ArmPrepared keeps the confirmed selective classifier monitored while a new
// transaction is reviewed; the ordinary watchdog takes over before apply.
func (w ProcessWatchdog) ArmPrepared(id string) error { return w.arm(id, "prepared-watchdog") }

func (w ProcessWatchdog) arm(id, mode string) error {
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
		mode,
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

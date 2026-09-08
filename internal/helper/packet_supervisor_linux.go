//go:build linux

package helper

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const packetWorkerBinary = "/usr/libexec/openrhp-helper"

// startPacketWorker keeps the liveness writer exclusively in the manager. Kernel
// descriptor cleanup on manager SIGKILL wakes the independent root supervisor,
// including after nfqws drops privilege and loses Linux's parent-death signal.
func startPacketWorker(slot int) (*exec.Cmd, io.Closer, error) {
	if slot < 1 || slot > 250 {
		return nil, nil, errors.New("invalid_packet_source: invalid resource slot")
	}
	if os.Geteuid() != 0 {
		return nil, nil, errors.New("capability_unavailable: packet supervisor requires root")
	}
	for _, p := range []string{"/usr", "/usr/libexec", packetWorkerBinary} {
		st, err := os.Lstat(p)
		if err != nil {
			return nil, nil, errors.New(
				"packet_supervisor_missing: install the trusted helper package",
			)
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || st.Mode().Perm()&0o022 != 0 || st.Mode()&os.ModeSymlink != 0 ||
			(p == packetWorkerBinary && (!st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0)) {
			return nil, nil, errors.New(
				"packet_supervisor_untrusted: helper and parent directories must be root owned and protected",
			)
		}
	}
	read, write, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		_ = read.Close()
		_ = write.Close()
		return nil, nil, err
	}
	cmd := exec.Command(packetWorkerBinary, "packet-worker", "--slot", strconv.Itoa(slot))
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	cmd.ExtraFiles = []*os.File{read, readyWrite}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err = cmd.Start(); err != nil {
		_ = read.Close()
		_ = write.Close()
		_ = readyRead.Close()
		_ = readyWrite.Close()
		return nil, nil, errors.New("packet_start_failed: supervisor could not start")
	}
	_ = read.Close()
	_ = readyWrite.Close()
	defer func() { _ = readyRead.Close() }()
	ready := make(chan bool, 1)
	go func() {
		var token [6]byte
		_, e := io.ReadFull(readyRead, token[:])
		ready <- e == nil && string(token[:]) == "ready\n"
	}()
	ok := false
	select {
	case ok = <-ready:
	case <-time.After(5 * time.Second):
	}
	if !ok {
		_ = write.Close()
		exited := make(chan struct{})
		go func() { _ = cmd.Wait(); close(exited) }()
		select {
		case <-exited:
		case <-time.After(2 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-exited
		}
		return nil, nil, errors.New("packet_start_failed: source queue did not become ready")
	}
	return cmd, write, nil
}

// RunPacketWorker is a fixed, root-only worker entrypoint; FD 3 is the private
// manager-liveness pipe. No request controls the executable, arguments or files.
func RunPacketWorker(slot int) error {
	if slot < 1 || slot > 250 {
		return errors.New("invalid_packet_source: invalid resource slot")
	}
	if err := trustedPacketBinary(); err != nil {
		return err
	}
	life := os.NewFile(3, "packet-manager-liveness")
	if life == nil {
		return errors.New("packet_worker_invalid: liveness descriptor required")
	}
	defer func() { _ = life.Close() }()
	syscall.CloseOnExec(3)
	ready := os.NewFile(4, "packet-worker-readiness")
	if ready == nil {
		return errors.New("packet_worker_invalid: readiness descriptor required")
	}
	defer func() { _ = ready.Close() }()
	syscall.CloseOnExec(4)
	rst, re := ready.Stat()
	if re != nil || rst.Mode()&os.ModeNamedPipe == 0 {
		return errors.New("packet_worker_invalid: readiness descriptor must be a pipe")
	}
	st, err := life.Stat()
	if err != nil || st.Mode()&os.ModeNamedPipe == 0 {
		return errors.New("packet_worker_invalid: liveness descriptor must be a pipe")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	go func() { var b [1]byte; _, _ = life.Read(b[:]); cancel() }()
	if err = verifyPacketVersion(ctx); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return nil
	}
	cmd := exec.Command(nfqwsBinary, packetArgs(slot)...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	if err = cmd.Start(); err != nil {
		return errors.New("packet_start_failed: nfqws could not start")
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	stopChild := func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(750 * time.Millisecond):
			_ = cmd.Process.Kill()
			<-exited
		}
	}
	// The kernel queue must be bound to this child, not merely present or
	// owned by another process. Never report a worker waiting on its version
	// check or a child that has not bound its source queue as ready.
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for !packetQueueReady(slot, cmd.Process.Pid) {
		select {
		case <-exited:
			return errors.New("packet_start_failed: nfqws exited before binding its queue")
		case <-ctx.Done():
			stopChild()
			return nil
		case <-deadline.C:
			stopChild()
			return errors.New("packet_start_failed: source queue bind deadline exceeded")
		case <-tick.C:
		}
	}
	if _, err = io.WriteString(ready, "ready\n"); err != nil {
		stopChild()
		return errors.New("packet_start_failed: manager readiness channel closed")
	}
	_ = ready.Close()
	select {
	case err = <-exited:
		if err != nil {
			return errors.New("packet_engine_exited: nfqws stopped")
		}
		return nil
	case <-ctx.Done():
		stopChild()
		return nil
	}
}

func packetQueueReady(slot, pid int) bool {
	f, e := os.Open("/proc/net/netfilter/nfnetlink_queue")
	if e != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	raw, e := io.ReadAll(io.LimitReader(f, 64<<10))
	if e != nil {
		return false
	}
	return packetQueueOwned(raw, 21000+slot, pid)
}

func packetQueueOwned(raw []byte, queue, pid int) bool {
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		q, e1 := strconv.Atoi(fields[0])
		p, e2 := strconv.Atoi(fields[1])
		if e1 == nil && e2 == nil && q == queue && p == pid {
			return true
		}
	}
	return false
}

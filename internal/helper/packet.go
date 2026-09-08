package helper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	NFQWSVersion = "v72.10"
	NFQWSCommit  = "f0b0d89"
	nfqwsBinary  = "/usr/bin/nfqws"
)

var packetSourceID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

type packetProcess struct {
	liveness   io.Closer
	rulesReady bool
	slot       int
	cmd        *exec.Cmd
	done       chan struct{}
	running    bool
}

// PacketManager starts one pinned, root-owned nfqws per source queue. It never accepts scripts, binaries, paths or argv from a request.
type PacketManager struct {
	mu        sync.Mutex
	processes map[string]*packetProcess
}

func NewPacketManager() *PacketManager {
	return &PacketManager{processes: make(map[string]*packetProcess)}
}

func packetArgs(slot int) []string {
	return []string{
		fmt.Sprintf("--qnum=%d", 21000+slot),
		fmt.Sprintf("--dpi-desync-fwmark=0x%x", uint32(0x4f000000)|uint32(slot)<<16|0x8000),
		"--filter-tcp=443",
		"--dpi-desync=multisplit",
		"--dpi-desync-split-pos=1,midsld",
		"--dpi-desync-repeats=1",
		"--user=nobody",
	}
}

func validatePacketRequest(id string, slot int) error {
	if !packetSourceID.MatchString(id) || slot < 1 || slot > 250 {
		return errors.New("invalid_packet_source: invalid source identifier or resource slot")
	}
	return nil
}

func trustedPacketBinary() error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New(
			"capability_unavailable: packet engine requires the Linux privileged helper",
		)
	}
	for _, path := range []string{"/usr", "/usr/bin", nfqwsBinary} {
		info, e := os.Lstat(path)
		if e != nil {
			return errors.New("engine_missing: pinned nfqws package is not installed")
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || info.Mode().Perm()&0o022 != 0 || info.Mode()&os.ModeSymlink != 0 {
			return errors.New(
				"engine_untrusted: nfqws and its parent directories must be root owned and not writable by other users",
			)
		}
		if path == nfqwsBinary && (!info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0) {
			return errors.New("engine_untrusted: nfqws must be a regular executable")
		}
	}
	return nil
}

type cappedPacketOutput struct{ bytes.Buffer }

func (b *cappedPacketOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 4096 {
		return 0, errors.New("engine version output exceeds limit")
	}
	return b.Buffer.Write(p)
}

func verifyPacketVersion(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, nfqwsBinary, "--version")
	var b cappedPacketOutput
	cmd.Stdout = &b
	cmd.Stderr = &b
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	if e := cmd.Run(); e != nil {
		return errors.New("engine_version_failed: could not verify nfqws version")
	}
	if !validPacketVersion(b.String()) {
		return errors.New("engine_version_unsupported: install the pinned nfqws v72.10 build")
	}
	return nil
}

func validPacketVersion(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		if line == "github version "+NFQWSVersion+" ("+NFQWSCommit+")" {
			return true
		}
	}
	return false
}

func (m *PacketManager) Start(ctx context.Context, id string, slot int) error {
	if e := validatePacketRequest(id, slot); e != nil {
		return e
	}
	if e := trustedPacketBinary(); e != nil {
		return e
	}
	if e := verifyPacketVersion(ctx); e != nil {
		return e
	}
	m.mu.Lock()
	if m.processes == nil {
		m.processes = make(map[string]*packetProcess)
	}
	if p := m.processes[id]; p != nil {
		if p.slot == slot && !p.running {
			delete(m.processes, id)
		} else if p.slot == slot && p.running {
			m.mu.Unlock()
			return nil
		}
		if p.running || p.slot != slot {
			m.mu.Unlock()
			return errors.New("packet_source_conflict: stop the previous source allocation first")
		}
	}
	for _, p := range m.processes {
		if p.slot == slot {
			m.mu.Unlock()
			return errors.New("packet_slot_busy: queue already belongs to another source")
		}
	}
	cmd, liveness, e := startPacketWorker(slot)
	if e != nil {
		m.mu.Unlock()
		return e
	}
	p := &packetProcess{
		slot:     slot,
		cmd:      cmd,
		liveness: liveness,
		done:     make(chan struct{}),
		running:  true,
	}
	m.processes[id] = p
	if e := m.refreshPacketRules(ctx); e != nil {
		delete(m.processes, id)
		_ = liveness.Close()
		m.mu.Unlock()
		_ = cmd.Wait()
		return e
	}
	p.rulesReady = true
	m.mu.Unlock()
	go func() {
		_ = cmd.Wait()
		_ = liveness.Close()
		m.mu.Lock()
		p.running = false
		close(p.done)
		m.mu.Unlock()
	}()
	// nfqws binds its queue synchronously during startup; detect immediate option, permission and duplicate-queue failures.
	select {
	case <-ctx.Done():
		_ = m.Stop(context.Background(), id)
		return ctx.Err()
	case <-p.done:
		return errors.New("packet_start_failed: nfqws exited during initialization")
	case <-time.After(150 * time.Millisecond):
		return nil
	}
}

func (m *PacketManager) Running(id string, slot int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.processes[id]
	return p != nil && p.running && p.rulesReady && p.slot == slot
}

func (m *PacketManager) Stop(ctx context.Context, id string) error {
	m.mu.Lock()
	p := m.processes[id]
	if p == nil {
		m.mu.Unlock()
		return nil
	}
	if p.liveness != nil {
		_ = p.liveness.Close()
	}
	m.mu.Unlock()
	select {
	case <-p.done:
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(2 * time.Second):
		_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
		<-p.done
	}
	m.mu.Lock()
	if m.processes[id] == p {
		delete(m.processes, id)
	}
	err := m.refreshPacketRules(ctx)
	m.mu.Unlock()
	return err
}

func (m *PacketManager) Close() error {
	m.mu.Lock()
	ids := make([]string, 0, len(m.processes))
	for id := range m.processes {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	for _, id := range ids {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = m.Stop(ctx, id)
		cancel()
	}
	return nil
}

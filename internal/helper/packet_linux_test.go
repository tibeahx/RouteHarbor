//go:build linux

package helper

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestNativePacketLifecycle(t *testing.T) {
	if os.Getenv("ROUTEHARBOR_PACKET_LAB") != "1" {
		t.Skip("requires disposable privileged pinned nfqws Linux lab")
	}
	m := NewPacketManager()
	defer func() { _ = m.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if e := m.Start(ctx, "profile-a", 21); e != nil {
		t.Fatal(e)
	}
	if e := m.Start(ctx, "profile-b", 22); e != nil {
		t.Fatal(e)
	}
	if !m.Running("profile-a", 21) || !m.Running("profile-b", 22) {
		t.Fatal("packet processes or independent probe rules missing")
	}
	if slot, ready := m.Path("profile-a"); !ready || slot != 21 {
		t.Fatal("independent source path unavailable")
	}
	if e := m.Start(ctx, "collision", 21); e == nil {
		t.Fatal("two profiles acquired same queue")
	}
	if e := m.Stop(ctx, "profile-a"); e != nil {
		t.Fatal(e)
	}
	if m.Running("profile-a", 21) || !m.Running("profile-b", 22) {
		t.Fatal("stopping A affected B")
	}
	if e := m.Start(ctx, "profile-a", 21); e != nil {
		t.Fatal("restart failed", e)
	}
	m.mu.Lock()
	p := m.processes["profile-a"]
	m.mu.Unlock()
	if e := syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL); e != nil {
		t.Fatal(e)
	}
	select {
	case <-p.done:
	case <-ctx.Done():
		t.Fatal("process did not exit")
	}
	if m.Running("profile-a", 21) {
		t.Fatal("crashed packet engine reported running")
	}
	if !m.Running("profile-b", 22) {
		t.Fatal("A crash affected B")
	}
}

package adapter

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/model"
)

func TestRestoreAllocationsPreservesConfirmedLANPortsAndMarks(t *testing.T) {
	ctx := context.Background()
	s := source("sing-box", `{"type":"http","server":"1.1.1.1","server_port":8080}`)
	first := NewManager(filepath.Join(t.TempDir(), "engine"))
	first.DNSResolver = "8.8.8.8"
	p, e := first.ProbePath(ctx, s)
	if e != nil {
		t.Fatal(e)
	}
	if e = first.Close(ctx); e != nil {
		t.Fatal(e)
	}
	p.Slot = 17
	p.Mark = Mark(17)
	p.Queue = 21017
	second := NewManager(filepath.Join(t.TempDir(), "engine"))
	second.DNSResolver = "8.8.8.8"
	defer func() {
		if e := second.Close(ctx); e != nil {
			t.Error(e)
		}
	}()
	if e = second.RestoreAllocations(ctx, []model.Source{s}, []Path{p}); e != nil {
		t.Fatal(e)
	}
	got, e := second.ProbePath(ctx, s)
	if e != nil {
		t.Fatal(e)
	}
	if got.Slot != 17 || got.Mark != p.Mark || got.TransparentPort != p.TransparentPort ||
		got.DNSPort != p.DNSPort {
		t.Fatal("confirmed source allocation changed", p, got)
	}
	newSource := source("direct", `{}`)
	newSource.ID = "new"
	n, e := second.ProbePath(ctx, newSource)
	if e != nil || n.Slot == 17 {
		t.Fatal("new source reused restored slot", n, e)
	}
}

func TestRestoreRejectsOccupiedPortWithoutTakingOverListener(t *testing.T) {
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = listener.Close() }()
	s := source("sing-box", `{"type":"http","server":"1.1.1.1","server_port":8080}`)
	p := Path{
		SourceID:        s.ID,
		Kind:            s.Type,
		Slot:            1,
		TransparentPort: listener.Addr().(*net.TCPAddr).Port,
		UDP:             false,
	}
	m := NewManager(filepath.Join(t.TempDir(), "engine"))
	defer func() {
		if e := m.Close(context.Background()); e != nil {
			t.Error(e)
		}
	}()
	if e = m.RestoreAllocations(context.Background(), []model.Source{s}, []Path{p}); e == nil {
		t.Fatal("restored input replaced an occupied listener")
	}
	done := make(chan error, 1)
	go func() {
		c, e := listener.Accept()
		if e == nil {
			_ = c.Close()
		}
		done <- e
	}()
	conn, e := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if e != nil {
		t.Fatal("unrelated listener was disturbed", e)
	}
	_ = conn.Close()
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}

func TestRestoreRejectsInconsistentSourceIntent(t *testing.T) {
	s := source("interface", `{"name":"wg0"}`)
	base := Path{SourceID: s.ID, Kind: s.Type, Slot: 1, Interface: "wg0", UDP: true}
	for _, mutate := range []func(*Path){func(p *Path) { p.SourceID = "unknown" }, func(p *Path) { p.Slot = 0 }, func(p *Path) { p.Interface = "evil0" }, func(p *Path) { p.Kind = "direct" }, func(p *Path) { p.UDP = false }, func(p *Path) { p.IPv6 = true }, func(p *Path) { p.Mark = 1 }, func(p *Path) { p.TransparentPort = 12345 }} {
		p := base
		mutate(&p)
		m := NewManager(filepath.Join(t.TempDir(), "engine"))
		if e := m.RestoreAllocations(context.Background(), []model.Source{s}, []Path{p}); e == nil {
			t.Fatal("inconsistent allocation accepted", p)
		}
	}
}

type nativeRegistrationRecorder struct {
	calls   []Path
	stopped []string
}

func (r *nativeRegistrationRecorder) RegisterProbe(
	_ context.Context,
	id, kind string,
	slot int,
	device string,
) error {
	r.calls = append(r.calls, Path{SourceID: id, Kind: kind, Slot: slot, Interface: device})
	return nil
}

func (r *nativeRegistrationRecorder) UnregisterProbe(_ context.Context, id string) error {
	r.stopped = append(r.stopped, id)
	return nil
}

func TestNativeProbePreparationRegistersRenewedAndRestoredAllocation(t *testing.T) {
	ctx := context.Background()
	s := source("direct", `{}`)
	registry := &nativeRegistrationRecorder{}
	m := NewManager(filepath.Join(t.TempDir(), "engine"))
	m.NativeProbes = registry
	if e := m.Prepare(ctx, s); e != nil {
		t.Fatal(e)
	}
	if e := m.Prepare(ctx, s); e != nil {
		t.Fatal(e)
	}
	if len(registry.calls) != 2 || registry.calls[0].Slot != registry.calls[1].Slot {
		t.Fatal("native preparation did not renew same independent allocation")
	}
	if e := m.Stop(ctx, s.ID); e != nil {
		t.Fatal(e)
	}
	if len(registry.stopped) != 1 || registry.stopped[0] != s.ID {
		t.Fatal("native source was not unregistered")
	}
	p := AllocatePath(s.ID, s.Type, 17)
	if e := m.RestoreAllocations(ctx, []model.Source{s}, []Path{p}); e != nil {
		t.Fatal(e)
	}
	if registry.calls[len(registry.calls)-1].Slot != 17 {
		t.Fatal("restoration registered a different slot")
	}
	if e := m.Close(ctx); e != nil {
		t.Fatal(e)
	}
}

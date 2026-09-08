package helper

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tibeahx/OpenRHP/internal/dataplane"
	"github.com/tibeahx/OpenRHP/internal/platform"
)

func TestNativeProbeRegistrationBeforeTransactionAndAllocationConflicts(t *testing.T) {
	b := &memoryBackend{}
	m := testManager(t, b, &testWatchdog{})
	s := &Server{Manager: m}
	p := NativeProbePath{SourceID: "direct-a", Kind: "direct", Slot: 17}
	if e := s.registerProbe(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	if got, e := s.probePath(p.SourceID); e != nil || got.Slot != 17 || got.Kind != "direct" {
		t.Fatal("first-use direct probe not independently registered", got, e)
	}
	if len(b.applied) != 0 {
		t.Fatal("registration changed routes")
	}
	for _, other := range []NativeProbePath{{SourceID: "b", Kind: "direct", Slot: 17}, {SourceID: p.SourceID, Kind: "direct", Slot: 18}} {
		if e := s.registerProbe(context.Background(), other); e == nil {
			t.Fatal("allocation conflict accepted", other)
		}
	}
	if e := s.unregisterProbe(p.SourceID); e != nil {
		t.Fatal(e)
	}
	if _, e := s.probePath(p.SourceID); e == nil {
		t.Fatal("unregistered uncommitted probe remained available")
	}
	s.Packet = NewPacketManager()
	s.Packet.processes["dpi"] = &packetProcess{slot: 17}
	if e := s.registerProbe(context.Background(), p); e == nil {
		t.Fatal("native registration collided with packet queue")
	}
	s.Packet = nil
	d := testDesired()
	d.Paths = []dataplane.Path{{SourceID: "committed", Kind: "direct", Slot: 17}}
	if e := m.locked(
		func(state *State) error { state.Committed = &d; return m.save(state) },
	); e != nil {
		t.Fatal(e)
	}
	if e := s.registerProbe(context.Background(), p); e == nil {
		t.Fatal("native registration collided with committed path")
	}
}

func TestNativeProbeLeaseExpiryNeverReassignsCommittedSlots(t *testing.T) {
	m := testManager(t, &memoryBackend{}, &testWatchdog{})
	s := &Server{
		Manager: m,
		nativeProbes: map[string]nativeProbeRegistration{
			"old": {
				Path: NativeProbePath{SourceID: "old", Kind: "direct", Slot: 8},
				Seen: time.Now().Add(-2 * time.Minute),
			},
		},
	}
	p := NativeProbePath{SourceID: "new", Kind: "direct", Slot: 8}
	if e := s.registerProbe(context.Background(), p); e != nil {
		t.Fatal("abandoned uncommitted lease not released", e)
	}
}

func TestNativeProbeProtocolBoundsAndTunnelEvidence(t *testing.T) {
	valid := Request{
		Operation: "register_probe",
		ProbePath: &NativeProbePath{SourceID: "a", Kind: "direct", Slot: 1},
	}
	if e := validateRequest(valid); e != nil {
		t.Fatal(e)
	}
	for _, r := range []Request{{Operation: "register_probe"}, {Operation: "register_probe", ProbePath: &NativeProbePath{SourceID: "a", Kind: "packet-engine", Slot: 1}}, {Operation: "register_probe", ProbePath: &NativeProbePath{SourceID: "a", Kind: "direct", Slot: 251}}, {Operation: "register_probe", ProbePath: &NativeProbePath{SourceID: "a", Kind: "direct", Slot: 1, Interface: "eth0"}}, {Operation: "status", ProbePath: valid.ProbePath}, {Operation: "register_probe", ProbePath: valid.ProbePath, Address: "1.1.1.1:443"}} {
		if e := validateRequest(r); e == nil {
			t.Fatal("unsafe registration request accepted", r)
		}
	}
	raw := []byte(
		`{"operation":"register_probe","probe_path":{"source_id":"a","kind":"direct","slot":1,"mark":123}}`,
	)
	var r Request
	if e := DecodeStrict(raw, &r); e == nil {
		t.Fatal("arbitrary mark accepted")
	}
	interfaces := []platform.Interface{{Device: "vpn0", Protocol: "wireguard", Up: true}}
	if e := validateTunnelEvidence(
		"vpn0",
		interfaces,
		[]byte(`[{"ifname":"vpn0","linkinfo":{"info_kind":"wireguard"}}]`),
	); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"veth", "bridge", "dummy", "bond", "macvlan", ""} {
		raw := []byte(`[{"ifname":"vpn0","linkinfo":{"info_kind":"` + kind + `"}}]`)
		if e := validateTunnelEvidence("vpn0", interfaces, raw); e == nil {
			t.Fatal("physical or virtual LAN interface allowed", kind)
		}
	}
	interfaces[0].Protocol = "static"
	if e := validateTunnelEvidence(
		"vpn0",
		interfaces,
		[]byte(`[{"ifname":"vpn0","linkinfo":{"info_kind":"wireguard"}}]`),
	); e == nil {
		t.Fatal("netifd static interface accepted")
	}
	if e := validateNativeProbe(
		NativeProbePath{SourceID: strings.Repeat("x", 65), Kind: "direct", Slot: 1},
	); e == nil {
		t.Fatal("unbounded source ID")
	}
}

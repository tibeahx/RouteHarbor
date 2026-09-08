package control

import (
	"context"
	"testing"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/dataplane"
	"github.com/tibeahx/OpenRHP/internal/helper"
	"github.com/tibeahx/OpenRHP/internal/model"
)

func TestStartupRestoresConfirmedAllocationAndStagedRemovedSource(t *testing.T) {
	r := runtimeFixture(t)
	confirmed := r.Store.Get()
	if e := r.Store.SaveConfirmed(confirmed); e != nil {
		t.Fatal(e)
	}
	changed := r.Store.Get()
	changed.Sources = nil
	if _, e := r.Store.Replace(changed.Revision, changed); e != nil {
		t.Fatal(e)
	}
	r.Reload()
	d := dataplane.Desired{
		Network:  confirmed.Network,
		Fallback: confirmed.Policy.Fallback,
		Selected: "direct",
		Paths:    []dataplane.Path{{SourceID: "direct", Kind: "direct", Slot: 17, UDP: true}},
	}
	client := &coordinatorClient{state: helper.State{Committed: &d, Guarded: true}}
	n := &NetworkCoordinator{Runtime: r, Client: client}
	if e := n.Initialize(context.Background()); e != nil {
		t.Fatal(e)
	}
	status := r.Adapters.Status("direct")
	if status.State != "running" || status.Path.Mark != adapter.Mark(17) {
		t.Fatal("retired committed source did not restore", status)
	}
	if _, ok := r.retired["direct"]; !ok {
		t.Fatal("confirmed source secrets not retained across staged deletion")
	}
	if n.confirmedRevision != 0 {
		t.Fatal("unconfirmed edited config became eligible for automatic network mutation")
	}
	r.retain(map[string]bool{})
	if r.Adapters.Status("direct").State != "stopped" {
		t.Fatal("retired restored source not stopped on confirmation")
	}
}

func TestConfirmedTransactionCheckpointClosesPromotionCrashGap(t *testing.T) {
	r := runtimeFixture(t)
	c := r.Store.Get()
	id := "0123456789abcdef0123456789abcdef"
	if e := r.Store.SaveCheckpoint(id, c); e != nil {
		t.Fatal(e)
	}
	d := dataplane.Desired{
		Network:  c.Network,
		Fallback: c.Policy.Fallback,
		Selected: "direct",
		Paths:    []dataplane.Path{{SourceID: "direct", Kind: "direct", Slot: 8, UDP: true}},
	}
	client := &coordinatorClient{
		state: helper.State{
			Committed:   &d,
			Transaction: &helper.Transaction{ID: id, State: "confirmed", Candidate: d},
			Guarded:     true,
		},
	}
	n := &NetworkCoordinator{Runtime: r, Client: client}
	if e := n.Initialize(context.Background()); e != nil {
		t.Fatal(e)
	}
	if n.confirmedRevision != c.Revision || r.Adapters.Status("direct").Path.Slot != 8 {
		t.Fatal("confirmed crash-gap snapshot was not restored")
	}
	if _, ok, e := r.Store.Confirmed(); e != nil || !ok {
		t.Fatal("confirmed snapshot was not finalized", e)
	}
}

func TestMissingPrivateCheckpointBlocksProbesButLeavesStatusAvailable(t *testing.T) {
	r := runtimeFixture(t)
	c := r.Store.Get()
	d := dataplane.Desired{
		Network:  c.Network,
		Fallback: c.Policy.Fallback,
		Paths:    []dataplane.Path{{SourceID: "direct", Kind: "direct", Slot: 1, UDP: true}},
	}
	n := &NetworkCoordinator{
		Runtime: r,
		Client:  &coordinatorClient{state: helper.State{Committed: &d, Guarded: true}},
	}
	if e := n.Initialize(context.Background()); e == nil {
		t.Fatal("unproven source configuration silently reattached to committed routing")
	}
	if _, e := r.Probe(context.Background(), "direct", false); e == nil {
		t.Fatal("probe ran with mismatched startup allocation")
	}
	if r.Status()["path_initialization_error"] != "confirmed_configuration_missing" {
		t.Fatal("status did not explain safe startup block")
	}
}

type restoredDNSRecorder struct {
	managed  bool
	resolver string
}

func (d *restoredDNSRecorder) ConfigureDNS(managed bool, resolver string) {
	d.managed, d.resolver = managed, resolver
}

func (d *restoredDNSRecorder) Run(
	context.Context,
	model.Source,
	[]model.Target,
	model.ProbeSettings,
	bool,
) (model.Measurement, error) {
	return model.Measurement{}, nil
}

func TestStartupDNSUsesCommittedPolicyAfterOfflineDraftChange(t *testing.T) {
	r := runtimeFixture(t)
	confirmed := r.Store.Get()
	confirmed.Network.Enabled = true
	confirmed.Network.LANInterfaces = []string{"br-lan"}
	confirmed.Network.WANInterface = "eth0"
	confirmed.Network.LocalPrefixes = []string{"192.168.1.0/24"}
	confirmed.Policy.Mode = "auto"
	confirmed.Network.DNSResolver = "8.8.8.8"
	if e := r.Store.SaveConfirmed(confirmed); e != nil {
		t.Fatal(e)
	}
	// The current draft remains disabled, as if edited while the controller was down.
	recorder := &restoredDNSRecorder{}
	r.Prober = recorder
	d := dataplane.Desired{
		Network:  confirmed.Network,
		Fallback: confirmed.Policy.Fallback,
		Selected: "direct",
		Paths:    []dataplane.Path{{SourceID: "direct", Kind: "direct", Slot: 1, UDP: true}},
	}
	n := &NetworkCoordinator{
		Runtime: r,
		Client:  &coordinatorClient{state: helper.State{Committed: &d, Guarded: true}},
	}
	if e := n.Initialize(context.Background()); e != nil {
		t.Fatal(e)
	}
	if !recorder.managed || recorder.resolver != "8.8.8.8" {
		t.Fatal("restored path used draft DNS policy", recorder)
	}
}

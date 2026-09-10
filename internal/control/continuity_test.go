package control

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tibeahx/RouteHarbor/internal/adapter"
	"github.com/tibeahx/RouteHarbor/internal/config"
	"github.com/tibeahx/RouteHarbor/internal/continuity"
	"github.com/tibeahx/RouteHarbor/internal/dataplane"
	"github.com/tibeahx/RouteHarbor/internal/helper"
	"github.com/tibeahx/RouteHarbor/internal/model"
)

type aliveContinuityProcess struct{}

func (aliveContinuityProcess) Alive() bool                 { return true }
func (aliveContinuityProcess) Done() <-chan struct{}       { return nil }
func (aliveContinuityProcess) Close(context.Context) error { return nil }

func TestContinuitySelectionNeverMutatesLANRules(t *testing.T) {
	r := runtimeFixture(t)
	c := r.Store.Get()
	r.decision = model.Decision{Selected: "direct"}
	r.Continuity = &ContinuityControl{
		process:     aliveContinuityProcess{},
		request:     &helper.ContinuityWorkerRequest{Sources: []adapter.Path{{SourceID: "direct"}}},
		lastPrimary: "direct",
	}
	d := dataplane.Desired{Selected: "old", Continuity: &dataplane.ContinuityIntent{}}
	client := &coordinatorClient{state: helper.State{Committed: &d}}
	n := &NetworkCoordinator{
		Runtime:           r,
		Client:            client,
		initialized:       true,
		confirmedRevision: c.Revision,
	}
	n.Sync(context.Background())
	if client.switched != 0 || n.lastError != "" {
		t.Fatalf("transport switch touched rules: %d %s", client.switched, n.lastError)
	}
	client.state.Guarded = true
	n.Sync(context.Background())
	if client.switched != 0 || n.lastError != "continuity_requires_confirmed_routing" {
		t.Fatal("guard bypassed")
	}
}

func TestContinuityConfigurationAndProbeBoundary(t *testing.T) {
	r := runtimeFixture(t)
	old := r.Store.Get()
	old.Network.Enabled = true
	p := config.ContinuityDefaults()
	p.Enabled = true
	p.RelayAddress = "8.8.8.8:8443"
	p.RelayFingerprint = strings.Repeat("a", 64)
	old.Continuity = &p
	d := dataplane.Desired{
		Network:       old.Network,
		Paths:         []dataplane.Path{{SourceID: "direct", Kind: "direct", Slot: 1}},
		Fallback:      old.Policy.Fallback,
		BreakExisting: old.Policy.BreakExisting,
		Continuity:    &dataplane.ContinuityIntent{Config: p},
	}
	if !matchesDesired(old, d) {
		t.Fatal("matching continuity checkpoint rejected")
	}
	d.Continuity = nil
	if matchesDesired(old, d) {
		t.Fatal("continuity checkpoint accepted as direct routing")
	}
	d.Continuity = &dataplane.ContinuityIntent{Config: p}
	client := &coordinatorClient{state: helper.State{Committed: &d}}
	n := &NetworkCoordinator{Runtime: r, Client: client}
	clone := func() model.Config {
		raw, _ := json.Marshal(old)
		var c model.Config
		_ = json.Unmarshal(raw, &c)
		return c
	}
	next := clone()
	next.Sources[0].Name = "Renamed"
	if e := n.ValidateChange(context.Background(), old, next); e != nil {
		t.Fatal("metadata edit rejected", e)
	}
	next = clone()
	next.Continuity.RelayAddress = "1.1.1.1:8443"
	if e := n.ValidateChange(context.Background(), old, next); e == nil {
		t.Fatal("live relay replaced without disabling")
	}
	next = clone()
	next.Continuity.Enabled = false
	if e := n.ValidateChange(context.Background(), old, next); e != nil {
		t.Fatal("staged disable rejected", e)
	}
	if got := selectionTargets(old); len(got) != 1 || got[0].ID != "relay" || !got[0].Required {
		t.Fatal("destination errors can rank carrier", got)
	}
	old.Continuity = nil
	if len(selectionTargets(old)) != len(old.Targets) {
		t.Fatal("legacy probe targets changed")
	}
}

func TestContinuityPublicStatusContainsNoWorkerCredentials(t *testing.T) {
	cc := &ContinuityControl{
		request: &helper.ContinuityWorkerRequest{
			PrivateKey:  "SENSITIVE KEY",
			Certificate: "SENSITIVE CERT",
		},
		status: helper.ContinuityStatus{
			Snapshot: continuity.Snapshot{Status: "Degraded", Qualified: false},
			Running:  true,
		},
	}
	raw, e := json.Marshal(cc.Public())
	if e != nil || strings.Contains(string(raw), "SENSITIVE") {
		t.Fatal("private launch payload disclosed")
	}
	if cc.Ready("missing") {
		t.Fatal("unconnected path reported ready")
	}
	cc.status.Paths = []continuity.PathSnapshot{{Name: "alpha", Ready: true}}
	if !cc.Ready("alpha") || cc.Public()["qualified"] != false {
		t.Fatal("TLS readiness confused with qualification")
	}
}

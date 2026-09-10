package control

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tibeahx/OpenRHP/internal/config"
	"github.com/tibeahx/OpenRHP/internal/dataplane"
	"github.com/tibeahx/OpenRHP/internal/helper"
	"github.com/tibeahx/OpenRHP/internal/model"
	"github.com/tibeahx/OpenRHP/internal/selection"
)

func TestSelectiveRuntimeExcludesDirectExitButRetainsRelayCarrier(t *testing.T) {
	for _, mode := range []string{"legacy", "selective", "selective-relay"} {
		t.Run(mode, func(t *testing.T) {
			c := config.Defaults()
			c.Policy.Mode = "auto"
			c.Policy.RecoveryConfirmations = 1
			c.Policy.Confirmations = 1
			c.Sources = []model.Source{{ID: "wan", Type: "direct", Enabled: true, Auto: true}}
			if mode == "legacy" {
				c.Routing = nil
			}
			if mode == "selective-relay" {
				c.Continuity = &model.ContinuityConfig{Enabled: true}
			}
			now := time.Now()
			sel := selection.New(c.Policy)
			sel.SetTargets([]model.Target{{ID: "resource", Required: true}})
			sel.Observe(
				model.Measurement{
					SourceID: "wan",
					At:       now,
					Resources: []model.ResourceResult{
						{TargetID: "resource", Required: true, Success: true, LatencyMS: 1},
					},
				},
			)
			r := &Runtime{selector: sel}
			r.evaluateLocked(c, now)
			want := "wan"
			if mode == "selective" {
				want = ""
			}
			if r.decision.Selected != want {
				t.Fatalf("got %q want %q", r.decision.Selected, want)
			}
		})
	}
}

func TestSelectiveCheckpointRequiresExactPolicyAndPresence(t *testing.T) {
	c := config.Defaults()
	d := dataplane.Desired{
		Network:  c.Network,
		Fallback: c.Policy.Fallback,
		Selective: &dataplane.SelectiveIntent{
			FailurePolicy: "direct",
			PolicyHash:    routingConfigHash(c),
		},
	}
	if !matchesDesired(c, d) {
		t.Fatal("exact selective checkpoint rejected")
	}
	if len(d.Selective.PolicyHash) != 64 {
		t.Fatal("missing policy binding")
	}
	saved := c.Routing
	c.Routing = nil
	if matchesDesired(c, d) {
		t.Fatal("selective journal accepted legacy config")
	}
	c.Routing = saved
	d.Selective = nil
	if matchesDesired(c, d) {
		t.Fatal("legacy journal accepted selective config")
	}
	d.Selective = &dataplane.SelectiveIntent{
		FailurePolicy: "direct",
		PolicyHash:    routingConfigHash(c),
	}
	c.Routing.Exceptions = []model.RoutingRule{{Action: "bypass", Domain: "example.org"}}
	if matchesDesired(c, d) {
		t.Fatal("changed domain policy reattached to old dispatcher")
	}
	d.Selective.PolicyHash = routingConfigHash(c)
	d.Selective.FailurePolicy = "closed"
	if matchesDesired(c, d) {
		t.Fatal("failure policy mismatch accepted")
	}
}

func TestSelectiveMissingServiceCannotUseLegacySwitchOrClearMaintenance(t *testing.T) {
	r := runtimeFixture(t)
	c := r.Store.Get()
	r.decision = model.Decision{Selected: "direct"}
	d := dataplane.Desired{
		Selected:  "",
		Selective: &dataplane.SelectiveIntent{PolicyHash: strings.Repeat("a", 64)},
	}
	client := &coordinatorClient{state: helper.State{Committed: &d, Guarded: true}}
	n := &NetworkCoordinator{
		Runtime:           r,
		Client:            client,
		initialized:       true,
		confirmedRevision: c.Revision,
	}
	n.Sync(context.Background())
	if client.switched != 0 || n.lastError != "selective_dispatcher_unavailable" {
		t.Fatal(
			"selective failure escaped into legacy route switching",
			client.switched,
			n.lastError,
		)
	}
	client.state.MaintenanceHold = true
	n.Sync(context.Background())
	if client.switched != 0 || n.lastError != "maintenance_requires_confirmed_routing" {
		t.Fatal("selective path ignored maintenance hold", n.lastError)
	}
	current, err := n.Current(context.Background())
	if err != nil || current["emergency_direct"] != false {
		t.Fatal("maintenance hold presented as emergency direct", current, err)
	}
}

func TestSelectiveAppliedCandidateDrivesCurrentStateBeforeConfirmation(t *testing.T) {
	r := runtimeFixture(t)
	c := r.Store.Get()
	old := dataplane.Desired{Selected: "old"}
	candidate := dataplane.Desired{
		Selected:  "new",
		Selective: &dataplane.SelectiveIntent{PolicyHash: strings.Repeat("b", 64)},
	}
	client := &coordinatorClient{
		state: helper.State{
			Committed:   &old,
			Transaction: &helper.Transaction{State: "applied", Candidate: candidate},
		},
	}
	n := &NetworkCoordinator{
		Runtime:           r,
		Client:            client,
		initialized:       true,
		confirmedRevision: c.Revision,
	}
	r.decision = model.Decision{Selected: "draft-choice"}
	n.Sync(context.Background())
	if client.switched != 0 || n.lastError != "selective_dispatcher_unavailable" {
		t.Fatal(
			"applied selective candidate entered legacy switching",
			client.switched,
			n.lastError,
		)
	}
	current, err := n.Current(context.Background())
	if err != nil || current["selected"] != "new" || current["applied"] != true {
		t.Fatal("current status described old committed path after apply", current, err)
	}
	for _, state := range []string{"prepared", "applying", "rolling-back", "rolled-back", "confirmed", "failed"} {
		client.state.Transaction.State = state
		if got := effectiveRoutingDesired(client.state); got != &old {
			t.Fatalf("%s used unapplied candidate", state)
		}
	}
	client.state.Committed = nil
	client.state.Transaction.State = "applied"
	current, err = n.Current(context.Background())
	if err != nil || current["applied"] != true || current["selected"] != "new" {
		t.Fatal("initial applied ingress reported inactive", current, err)
	}
}

package control

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tibeahx/OpenRHP/internal/dataplane"
	"github.com/tibeahx/OpenRHP/internal/helper"
	"github.com/tibeahx/OpenRHP/internal/model"
	"github.com/tibeahx/OpenRHP/internal/platform"
)

type coordinatorClient struct {
	state    helper.State
	switched int
}

func (c *coordinatorClient) Status(context.Context) (helper.State, error) {
	return c.state, nil
}

func (c *coordinatorClient) Prepare(
	context.Context,
	dataplane.Desired,
) (helper.Transaction, error) {
	return helper.Transaction{}, nil
}

func (c *coordinatorClient) Apply(
	context.Context,
	string,
	time.Duration,
) (helper.Transaction, error) {
	return helper.Transaction{}, nil
}

func (c *coordinatorClient) Confirm(context.Context, string) (helper.Transaction, error) {
	return helper.Transaction{}, nil
}

func (c *coordinatorClient) Rollback(context.Context, string) (helper.Transaction, error) {
	return helper.Transaction{}, nil
}

func (c *coordinatorClient) Switch(context.Context, string) (helper.Transaction, error) {
	c.switched++
	return helper.Transaction{}, nil
}

func TestPrepareUsesPrivilegedPlatformDiscovery(t *testing.T) {
	r := runtimeFixture(t)
	called := false
	n := &NetworkCoordinator{
		Runtime: r,
		Client:  &coordinatorClient{},
		Platform: func(context.Context) (platform.Report, error) {
			called = true
			return platform.Report{Supported: true, OS: "OpenWrt"}, nil
		},
	}
	if _, err := n.Prepare(
		context.Background(),
		r.Store.Get(),
		120,
	); err == nil || err.Error() != "network disabled" ||
		!called {
		t.Fatalf("privileged platform discovery was not used: called=%v err=%v", called, err)
	}
	n.Platform = func(context.Context) (platform.Report, error) {
		return platform.Report{Supported: true}, errors.New("private discovery failure")
	}
	if _, err := n.Prepare(
		context.Background(),
		r.Store.Get(),
		120,
	); err == nil ||
		err.Error() != "privileged platform discovery is unavailable" {
		t.Fatalf("failed platform discovery was accepted: %v", err)
	}
}

func TestCommittedPathEditsRequireSafeRemovalAndPendingTransactionsLockConfig(t *testing.T) {
	r := runtimeFixture(t)
	old := r.Store.Get()
	old.Network.Enabled = true
	client := &coordinatorClient{
		state: helper.State{
			Committed: &dataplane.Desired{
				Network: old.Network,
				Paths:   []dataplane.Path{{SourceID: "direct", Kind: "direct", Slot: 1}},
			},
		},
	}
	n := &NetworkCoordinator{Runtime: r, Client: client}
	next := r.Store.Get()
	next.Network = old.Network
	next.Sources[0].Name = "A new name"
	if e := n.ValidateChange(context.Background(), old, next); e != nil {
		t.Fatal("metadata change rejected", e)
	}
	next.Sources[0].Type = "interface"
	if e := n.ValidateChange(context.Background(), old, next); e == nil {
		t.Fatal("live connection settings changed before network transaction")
	}
	next = old
	next.Sources = nil
	if e := n.ValidateChange(context.Background(), old, next); e != nil {
		t.Fatal("safe staged removal rejected", e)
	}
	next = old
	next.Network.Enabled = false
	if e := n.ValidateChange(
		context.Background(),
		old,
		next,
	); e == nil ||
		!strings.Contains(e.Error(), "decommission") {
		t.Fatal("unsupported network disable was misleadingly accepted", e)
	}
	// A draft edited offline cannot erase the committed network ownership.
	offline := next
	if e := n.ValidateChange(
		context.Background(),
		offline,
		offline,
	); e == nil ||
		!strings.Contains(e.Error(), "decommission") {
		t.Fatal("offline draft bypassed committed network disable protection", e)
	}
	offline.Network.Enabled = true
	offline.Network.DNSResolver = "8.8.8.8"
	if e := n.ValidateChange(context.Background(), offline, offline); e == nil {
		t.Fatal("offline draft replaced the committed DNS policy")
	}
	client.state.Transaction = &helper.Transaction{State: "applied"}
	if e := n.ValidateChange(context.Background(), old, old); e == nil {
		t.Fatal("config edit invalidated pending rollback")
	}
}

func TestGuardedNetworkIsNotReportedApplied(t *testing.T) {
	r := runtimeFixture(t)
	client := &coordinatorClient{
		state: helper.State{Committed: &dataplane.Desired{Selected: "direct"}, Guarded: true},
	}
	n := &NetworkCoordinator{Runtime: r, Client: client}
	state, e := n.Current(context.Background())
	if e != nil || state["applied"] != false || state["guarded"] != true {
		t.Fatal("guarded state reported active", state, e)
	}
	n.initialized = true
	n.confirmedRevision = r.Store.Get().Revision
	r.decision = model.Decision{Selected: "direct"}
	n.Sync(context.Background())
	if client.switched != 1 {
		t.Fatal("same selected path was not restored after an independent fw4 guard")
	}
}

func TestCurrentExposesResetFailureWithoutLosingCommittedRoute(t *testing.T) {
	r := runtimeFixture(t)
	d := dataplane.Desired{Selected: "new-source"}
	client := &coordinatorClient{
		state: helper.State{Committed: &d, Transaction: &helper.Transaction{
			ID:              "confirmed-switch",
			State:           "confirmed",
			FlowTermination: "failed",
			ErrorCode:       "conntrack_delete_failed",
		}},
	}
	n := &NetworkCoordinator{Runtime: r, Client: client}
	status, err := n.Current(context.Background())
	if err != nil || status["applied"] != true || status["selected"] != "new-source" ||
		status["last_error"] != "conntrack_delete_failed" || status["flow_termination"] != "failed" {
		t.Fatal(status, err)
	}
	client.state.Transaction.FlowTermination = "completed"
	client.state.Transaction.ErrorCode = ""
	status, err = n.Current(context.Background())
	if err != nil || status["last_error"] != "" {
		t.Fatal(status, err)
	}
}

package control

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/dataplane"
	"github.com/tibeahx/OpenRHP/internal/helper"
	"github.com/tibeahx/OpenRHP/internal/model"
	"github.com/tibeahx/OpenRHP/internal/platform"
)

type maintenanceRestoreBackend struct{}

func (maintenanceRestoreBackend) Check(context.Context, dataplane.Plan) error { return nil }
func (maintenanceRestoreBackend) Apply(context.Context, dataplane.Plan, *dataplane.Plan) error {
	return nil
}

func (maintenanceRestoreBackend) CheckQuarantine(
	context.Context,
	dataplane.Plan,
) error {
	return nil
}

func (maintenanceRestoreBackend) Quarantine(context.Context, dataplane.Plan) error { return nil }

type maintenanceRestoreWatchdog struct{}

func (maintenanceRestoreWatchdog) Arm(string) error { return nil }

type maintenanceRestoreClient struct {
	manager  *helper.Manager
	switches int
}

func (c *maintenanceRestoreClient) Status(context.Context) (helper.State, error) {
	return c.manager.Status()
}

func (c *maintenanceRestoreClient) Prepare(
	ctx context.Context,
	d dataplane.Desired,
) (helper.Transaction, error) {
	return c.manager.Prepare(ctx, d)
}

func (c *maintenanceRestoreClient) Apply(
	ctx context.Context,
	id string,
	timeout time.Duration,
) (helper.Transaction, error) {
	return c.manager.Apply(ctx, id, timeout)
}

func (c *maintenanceRestoreClient) Confirm(
	_ context.Context,
	id string,
) (helper.Transaction, error) {
	return c.manager.Confirm(id)
}

func (c *maintenanceRestoreClient) Rollback(
	ctx context.Context,
	id string,
) (helper.Transaction, error) {
	return c.manager.Rollback(ctx, id)
}

func (c *maintenanceRestoreClient) Switch(
	ctx context.Context,
	id string,
) (helper.Transaction, error) {
	c.switches++
	return c.manager.Switch(ctx, id)
}

func TestMaintenanceClosedRollbackRestartAllowsExplicitRecoveryOnly(t *testing.T) {
	ctx := context.Background()
	r := runtimeFixture(t)
	c := r.Store.Get()
	c.Network.Enabled = true
	c.Network.LANInterfaces = []string{"home0"}
	c.Network.WANInterface = "wan0"
	c.Network.LocalPrefixes = []string{"192.168.1.0/24"}
	c.Policy.Mode = "auto"
	c.Policy.Fallback = "direct"
	c, err := r.Store.Replace(c.Revision, c)
	if err != nil {
		t.Fatal(err)
	}
	r.Reload()
	r.decision = model.Decision{Selected: "direct"}
	stateDir := filepath.Join(t.TempDir(), "helper")
	m, err := helper.NewManager(stateDir, maintenanceRestoreBackend{}, maintenanceRestoreWatchdog{})
	if err != nil {
		t.Fatal(err)
	}
	client := &maintenanceRestoreClient{manager: m}
	coordinator := func() *NetworkCoordinator {
		return &NetworkCoordinator{
			Runtime:  r,
			Client:   client,
			Platform: func(context.Context) (platform.Report, error) { return platform.Report{Supported: true}, nil },
		}
	}
	n := coordinator()
	confirm := func() string {
		t.Helper()
		txn, err := n.Prepare(ctx, c, 90)
		if err != nil {
			t.Fatal(err)
		}
		id := txn["id"].(string)
		if _, err = n.Action(ctx, id, "apply"); err != nil {
			t.Fatal(err)
		}
		if _, err = n.Action(ctx, id, "confirm"); err != nil {
			t.Fatal(err)
		}
		return id
	}
	confirm()
	const job = "0123456789abcdef0123456789abcdef"
	if err = m.AcquireMaintenance(ctx, job, nil); err != nil {
		t.Fatal(err)
	}
	if err = m.ReleaseMaintenance(job); err != nil {
		t.Fatal(err)
	}
	txn, err := n.Prepare(ctx, c, 90)
	if err != nil {
		t.Fatal(err)
	}
	id := txn["id"].(string)
	if _, err = n.Action(ctx, id, "apply"); err != nil {
		t.Fatal(err)
	}
	if _, err = n.Action(ctx, id, "rollback"); err != nil {
		t.Fatal(err)
	}
	// Reopen the durable helper journal and construct a fresh API coordinator.
	client.manager, err = helper.NewManager(
		stateDir,
		maintenanceRestoreBackend{},
		maintenanceRestoreWatchdog{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Adapters.Close(ctx); err != nil {
		t.Fatal(err)
	}
	r.Adapters = adapter.NewManager(filepath.Join(t.TempDir(), "restarted-engines"))
	n = coordinator()
	if err = n.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	saved, found, err := r.Store.Confirmed()
	if err != nil || !found || saved.Policy.Fallback != "closed" {
		t.Fatal(saved, found, err)
	}
	if r.Store.Get().Policy.Fallback != "direct" {
		t.Fatal("recovery changed the current draft")
	}
	// Even if a scheduler considers this revision current, the durable hold wins.
	n.confirmedRevision = c.Revision
	n.Sync(ctx)
	if client.switches != 0 {
		t.Fatal("scheduler reopened maintenance quarantine")
	}
	state, err := client.manager.Status()
	if err != nil || !state.MaintenanceHold || !state.Guarded {
		t.Fatal(state, err)
	}
	confirm()
	state, err = client.manager.Status()
	if err != nil || state.MaintenanceHold || state.Guarded ||
		state.Committed.Fallback != "direct" {
		t.Fatal(state, err)
	}
}

func TestMaintenanceRollbackCheckpointRejectsUnprovenChanges(t *testing.T) {
	for _, mutation := range []string{"no-hold", "not-guarded", "not-rolled-back", "missing-checkpoint", "changed-slot", "changed-network", "different-rollback"} {
		t.Run(mutation, func(t *testing.T) {
			r := runtimeFixture(t)
			c := r.Store.Get()
			c.Policy.Fallback = "direct"
			id := "0123456789abcdef0123456789abcdef"
			if mutation != "missing-checkpoint" {
				if err := r.Store.SaveCheckpoint(id, c); err != nil {
					t.Fatal(err)
				}
			}
			candidate := dataplane.Desired{
				Network:  c.Network,
				Fallback: "direct",
				Selected: "direct",
				Paths: []dataplane.Path{
					{SourceID: "direct", Kind: "direct", Slot: 1, UDP: true},
				},
			}
			closed := candidate
			closed.Selected = ""
			closed.Fallback = "closed"
			state := helper.State{
				MaintenanceHold: true,
				Guarded:         true,
				Committed:       &closed,
				Transaction: &helper.Transaction{
					ID:        id,
					State:     "rolled-back",
					Candidate: candidate,
					Rollback:  closed,
				},
			}
			switch mutation {
			case "no-hold":
				state.MaintenanceHold = false
			case "not-guarded":
				state.Guarded = false
			case "not-rolled-back":
				state.Transaction.State = "confirmed"
			case "changed-slot":
				state.Committed.Paths = []dataplane.Path{
					{SourceID: "direct", Kind: "direct", Slot: 2, UDP: true},
				}
			case "changed-network":
				state.Committed.Network.WANInterface = "other0"
			case "different-rollback":
				state.Transaction.Rollback.Selected = "direct"
			}
			n := &NetworkCoordinator{Runtime: r}
			if _, ok, err := n.maintenanceRollbackCheckpoint(state); err != nil || ok {
				t.Fatal("unproven checkpoint accepted", ok, err)
			}
			if _, found, err := r.Store.Confirmed(); err != nil || found {
				t.Fatal("rejected recovery wrote a checkpoint", found, err)
			}
		})
	}
}

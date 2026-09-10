package helper

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/dataplane"
)

type maintenanceBackend struct {
	memoryBackend
	quarantineErr error
	quarantined   int
}

func (*maintenanceBackend) CheckQuarantine(context.Context, dataplane.Plan) error { return nil }
func (b *maintenanceBackend) Quarantine(_ context.Context, _ dataplane.Plan) error {
	b.quarantined++
	return b.quarantineErr
}

func confirmedMaintenanceFixture(t *testing.T) (*Manager, *maintenanceBackend) {
	t.Helper()
	b := &maintenanceBackend{}
	m := testManager(t, b, &testWatchdog{})
	tx, err := m.Prepare(context.Background(), testDesired())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Apply(context.Background(), tx.ID, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Confirm(tx.ID); err != nil {
		t.Fatal(err)
	}
	return m, b
}

func TestMaintenanceGateSurvivesRestartAndRequiresNewConfirmation(t *testing.T) {
	m, backend := confirmedMaintenanceFixture(t)
	ctx := context.Background()
	const job = "0123456789abcdef0123456789abcdef"
	if err := m.AcquireMaintenance(ctx, job, nil); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewManager(m.dir, backend, &testWatchdog{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.Prepare(ctx, testDesired()); !errors.Is(err, ErrMaintenanceActive) {
		t.Fatal(err)
	}
	if err = restarted.WithRuntime(
		func() error { t.Fatal("engine started during maintenance"); return nil },
	); !errors.Is(
		err,
		ErrMaintenanceActive,
	) {
		t.Fatal(err)
	}
	state, err := restarted.Status()
	if err != nil || !state.Guarded || state.MaintenanceJob != job {
		t.Fatal(state, err)
	}
	if _, err = restarted.Confirm(state.Transaction.ID); !errors.Is(err, ErrMaintenanceActive) {
		t.Fatal(err)
	}
	if err = restarted.ReleaseMaintenance(job); err != nil {
		t.Fatal(err)
	}
	if err = restarted.ReleaseMaintenance(job); err != nil {
		t.Fatal("release retry after lost acknowledgement failed", err)
	}
	if _, err = restarted.Confirm(state.Transaction.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.prepare(ctx, testDesired(), true); !errors.Is(err, ErrMaintenanceActive) {
		t.Fatal("old confirm/automatic prepare reopened routing", err)
	}
	tx, err := restarted.Prepare(ctx, testDesired())
	if err != nil {
		t.Fatal(err)
	}
	if tx.Rollback.Selected != "" || tx.Rollback.Fallback != "closed" {
		t.Fatal("maintenance rollback must stay closed", tx)
	}
	if _, err = restarted.Apply(ctx, tx.ID, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.Confirm(tx.ID); err != nil {
		t.Fatal(err)
	}
	state, err = restarted.Status()
	if err != nil || state.MaintenanceHold || state.MaintenanceJob != "" {
		t.Fatal(state, err)
	}
	if _, err = restarted.prepare(ctx, testDesired(), true); err != nil {
		t.Fatal(err)
	}
	if err = restarted.ReleaseMaintenance(job); err != nil {
		t.Fatal("old release retry disturbed new routing", err)
	}
	if err = restarted.AcquireMaintenance(ctx, job, nil); err == nil {
		t.Fatal("completed maintenance job reacquired the routing gate")
	}
}

func TestFailedMaintenanceQuarantineKeepsGateAndSameJobCanRetry(t *testing.T) {
	m, backend := confirmedMaintenanceFixture(t)
	ctx := context.Background()
	const job = "0123456789abcdef0123456789abcdef"
	backend.quarantineErr = errors.New("injected quarantine failure")
	if err := m.AcquireMaintenance(ctx, job, nil); err == nil {
		t.Fatal("quarantine failure ignored")
	}
	state, err := m.Status()
	if err != nil || state.MaintenanceJob != job || !state.MaintenanceHold {
		t.Fatal(state, err)
	}
	if err = m.AcquireMaintenance(
		ctx,
		"abcdef0123456789abcdef0123456789",
		nil,
	); !errors.Is(
		err,
		ErrMaintenanceActive,
	) {
		t.Fatal(err)
	}
	if err = m.ReleaseMaintenance("abcdef0123456789abcdef0123456789"); err == nil {
		t.Fatal("other job released gate")
	}
	backend.quarantineErr = nil
	if err = m.AcquireMaintenance(ctx, job, nil); err != nil {
		t.Fatal(err)
	}
	if backend.quarantined != 2 {
		t.Fatal("same job did not retry quarantine")
	}
}

func TestMaintenanceGateWaitsForBoundedRuntimeMutation(t *testing.T) {
	m, backend := confirmedMaintenanceFixture(t)
	other, err := NewManager(m.dir, backend, nil)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- m.WithRuntime(func() error { close(entered); <-release; return nil }) }()
	<-entered
	var checked atomic.Bool
	acquired := make(chan error, 1)
	go func() {
		acquired <- other.AcquireMaintenance(context.Background(), "0123456789abcdef0123456789abcdef", func() error { checked.Store(true); return nil })
	}()
	select {
	case err = <-acquired:
		t.Fatalf("gate raced an in-progress runtime mutation: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if err = <-acquired; err != nil || !checked.Load() {
		t.Fatal(err)
	}
}

func TestMaintenanceGateRejectsPendingNetworkOrCoverageBeforeQuarantine(t *testing.T) {
	m, backend := confirmedMaintenanceFixture(t)
	const job = "0123456789abcdef0123456789abcdef"
	ctx := context.Background()
	if err := m.AcquireMaintenance(
		ctx,
		job,
		func() error { return ErrBusy },
	); !errors.Is(
		err,
		ErrBusy,
	) {
		t.Fatal(err)
	}
	if _, err := m.Prepare(ctx, testDesired()); err != nil {
		t.Fatal(err)
	}
	if err := m.AcquireMaintenance(ctx, job, nil); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	state, err := m.Status()
	if err != nil || state.MaintenanceJob != "" || backend.quarantined != 0 {
		t.Fatal(state, err)
	}
}

func TestExplicitMaintenanceRecoveryReacquiresOnlyBeforeNewConfirmation(t *testing.T) {
	m, backend := confirmedMaintenanceFixture(t)
	ctx := context.Background()
	const job = "0123456789abcdef0123456789abcdef"
	if err := m.AcquireMaintenance(ctx, job, nil); err != nil {
		t.Fatal(err)
	}
	if err := m.ReleaseMaintenance(job); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewManager(m.dir, backend, &testWatchdog{})
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.AcquireMaintenance(ctx, job, nil); err == nil {
		t.Fatal("ordinary replay reacquired a released gate")
	}
	if err = restarted.ReacquireMaintenance(
		ctx,
		job,
		func() error { return ErrBusy },
	); !errors.Is(
		err,
		ErrBusy,
	) {
		t.Fatal("explicit recovery bypassed another privileged transaction", err)
	}
	before := backend.quarantined
	if err = restarted.ReacquireMaintenance(ctx, job, nil); err != nil {
		t.Fatal("explicit recovery could not repair a lost release acknowledgement", err)
	}
	state, err := restarted.Status()
	if err != nil || state.MaintenanceJob != job || !state.MaintenanceHold || !state.Guarded ||
		backend.quarantined != before+1 {
		t.Fatal(state, err, backend.quarantined)
	}
	if err = restarted.ReleaseMaintenance(job); err != nil {
		t.Fatal(err)
	}
	tx, err := restarted.Prepare(ctx, testDesired())
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.ReacquireMaintenance(ctx, job, nil); !errors.Is(err, ErrBusy) {
		t.Fatal("recovery bypassed a newly prepared routing transaction", err)
	}
	if _, err = restarted.Apply(ctx, tx.ID, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.Confirm(tx.ID); err != nil {
		t.Fatal(err)
	}
	before = backend.quarantined
	if err = restarted.ReacquireMaintenance(ctx, job, nil); err == nil {
		t.Fatal("old recovery disturbed newly confirmed routing")
	}
	state, err = restarted.Status()
	if err != nil || state.MaintenanceJob != "" || state.MaintenanceHold ||
		backend.quarantined != before {
		t.Fatal(state, err, backend.quarantined)
	}
}

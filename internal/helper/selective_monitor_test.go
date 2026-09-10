package helper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/dataplane"
)

type selectiveMonitorBackend struct {
	emergencyMemory
	ensures   int
	ensureErr error
}

func (b *selectiveMonitorBackend) EnsureSelectiveEmergencyGuards(
	context.Context,
	dataplane.Desired,
) error {
	b.ensures++
	return b.ensureErr
}

type selectiveMonitorWatchdog struct{ normal, prepared []string }

func (w *selectiveMonitorWatchdog) Arm(
	id string,
) error {
	w.normal = append(w.normal, id)
	return nil
}

func (w *selectiveMonitorWatchdog) ArmPrepared(id string) error {
	w.prepared = append(w.prepared, id)
	return nil
}

func selectiveMonitorFixture(
	t *testing.T,
) (*Manager, *selectiveMonitorBackend, *selectiveMonitorWatchdog, string) {
	t.Helper()
	b := &selectiveMonitorBackend{}
	w := &selectiveMonitorWatchdog{}
	m := testManager(t, b, w)
	ctx := context.Background()
	tx, err := m.Prepare(ctx, selectiveDesired())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Apply(ctx, tx.ID, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Confirm(tx.ID); err != nil {
		t.Fatal(err)
	}
	w.normal = nil
	w.prepared = nil
	return m, b, w, tx.ID
}

func TestSelectiveCompletedEmergencyMonitorRepairsOnlyGuardsAndFencesEpoch(t *testing.T) {
	m, b, _, id := selectiveMonitorFixture(t)
	ctx := context.Background()
	if err := m.SelectiveEmergency(ctx); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(m.dir, "transaction.json"))
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 3; index++ {
		if watch, err := m.WatchSelectiveOnceFor(ctx, id); err != nil || !watch {
			t.Fatal("completed emergency stopped monitoring", watch, err)
		}
	}
	after, err := os.ReadFile(filepath.Join(m.dir, "transaction.json"))
	if err != nil || string(before) != string(after) || b.emergencies != 1 || b.ensures != 3 {
		t.Fatal("steady guard repair rewrote recovery or journal", b.emergencies, b.ensures, err)
	}
	if watch, err := m.WatchSelectiveOnceFor(
		ctx,
		strings.Repeat("f", 32),
	); err != nil || watch ||
		b.ensures != 3 {
		t.Fatal("old monitor crossed transaction fence", watch, err)
	}
	b.ensureErr = errors.New("missing or foreign guard")
	if watch, err := m.WatchSelectiveOnceFor(ctx, id); !watch || !errors.Is(err, b.ensureErr) {
		t.Fatal("guard repair failure hidden", watch, err)
	}
	for round := 0; round < 3; round++ {
		if err = m.SelectiveEmergencyFor(ctx, id); err != nil || b.emergencies != 1 {
			t.Fatal("completed recovery was replayed after a guard failure", b.emergencies, err)
		}
	}
	after, err = os.ReadFile(filepath.Join(m.dir, "transaction.json"))
	if err != nil || string(before) != string(after) {
		t.Fatal("completed recovery retry rewrote its journal", err)
	}
	if err = m.locked(
		func(s *State) error { s.MaintenanceHold = true; return m.save(s) },
	); err != nil {
		t.Fatal(err)
	}
	beforeCount := b.ensures
	if watch, err := m.WatchSelectiveOnceFor(
		ctx,
		id,
	); err != nil || watch ||
		b.ensures != beforeCount {
		t.Fatal("explicit maintenance hold was repaired as direct", watch, err)
	}
}

func TestSelectiveEmergencyPrepareKeepsIndependentMonitor(t *testing.T) {
	m, b, w, old := selectiveMonitorFixture(t)
	ctx := context.Background()
	if err := m.SelectiveEmergency(ctx); err != nil {
		t.Fatal(err)
	}
	tx, err := m.Prepare(ctx, selectiveDesired())
	if err != nil {
		t.Fatal(err)
	}
	if len(w.prepared) != 1 || w.prepared[0] != tx.ID {
		t.Fatal("emergency prepare left guards unmonitored", w.prepared)
	}
	if watch, err := m.WatchSelectiveOnceFor(ctx, old); err != nil || watch {
		t.Fatal("old monitor survived replacement", watch, err)
	}
	if watch, err := m.WatchSelectiveOnceFor(ctx, tx.ID); err != nil || !watch || b.ensures != 1 {
		t.Fatal("prepared monitor did not retain emergency guards", watch, err)
	}
	if err = m.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	if len(w.prepared) != 2 || len(w.normal) != 0 {
		t.Fatal("prepared restart used incorrect monitor mode")
	}
}

func TestSelectiveResumeMonitorsCompletedStatesAndSkipsHolds(t *testing.T) {
	for _, state := range []string{"confirmed", "rolled-back", "failed", "prepared"} {
		t.Run(state, func(t *testing.T) {
			m, _, w, id := selectiveMonitorFixture(t)
			ctx := context.Background()
			if err := m.locked(
				func(s *State) error { s.Transaction.State = state; s.SelectiveEmergency = true; return m.save(s) },
			); err != nil {
				t.Fatal(err)
			}
			if err := m.Resume(ctx); err != nil {
				t.Fatal(err)
			}
			calls := w.normal
			if state == "prepared" {
				calls = w.prepared
			}
			if len(calls) != 1 || calls[0] != id {
				t.Fatal("completed selective state was not resumed", calls)
			}
			if err := m.locked(
				func(s *State) error { s.MaintenanceHold = true; return m.save(s) },
			); err != nil {
				t.Fatal(err)
			}
			if err := m.Resume(ctx); err != nil {
				t.Fatal(err)
			}
			if len(w.normal)+len(w.prepared) != 1 {
				t.Fatal("maintenance hold rearmed direct monitoring")
			}
		})
	}
	m, _, w, _ := selectiveMonitorFixture(t)
	if err := m.Resume(context.Background()); err != nil || len(w.normal) != 1 {
		t.Fatal("healthy confirmed classifier was not monitored", err)
	}
}

func TestWatchdogLeaseRetainsOwnerAndSeparatesPreparedHandoff(t *testing.T) {
	m, _, _, id := selectiveMonitorFixture(t)
	active, owner, err := m.WatchdogLease(id, false)
	if err != nil || !owner {
		t.Fatal(owner, err)
	}
	duplicate, owner, err := m.WatchdogLease(id, false)
	if err != nil || owner || duplicate != nil {
		t.Fatal("duplicate watchdog acquired held descriptor", owner, err)
	}
	prepared, owner, err := m.WatchdogLease(id, true)
	if err != nil || !owner {
		t.Fatal("apply/prepared handoff shared a lease", owner, err)
	}
	next, owner, err := m.WatchdogLease(strings.Repeat("a", 32), false)
	if err != nil || !owner {
		t.Fatal("future journal monitor could not acknowledge before commit", owner, err)
	}
	if err = active.Close(); err != nil {
		t.Fatal(err)
	}
	replacement, owner, err := m.WatchdogLease(id, false)
	if err != nil || !owner {
		t.Fatal("released owner could not be replaced", owner, err)
	}
	for _, lease := range []interface{ Close() error }{prepared, next, replacement} {
		if err = lease.Close(); err != nil {
			t.Fatal(err)
		}
	}
	files, err := filepath.Glob(filepath.Join(m.dir, ".watchdog-*.lock"))
	if err != nil || len(files) != 0 {
		t.Fatal("completed monitors left unbounded lease files", files, err)
	}
	if _, _, err = m.WatchdogLease("../unsafe", false); err == nil {
		t.Fatal("unsafe lease identity accepted")
	}
}

func TestWatchdogLeaseRejectsContenderOpenedBeforeOwnerUnlink(t *testing.T) {
	m, _, _, id := selectiveMonitorFixture(t)
	owner, owned, err := m.WatchdogLease(id, false)
	if err != nil || !owned {
		t.Fatal(owned, err)
	}
	path := filepath.Join(m.dir, ".watchdog-"+id+"-active.lock")
	stale, err := openPrivate(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stale.Close() }()
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	replacement, owned, err := m.WatchdogLease(id, false)
	if err != nil || !owned {
		t.Fatal(owned, err)
	}
	defer func() { _ = replacement.Close() }()
	if owned, err = lockCurrentWatchdogFile(
		stale,
	); owned ||
		!errors.Is(err, errWatchdogLeaseReplaced) {
		t.Fatal("unlinked inode acknowledged a second monitor", owned, err)
	}
	if duplicate, owned, err := m.WatchdogLease(
		id,
		false,
	); owned || err != nil ||
		duplicate != nil {
		t.Fatal("replacement owner was not retained", owned, err)
	}
	if err = replacement.Close(); err != nil {
		t.Fatal(err)
	}
	if owned, err = lockCurrentWatchdogFile(
		stale,
	); owned ||
		!errors.Is(err, errWatchdogLeaseReplaced) {
		t.Fatal("missing pathname acknowledged stale descriptor", owned, err)
	}
}

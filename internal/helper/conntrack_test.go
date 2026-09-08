package helper

import (
	"context"
	"errors"
	"testing"
	"time"
)

type resetBackend struct {
	memoryBackend
	checkReset  error
	failReset   bool
	slots       []uint16
	beforeReset func()
}

func (b *resetBackend) CheckFlowReset(context.Context) error { return b.checkReset }
func (b *resetBackend) ResetFlowTracking(_ context.Context, slot uint16) error {
	if b.beforeReset != nil {
		b.beforeReset()
	}
	b.slots = append(b.slots, slot)
	if b.failReset {
		return errors.New("injected reset failure")
	}
	return nil
}

func applyAndConfirm(t *testing.T, m *Manager, selected string, reset bool) Transaction {
	t.Helper()
	d := testDesired()
	d.Selected, d.BreakExisting = selected, reset
	x, err := m.Prepare(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Apply(context.Background(), x.ID, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	x, err = m.Confirm(x.ID)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func TestFlowResetOptInPreviousOnlyAndDurableFailure(t *testing.T) {
	b := &resetBackend{}
	m := testManager(t, b, &testWatchdog{})
	applyAndConfirm(t, m, "a", true)
	if len(b.slots) != 0 {
		t.Fatal("initial configuration reset unrelated tracking")
	}
	applyAndConfirm(t, m, "b", false)
	if len(b.slots) != 0 {
		t.Fatal("default behavior reset existing tracking")
	}
	applyAndConfirm(t, m, "b", true)
	if len(b.slots) != 0 {
		t.Fatal("unchanged source reset its own tracking")
	}
	b.failReset = true
	b.beforeReset = func() {
		s, err := m.read()
		if err != nil || s.Committed == nil || s.Committed.Selected != "a" ||
			s.Transaction.State != "confirmed" || s.Transaction.FlowTermination != "pending" {
			t.Fatal("reset preceded durable routing confirmation", s, err)
		}
	}
	x := applyAndConfirm(t, m, "a", true)
	if x.State != "confirmed" || x.FlowTermination != "failed" ||
		x.ErrorCode != "conntrack_delete_failed" ||
		len(b.slots) != 1 ||
		b.slots[0] != 2 {
		t.Fatal(x, b.slots)
	}
	// A duplicate confirmation explicitly retries a failure; completed work never repeats.
	b.failReset = false
	x, err := m.Confirm(x.ID)
	if err != nil || x.FlowTermination != "completed" || x.ErrorCode != "" {
		t.Fatal(x, err)
	}
	if _, err = m.Confirm(x.ID); err != nil || len(b.slots) != 2 {
		t.Fatal(b.slots, err)
	}
}

func TestFlowResetPreflightAndRollback(t *testing.T) {
	for _, b := range []Backend{&memoryBackend{}, &resetBackend{checkReset: errors.New("capability_unavailable")}} {
		m := testManager(t, b, &testWatchdog{})
		d := testDesired()
		d.BreakExisting = true
		if _, err := m.Prepare(context.Background(), d); err == nil {
			t.Fatal("missing dependency accepted")
		}
		s, err := m.Status()
		if err != nil || s.Transaction != nil {
			t.Fatal("preflight wrote a transaction", s, err)
		}
	}
	b := &resetBackend{}
	m := testManager(t, b, &testWatchdog{})
	applyAndConfirm(t, m, "a", true)
	d := testDesired()
	d.Selected, d.BreakExisting = "b", true
	x, err := m.Prepare(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Apply(context.Background(), x.ID, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Rollback(context.Background(), x.ID); err != nil {
		t.Fatal(err)
	}
	if len(b.slots) != 0 {
		t.Fatal("unconfirmed/rolled-back routing reset tracking")
	}
}

func TestFlowResetPendingSurvivesRestart(t *testing.T) {
	b := &resetBackend{}
	m := testManager(t, b, &testWatchdog{})
	applyAndConfirm(t, m, "a", true)
	x := applyAndConfirm(t, m, "b", true)
	// The durable point immediately before deletion, shared with real crash replay.
	if err := m.locked(func(s *State) error {
		s.Transaction.FlowTermination = "pending"
		return m.save(s)
	}); err != nil {
		t.Fatal(err)
	}
	b.slots = nil
	restarted, err := NewManager(m.dir, b, &testWatchdog{})
	if err != nil {
		t.Fatal(err)
	}
	done, err := restarted.Recover(context.Background())
	if err != nil || !done || len(b.slots) != 1 || b.slots[0] != 1 {
		t.Fatal(done, err, b.slots)
	}
	s, err := restarted.Status()
	if err != nil || s.Committed.Selected != "b" || s.Transaction.ID != x.ID ||
		s.Transaction.FlowTermination != "completed" {
		t.Fatal(s, err)
	}
	if _, err = restarted.Recover(context.Background()); err != nil || len(b.slots) != 1 {
		t.Fatal(err, b.slots)
	}
}

func TestFlowResetRejectsInvalidJournalScope(t *testing.T) {
	b := &resetBackend{}
	m := testManager(t, b, &testWatchdog{})
	applyAndConfirm(t, m, "a", true)
	if err := m.locked(func(s *State) error {
		s.Transaction.FlowTermination = "pending"
		return m.save(s)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Status(); err == nil {
		t.Fatal("reset without a previous selected path accepted")
	}
	for _, slot := range []uint16{0, 251, 65535} {
		if err := (systemConntrack{}).reset(context.Background(), slot); err == nil {
			t.Fatal(slot)
		}
	}
}

func TestOldFlowResetRetryCannotDeleteNewCurrentSource(t *testing.T) {
	b := &resetBackend{}
	m := testManager(t, b, &testWatchdog{})
	applyAndConfirm(t, m, "a", true)
	b.failReset = true
	old := applyAndConfirm(t, m, "b", true)
	b.failReset = false
	applyAndConfirm(t, m, "a", true)
	calls := len(b.slots)
	if _, err := m.Confirm(old.ID); err == nil || len(b.slots) != calls {
		t.Fatal("old retry reset current source", err, b.slots)
	}
}

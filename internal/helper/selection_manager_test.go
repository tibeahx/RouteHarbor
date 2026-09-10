package helper

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/dataplane"
)

type selectionMemoryBackend struct {
	memoryBackend
	selected          []dataplane.Plan
	selectionErr      error
	checkSelectionErr error
	crash             bool
}

func (b *selectionMemoryBackend) CheckSelection(
	_ context.Context,
	next, previous dataplane.Plan,
) error {
	if b.checkSelectionErr != nil {
		return b.checkSelectionErr
	}
	_, err := dataplane.SelectionNFT(previous.Desired, next.Desired)
	return err
}

func (b *selectionMemoryBackend) ApplySelection(_ context.Context, next, _ dataplane.Plan) error {
	b.selected = append(b.selected, next)
	if b.crash {
		panic("simulated crash after kernel commit")
	}
	return b.selectionErr
}

func committedSelectionManager(t *testing.T) (*Manager, *selectionMemoryBackend, *testWatchdog) {
	t.Helper()
	b, w := &selectionMemoryBackend{}, &testWatchdog{}
	m := testManager(t, b, w)
	tx, err := m.Prepare(context.Background(), testDesired())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Apply(context.Background(), tx.ID, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Confirm(tx.ID); err != nil {
		t.Fatal(err)
	}
	return m, b, w
}

func TestSelectionJournalCommitsWithoutFullApply(t *testing.T) {
	m, b, w := committedSelectionManager(t)
	b.checkErr = errors.New("old retained endpoint is unavailable")
	tx, err := m.Switch(context.Background(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if tx.State != "confirmed" || tx.Kind != "selection" || tx.Previous.Selected != "a" ||
		tx.Candidate.Selected != "b" ||
		len(b.applied) != 1 ||
		len(b.selected) != 1 ||
		w.armed != 2 {
		t.Fatalf("not a single journaled selection: %+v", tx)
	}
	s, err := m.Status()
	if err != nil || s.Committed.Selected != "b" || s.Guarded {
		t.Fatal(s, err)
	}
	if _, err = m.Switch(context.Background(), "b"); err != nil || len(b.selected) != 1 {
		t.Fatal("duplicate selection mutated network", err)
	}
}

func TestSelectionAmbiguousCommitRollsBackFailClosed(t *testing.T) {
	m, b, _ := committedSelectionManager(t)
	b.selectionErr = errors.New("timeout after kernel committed")
	tx, err := m.Switch(context.Background(), "b")
	if err == nil || tx.State != "rolled-back" || len(b.selected) != 1 || len(b.applied) != 2 {
		t.Fatal(tx, err)
	}
	s, err := m.Status()
	if err != nil || !s.Guarded || s.Committed.Selected != "" || s.Committed.Fallback != "closed" {
		t.Fatal(s, err)
	}
}

func TestSelectionCrashJournalRecoversInNewManager(t *testing.T) {
	m, b, _ := committedSelectionManager(t)
	b.crash = true
	func() {
		defer func() {
			if recover() == nil {
				t.Error("crash was not injected")
			}
		}()
		_, _ = m.Switch(context.Background(), "b")
	}()
	fresh, err := NewManager(m.dir, b, nil)
	if err != nil {
		t.Fatal(err)
	}
	fresh.now = func() time.Time { return time.Now().Add(time.Minute) }
	if done, err := fresh.Recover(context.Background()); !done || err != nil {
		t.Fatal(done, err)
	}
	s, err := fresh.Status()
	if err != nil || s.Transaction.Kind != "selection" || s.Transaction.State != "rolled-back" ||
		s.Committed.Selected != "" {
		t.Fatal(s, err)
	}
}

func TestSelectionRequiresWatchdogAndHealthyTarget(t *testing.T) {
	for _, scenario := range []string{"watchdog", "target", "busy", "maintenance", "unknown"} {
		t.Run(scenario, func(t *testing.T) {
			m, b, w := committedSelectionManager(t)
			source := "b"
			switch scenario {
			case "watchdog":
				w.err = errors.New("could not arm")
			case "target":
				b.checkSelectionErr = errors.New("target is down")
			case "unknown":
				source = "missing"
			case "busy":
				if _, err := m.Prepare(context.Background(), testDesired()); err != nil {
					t.Fatal(err)
				}
			case "maintenance":
				if err := m.locked(
					func(s *State) error { s.MaintenanceHold = true; return m.save(s) },
				); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := m.Switch(context.Background(), source); err == nil {
				t.Fatal("unsafe switch accepted")
			}
			if len(b.selected) != 0 || len(b.applied) != 1 {
				t.Fatal("network mutated before preconditions")
			}
		})
	}
}

func TestSelectionMigrationUsesFullTransaction(t *testing.T) {
	m, b, _ := committedSelectionManager(t)
	b.checkSelectionErr = errSelectionFullApply
	tx, err := m.Switch(context.Background(), "b")
	if err != nil || tx.State != "confirmed" || tx.Kind != "" || len(b.selected) != 0 ||
		len(b.applied) != 2 {
		t.Fatal(tx, err)
	}
}

func TestSelectionRPCRefusesUnownedManagedTargetButNotFailedRetainedEngine(t *testing.T) {
	m, b, _ := committedSelectionManager(t)
	if err := m.locked(func(s *State) error {
		s.Committed.Paths = []dataplane.Path{
			{SourceID: "a", Kind: "tproxy", Slot: 1, Port: 12001, UDP: true},
			{SourceID: "b", Kind: "direct", Slot: 2},
		}
		return m.save(s)
	}); err != nil {
		t.Fatal(err)
	}
	s := &Server{Manager: m}
	if _, err := s.switchRegistered(context.Background(), "b"); err != nil {
		t.Fatal("dead retained engine blocked healthy target", err)
	}
	if len(b.selected) != 1 {
		t.Fatal("selection was not applied")
	}
	if _, err := s.switchRegistered(
		context.Background(),
		"a",
	); err == nil ||
		!strings.Contains(err.Error(), "engine_input_unowned") {
		t.Fatal("unowned target accepted", err)
	}
}

func TestSelectionChainOwnershipUsesOnlyStructuralComment(t *testing.T) {
	good := "table inet routeharbor {\n chain select_flow {\n comment \"RouteHarbor classifier v1\"\n ct mark set 1\n }\n}\n"
	if !selectionChainOwnedText([]byte(good)) {
		t.Fatal("owned chain rejected")
	}
	for _, bad := range []string{
		strings.Replace(good, "chain select_flow", "chain other", 1),
		strings.Replace(good, "comment \"RouteHarbor", "counter comment \"RouteHarbor", 1),
		strings.Replace(good, "table inet routeharbor", "table inet foreign", 1),
		strings.Replace(good, "classifier v1", "classifier v2", 1),
	} {
		if selectionChainOwnedText([]byte(bad)) {
			t.Fatal("foreign rule comment authorized selection", bad)
		}
	}
}

package helper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/dataplane"
	"github.com/tibeahx/RouteHarbor/internal/model"
)

type memoryBackend struct {
	mu       sync.Mutex
	applied  []dataplane.Plan
	failNext bool
	checkErr error
}

func (b *memoryBackend) Check(context.Context, dataplane.Plan) error {
	return b.checkErr
}

func (b *memoryBackend) Apply(_ context.Context, p dataplane.Plan, _ *dataplane.Plan) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failNext {
		b.failNext = false
		return errors.New("injected failure")
	}
	b.applied = append(b.applied, p)
	return nil
}

type testWatchdog struct {
	err   error
	armed int
}

func (w *testWatchdog) ArmPrepared(string) error { w.armed++; return w.err }

func (w *testWatchdog) Arm(string) error {
	w.armed++
	return w.err
}

func testDesired() dataplane.Desired {
	return dataplane.Desired{
		Network: model.Network{
			Enabled:       true,
			LANInterfaces: []string{"home0"},
			WANInterface:  "outside0",
			LocalPrefixes: []string{"10.44.0.0/24"},
			IPv6:          "block",
			DNS:           "block",
		},
		Paths: []dataplane.Path{
			{SourceID: "a", Kind: "direct", Slot: 1},
			{SourceID: "b", Kind: "direct", Slot: 2},
		},
		Selected: "a",
		Fallback: "closed",
	}
}

func testManager(t *testing.T, b Backend, w Watchdog) *Manager {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	m, e := NewManager(dir, b, w)
	if e != nil {
		t.Fatal(e)
	}
	return m
}

func TestCrashRecoverySurvivesNewManager(t *testing.T) {
	b := &memoryBackend{}
	w := &testWatchdog{}
	m := testManager(t, b, w)
	now := time.Now().UTC()
	m.now = func() time.Time { return now }
	tx, e := m.Prepare(context.Background(), testDesired())
	if e != nil {
		t.Fatal(e)
	}
	tx, e = m.Apply(context.Background(), tx.ID, 30*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if tx.State != "applied" || w.armed != 1 {
		t.Fatal(tx)
	}
	// A new process has no in-memory transaction state and reconstructs the policy.
	restarted, e := NewManager(m.dir, b, nil)
	if e != nil {
		t.Fatal(e)
	}
	restarted.now = func() time.Time { return now.Add(time.Minute) }
	done, e := restarted.Recover(context.Background())
	if e != nil || !done {
		t.Fatal(done, e)
	}
	s, e := restarted.Status()
	if e != nil {
		t.Fatal(e)
	}
	if s.Transaction.State != "rolled-back" || s.Committed.Selected != "" {
		t.Fatalf("unsafe recovery %+v", s)
	}
	if b.applied[len(b.applied)-1].Desired.Fallback != "closed" {
		t.Fatal("rollback changed policy")
	}
}

func TestNoMutationBeforeIndependentWatchdogReady(t *testing.T) {
	b := &memoryBackend{}
	m := testManager(t, b, &testWatchdog{err: errors.New("process failed")})
	tx, e := m.Prepare(context.Background(), testDesired())
	if e != nil {
		t.Fatal(e)
	}
	_, e = m.Apply(context.Background(), tx.ID, 30*time.Second)
	if e == nil || len(b.applied) != 0 {
		t.Fatal("network changed without watchdog")
	}
}

func TestApplyFailureRollsBackToSafeState(t *testing.T) {
	b := &memoryBackend{failNext: true}
	m := testManager(t, b, &testWatchdog{})
	tx, e := m.Prepare(context.Background(), testDesired())
	if e != nil {
		t.Fatal(e)
	}
	tx, e = m.Apply(context.Background(), tx.ID, 30*time.Second)
	if e == nil || tx.State != "rolled-back" {
		t.Fatal(tx, e)
	}
	if len(b.applied) != 1 || b.applied[0].Desired.Selected != "" {
		t.Fatal("safe rollback missing")
	}
}

func TestPendingTransactionSerializedAndConfirmIdempotent(t *testing.T) {
	m := testManager(t, &memoryBackend{}, &testWatchdog{})
	tx, e := m.Prepare(context.Background(), testDesired())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.Prepare(context.Background(), testDesired()); !errors.Is(e, ErrBusy) {
		t.Fatal(e)
	}
	if _, e = m.Confirm(tx.ID); e == nil {
		t.Fatal("confirmed before apply")
	}
	if _, e = m.Apply(context.Background(), tx.ID, 30*time.Second); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		tx, e = m.Confirm(tx.ID)
		if e != nil || tx.State != "confirmed" {
			t.Fatal(tx, e)
		}
	}
}

func TestJournalSymlinkAndUnknownVersionRejected(t *testing.T) {
	m := testManager(t, &memoryBackend{}, nil)
	foreign := filepath.Join(t.TempDir(), "foreign")
	if e := os.WriteFile(foreign, []byte(`{"version":1}`), 0o600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(foreign, filepath.Join(m.dir, "transaction.json")); e != nil {
		t.Fatal(e)
	}
	if _, e := m.Status(); e == nil {
		t.Fatal("followed journal symlink")
	}
	if err := os.Remove(filepath.Join(m.dir, "transaction.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(m.dir, "transaction.json"),
		[]byte(`{"version":99}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, e := m.Status(); e == nil {
		t.Fatal("accepted unknown schema")
	}
}

func TestConfirmedSlotsCannotBeReassigned(t *testing.T) {
	m := testManager(t, &memoryBackend{}, &testWatchdog{})
	d := testDesired()
	tx, err := m.Prepare(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Apply(context.Background(), tx.ID, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Confirm(tx.ID); err != nil {
		t.Fatal(err)
	}
	d.Paths[0].SourceID = "hijack"
	d.Selected = "hijack"
	if _, e := m.Prepare(
		context.Background(),
		d,
	); e == nil ||
		!strings.Contains(e.Error(), "allocation_conflict") {
		t.Fatal(e)
	}
}

func TestStrictHelperPayloads(t *testing.T) {
	for _, body := range []string{`{"operation":"status","command":"reboot"}`, `{"operation":"status","operation":"apply"}`, `{"operation":"status"} {}`, `{"operation":"run","address":"/etc/shadow"}`, `{"operation":"apply","transaction_id":"../../etc/shadow"}`, `{"operation":"status","source_id":"x"}`, `{"operation":"start_packet","source_id":"x","slot":65535}`} {
		var req Request
		e := DecodeStrict([]byte(body), &req)
		if e == nil {
			e = validateRequest(req)
		}
		if e == nil {
			t.Errorf("accepted %s", body)
		}
	}
}

func TestAppliedLANGuardOrderCannotBeReassigned(t *testing.T) {
	m := testManager(t, &memoryBackend{}, &testWatchdog{})
	d := testDesired()
	d.Network.LANInterfaces = []string{"home0", "home1"}
	tx, err := m.Prepare(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Apply(context.Background(), tx.ID, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Confirm(tx.ID); err != nil {
		t.Fatal(err)
	}
	for _, devices := range [][]string{{"home1", "home0"}, {"home0"}, {"home0", "home1", "home2"}} {
		d.Network.LANInterfaces = devices
		if _, err = m.Prepare(
			context.Background(),
			d,
		); err == nil ||
			!strings.Contains(err.Error(), "active_lan_change") {
			t.Fatalf("guard priority reassignment was accepted: %v", err)
		}
	}
}

func TestRecoverySafetyOwnershipDoesNotAcceptMarkedForeignRule(t *testing.T) {
	p, err := dataplane.Compile(testDesired())
	if err != nil {
		t.Fatal(err)
	}
	rule := ipRule{Priority: 30000, Table: []byte(`20999`), IIF: "home0"}
	if !safetyRuleAllowed(rule, &p) {
		t.Fatal("owned rule rejected")
	}
	rule.FWMark = []byte(`123`)
	if safetyRuleAllowed(rule, &p) {
		t.Fatal("foreign marked rule accepted as catch-all guard")
	}
}

func TestProbeSSRFAddresses(t *testing.T) {
	for _, address := range []string{"127.0.0.1:443", "[::1]:443", "[::ffff:127.0.0.1]:443", "10.0.0.1:80", "169.254.169.254:80", "[64:ff9b::a00:1]:80", "192.0.2.1:443", "example.com:443", "[2001:db8::1]:443", "[fe80::1%en0]:80"} {
		if _, e := validateProbeAddress(address); e == nil {
			t.Errorf("accepted %s", address)
		}
	}
	if _, e := validateProbeAddress("8.8.8.8:443"); e != nil {
		t.Fatal(e)
	}
}

func FuzzHelperDecoder(f *testing.F) {
	f.Add([]byte(`{"operation":"status"}`))
	f.Add([]byte(`{"operation":"status","operation":"apply"}`))
	f.Fuzz(func(t *testing.T, b []byte) { var req Request; _ = DecodeStrict(b, &req) })
}

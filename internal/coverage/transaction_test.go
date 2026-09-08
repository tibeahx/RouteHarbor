package coverage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixtureBackend struct {
	wifi                 WiFi
	applied, restored    int
	applyErr, restoreErr bool
}

func (b *fixtureBackend) Inspect(
	context.Context,
) (Setup, error) {
	return Setup{Managed: true}, nil
}

func (b *fixtureBackend) Check(context.Context, Plan) (WiFi, error) {
	return b.wifi, nil
}

func (b *fixtureBackend) Snapshot(_ context.Context, p Plan) (Snapshot, error) {
	data, err := json.Marshal(wirelessSnapshot{APSection: p.APSection})
	return Snapshot{"wireless": data}, err
}

func (b *fixtureBackend) Apply(context.Context, Plan) error {
	b.applied++
	if b.applyErr {
		return errors.New("private backend failure")
	}
	return nil
}

func (b *fixtureBackend) Restore(context.Context, Snapshot) error {
	b.restored++
	if b.restoreErr {
		return errors.New("private restore failure")
	}
	return nil
}

type fixtureWatchdog struct {
	armed int
	fail  bool
}

func (w *fixtureWatchdog) Arm(string) error {
	w.armed++
	if w.fail {
		return errors.New("fixture arm failure")
	}
	return nil
}

func validPlan() Plan {
	return Plan{
		Mode:                   "wds",
		APSection:              "main_ap",
		Network:                "lan",
		PeerFingerprint:        strings.Repeat("a", 64),
		AdoptExistingAP:        true,
		PreserveManagementPath: true,
	}
}

func managerFixture(t *testing.T) (*Manager, *fixtureBackend, *fixtureWatchdog, string) {
	t.Helper()
	dir := t.TempDir()
	b := &fixtureBackend{
		wifi: WiFi{SSID: "Existing home", Passphrase: "canary-private-gateway-key", Channel: 6},
	}
	w := &fixtureWatchdog{}
	m, err := NewManager(dir, b, w)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m, b, w, dir
}

func preparedFixture(t *testing.T, m *Manager) Transaction {
	t.Helper()
	tx, err := m.Prepare(context.Background(), "fixture-prepare-0001", validPlan())
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func appliedFixture(t *testing.T, m *Manager) Transaction {
	t.Helper()
	tx := preparedFixture(t, m)
	tx, err := m.Apply(context.Background(), tx.ID, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func TestConfirmRetainsCompensationUntilFinalize(t *testing.T) {
	ctx := context.Background()
	m, b, w, dir := managerFixture(t)
	tx := appliedFixture(t, m)
	if w.armed != 1 || b.applied != 1 {
		t.Fatal("write happened without independent watchdog")
	}
	if _, err := m.Confirm(ctx, tx.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.CanRemove(); err == nil {
		t.Fatal("confirmed compensation discarded before finalization")
	}
	m.now = func() time.Time { return tx.Deadline.Add(time.Hour) }
	if done, err := m.Recover(ctx); err != nil || !done || b.restored != 0 {
		t.Fatal("confirmed gateway rolled back behind confirmed node")
	}
	reopened, err := NewManager(dir, b, w)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	if _, err := reopened.Rollback(ctx, tx.ID); err != nil {
		t.Fatal(err)
	}
	if b.restored != 1 {
		t.Fatal("restart lost confirmed compensation")
	}
	if err := reopened.CanRemove(); err != nil {
		t.Fatal(err)
	}
}

func TestFinalizeAndConfirmReplayAfterLostResponse(t *testing.T) {
	ctx := context.Background()
	m, b, _, dir := managerFixture(t)
	tx := appliedFixture(t, m)
	if _, err := m.Confirm(ctx, tx.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Finalize(tx.ID); err != nil {
		t.Fatal(err)
	}
	if out, err := m.Confirm(ctx, tx.ID); err != nil || out.State != "finalized" {
		t.Fatal("lost finalize response cannot reconcile", err)
	}
	if _, err := m.Finalize(tx.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Rollback(ctx, tx.ID); err == nil || b.restored != 0 {
		t.Fatal("finalized transaction remained reversible")
	}
	data, err := os.ReadFile(filepath.Join(dir, "transaction.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), b.wifi.Passphrase) ||
		strings.Contains(string(data), "gateway_wifi") ||
		strings.Contains(string(data), "snapshot") {
		t.Fatal("finalized journal retained private material")
	}
	if err := m.CanRemove(); err != nil {
		t.Fatal(err)
	}
}

func TestExpiredTransactionRestoresAcrossRestartAndRetries(t *testing.T) {
	ctx := context.Background()
	m, b, w, dir := managerFixture(t)
	tx := appliedFixture(t, m)
	reopened, err := NewManager(dir, b, w)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	reopened.now = func() time.Time { return tx.Deadline }
	if err := reopened.Resume(); err != nil || w.armed != 2 {
		t.Fatal("helper restart did not rearm")
	}
	b.restoreErr = true
	if _, err := reopened.Recover(ctx); err == nil {
		t.Fatal("restore failure ignored")
	}
	if err := reopened.CanRemove(); err == nil {
		t.Fatal("unresolved rollback permitted uninstall")
	}
	b.restoreErr = false
	if done, err := reopened.Recover(ctx); err != nil || !done || b.restored != 2 {
		t.Fatal("durable rollback retry failed", err)
	}
}

func TestNoMutationWithoutWatchdogOrStableCredentials(t *testing.T) {
	for _, mode := range []string{"no-watchdog", "broken-watchdog", "changed-password", "changed-ssid", "changed-channel"} {
		t.Run(mode, func(t *testing.T) {
			m, b, w, _ := managerFixture(t)
			tx := preparedFixture(t, m)
			switch mode {
			case "no-watchdog":
				m.watchdog = nil
			case "broken-watchdog":
				w.fail = true
			case "changed-password":
				b.wifi.Passphrase = "different-private-key"
			case "changed-ssid":
				b.wifi.SSID = "changed"
			case "changed-channel":
				b.wifi.Channel = 11
			}
			if _, err := m.Apply(
				context.Background(),
				tx.ID,
				30*time.Second,
			); err == nil ||
				b.applied != 0 {
				t.Fatal("unsafe apply")
			}
		})
	}
}

func TestApplyFailureCompensatesAndPublicStatusHidesKey(t *testing.T) {
	ctx := context.Background()
	m, b, _, _ := managerFixture(t)
	tx := preparedFixture(t, m)
	status, err := m.Status()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), b.wifi.Passphrase) ||
		strings.Contains(string(data), "node_wifi") {
		t.Fatal("private Wi-Fi in ordinary status")
	}
	b.applyErr = true
	if _, err := m.Apply(
		ctx,
		tx.ID,
		30*time.Second,
	); err == nil || strings.Contains(err.Error(), "private") ||
		b.restored != 1 {
		t.Fatal("apply did not compensate safely")
	}
}

func TestPrepareCASAndStrictJournal(t *testing.T) {
	m, _, _, dir := managerFixture(t)
	tx := preparedFixture(t, m)
	if repeat, err := m.Prepare(
		context.Background(),
		"fixture-prepare-0001",
		validPlan(),
	); err != nil ||
		repeat.ID != tx.ID {
		t.Fatal("idempotency lost")
	}
	p := validPlan()
	p.Mode = "mesh"
	if _, err := m.Prepare(context.Background(), "fixture-prepare-0001", p); err == nil {
		t.Fatal("conflicting replay accepted")
	}
	if _, err := m.Prepare(context.Background(), "fixture-prepare-0002", p); err == nil {
		t.Fatal("parallel prepare accepted")
	}
	data, err := os.ReadFile(filepath.Join(dir, "transaction.json"))
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string][]byte{
		"duplicate": append([]byte(`{"version":1,`), data[1:]...),
		"role":      []byte(strings.Replace(string(data), "gateway-backhaul", "node", 1)),
		"snapshot": []byte(
			strings.Replace(string(data), `"ap_section":"main_ap"`, `"ap_section":"foreign_ap"`, 1),
		),
		"unknown": append(data[:len(data)-1], []byte(`,"unknown":true}`)...),
	}
	for name, bad := range mutations {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(dir, "transaction.json"), bad, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := m.Status(); err == nil {
				t.Fatal("invalid journal accepted")
			}
		})
	}
}

func TestOperationAllowlist(t *testing.T) {
	p := validPlan()
	id := strings.Repeat("a", 32)
	for _, op := range []Operation{{Action: "shell", ID: id}, {Action: "inspect", ID: id}, {Action: "status", Key: "bad"}, {Action: "prepare", Plan: &p, Key: "short"}, {Action: "apply", ID: id, TimeoutSeconds: 29}, {Action: "confirm", ID: id, Plan: &p}, {Action: "validate", Plan: &p, Key: "notallowed-key00"}} {
		if ValidateOperation(op) == nil {
			t.Fatalf("accepted invalid operation: %+v", op)
		}
	}
	for _, op := range []Operation{{Action: "inspect"}, {Action: "status"}, {Action: "prepare", Plan: &p, Key: "fixture-prepare-0001"}, {Action: "validate", Plan: &p}, {Action: "apply", ID: id, TimeoutSeconds: 30}, {Action: "confirm", ID: id}, {Action: "finalize", ID: id}} {
		if err := ValidateOperation(op); err != nil {
			t.Fatal(err)
		}
	}
}

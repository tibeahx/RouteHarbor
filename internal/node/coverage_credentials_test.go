package node

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/tibeahx/RouteHarbor/internal/coverage"
)

// The real gateway and node transaction managers are used; only the gateway's
// OpenWrt configuration effects are injected. The separate administrator key
// change is outside RouteHarbor's gateway snapshot and compensation scope.
type credentialsBackend struct {
	mu   sync.Mutex
	wifi coverage.WiFi
}

func (b *credentialsBackend) Inspect(context.Context) (coverage.Setup, error) {
	return coverage.Setup{Managed: true}, nil
}

func (b *credentialsBackend) Check(context.Context, coverage.Plan) (coverage.WiFi, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.wifi, nil
}

func (b *credentialsBackend) Snapshot(
	_ context.Context,
	p coverage.Plan,
) (coverage.Snapshot, error) {
	data, err := json.Marshal(map[string]any{
		"ap_section": p.APSection, "wds": nil, "wds_owner": nil, "mesh": nil,
	})
	return coverage.Snapshot{"wireless": data}, err
}

func (b *credentialsBackend) Apply(context.Context, coverage.Plan) error { return nil }

func (b *credentialsBackend) Restore(context.Context, coverage.Snapshot) error { return nil }

func TestFreshCoveragePreparationSynchronizesSeparatelyChangedHomeKey(t *testing.T) {
	backend := &credentialsBackend{
		wifi: coverage.WiFi{SSID: "Home", Passphrase: coverageCanary, Channel: 6},
	}
	gateway, err := coverage.NewManager(t.TempDir(), backend, fakeWatchdog{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := gateway.Close(); err != nil {
			t.Error(err)
		}
	})
	f := newCoverageFixture(t)
	f.service.coverageMu.Lock()
	f.service.gatewayOperator = gateway
	f.service.coverageMu.Unlock()
	original := f.prepare(t)
	if _, err = f.action("apply", original.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.action("confirm", original.ID); err != nil {
		t.Fatal(err)
	}

	const replacement = "SEPARATE-ADMIN-HOME-KEY-CANARY"
	backend.mu.Lock()
	backend.wifi.Passphrase = replacement
	backend.mu.Unlock()
	// Replaying the old logical request is deliberately not a key rotation.
	if replay := f.prepare(t); replay.ID != original.ID || replay.State != "confirmed" {
		t.Fatal("old idempotency key silently started a credential change")
	}
	request := coverageOperation{
		Key: "explicit-home-key-sync-123456", Plan: &f.plan,
		GatewayPlan: &f.gatewayPlan,
	}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.service.Operate(context.Background(), f.nodeID, "prepare", raw)
	if err != nil {
		t.Fatal(err)
	}
	transaction := result["transaction"].(coverageTransaction)
	if transaction.ID == original.ID || transaction.State != "prepared" {
		t.Fatal("fresh synchronization did not create its own transaction")
	}
	public, err := json.Marshal(result)
	if err != nil || strings.Contains(string(public), replacement) ||
		strings.Contains(string(public), coverageCanary) {
		t.Fatal("private credential escaped preparation", err)
	}
	if err = f.manager.locked(func(j *journal) error {
		if j.Transaction == nil || j.Transaction.Plan.Passphrase != replacement {
			return errors.New("node did not receive current gateway credential")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.action("apply", transaction.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.action("confirm", transaction.ID); err != nil {
		t.Fatal(err)
	}
	if err = f.manager.locked(func(j *journal) error {
		if j.Transaction == nil || j.Transaction.State != "confirmed" ||
			j.Transaction.Plan.Passphrase != "" {
			return errors.New("confirmed node retained private credential")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

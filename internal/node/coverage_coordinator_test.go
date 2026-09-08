package node

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const coverageCanary = "COVERAGE-WIFI-PRIVATE-CANARY"

type coverageEvents struct {
	mu     sync.Mutex
	values []string
}

func (e *coverageEvents) add(value string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.values = append(e.values, value)
}

func (e *coverageEvents) actions() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.values...)
}

type coverageGatewayFixture struct {
	mu           sync.Mutex
	transaction  GatewayTransaction
	events       *coverageEvents
	failAction   string
	loseFinalize bool
}

func (g *coverageGatewayFixture) Do(
	_ context.Context,
	op GatewayOperation,
) (map[string]any, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failAction == op.Action {
		return nil, errors.New("gateway fixture failure")
	}
	wifi := GatewayWiFi{SSID: "Home", Passphrase: coverageCanary, Channel: 6}
	switch op.Action {
	case "inspect":
		return map[string]any{"gateway_setup": map[string]any{"managed": true}}, nil
	case "validate":
		return map[string]any{"node_wifi": wifi, "transaction": g.transaction}, nil
	case "prepare":
		if g.transaction.ID == "" {
			g.transaction = GatewayTransaction{
				ID:    strings.Repeat("a", 32),
				State: "prepared",
				Plan:  *op.Plan,
			}
		}
		return map[string]any{"node_wifi": wifi, "transaction": g.transaction}, nil
	case "apply":
		g.events.add("gateway-apply")
		g.transaction.State = "applied"
		g.transaction.Deadline = time.Now().Add(time.Duration(op.TimeoutSeconds) * time.Second)
	case "confirm":
		if g.transaction.State == "finalized" {
			return map[string]any{"transaction": g.transaction}, nil
		}
		if g.transaction.State == "rolled-back" {
			return nil, errors.New("expired")
		}
		g.events.add("gateway-confirm")
		g.transaction.State = "confirmed"
		g.transaction.Deadline = time.Time{}
	case "finalize":
		g.events.add("gateway-finalize")
		g.transaction.State = "finalized"
		if g.loseFinalize {
			g.loseFinalize = false
			return nil, errors.New("lost finalization response")
		}
	case "rollback":
		g.events.add("gateway-rollback")
		g.transaction.State = "rolled-back"
	case "status":
	default:
		return nil, errors.New("invalid fixture operation")
	}
	return map[string]any{"transaction": g.transaction}, nil
}

type coverageNodeFixture struct {
	operator         Operator
	events           *coverageEvents
	mu               sync.Mutex
	loseConfirmation bool
	losePrepare      bool
	failConfirm      bool
	failStatus       bool
}

func (n *coverageNodeFixture) Do(ctx context.Context, op Operation) (map[string]any, error) {
	n.mu.Lock()
	fail := (op.Action == "confirm" && n.failConfirm) || (op.Action == "status" && n.failStatus)
	n.mu.Unlock()
	if fail {
		return nil, errors.New("unreachable fixture")
	}
	if op.Action == "apply" || op.Action == "confirm" || op.Action == "rollback" {
		n.events.add("node-" + op.Action)
	}
	result, err := n.operator.Do(ctx, op)
	n.mu.Lock()
	defer n.mu.Unlock()
	if op.Action == "confirm" && err == nil && n.loseConfirmation {
		n.loseConfirmation = false
		return nil, errors.New("lost confirmation response")
	}
	if op.Action == "prepare" && err == nil && n.losePrepare {
		n.losePrepare = false
		return nil, errors.New("lost prepare response")
	}
	return result, err
}

type coverageFixture struct {
	service     *Service
	gateway     *coverageGatewayFixture
	peer        *coverageNodeFixture
	manager     *Manager
	backend     *fakeBackend
	events      *coverageEvents
	nodeID      string
	dir         string
	plan        Plan
	gatewayPlan GatewayPlan
}

func newCoverageFixture(t *testing.T) *coverageFixture {
	t.Helper()
	identity, e := LoadIdentity(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	pairing, e := NewPairing(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := pairing.Close(); e != nil {
			t.Error(e)
		}
	})
	backend := &fakeBackend{}
	manager, e := NewManager(t.TempDir(), backend, fakeWatchdog{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := manager.Close(); e != nil {
			t.Error(e)
		}
	})
	events := &coverageEvents{}
	peer := &coverageNodeFixture{operator: LocalOperator{Manager: manager}, events: events}
	var gatewayFingerprint string
	agent := &Agent{
		Identity: identity,
		Pairing:  pairing,
		Capabilities: func(context.Context) Capabilities {
			c := caps()
			c.VerifiedPeerFingerprint, c.VerifiedRadio, c.VerifiedMode = gatewayFingerprint, "radio0", "wds"
			return c
		},
		Operator: peer,
	}
	server := httptest.NewUnstartedServer(agent)
	server.TLS = agent.TLSConfig()
	t.Cleanup(server.Close)
	dir := t.TempDir()
	service, e := NewService(dir, func(context.Context) Capabilities {
		c := caps()
		c.VerifiedPeerFingerprint, c.VerifiedRadio, c.VerifiedMode = identity.Fingerprint, "radio1", "wds"
		return c
	})
	if e != nil {
		t.Fatal(e)
	}
	gatewayFingerprint = service.identity.Fingerprint
	server.StartTLS()
	gateway := &coverageGatewayFixture{events: events}
	if e = service.ConfigureGateway(gateway); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := service.Close(); e != nil {
			t.Error(e)
		}
	})
	code, e := pairing.Bootstrap(time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	request, _ := json.Marshal(
		map[string]string{
			"address":     server.URL,
			"fingerprint": identity.Fingerprint,
			"code":        code,
			"name":        "Office",
		},
	)
	if _, e = service.Pair(context.Background(), request); e != nil {
		t.Fatal(e)
	}
	p := plan()
	p.Mode = "wds"
	p.Uplink = "backhaul"
	p.EthernetUplink = "port2"
	p.Radio = "radio0"
	p.ShareRadio = true
	gp := GatewayPlan{
		Mode:                   "wds",
		APSection:              "homeap",
		Network:                "home",
		PeerFingerprint:        identity.Fingerprint,
		AdoptExistingAP:        true,
		PreserveManagementPath: true,
	}
	return &coverageFixture{
		service:     service,
		gateway:     gateway,
		peer:        peer,
		manager:     manager,
		backend:     backend,
		events:      events,
		nodeID:      identity.ID,
		dir:         dir,
		plan:        p,
		gatewayPlan: gp,
	}
}

func (f *coverageFixture) prepare(t *testing.T) coverageTransaction {
	t.Helper()
	op := coverageOperation{
		Key: "paired-request-123456", Plan: &f.plan,
		GatewayPlan: &f.gatewayPlan,
	}
	raw, _ := json.Marshal(op)
	result, e := f.service.Operate(context.Background(), f.nodeID, "prepare", raw)
	if e != nil {
		t.Fatal(e)
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), coverageCanary) {
		t.Fatal("private helper Wi-Fi material reached public prepare result")
	}
	return result["transaction"].(coverageTransaction)
}

func (f *coverageFixture) action(action, id string) (map[string]any, error) {
	raw, _ := json.Marshal(Operation{ID: id, TimeoutSeconds: 90})
	return f.service.Operate(context.Background(), f.nodeID, action, raw)
}

func TestCoveragePairUsesGatewayFirstAndRedactsPrivateWiFi(t *testing.T) {
	f := newCoverageFixture(t)
	preview, _ := json.Marshal(coveragePlan{Plan: f.plan, GatewayPlan: &f.gatewayPlan})
	result, e := f.service.Plan(context.Background(), f.nodeID, preview)
	if e != nil {
		t.Fatal(e)
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), coverageCanary) {
		t.Fatal("preview leaked private Wi-Fi")
	}
	transaction := f.prepare(t)
	if _, e = f.action("apply", transaction.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = f.action("confirm", transaction.ID); e != nil {
		t.Fatal(e)
	}
	want := []string{
		"gateway-apply",
		"node-apply",
		"gateway-confirm",
		"node-confirm",
		"gateway-finalize",
	}
	if got := f.events.actions(); !reflect.DeepEqual(got, want) {
		t.Fatalf("wrong pair ordering %v", got)
	}
	stored, e := os.ReadFile(filepath.Join(f.dir, "coverage.json"))
	if e != nil || strings.Contains(string(stored), coverageCanary) {
		t.Fatal("confirmed coordinator retained private material", e)
	}
	// A subsequent ordinary Ethernet plan returns to the existing node flow.
	p := plan()
	request, _ := json.Marshal(Operation{Key: "ethernet-request-123456", Plan: &p})
	if _, e = f.service.Operate(context.Background(), f.nodeID, "prepare", request); e != nil {
		t.Fatal(e)
	}
	status, e := f.action("status", "")
	if e != nil || status["coordinated"] != nil {
		t.Fatal("Ethernet status remained attached to obsolete Wi-Fi saga", e)
	}
}

func TestCoveragePairCompensatesFailedNodeApply(t *testing.T) {
	f := newCoverageFixture(t)
	f.backend.failApply = true
	transaction := f.prepare(t)
	if _, e := f.action("apply", transaction.ID); e == nil {
		t.Fatal("node apply failure was ignored")
	}
	status, e := f.action("status", "")
	if e != nil {
		t.Fatal(e)
	}
	if status["transaction"].(coverageTransaction).State != "rolled-back" {
		t.Fatal(status)
	}
	want := []string{"gateway-apply", "node-apply", "node-rollback", "gateway-rollback"}
	if got := f.events.actions(); !reflect.DeepEqual(got, want) {
		t.Fatalf("missing compensating rollback %v", got)
	}
}

func TestCoveragePairRecoversLostNodeConfirmation(t *testing.T) {
	f := newCoverageFixture(t)
	f.peer.loseConfirmation = true
	transaction := f.prepare(t)
	if _, e := f.action("apply", transaction.ID); e != nil {
		t.Fatal(e)
	}
	result, e := f.action("confirm", transaction.ID)
	if e != nil || result["transaction"].(coverageTransaction).State != "confirmed" {
		t.Fatal("lost response caused wrong rollback", result, e)
	}
	for _, event := range f.events.actions() {
		if event == "gateway-rollback" {
			t.Fatal("gateway rolled back behind committed node")
		}
	}
}

func TestCoveragePairRestartReconcilesDurableConfirmationIntent(t *testing.T) {
	f := newCoverageFixture(t)
	transaction := f.prepare(t)
	if _, e := f.action("apply", transaction.ID); e != nil {
		t.Fatal(e)
	}
	f.peer.mu.Lock()
	f.peer.failConfirm = true
	f.peer.failStatus = true
	f.peer.mu.Unlock()
	if _, e := f.action("confirm", transaction.ID); e == nil {
		t.Fatal("unreachable node was reported confirmed")
	}
	// A new gateway service loads the persisted pair phases and identities.
	restarted, e := NewService(f.dir, func(context.Context) Capabilities { return caps() })
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := restarted.Close(); e != nil {
			t.Error(e)
		}
	})
	if e = restarted.ConfigureGateway(f.gateway); e != nil {
		t.Fatal(e)
	}
	f.peer.mu.Lock()
	f.peer.failConfirm = false
	f.peer.failStatus = false
	f.peer.mu.Unlock()
	if e = restarted.recoverCoverage(context.Background()); e != nil {
		t.Fatal(e)
	}
	j, e := restarted.loadCoverage()
	if e != nil || j.Entries[f.nodeID].Transaction.State != "confirmed" {
		t.Fatal("durable confirmation was not completed", e)
	}
}

func TestCoverageFinalizationReplayNeverRollsGatewayBackBehindConfirmedNode(t *testing.T) {
	f := newCoverageFixture(t)
	transaction := f.prepare(t)
	if _, e := f.action("apply", transaction.ID); e != nil {
		t.Fatal(e)
	}
	f.gateway.mu.Lock()
	f.gateway.loseFinalize = true
	f.gateway.mu.Unlock()
	if _, e := f.action("confirm", transaction.ID); e == nil {
		t.Fatal("lost finalization response was reported complete")
	}
	if _, e := f.action("rollback", transaction.ID); e == nil {
		t.Fatal("uncertain confirmation allowed rollback behind a committed node")
	}
	if e := f.service.recoverCoverage(context.Background()); e != nil {
		t.Fatal(e)
	}
	status, e := f.action("status", "")
	if e != nil || status["transaction"].(coverageTransaction).State != "confirmed" {
		t.Fatal("lost finalization was not reconciled", status, e)
	}
	for _, event := range f.events.actions() {
		if event == "gateway-rollback" || event == "node-rollback" {
			t.Fatal("committed pair was rolled back", f.events.actions())
		}
	}
}

func TestCoverageRevokedReceiptBlocksApplyBeforeEitherParticipantChanges(t *testing.T) {
	f := newCoverageFixture(t)
	transaction := f.prepare(t)
	original := f.service.gateway
	f.service.gateway = func(ctx context.Context) Capabilities {
		c := original(ctx)
		c.VerifiedPeerFingerprint = ""
		return c
	}
	if _, e := f.action(
		"apply",
		transaction.ID,
	); e == nil ||
		e.Error() != "wireless_pair_receipt_mismatch" {
		t.Fatal("revoked receipt enabled apply", e)
	}
	if got := f.events.actions(); len(got) != 0 {
		t.Fatal("a participant changed before current receipt verification", got)
	}
}

func TestCoveragePendingPairBlocksUnpairAndEthernetReplacement(t *testing.T) {
	f := newCoverageFixture(t)
	f.prepare(t)
	j, e := f.service.loadCoverage()
	if e != nil {
		t.Fatal(e)
	}
	for _, action := range []string{"apply", "confirm", "rollback"} {
		if _, e := f.action(action, j.Entries[f.nodeID].Node.ID); e == nil {
			t.Fatal("participant ID bypassed paired transaction ordering", action)
		}
	}
	if e := f.service.Unpair(context.Background(), f.nodeID); e == nil {
		t.Fatal("pending pair lost its trusted peer identity")
	}
	p := plan()
	raw, _ := json.Marshal(Operation{Key: "ethernet-request-123456", Plan: &p})
	if _, e := f.service.Operate(context.Background(), f.nodeID, "prepare", raw); e == nil {
		t.Fatal("Ethernet plan displaced a pending gateway pair")
	}
}

func TestCoverageCancellationRecoversLostPrepareIdentity(t *testing.T) {
	f := newCoverageFixture(t)
	f.peer.losePrepare = true
	op := coverageOperation{
		Key: "paired-request-123456", Plan: &f.plan,
		GatewayPlan: &f.gatewayPlan,
	}
	raw, _ := json.Marshal(op)
	if _, e := f.service.Operate(context.Background(), f.nodeID, "prepare", raw); e == nil {
		t.Fatal("lost prepare response reported complete")
	}
	j, e := f.service.loadCoverage()
	if e != nil {
		t.Fatal(e)
	}
	entry := j.Entries[f.nodeID]
	if entry.Node.ID != "" || entry.Transaction.State != "preparing" {
		t.Fatal("fixture did not lose participant identity")
	}
	if _, e = f.action("rollback", entry.Transaction.ID); e != nil {
		t.Fatal(e)
	}
	status, e := f.manager.Status()
	if e != nil || status["transaction"].(*Transaction).State != "rolled-back" ||
		f.backend.applies != 0 {
		t.Fatal("cancel guessed or lost the prepared node transaction", status, e)
	}
}

func TestCoverageRestartCompensatesIndependentNodeDeadline(t *testing.T) {
	f := newCoverageFixture(t)
	transaction := f.prepare(t)
	if _, e := f.action("apply", transaction.ID); e != nil {
		t.Fatal(e)
	}
	f.peer.mu.Lock()
	f.peer.failConfirm = true
	f.peer.failStatus = true
	f.peer.mu.Unlock()
	if _, e := f.action("confirm", transaction.ID); e == nil {
		t.Fatal("uncertain node confirmation was ignored")
	}
	status, e := f.action("status", "")
	if e != nil || status["gateway_setup"] == nil || status["node_issue"] == nil {
		t.Fatal("peer failure hid local gateway inspection", status, e)
	}
	// The independent node watchdog continues after gateway confirmation/API loss.
	f.manager.mu.Lock()
	f.manager.now = func() time.Time { return time.Now().Add(4 * time.Minute) }
	f.manager.mu.Unlock()
	if done, e := f.manager.Recover(context.Background()); e != nil || !done {
		t.Fatal(done, e)
	}
	f.peer.mu.Lock()
	f.peer.failConfirm = false
	f.peer.failStatus = false
	f.peer.mu.Unlock()
	if e := f.service.recoverCoverage(
		context.Background(),
	); e == nil ||
		e.Error() != "node_confirmation_failed_and_rolled_back" {
		t.Fatal("failed confirmation reported success", e)
	}
	j, e := f.service.loadCoverage()
	if e != nil || j.Entries[f.nodeID].Transaction.State != "rolled-back" {
		t.Fatal("gateway compensation did not follow node watchdog", e)
	}
}

func TestCoverageExpiredGatewayCompensatesUnconfirmedNode(t *testing.T) {
	f := newCoverageFixture(t)
	transaction := f.prepare(t)
	if _, e := f.action("apply", transaction.ID); e != nil {
		t.Fatal(e)
	}
	f.gateway.mu.Lock()
	f.gateway.transaction.State = "rolled-back"
	f.gateway.mu.Unlock()
	result, e := f.action("confirm", transaction.ID)
	if e == nil || result["transaction"].(coverageTransaction).State != "rolled-back" ||
		f.backend.restores != 1 {
		t.Fatal("expired gateway left an unconfirmed node applied", result, e)
	}
}

func TestCoverageReceiptsMustBindBothPeerIdentitiesRadioAndMode(t *testing.T) {
	f := newCoverageFixture(t)
	record, e := f.service.node(context.Background(), f.nodeID)
	if e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Record){
		func(r *Record) { r.Capabilities.VerifiedPeerFingerprint = strings.Repeat("f", 64) },
		func(r *Record) { r.Capabilities.VerifiedRadio = "radio9" },
		func(r *Record) { r.Capabilities.VerifiedMode = "mesh" },
		func(r *Record) { r.Capabilities.VerifiedPeerFingerprint = "" },
	} {
		copy := record
		mutate(&copy)
		if _, _, e := f.service.validateCoverage(
			context.Background(),
			copy,
			f.plan,
			&f.gatewayPlan,
		); e == nil {
			t.Fatal("mismatched node receipt enabled wireless")
		}
	}
	original := f.service.gateway
	f.service.gateway = func(ctx context.Context) Capabilities {
		c := original(ctx)
		c.VerifiedPeerFingerprint = strings.Repeat("f", 64)
		return c
	}
	if _, _, e := f.service.validateCoverage(
		context.Background(),
		record,
		f.plan,
		&f.gatewayPlan,
	); e == nil {
		t.Fatal("gateway receipt for another peer enabled wireless")
	}
}

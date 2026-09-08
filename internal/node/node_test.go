package node

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func caps() Capabilities {
	return Capabilities{
		OpenWrt:              true,
		Ethernet:             true,
		AP:                   true,
		WDS:                  true,
		Mesh:                 true,
		EncryptedBackhaul:    true,
		ConcurrentRadio:      true,
		GatewayBackhaulReady: true,
	}
}

func plan() Plan {
	return Plan{
		Name:                   "Office",
		Mode:                   "ethernet",
		ManagementInterface:    "home",
		BridgeSection:          "homebridge",
		BridgeDevice:           "br-home",
		LANPorts:               []string{"port1", "port2"},
		Uplink:                 "port2",
		ManagementAddress:      "10.0.8.2/24",
		GatewayAddress:         "10.0.8.1",
		PreserveManagementPath: true,
	}
}

func TestModeIntersectionPrefersProvenWiFi(t *testing.T) {
	if got := CompatibleModes(
		caps(),
		caps(),
	); !reflect.DeepEqual(
		got,
		[]string{"wds", "mesh", "ethernet"},
	) {
		t.Fatalf("unexpected modes: %v", got)
	}
	peer := caps()
	peer.EncryptedBackhaul = false
	if got := CompatibleModes(caps(), peer); !reflect.DeepEqual(got, []string{"ethernet"}) {
		t.Fatalf("insecure wireless offered: %v", got)
	}
	peer.OpenWrt = false
	if len(CompatibleModes(caps(), peer)) != 0 {
		t.Fatal("stock node advertised as fully managed")
	}
	gateway := caps()
	gateway.GatewayBackhaulReady = false
	if got := CompatibleModes(gateway, caps()); !reflect.DeepEqual(got, []string{"ethernet"}) {
		t.Fatalf("wireless offered without gateway counterpart: %v", got)
	}
}

func TestPlanRejectsCompetingGatewayAndUnverifiedRadios(t *testing.T) {
	if e := ValidatePlan(plan(), caps(), caps()); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Plan){func(p *Plan) { p.DHCPServer = true }, func(p *Plan) { p.NAT = true }, func(p *Plan) { p.RouterAdvertisements = true }, func(p *Plan) { p.PreserveManagementPath = false }, func(p *Plan) { p.LANPorts = append(p.LANPorts, "port2") }, func(p *Plan) { p.Uplink = "otherport" }, func(p *Plan) { p.GatewayAddress = "10.8.0.1" }, func(p *Plan) { p.ManagementInterface = "$(id)" }, func(p *Plan) { p.Mode = "repeater" }, func(p *Plan) { p.Radio = "radio0"; p.SSID = "home"; p.Passphrase = "short"; p.Channel = 1 }} {
		p := plan()
		mutate(&p)
		if e := ValidatePlan(p, caps(), caps()); e == nil {
			t.Fatalf("unsafe plan accepted: %+v", RedactPlan(p))
		}
	}
	p := plan()
	p.Mode = "wds"
	p.Uplink = "wlanbackhaul"
	p.Radio = "radio0"
	p.SSID = "Home"
	p.Passphrase = "example-test-passphrase"
	p.Channel = 6
	p.ShareRadio = true
	peer := caps()
	peer.ConcurrentRadio = false
	if ValidatePlan(p, caps(), peer) == nil {
		t.Fatal("unverified shared radio accepted")
	}
}

func TestUniqueDurableIdentitiesAndExactPinning(t *testing.T) {
	dir := t.TempDir()
	a, e := LoadIdentity(dir)
	if e != nil {
		t.Fatal(e)
	}
	again, e := LoadIdentity(dir)
	if e != nil {
		t.Fatal(e)
	}
	b, e := LoadIdentity(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if a.Fingerprint != again.Fingerprint || a.ID != again.ID {
		t.Fatal("identity changed on restart")
	}
	if a.Fingerprint == b.Fingerprint || a.ID == b.ID {
		t.Fatal("devices share an identity")
	}
	config, e := PinnedTLS(a, b.Fingerprint)
	if e != nil {
		t.Fatal(e)
	}
	if config.MinVersion != tls.VersionTLS13 || config.VerifyConnection == nil {
		t.Fatal("TLS validation missing")
	}
	if e = config.VerifyConnection(
		tls.ConnectionState{PeerCertificates: []*x509.Certificate{b.Certificate.Leaf}},
	); e != nil {
		t.Fatal(e)
	}
	if e = config.VerifyConnection(
		tls.ConnectionState{PeerCertificates: []*x509.Certificate{a.Certificate.Leaf}},
	); e == nil {
		t.Fatal("wrong fingerprint accepted")
	}
	if _, e = PinnedTLS(a, "unverified"); e == nil {
		t.Fatal("invalid pin accepted")
	}
	info, e := os.Stat(filepath.Join(dir, "identity.json"))
	if e != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("identity not private")
	}
}

func TestEnrollmentExpiryAttemptsReplayAndRevocation(t *testing.T) {
	for _, scenario := range []string{"expiry", "attempts", "success"} {
		t.Run(scenario, func(t *testing.T) {
			p, e := NewPairing(t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			defer func() { _ = p.Close() }()
			now := time.Now()
			p.now = func() time.Time { return now }
			pin := strings.Repeat("ab", 32)
			code, e := p.Bootstrap(time.Minute)
			if e != nil {
				t.Fatal(e)
			}
			if p.Authorized(pin) {
				t.Fatal("discovery conferred authorization")
			}
			switch scenario {
			case "expiry":
				now = now.Add(time.Minute)
				if p.Enroll(code, pin) == nil {
					t.Fatal("expired code accepted")
				}
			case "attempts":
				for range 5 {
					if p.Enroll(strings.Repeat("x", 43), pin) == nil {
						t.Fatal("wrong code accepted")
					}
				}
				if p.Enroll(code, pin) == nil {
					t.Fatal("attempt cap bypassed")
				}
			case "success":
				if e = p.Enroll(code, pin); e != nil {
					t.Fatal(e)
				}
				if !p.Authorized(pin) {
					t.Fatal("enrollment did not bind peer")
				}
				if p.Enroll(code, pin) == nil {
					t.Fatal("one-use code replayed")
				}
				if _, e = p.Bootstrap(time.Minute); e == nil {
					t.Fatal("bootstrap silently revoked enrollment")
				}
				if p.Revoke(strings.Repeat("bc", 32)) == nil {
					t.Fatal("foreign peer revoked node")
				}
				if e = p.Revoke(pin); e != nil {
					t.Fatal(e)
				}
				if p.Authorized(pin) {
					t.Fatal("revoked peer remains authorized")
				}
				if p.Enroll(code, pin) == nil {
					t.Fatal("revocation resurrected consumed code")
				}
			}
		})
	}
}

func TestEnrollmentRaceHasExactlyOneWinner(t *testing.T) {
	dir := t.TempDir()
	a, e := NewPairing(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = a.Close() }()
	b, e := NewPairing(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = b.Close() }()
	code, e := a.Bootstrap(time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	var winners atomic.Int64
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := a
			if i%2 == 0 {
				p = b
			}
			if p.Enroll(code, strings.Repeat("ab", 32)) == nil {
				winners.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("enrollment winners: %d", winners.Load())
	}
}

type fakeBackend struct {
	checks, applies, restores int
	failApply, failRestore    bool
	events                    *[]string
}

func (b *fakeBackend) Check(_ context.Context, p Plan) error {
	b.checks++
	return ValidatePlan(p, caps(), caps())
}

func (b *fakeBackend) Snapshot(context.Context) (Snapshot, error) {
	return Snapshot{
		"network":  []byte("original-network"),
		"wireless": []byte("PRIVATE-WIFI-KEY"),
		"dhcp":     []byte("original-dhcp"),
		"firewall": []byte("original-firewall"),
	}, nil
}

func (b *fakeBackend) Apply(context.Context, Plan) error {
	b.applies++
	if b.events != nil {
		*b.events = append(*b.events, "apply")
	}
	if b.failApply {
		return errors.New("simulated failure")
	}
	return nil
}

func (b *fakeBackend) Restore(context.Context, Snapshot, Plan) error {
	b.restores++
	if b.failRestore {
		return errors.New("simulated restore failure")
	}
	return nil
}

type fakeWatchdog struct {
	events *[]string
	fail   bool
}

func (w fakeWatchdog) Arm(string) error {
	if w.events != nil {
		*w.events = append(*w.events, "arm")
	}
	if w.fail {
		return errors.New("missing watchdog")
	}
	return nil
}

func TestNodeTransactionIdempotencyAndIndependentRecovery(t *testing.T) {
	dir := t.TempDir()
	events := []string{}
	backend := &fakeBackend{events: &events}
	m, e := NewManager(dir, backend, fakeWatchdog{events: &events})
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = m.Close() }()
	now := time.Now()
	m.now = func() time.Time { return now }
	ctx := context.Background()
	prepared, e := m.Prepare(ctx, "request-1234567890", plan())
	if e != nil {
		t.Fatal(e)
	}
	again, e := m.Prepare(ctx, "request-1234567890", plan())
	if e != nil || again.ID != prepared.ID {
		t.Fatal("prepare retry duplicated operation")
	}
	different := plan()
	different.Name = "Changed"
	if _, e = m.Prepare(ctx, "request-1234567890", different); e == nil {
		t.Fatal("idempotency key reused for different plan")
	}
	if _, e = m.Apply(ctx, prepared.ID, 30*time.Second); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(events, []string{"arm", "apply"}) {
		t.Fatalf("mutation occurred before watchdog: %v", events)
	}
	if _, e = m.Apply(ctx, prepared.ID, 30*time.Second); e != nil || backend.applies != 1 {
		t.Fatal("apply replay duplicated mutation")
	}
	// A separately instantiated process reads only the persisted journal.
	other, e := NewManager(dir, backend, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = other.Close() }()
	other.now = func() time.Time { return now.Add(31 * time.Second) }
	done, e := other.Recover(ctx)
	if e != nil || !done || backend.restores != 1 {
		t.Fatalf("independent recovery failed: %v", e)
	}
	status, e := m.Status()
	if e != nil {
		t.Fatal(e)
	}
	data, _ := json.Marshal(status)
	if strings.Contains(string(data), "PRIVATE-WIFI-KEY") ||
		!strings.Contains(string(data), "rolled-back") {
		t.Fatalf("unsafe or incorrect status: %s", data)
	}
}

func TestWatchdogRequiredAndApplyFailureRollsBack(t *testing.T) {
	for _, scenario := range []string{"absent", "not-ready", "apply-failure", "confirmation"} {
		t.Run(scenario, func(t *testing.T) {
			backend := &fakeBackend{}
			var watchdog Watchdog = fakeWatchdog{}
			if scenario == "absent" {
				watchdog = nil
			}
			if scenario == "not-ready" {
				watchdog = fakeWatchdog{fail: true}
			}
			if scenario == "apply-failure" {
				backend.failApply = true
			}
			m, e := NewManager(t.TempDir(), backend, watchdog)
			if e != nil {
				t.Fatal(e)
			}
			defer func() { _ = m.Close() }()
			ctx := context.Background()
			prepared, e := m.Prepare(ctx, "request-1234567890", plan())
			if e != nil {
				t.Fatal(e)
			}
			applied, e := m.Apply(ctx, prepared.ID, 30*time.Second)
			if scenario == "confirmation" {
				if e != nil {
					t.Fatal(e)
				}
				confirmed, e := m.Confirm(ctx, applied.ID)
				if e != nil || confirmed.State != "confirmed" {
					t.Fatalf("confirm failed: %v", e)
				}
				if _, e = m.Confirm(ctx, applied.ID); e != nil {
					t.Fatal("confirm retry rejected")
				}
				if done, e := m.Recover(ctx); e != nil || !done || backend.restores != 0 {
					t.Fatal("confirmed node rolled back")
				}
				return
			}
			if e == nil {
				t.Fatal("failure scenario succeeded")
			}
			if scenario == "apply-failure" {
				if backend.applies != 1 || backend.restores != 1 {
					t.Fatal("failed apply not rolled back")
				}
			} else if backend.applies != 0 {
				t.Fatal("network changed without ready watchdog")
			}
		})
	}
}

func TestInterruptedRollbackIsRetried(t *testing.T) {
	backend := &fakeBackend{failRestore: true}
	m, e := NewManager(t.TempDir(), backend, fakeWatchdog{})
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = m.Close() }()
	now := time.Now()
	m.now = func() time.Time { return now }
	ctx := context.Background()
	tr, e := m.Prepare(ctx, "request-1234567890", plan())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.Apply(ctx, tr.ID, 30*time.Second); e != nil {
		t.Fatal(e)
	}
	now = now.Add(31 * time.Second)
	if _, e = m.Recover(ctx); e == nil {
		t.Fatal("restore failure hidden")
	}
	backend.failRestore = false
	if done, e := m.Recover(ctx); e != nil || !done || backend.restores != 2 {
		t.Fatalf("interrupted rollback not retried: %v", e)
	}
}

func TestAgentPairingAndGatewayServiceOverPinnedTLS(t *testing.T) {
	ctx := context.Background()
	nodeDir := t.TempDir()
	identity, e := LoadIdentity(nodeDir)
	if e != nil {
		t.Fatal(e)
	}
	pairing, e := NewPairing(nodeDir)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = pairing.Close() }()
	code, e := pairing.Bootstrap(time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	manager, e := NewManager(t.TempDir(), &fakeBackend{}, fakeWatchdog{})
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = manager.Close() }()
	agent := &Agent{
		Identity:     identity,
		Pairing:      pairing,
		Capabilities: func(context.Context) Capabilities { return caps() },
		Operator:     LocalOperator{Manager: manager},
	}
	server := httptest.NewUnstartedServer(agent)
	server.TLS = agent.TLSConfig()
	server.StartTLS()
	defer server.Close()
	registryDir := t.TempDir()
	gateway, e := NewService(registryDir, func(context.Context) Capabilities { return caps() })
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = gateway.Close() }()
	if _, e = gateway.request(
		ctx,
		server.URL,
		identity.Fingerprint,
		http.MethodGet,
		"/node/v1/status",
		nil,
	); e == nil {
		t.Fatal("unpaired certificate had control")
	}
	badPin := strings.Repeat("cd", 32)
	if _, e = gateway.request(
		ctx,
		server.URL,
		badPin,
		http.MethodGet,
		"/node/v1/status",
		nil,
	); e == nil {
		t.Fatal("forged AP fingerprint accepted")
	}
	raw, _ := json.Marshal(
		map[string]string{
			"address":     server.URL,
			"fingerprint": identity.Fingerprint,
			"code":        code,
			"name":        "Office",
		},
	)
	if _, e = gateway.Pair(ctx, raw); e != nil {
		t.Fatal(e)
	}
	if !pairing.Authorized(gateway.identity.Fingerprint) {
		t.Fatal("gateway not bound")
	}
	registry, e := os.ReadFile(filepath.Join(registryDir, "nodes.json"))
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(registry), code) {
		t.Fatal("one-time code persisted in gateway registry")
	}
	p := plan()
	raw, _ = json.Marshal(p)
	if _, e = gateway.Plan(ctx, identity.ID, raw); e != nil {
		t.Fatal(e)
	}
	op := Operation{Key: "request-1234567890", Plan: &p}
	raw, _ = json.Marshal(op)
	result, e := gateway.Operate(ctx, identity.ID, "prepare", raw)
	if e != nil {
		t.Fatal(e)
	}
	var tr Transaction
	data, _ := json.Marshal(result["transaction"])
	if e = json.Unmarshal(data, &tr); e != nil {
		t.Fatal(e)
	}
	raw, _ = json.Marshal(Operation{ID: tr.ID, TimeoutSeconds: 30})
	if _, e = gateway.Operate(ctx, identity.ID, "apply", raw); e != nil {
		t.Fatal(e)
	}
	if _, e = gateway.Operate(ctx, identity.ID, "confirm", raw); e != nil {
		t.Fatal(e)
	}
	if e = gateway.Unpair(ctx, identity.ID); e != nil {
		t.Fatal(e)
	}
	if pairing.Authorized(gateway.identity.Fingerprint) {
		t.Fatal("node trust not revoked")
	}
	if len(gateway.List().([]Record)) != 0 {
		t.Fatal("gateway trust not revoked")
	}
}

func TestNodeAddressAndStateSecurity(t *testing.T) {
	for _, address := range []string{"http://10.0.0.2", "https://evil.example", "https://8.8.8.8", "https://user:secret@10.0.0.2", "https://10.0.0.2/path", "https://10.0.0.2/?code=secret", "https://0.0.0.0"} {
		if validateAddress(address) == nil {
			t.Fatalf("unsafe node address accepted: %s", address)
		}
	}
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "identity.json")
	if e := os.WriteFile(outside, []byte("private"), 0o600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(outside, filepath.Join(dir, "identity.json")); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadIdentity(dir); e == nil {
		t.Fatal("symlink identity accepted")
	}
	data, _ := os.ReadFile(outside)
	if string(data) != "private" {
		t.Fatal("outside identity mutated")
	}
}

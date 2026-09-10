package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/config"
	"github.com/tibeahx/OpenRHP/internal/dataplane"
	"github.com/tibeahx/OpenRHP/internal/dispatch"
	"github.com/tibeahx/OpenRHP/internal/helper"
	"github.com/tibeahx/OpenRHP/internal/model"
	"github.com/tibeahx/OpenRHP/internal/routing"
)

type routingTestProcess struct {
	live  atomic.Bool
	stops atomic.Int32
}

func (p *routingTestProcess) Alive() bool         { return p.live.Load() }
func (*routingTestProcess) Done() <-chan struct{} { return nil }
func (p *routingTestProcess) Close(context.Context) error {
	p.live.Store(false)
	p.stops.Add(1)
	return nil
}

type routingTestHelper struct {
	mu          sync.Mutex
	starts      []dispatch.Spec
	requests    []helper.DispatcherRequest
	processes   map[int]*routingTestProcess
	snapshots   map[string]routing.Snapshot
	wan         string
	publication uint64
	failure     error
}

func (h *routingTestHelper) UploadSnapshot(
	_ context.Context,
	s routing.Snapshot,
) (routing.SnapshotRef, error) {
	data, err := routing.EncodeSnapshot(s)
	if err != nil {
		return routing.SnapshotRef{}, err
	}
	ref := routing.Reference(s, data)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.snapshots[ref.SHA256] = s
	return ref, nil
}

func (h *routingTestHelper) LoadRoutingSnapshot(
	_ context.Context,
	g uint64,
	hash string,
) (routing.Snapshot, routing.SnapshotRef, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.snapshots[hash]
	if !ok || s.Generation != g {
		return s, routing.SnapshotRef{}, errors.New("missing snapshot")
	}
	data, err := routing.EncodeSnapshot(s)
	return s, routing.Reference(s, data), err
}

func (h *routingTestHelper) StartDispatcher(
	_ context.Context,
	s dispatch.Spec,
	_ routing.SnapshotRef,
	_ func(string),
) (adapter.ManagedProcess, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p := &routingTestProcess{}
	p.live.Store(true)
	h.starts = append(h.starts, s)
	h.processes[s.Allocation.Path.Slot] = p
	return p, nil
}

func (h *routingTestHelper) Dispatcher(
	_ context.Context,
	r helper.DispatcherRequest,
) (helper.DispatcherStatus, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.requests = append(h.requests, r)
	if h.failure != nil {
		return helper.DispatcherStatus{}, h.failure
	}
	if r.Action == "publish" {
		h.publication++
	}
	return helper.DispatcherStatus{
		Running:             true,
		Selected:            r.Selected,
		PublishedGeneration: h.publication,
		WANIdentity:         h.wan,
	}, nil
}

func (h *routingTestHelper) publications() []helper.DispatcherRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := []helper.DispatcherRequest{}
	for _, r := range h.requests {
		if r.Action == "publish" {
			out = append(out, r)
		}
	}
	return out
}

func routingControlFixture(
	t *testing.T,
) (*RoutingControl, *routingTestHelper, model.Config, []adapter.Path) {
	t.Helper()
	r := runtimeFixture(t)
	c := r.Store.Get()
	c.Routing = config.RoutingDefaults()
	c.Routing.Registry.Enabled = false
	c.Network = model.Network{
		Enabled:       true,
		LANInterfaces: []string{"lan0"},
		WANInterface:  "wan0",
		LocalPrefixes: []string{"192.168.1.0/24"},
		IPv6:          "block",
		DNS:           "selected-path",
		DNSResolver:   "8.8.8.8",
	}
	c.Policy.Mode = "auto"
	c.Sources = []model.Source{
		{
			ID:       "vpn",
			Name:     "VPN",
			Type:     "interface",
			Enabled:  true,
			Auto:     true,
			Settings: json.RawMessage(`{"name":"vpn0"}`),
		},
	}
	var err error
	c, err = r.Store.Replace(c.Revision, c)
	if err != nil {
		t.Fatal(err)
	}
	r.Reload()
	rc, err := NewRoutingControl(r, nil, filepath.Join(t.TempDir(), "routing"))
	if err != nil {
		t.Fatal(err)
	}
	h := &routingTestHelper{
		processes: map[int]*routingTestProcess{},
		snapshots: map[string]routing.Snapshot{},
		wan:       strings.Repeat("a", 64),
	}
	rc.client = h
	r.Routing = rc
	p := adapter.AllocatePath("vpn", "interface", 4)
	p.Interface = "vpn0"
	p.UDP = true
	return rc, h, c, []adapter.Path{p}
}

func activateRoutingTest(
	t *testing.T,
	rc *RoutingControl,
	c model.Config,
	paths []adapter.Path,
) *dataplane.SelectiveIntent {
	t.Helper()
	intent, err := rc.Prepare(context.Background(), c, paths, "vpn", nil)
	if err != nil {
		t.Fatal(err)
	}
	s := helper.State{
		Committed: &dataplane.Desired{Network: c.Network, Selected: "vpn", Selective: intent},
	}
	if err = rc.Sync(context.Background(), s, "vpn"); err != nil {
		t.Fatal(err)
	}
	return intent
}

func TestRoutingPrepareStagesPolicyWithoutPublishingOrReplacingLiveInstance(t *testing.T) {
	rc, h, c, paths := routingControlFixture(t)
	old := activateRoutingTest(t, rc, c, paths)
	active := rc.active
	candidate := c
	candidate.Routing = config.RedactRouting(c.Routing)
	candidate.Routing.Exceptions = []model.RoutingRule{
		{Action: "bypass", Domain: "blocked.example"},
	}
	next, err := rc.Prepare(context.Background(), candidate, paths, "vpn", nil)
	if err != nil {
		t.Fatal(err)
	}
	if next.Path.Slot == old.Path.Slot || rc.active != active ||
		!h.processes[int(old.Path.Slot)].Alive() ||
		len(h.publications()) != 0 {
		t.Fatal("prepare mutated committed classifier")
	}
	if next.FakePool == old.FakePool {
		t.Fatal("staged dispatcher reused the active FakeIP pool")
	}
	decision, err := rc.Check(context.Background(), "blocked.example")
	if err != nil || decision.(map[string]any)["action"] != "direct" {
		t.Fatal("unapplied rules became active", decision, err)
	}
	state := helper.State{
		Committed: &dataplane.Desired{Selected: "vpn", Selective: old},
		Transaction: &helper.Transaction{
			State:     "applied",
			Candidate: dataplane.Desired{Selected: "vpn", Selective: next},
			Rollback:  dataplane.Desired{Selected: "vpn", Selective: old},
		},
	}
	if err = rc.Sync(context.Background(), state, "vpn"); err != nil {
		t.Fatal(err)
	}
	if !h.processes[int(old.Path.Slot)].Alive() {
		t.Fatal("rollback instance stopped before confirm")
	}
	decision, err = rc.Check(context.Background(), "blocked.example")
	if err != nil || decision.(map[string]any)["action"] != "bypass" {
		t.Fatal("applied candidate ingress is using previous classification", decision, err)
	}
	state.Transaction.State = "confirmed"
	state.Committed = &state.Transaction.Candidate
	if err = rc.Sync(context.Background(), state, "vpn"); err != nil {
		t.Fatal(err)
	}
	if h.processes[int(old.Path.Slot)].Alive() || len(rc.instances) != 1 {
		t.Fatal("confirmed superseded instance retained")
	}
	decision, err = rc.Check(context.Background(), "blocked.example")
	if err != nil || decision.(map[string]any)["action"] != "bypass" {
		t.Fatal("confirmed rule missing", decision, err)
	}
}

func TestRoutingRollbackKeepsPreviousPolicyAndClosesStagedInstance(t *testing.T) {
	rc, h, c, paths := routingControlFixture(t)
	old := activateRoutingTest(t, rc, c, paths)
	candidate := c
	candidate.Routing = config.RedactRouting(c.Routing)
	candidate.Routing.Exceptions = []model.RoutingRule{
		{Action: "bypass", Domain: "blocked.example"},
	}
	staged, err := rc.Prepare(context.Background(), candidate, paths, "vpn", nil)
	if err != nil {
		t.Fatal(err)
	}
	state := helper.State{
		Committed: &dataplane.Desired{Selected: "vpn", Selective: old},
		Transaction: &helper.Transaction{
			State:     "rolled-back",
			Candidate: dataplane.Desired{Selective: staged},
			Rollback:  dataplane.Desired{Selective: old},
		},
	}
	if err = rc.Sync(context.Background(), state, "vpn"); err != nil {
		t.Fatal(err)
	}
	if rc.active != int(old.Path.Slot) || !h.processes[int(old.Path.Slot)].Alive() ||
		h.processes[int(staged.Path.Slot)].Alive() {
		t.Fatal("rollback lost previous dispatcher")
	}
	value, err := rc.Check(context.Background(), "blocked.example")
	if err != nil || value.(map[string]any)["action"] != "direct" {
		t.Fatal("rolled-back candidate rule survived", value, err)
	}
}

func TestRoutingRefreshFailureKeepsLastGoodAndNoDNSHistoryInDiagnostics(t *testing.T) {
	rc, _, c, paths := routingControlFixture(t)
	c.Routing.Detection.Enabled = true
	c.Routing.Detection.ControlTargetIDs = []string{"web"}
	activateRoutingTest(t, rc, c, paths)
	expected := routing.Snapshot{
		Generation: 2,
		CreatedAt:  time.Now().UTC(),
		Domains:    []string{"registry.example"},
		CIDRs:      []string{},
	}
	rc.fetch = func(context.Context, uint64, time.Time) (routing.Snapshot, error) { return expected, nil }
	if _, err := rc.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := rc.snapshot
	beforeRef := rc.ref
	rc.fetch = func(context.Context, uint64, time.Time) (routing.Snapshot, error) {
		return routing.Snapshot{}, errors.New("SECRET fetched payload")
	}
	if _, err := rc.Refresh(
		context.Background(),
	); err == nil ||
		strings.Contains(err.Error(), "SECRET") {
		t.Fatal("refresh failure not private", err)
	}
	if !reflect.DeepEqual(before, rc.snapshot) || beforeRef != rc.ref || rc.state != "ready" {
		t.Fatal("failed update replaced rules or triggered emergency")
	}
	rc.Observe("private-browsing.example")
	status := rc.Status().(map[string]any)
	if status["detection"].(map[string]any)["pending_count"] != 1 {
		t.Fatal("DNS observation did not reach the private queue")
	}
	draft := rc.Runtime.Store.Get()
	draft.Routing = nil
	if _, err := rc.Runtime.Store.Replace(draft.Revision, draft); err != nil {
		t.Fatal(err)
	}
	if rc.Status().(map[string]any)["mode"] != "selective" {
		t.Fatal("saved draft replaced the reported applied mode")
	}
	raw, err := json.Marshal(status)
	if err != nil || strings.Contains(string(raw), "private-browsing") ||
		strings.Contains(string(raw), "SECRET") ||
		strings.Contains(string(raw), "verified_generation") {
		t.Fatal("status disclosed DNS history or fabricated engine ACK", string(raw), err)
	}
}

func TestRoutingLegacyStatusDoesNotClaimSelectiveEmergencyDirect(t *testing.T) {
	rc, _, _, _ := routingControlFixture(t)
	c := rc.Runtime.Store.Get()
	c.Routing = nil
	if _, err := rc.Runtime.Store.Replace(c.Revision, c); err != nil {
		t.Fatal(err)
	}
	status := rc.Status().(map[string]any)
	if status["mode"] != "legacy-all" {
		t.Fatal("legacy mode changed", status)
	}
	for _, field := range []string{"default_action", "failure_policy"} {
		if _, ok := status[field]; ok {
			t.Fatalf("legacy status claimed selective %s", field)
		}
	}
}

func TestRoutingFailedHelperPublicationRetainsAppliedRulesAndRetries(t *testing.T) {
	rc, h, c, paths := routingControlFixture(t)
	c.Routing.Registry.Enabled = true
	rc.snapshot = emptyRoutingSnapshot()
	activateRoutingTest(t, rc, c, paths)
	i := rc.instances[rc.active]
	previous := i.ref
	rc.fetch = func(context.Context, uint64, time.Time) (routing.Snapshot, error) {
		return routing.Snapshot{
			Generation: 2,
			CreatedAt:  time.Now(),
			Domains:    []string{"newly-listed.example"},
			CIDRs:      []string{},
		}, nil
	}
	h.failure = errors.New("SECRET helper details")
	if _, err := rc.Refresh(context.Background()); err == nil {
		t.Fatal("failed publication reported success")
	}
	if i.ref != previous ||
		i.classifier.Decide("newly-listed.example", netip.Addr{}, time.Now()).Action != "direct" ||
		rc.state != "ready" {
		t.Fatal("failed publication replaced applied rules or caused emergency")
	}
	h.failure = nil
	rc.run(time.Now())
	if i.ref.Generation != 2 ||
		i.classifier.Decide("newly-listed.example", netip.Addr{}, time.Now()).Action != "bypass" ||
		len(h.starts) != 1 {
		t.Fatal("validated update did not retry through hot publication")
	}
}

func TestRoutingUnavailableComparisonRunnerDoesNotConsumeCandidate(t *testing.T) {
	rc, _, c, paths := routingControlFixture(t)
	c.Routing.Detection.Enabled = true
	c.Routing.Detection.ControlTargetIDs = []string{"web"}
	activateRoutingTest(t, rc, c, paths)
	rc.Observe("unknown.example")
	rc.run(time.Now())
	status := rc.instances[rc.active].detector.Status(time.Now())
	if status.Candidates != 1 || status.InFlight != 0 || status.Learned != 0 {
		t.Fatal("unsupported comparison runner consumed or classified work", status)
	}
}

func TestRoutingLearnedExpiryPublishesRemovalWithoutRestart(t *testing.T) {
	rc, h, c, paths := routingControlFixture(t)
	c.Routing.Detection.Enabled = true
	c.Routing.Detection.ControlTargetIDs = []string{"web"}
	activateRoutingTest(t, rc, c, paths)
	i := rc.instances[rc.active]
	base := time.Now().Add(-time.Hour)
	domain := "temporary.example"
	i.detector.Observe(domain, base)
	for n := 0; n < 3; n++ {
		at := base.Add(time.Duration(n) * routing.DetectionSpacing)
		candidate, ok := i.detector.Next(at, "wan0:vpn")
		if !ok {
			t.Fatal("candidate unavailable")
		}
		i.detector.Record(
			candidate,
			routing.Round{
				Complete:  true,
				ControlOK: true,
				ControlAt: at,
				Addresses: []routing.AddressResult{
					{IP: netip.MustParseAddr("8.8.8.8"), BypassSuccess: true},
				},
			},
			at,
		)
	}
	learned := i.detector.Learned(base.Add(20 * time.Second))
	if len(learned) != 1 {
		t.Fatal("failed to create rule")
	}
	if err := rc.publish(context.Background(), i, i.snapshot, learned); err != nil {
		t.Fatal(err)
	}
	starts := len(h.starts)
	rc.run(base.Add(time.Hour + 21*time.Second))
	pubs := h.publications()
	if len(pubs) != 2 || len(pubs[1].Learned) != 0 || len(i.learned) != 0 ||
		len(h.starts) != starts {
		t.Fatal("expiry did not remove rule through hot publication", pubs)
	}
}

func TestRoutingRestoreUsesJournalSnapshotAndReusesExactIngress(t *testing.T) {
	rc, _, c, paths := routingControlFixture(t)
	old := activateRoutingTest(t, rc, c, paths)
	if err := rc.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	rc.snapshot = routing.Snapshot{
		Generation: 99,
		CreatedAt:  time.Now(),
		Domains:    []string{"new.example"},
		CIDRs:      []string{},
	}
	restored, err := rc.Prepare(context.Background(), c, paths, "vpn", old)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Path != old.Path || restored.DNSFrontPort != old.DNSFrontPort ||
		restored.Snapshot != old.Snapshot {
		t.Fatal("restart changed journal allocation or registry", old, restored)
	}
	if restored.FakePool != old.FakePool {
		t.Fatal("restart changed the durable FakeIP mapping pool")
	}
	if rc.closed || rc.ctx.Err() != nil {
		t.Fatal("close poisoned later recovery")
	}
}

func TestRoutingAbortedFirstPreparationReleasesOnlyTerminalStage(t *testing.T) {
	rc, h, c, paths := routingControlFixture(t)
	staged, err := rc.Prepare(context.Background(), c, paths, "vpn", nil)
	if err != nil {
		t.Fatal(err)
	}
	s := helper.State{
		Transaction: &helper.Transaction{
			State:     "prepared",
			Candidate: dataplane.Desired{Selected: "vpn", Selective: staged},
		},
	}
	if err := rc.Sync(
		context.Background(),
		s,
		"vpn",
	); err != nil || len(rc.instances) != 1 ||
		!h.processes[int(staged.Path.Slot)].Alive() {
		t.Fatal("unapplied preparation lost its reserved instance", err)
	}
	s.Transaction.State = "rolled-back"
	if err := rc.Sync(
		context.Background(),
		s,
		"vpn",
	); err != nil || len(rc.instances) != 0 ||
		h.processes[int(staged.Path.Slot)].Alive() {
		t.Fatal("aborted initial preparation retained its instance", err)
	}
	if _, err := rc.Prepare(context.Background(), c, paths, "vpn", nil); err != nil {
		t.Fatal("aborted initial transaction poisoned retry", err)
	}
}

func TestRoutingEmergencyRetainsCommittedAndReleasesAbortedStage(t *testing.T) {
	rc, h, c, paths := routingControlFixture(t)
	old := activateRoutingTest(t, rc, c, paths)
	c.Routing = config.RedactRouting(c.Routing)
	c.Routing.Exceptions = []model.RoutingRule{{Action: "bypass", Domain: "later.example"}}
	staged, err := rc.Prepare(context.Background(), c, paths, "vpn", nil)
	if err != nil {
		t.Fatal(err)
	}
	s := helper.State{
		Committed:          &dataplane.Desired{Selected: "vpn", Selective: old},
		SelectiveEmergency: true,
		Transaction: &helper.Transaction{
			State:     "rolled-back",
			Candidate: dataplane.Desired{Selective: staged},
		},
	}
	if err := rc.Sync(
		context.Background(),
		s,
		"vpn",
	); err != nil || len(rc.instances) != 1 || !h.processes[int(old.Path.Slot)].Alive() || h.processes[int(staged.Path.Slot)].Alive() ||
		rc.state != "emergency-direct" {
		t.Fatal("emergency retained aborted stage or discarded committed recovery instance", err)
	}
	if _, err := rc.Prepare(context.Background(), c, paths, "vpn", nil); err != nil {
		t.Fatal("emergency recovery preparation exhausted staged slots", err)
	}
}

func TestRoutingDirectCannotBecomeDefaultBypass(t *testing.T) {
	rc, _, c, paths := routingControlFixture(t)
	direct := adapter.AllocatePath("wan", "direct", 5)
	direct.UDP = true
	paths = append(paths, direct)
	if _, err := rc.Prepare(context.Background(), c, paths, "wan", nil); err == nil {
		t.Fatal("direct source accepted as bypass")
	}
	if _, err := rc.Prepare(context.Background(), c, paths, "vpn", nil); err != nil {
		t.Fatal("valid bypass with independently prepared WAN rejected", err)
	}
}

type routingTestProbe struct{ afterCompare func() }

func (p routingTestProbe) Run(
	context.Context,
	model.Source,
	[]model.Target,
	model.ProbeSettings,
	bool,
) (model.Measurement, error) {
	return model.Measurement{}, nil
}

func (p routingTestProbe) Compare(
	context.Context,
	string,
	adapter.Path,
	adapter.Path,
	model.ProbeSettings,
) (routing.Round, error) {
	if p.afterCompare != nil {
		p.afterCompare()
	}
	return routing.Round{
		Complete: true,
		Addresses: []routing.AddressResult{
			{IP: netip.MustParseAddr("8.8.8.8"), BypassSuccess: true},
		},
	}, nil
}

func (routingTestProbe) ControlTLSForFamilies(
	context.Context,
	model.Target,
	adapter.Path,
	model.ProbeSettings,
	bool,
	bool,
) (time.Time, error) {
	return time.Now(), nil
}

func TestRoutingComparisonsDiscardEvidenceAcrossWANAndSourceChanges(t *testing.T) {
	for _, scenario := range []string{"stable", "WAN-before", "WAN-during", "source-during"} {
		t.Run(scenario, func(t *testing.T) {
			rc, h, c, paths := routingControlFixture(t)
			c.Routing.Detection.Enabled = true
			c.Routing.Detection.ControlTargetIDs = []string{"web"}
			activateRoutingTest(t, rc, c, paths)
			i := rc.instances[rc.active]
			domain := "restriction.example"
			base := time.Now().Add(-30 * time.Second)
			i.detector.Observe(domain, base)
			for n := 0; n < 2; n++ {
				at := base.Add(time.Duration(n) * routing.DetectionSpacing)
				candidate, ok := i.detector.Next(at, h.wan+":vpn")
				if !ok {
					t.Fatal("missing candidate")
				}
				i.detector.Record(
					candidate,
					routing.Round{
						Complete:  true,
						ControlOK: true,
						ControlAt: at,
						Addresses: []routing.AddressResult{
							{IP: netip.MustParseAddr("8.8.8.8"), BypassSuccess: true},
						},
					},
					at,
				)
			}
			changeWAN := func() { h.mu.Lock(); h.wan = strings.Repeat("b", 64); h.mu.Unlock() }
			probe := routingTestProbe{}
			switch scenario {
			case "WAN-before":
				changeWAN()
			case "WAN-during":
				probe.afterCompare = changeWAN
			case "source-during":
				probe.afterCompare = func() { rc.mu.Lock(); i.selected = "other"; rc.mu.Unlock() }
			}
			rc.Runtime.Prober = probe
			rc.run(time.Now())
			learned := i.detector.Learned(time.Now())
			if scenario == "stable" && len(learned) != 1 {
				t.Fatal("stable third confirmation was not learned")
			}
			if scenario != "stable" && len(learned) != 0 {
				t.Fatal("WAN/source change retained restriction confirmation")
			}
		})
	}
}

package control

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/adapter"
	"github.com/tibeahx/RouteHarbor/internal/dataplane"
	"github.com/tibeahx/RouteHarbor/internal/dispatch"
	"github.com/tibeahx/RouteHarbor/internal/helper"
	"github.com/tibeahx/RouteHarbor/internal/model"
	"github.com/tibeahx/RouteHarbor/internal/routing"
)

type routingHelper interface {
	LoadRoutingSnapshot(
		context.Context,
		uint64,
		string,
	) (routing.Snapshot, routing.SnapshotRef, error)
	Dispatcher(context.Context, helper.DispatcherRequest) (helper.DispatcherStatus, error)
	StartDispatcher(
		context.Context,
		dispatch.Spec,
		routing.SnapshotRef,
		func(string),
	) (adapter.ManagedProcess, error)
	UploadSnapshot(context.Context, routing.Snapshot) (routing.SnapshotRef, error)
}
type routingProbe interface {
	Compare(
		context.Context,
		string,
		adapter.Path,
		adapter.Path,
		model.ProbeSettings,
	) (routing.Round, error)
	ControlTLSForFamilies(
		context.Context,
		model.Target,
		adapter.Path,
		model.ProbeSettings,
		bool,
		bool,
	) (time.Time, error)
}
type routingInstance struct {
	key        string
	config     model.Config
	spec       dispatch.Spec
	ref        routing.SnapshotRef
	snapshot   routing.Snapshot
	process    adapter.ManagedProcess
	classifier *routing.Classifier
	detector   *routing.Detector
	learned    map[string]time.Time
	published  uint64
	selected   string
}

// RoutingControl retains at most the committed and one staged dispatcher. A
// prepare starts isolated listeners; only the network transaction moves LAN
// ingress. The previous instance remains available throughout rollback.
type RoutingControl struct {
	refreshMu                           sync.Mutex
	Runtime                             *Runtime
	client                              routingHelper
	store                               *routing.SnapshotStore
	fetch                               func(context.Context, uint64, time.Time) (routing.Snapshot, error)
	mu                                  sync.Mutex
	operations                          sync.Mutex
	instances                           map[int]*routingInstance
	active                              int
	snapshot                            routing.Snapshot
	ref                                 routing.SnapshotRef
	nextRefresh                         time.Time
	registryError, detectorError, state string
	busy                                bool
	closed                              bool
	wg                                  sync.WaitGroup
	ctx                                 context.Context
	cancel                              context.CancelFunc
}

func NewRoutingControl(
	r *Runtime,
	client *helper.Client,
	directory string,
) (*RoutingControl, error) {
	store, e := routing.NewSnapshotStore(directory)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(r.ctx)
	rc := &RoutingControl{
		Runtime:   r,
		client:    client,
		store:     store,
		fetch:     (routing.RegistryFetcher{}).Fetch,
		instances: map[int]*routingInstance{},
		state:     "inactive",
		ctx:       ctx,
		cancel:    cancel,
	}
	rc.snapshot, rc.ref, e = store.Load()
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		rc.registryError = "registry_snapshot_unavailable"
	}
	return rc, nil
}

func emptyRoutingSnapshot() routing.Snapshot {
	return routing.Snapshot{
		Generation: 1,
		CreatedAt:  time.Unix(1, 0).UTC(),
		Domains:    []string{},
		CIDRs:      []string{},
	}
}

func (rc *RoutingControl) Status() any {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	now := time.Now()
	cfg := rc.Runtime.Store.Get()
	mode := "legacy-all"
	if active := rc.instances[rc.active]; active != nil {
		cfg = active.config
	}
	if model.SelectiveRouting(cfg) {
		mode = "selective"
	}
	reg := map[string]any{
		"provider":         routing.RegistryProvider,
		"provenance":       routing.RegistryProvenance,
		"generation":       rc.snapshot.Generation,
		"domain_count":     len(rc.snapshot.Domains),
		"cidr_count":       len(rc.snapshot.CIDRs),
		"rejected_domains": rc.snapshot.RejectedDomains,
		"stale": rc.snapshot.CreatedAt.IsZero() ||
			now.Sub(rc.snapshot.CreatedAt) > 24*time.Hour,
		"last_error": rc.registryError,
	}
	if !rc.snapshot.CreatedAt.IsZero() {
		reg["updated_at"] = rc.snapshot.CreatedAt
		reg["age_seconds"] = int64(max(0, now.Sub(rc.snapshot.CreatedAt).Seconds()))
	}
	out := map[string]any{
		"mode":     mode,
		"state":    rc.state,
		"registry": reg,
		"detection": map[string]any{
			"enabled":       false,
			"learned_count": 0,
			"pending_count": 0,
			"last_error":    rc.detectorError,
		},
	}
	if mode == "selective" {
		out["default_action"] = "direct"
		out["failure_policy"] = "direct"
	}
	if i := rc.instances[rc.active]; i != nil {
		d := i.detector.Status(now)
		out["detection"] = map[string]any{
			"enabled":       d.Enabled,
			"learned_count": d.Learned,
			"pending_count": d.Candidates,
			"in_flight":     d.InFlight,
			"dropped":       d.Dropped,
			"indeterminate": d.Indeterminate,
			"last_error":    rc.detectorError,
		}
		out["selected"] = i.selected
		out["published_generation"] = i.published
		// File publication is observable. The engine supplies no rule-set digest ACK;
		// absence of verified_generation intentionally does not claim application.
		if !i.process.Alive() && rc.state == "ready" {
			out["state"] = "unavailable"
		}
	}
	return out
}

func (rc *RoutingControl) Observe(domain string) {
	if !rc.mu.TryLock() {
		return
	}
	defer rc.mu.Unlock()
	i := rc.instances[rc.active]
	if i == nil || rc.state != "ready" {
		return
	}
	if d := i.classifier.Decide(
		domain,
		netip.Addr{},
		time.Now(),
	); d.Action == "direct" &&
		d.Reason == "Default direct" {
		i.detector.Observe(domain, time.Now())
	}
}

func (rc *RoutingControl) Check(ctx context.Context, destination string) (any, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	domain, e := routing.CanonicalDomain(destination)
	ip, ie := netip.ParseAddr(destination)
	if e != nil && ie != nil {
		return nil, errors.New("invalid public destination")
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()
	i := rc.instances[rc.active]
	if i == nil {
		return nil, errors.New("routing is not applied")
	}
	d := i.classifier.Decide(domain, ip, time.Now())
	route := d.Action
	if rc.state == "emergency-direct" {
		d = routing.Decision{Action: "direct", Reason: "Emergency direct"}
		route = "direct"
	} else if d.Action == "bypass" {
		route = i.selected
		if route == "" {
			route = "unavailable"
		}
	}
	if d.Reason == "Default direct" && domain != "" {
		i.detector.Observe(domain, time.Now())
	}
	return map[string]any{"action": d.Action, "reason": d.Reason, "route": route}, nil
}

// Refresh downloads first, validates both lists, then atomically saves a complete
// generation. Any error leaves the current engine rules untouched.
func (rc *RoutingControl) Refresh(ctx context.Context) (any, error) {
	if e := rc.refresh(ctx); e != nil {
		return nil, e
	}
	rc.mu.Lock()
	i := rc.instances[rc.active]
	ready := rc.state == "ready"
	snapshot := rc.snapshot
	rc.mu.Unlock()
	if i != nil && ready && i.spec.Routing.Registry.Enabled {
		if e := rc.publish(ctx, i, snapshot, i.detector.Learned(time.Now())); e != nil {
			return nil, e
		}
	}
	return rc.Status(), nil
}

func (rc *RoutingControl) refresh(ctx context.Context) error {
	rc.refreshMu.Lock()
	defer rc.refreshMu.Unlock()
	rc.mu.Lock()
	generation := max(uint64(2), rc.snapshot.Generation+1)
	rc.nextRefresh = time.Now().Add(30 * time.Minute)
	rc.mu.Unlock()
	snapshot, e := rc.fetch(ctx, generation, time.Now())
	if e == nil {
		var ref routing.SnapshotRef
		ref, e = rc.store.Save(snapshot)
		if e == nil {
			rc.mu.Lock()
			rc.snapshot, rc.ref = snapshot, ref
			rc.registryError = ""
			rc.mu.Unlock()
		}
	}
	if e != nil {
		rc.mu.Lock()
		rc.registryError = "registry_update_failed"
		rc.mu.Unlock()
		return errors.New("registry update failed; previous rules retained")
	}
	return nil
}

func (rc *RoutingControl) Prepare(
	ctx context.Context,
	c model.Config,
	paths []adapter.Path,
	selected string,
	restored *dataplane.SelectiveIntent,
) (*dataplane.SelectiveIntent, error) {
	if !model.SelectiveRouting(c) {
		return nil, nil
	}
	rc.operations.Lock()
	defer rc.operations.Unlock()
	rc.mu.Lock()
	defer rc.mu.Unlock()
	sources := append([]adapter.Path(nil), paths...)
	for j := range sources {
		sources[j].ProxyURL = nil
	}
	sort.Slice(sources, func(a, b int) bool { return sources[a].Slot < sources[b].Slot })
	var bridge *dispatch.Bridge
	if continuityEnabled(c) {
		if rc.Runtime.Continuity == nil {
			return nil, errors.New("continuity unavailable")
		}
		bridge = rc.Runtime.Continuity.Bridge()
		if bridge == nil {
			return nil, errors.New("continuity bridge unavailable")
		}
	}
	for slot, i := range rc.instances {
		if !i.process.Alive() {
			_ = i.process.Close(ctx)
			rc.Runtime.Adapters.ForgetDispatcherFor(i.key)
			delete(rc.instances, slot)
		}
	}
	for _, i := range rc.instances {
		if i.process.Alive() && reflect.DeepEqual(i.spec.Routing, *c.Routing) &&
			reflect.DeepEqual(i.spec.Network, c.Network) &&
			reflect.DeepEqual(i.spec.Sources, sources) &&
			reflect.DeepEqual(i.spec.Continuity, bridge) &&
			(restored == nil || int(restored.Path.Slot) == i.spec.Allocation.Path.Slot) {
			return routingIntent(i), nil
		}
	}
	if len(rc.instances) >= 2 {
		return nil, errors.New("finish or roll back the pending routing transaction")
	}
	snapshot := rc.snapshot
	if restored != nil {
		var e error
		snapshot, _, e = rc.client.LoadRoutingSnapshot(
			ctx,
			restored.Snapshot.Generation,
			restored.Snapshot.SHA256,
		)
		if e != nil {
			return nil, e
		}
	}
	if restored != nil {
		// Exact journal snapshot remains authoritative until a confirmed publication.
	} else if !c.Routing.Registry.Enabled {
		snapshot = emptyRoutingSnapshot()
	} else if snapshot.Generation == 0 {
		// Initial list failure must not pretend that listed destinations are covered.
		rc.mu.Unlock()
		e := rc.refresh(ctx)
		rc.mu.Lock()
		if e != nil {
			return nil, e
		}
		snapshot = rc.snapshot
	}
	ref, e := rc.client.UploadSnapshot(ctx, snapshot)
	if e != nil {
		return nil, errors.New("registry helper publication failed")
	}
	var fixed *adapter.Path
	front := 0
	if restored != nil {
		p := restored.Path
		a := adapter.AllocatePath(adapter.DispatcherSourceID, "dispatcher", int(p.Slot))
		a.TransparentPort = int(p.Port)
		a.IPv6 = p.IPv6
		a.UDP = true
		fixed = &a
		front = int(restored.DNSFrontPort)
	}
	key := adapter.DispatcherSourceID + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	allocation, e := rc.Runtime.Adapters.ReserveDispatcherFor(
		key,
		fixed,
		front,
		c.Network.IPv6 == "proxy",
	)
	if e != nil {
		return nil, e
	}
	if restored != nil {
		allocation.FakePool = restored.FakePool
	} else {
		for _, other := range rc.instances {
			allocation.FakePool = 1 - other.spec.Allocation.FakePool
		}
	}
	spec := dispatch.Spec{
		Allocation: allocation,
		Network:    c.Network,
		Routing:    *c.Routing,
		Sources:    sources,
		Selected:   selected,
		Continuity: bridge,
	}
	if e = dispatch.Validate(spec); e != nil {
		rc.Runtime.Adapters.ForgetDispatcherFor(key)
		return nil, e
	}
	classifier, e := routing.NewClassifier(c.Routing.Exceptions, snapshot, nil)
	if e != nil {
		rc.Runtime.Adapters.ForgetDispatcherFor(key)
		return nil, e
	}
	rc.Runtime.Adapters.ReleaseDispatcherInputsFor(key)
	process, e := rc.client.StartDispatcher(ctx, spec, ref, rc.Observe)
	if e != nil {
		rc.Runtime.Adapters.ForgetDispatcherFor(key)
		return nil, e
	}
	i := &routingInstance{
		key:        key,
		config:     c,
		spec:       spec,
		ref:        ref,
		snapshot:   snapshot,
		process:    process,
		classifier: classifier,
		detector:   routing.NewDetector(c.Routing.Detection.Enabled),
		learned:    map[string]time.Time{},
		published:  1,
		selected:   selected,
	}
	rc.instances[allocation.Path.Slot] = i
	return routingIntent(i), nil
}

func routingIntent(i *routingInstance) *dataplane.SelectiveIntent {
	p := i.spec.Allocation.Path
	return &dataplane.SelectiveIntent{
		FakePool: i.spec.Allocation.FakePool,
		Path: dataplane.Path{
			SourceID: dataplane.SelectiveSourceID,
			Kind:     "tproxy",
			Slot:     uint16(p.Slot),
			Port:     uint16(p.TransparentPort),
			UDP:      true,
			IPv6:     p.IPv6,
		},
		DNSFrontPort:  uint16(i.spec.Allocation.DNSFrontPort),
		FakeIPv4:      dispatch.FakeIPv4,
		FakeIPv6:      dispatch.FakeIPv6,
		FailurePolicy: "direct",
		PolicyHash:    dispatch.PolicyHash(i.spec.Routing),
		Snapshot: dataplane.SelectiveSnapshotRef{
			Generation: i.ref.Generation,
			SHA256:     i.ref.SHA256,
		},
	}
}

func terminalRoutingTransaction(s helper.State) bool {
	return s.Transaction == nil || s.Transaction.State == "confirmed" ||
		s.Transaction.State == "rolled-back" ||
		s.Transaction.State == "failed"
}

func (rc *RoutingControl) Sync(ctx context.Context, s helper.State, selected string) error {
	rc.operations.Lock()
	defer rc.operations.Unlock()
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if terminalRoutingTransaction(s) {
		keep := 0
		if s.Committed != nil && s.Committed.Selective != nil {
			keep = int(s.Committed.Selective.Path.Slot)
		}
		for slot, old := range rc.instances {
			if slot == keep {
				continue
			}
			if e := old.process.Close(ctx); e != nil {
				return e
			}
			rc.Runtime.Adapters.ForgetDispatcherFor(old.key)
			delete(rc.instances, slot)
		}
	}
	effective := effectiveRoutingDesired(s)
	if effective == nil || effective.Selective == nil {
		rc.active = 0
		rc.state = "inactive"
		return nil
	}
	slot := int(effective.Selective.Path.Slot)
	i := rc.instances[slot]
	rc.active = slot
	if s.SelectiveEmergency || s.SelectiveEmergencyPending {
		rc.state = "emergency-direct"
		return nil
	}
	if s.Guarded {
		rc.state = "unavailable"
		return errors.New("routing requires a confirmed transaction")
	}
	if i == nil || !i.process.Alive() {
		rc.state = "unavailable"
		return errors.New("dispatcher unavailable")
	}
	rc.state = "ready"
	if s.MaintenanceJob != "" || s.MaintenanceHold {
		return nil
	}
	if i.selected != selected {
		status, e := rc.client.Dispatcher(
			ctx,
			helper.DispatcherRequest{Action: "select", Slot: slot, Selected: selected},
		)
		if e != nil {
			return e
		}
		i.selected = status.Selected
	}

	return nil
}

func (rc *RoutingControl) Tick(now time.Time) {
	rc.mu.Lock()
	if rc.closed || rc.busy {
		rc.mu.Unlock()
		return
	}
	i := rc.instances[rc.active]
	if i == nil || rc.state != "ready" || !i.process.Alive() {
		rc.mu.Unlock()
		return
	}
	rc.busy = true
	rc.wg.Add(1)
	rc.mu.Unlock()
	go func() {
		defer rc.wg.Done()
		defer func() { rc.mu.Lock(); rc.busy = false; rc.mu.Unlock() }()
		rc.run(now)
	}()
}

func (rc *RoutingControl) run(now time.Time) {
	rc.mu.Lock()
	i := rc.instances[rc.active]
	if i == nil || rc.state != "ready" {
		rc.mu.Unlock()
		return
	}
	refresh := i.spec.Routing.Registry.Enabled && !now.Before(rc.nextRefresh)
	rc.mu.Unlock()
	if refresh {
		_ = rc.refresh(rc.ctx)
	}
	rc.mu.Lock()
	// A background error disables only its subsystem; it never changes the state
	// consumed by the independent classifier/DNS watchdog.
	snapshot := i.snapshot
	if i.spec.Routing.Registry.Enabled && rc.snapshot.Generation > snapshot.Generation {
		snapshot = rc.snapshot
	}
	learned := i.detector.Learned(now)
	changed := snapshot.Generation != i.ref.Generation || !reflect.DeepEqual(learned, i.learned)

	runner, supported := rc.Runtime.Prober.(routingProbe)
	selected := i.selected
	rc.mu.Unlock()
	if changed {
		_ = rc.publish(rc.ctx, i, snapshot, learned)
	}
	if !supported || !i.spec.Routing.Detection.Enabled || selected == "" {
		return
	}
	before, e := rc.client.Dispatcher(
		rc.ctx,
		helper.DispatcherRequest{Action: "status", Slot: i.spec.Allocation.Path.Slot},
	)
	if e != nil || before.WANIdentity == "" {
		rc.mu.Lock()
		rc.detectorError = "WAN_identity_unavailable"
		rc.mu.Unlock()
		return
	}
	epoch := before.WANIdentity + ":" + selected
	candidate, check := i.detector.Next(now, epoch)
	if !check {
		return
	}

	direct := dispatcherProbePath(i.spec.Allocation.DirectPort)
	bypass := dispatcherProbePath(i.spec.Allocation.Path.ProxyPort)
	ctx, cancel := context.WithTimeout(rc.ctx, 2*time.Minute)
	defer cancel()
	round, e := runner.Compare(ctx, candidate.Domain, direct, bypass, i.config.Probes)
	if e == nil && round.Complete && len(round.Addresses) > 0 {
		want4, want6 := false, false
		for _, a := range round.Addresses {
			if a.IP.Is4() {
				want4 = true
			} else if a.IP.Is6() {
				want6 = true
			}
		}
		allowed := map[string]bool{}
		for _, id := range i.config.Routing.Detection.ControlTargetIDs {
			allowed[id] = true
		}
		for _, target := range i.config.Targets {
			if !allowed[target.ID] {
				continue
			}
			u, err := url.Parse(target.URL)
			if err != nil || u.Hostname() == candidate.Domain {
				continue
			}
			at, err := runner.ControlTLSForFamilies(
				ctx,
				target,
				direct,
				i.config.Probes,
				want4,
				want6,
			)
			if err == nil {
				round.ControlOK = true
				round.ControlAt = at
				break
			}
		}
	}
	after, identityErr := rc.client.Dispatcher(
		ctx,
		helper.DispatcherRequest{Action: "status", Slot: i.spec.Allocation.Path.Slot},
	)
	rc.mu.Lock()
	if identityErr != nil || after.WANIdentity != before.WANIdentity || i.selected != selected ||
		rc.instances[rc.active] != i ||
		rc.state != "ready" {
		round = routing.Round{}
	}
	if e != nil {
		rc.detectorError = "comparative_check_unavailable"
	} else {
		rc.detectorError = ""
	}
	changed = i.detector.Record(candidate, round, time.Now())
	learned = i.detector.Learned(time.Now())
	snapshot = i.snapshot
	rc.mu.Unlock()
	if changed {
		_ = rc.publish(ctx, i, snapshot, learned)
	}
}

func dispatcherProbePath(port int) adapter.Path {
	return adapter.Path{
		Kind:     "socks5",
		ProxyURL: &url.URL{Scheme: "socks5", Host: "127.0.0.1:" + strconv.Itoa(port)},
		UDP:      true,
		IPv6:     true,
	}
}

func (rc *RoutingControl) publish(
	ctx context.Context,
	i *routingInstance,
	snapshot routing.Snapshot,
	learned map[string]time.Time,
) error {
	rc.operations.Lock()
	defer rc.operations.Unlock()
	ref := i.ref
	var e error
	if snapshot.Generation != ref.Generation {
		ref, e = rc.client.UploadSnapshot(ctx, snapshot)
		if e != nil {
			return e
		}
	}
	names := make([]string, 0, len(learned))
	for d := range learned {
		names = append(names, d)
	}
	sort.Strings(names)
	classifier, e := routing.NewClassifier(i.spec.Routing.Exceptions, snapshot, learned)
	if e != nil {
		return e
	}
	status, e := rc.client.Dispatcher(
		ctx,
		helper.DispatcherRequest{
			Action:   "publish",
			Slot:     i.spec.Allocation.Path.Slot,
			Snapshot: &ref,
			Learned:  names,
		},
	)
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if e != nil {
		rc.detectorError = "rule_publication_failed"
		return e
	}
	i.ref, i.snapshot, i.classifier, i.learned, i.published = ref, snapshot, classifier, learned, status.PublishedGeneration
	return nil
}

func (rc *RoutingControl) Close(ctx context.Context) error {
	rc.mu.Lock()
	rc.closed = true
	rc.cancel()
	rc.mu.Unlock()
	rc.wg.Wait()
	rc.operations.Lock()
	defer rc.operations.Unlock()
	rc.mu.Lock()
	defer rc.mu.Unlock()
	var result error
	for slot, i := range rc.instances {
		if e := i.process.Close(ctx); e != nil {
			result = e
			continue
		}
		rc.Runtime.Adapters.ForgetDispatcherFor(i.key)
		delete(rc.instances, slot)
	}
	rc.active = 0
	rc.state = "inactive"
	if rc.Runtime.ctx.Err() == nil {
		rc.ctx, rc.cancel = context.WithCancel(rc.Runtime.ctx)
		rc.closed = false
	}
	return result
}

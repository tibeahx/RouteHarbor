package control

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/adapter"
	"github.com/tibeahx/RouteHarbor/internal/dataplane"
	"github.com/tibeahx/RouteHarbor/internal/helper"
	"github.com/tibeahx/RouteHarbor/internal/model"
	"github.com/tibeahx/RouteHarbor/internal/platform"
)

// NetworkCoordinator binds runtime adapter allocations to typed helper requests.
// Configuration saves alone never apply router rules.
type NetworkClient interface {
	Status(context.Context) (helper.State, error)
	Prepare(context.Context, dataplane.Desired) (helper.Transaction, error)
	Apply(context.Context, string, time.Duration) (helper.Transaction, error)
	Confirm(context.Context, string) (helper.Transaction, error)
	Rollback(context.Context, string) (helper.Transaction, error)
	Switch(context.Context, string) (helper.Transaction, error)
}

type NetworkCoordinator struct {
	Runtime           *Runtime
	Client            NetworkClient
	Platform          func(context.Context) (platform.Report, error)
	mu                sync.Mutex
	preparedRevision  uint64
	confirmedRevision uint64
	transaction       string
	timeout           time.Duration
	lastError         string
	initialized       bool
	nextInitialize    time.Time
}

func (n *NetworkCoordinator) Prepare(
	ctx context.Context,
	c model.Config,
	timeout int,
) (map[string]any, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if e := n.initializeLocked(ctx); e != nil {
		return nil, e
	}
	if timeout < 30 || timeout > 180 {
		return nil, errors.New("confirmation timeout must be 30 to 180 seconds")
	}
	// Finalize a previous successful helper confirmation before replacing its
	// transaction record. This also closes a transient SaveConfirmed failure.
	previous, e := n.Client.Status(ctx)
	if e != nil {
		return nil, e
	}
	if previous.Committed != nil && previous.Transaction != nil &&
		previous.Transaction.State == "confirmed" {
		saved, found, err := n.Runtime.Store.Checkpoint(previous.Transaction.ID)
		if err != nil {
			return nil, errors.New("previous confirmed checkpoint is unreadable")
		}
		if found {
			if !matchesDesired(saved, *previous.Committed) {
				return nil, errors.New("previous confirmed checkpoint does not match helper intent")
			}
			if err = n.Runtime.Store.SaveConfirmed(saved); err != nil {
				return nil, errors.New("previous confirmed checkpoint could not be finalized")
			}
		}
	}
	var report platform.Report
	if n.Platform == nil {
		report = platform.Detect(ctx)
	} else {
		report, e = n.Platform(ctx)
		if e != nil {
			return nil, errors.New("privileged platform discovery is unavailable")
		}
	}
	if !report.Supported {
		return nil, errors.New("unsupported platform")
	}
	if !c.Network.Enabled {
		return nil, errors.New("network disabled")
	}
	paths := []dataplane.Path{}
	carrierPaths := []adapter.Path{}
	unavailable := []string{}
	committed := map[string]bool{}
	if previous.Committed != nil {
		for _, path := range previous.Committed.Paths {
			committed[path.SourceID] = true
		}
	}
	n.Runtime.mu.Lock()
	selected := n.Runtime.decision.Selected
	n.Runtime.mu.Unlock()
	for _, s := range c.Sources {
		if !s.Enabled {
			continue
		}
		if e := n.Runtime.Adapters.Validate(s); e != nil {
			return nil, e
		}
		if e := n.Runtime.Adapters.Start(ctx, s); e != nil {
			if committed[s.ID] {
				return nil, errors.New(
					"retained source engine is unavailable; restore it before changing routing so existing flows cannot reach an untrusted input",
				)
			}
			if s.ID == selected {
				return nil, errors.New(
					"selected source is unavailable; select a healthy prepared source before applying routing",
				)
			}
			unavailable = append(unavailable, s.ID)
			continue
		}
		p, e := n.Runtime.Adapters.ProbePath(ctx, s)
		if e != nil {
			return nil, e
		}
		kind := s.Type
		carrierPaths = append(carrierPaths, p)
		if p.TransparentPort > 0 {
			kind = "tproxy"
		}
		paths = append(
			paths,
			dataplane.Path{
				SourceID:  s.ID,
				Kind:      kind,
				Slot:      uint16(p.Slot),
				Port:      uint16(p.TransparentPort),
				DNSPort:   uint16(p.DNSPort),
				Interface: p.Interface,
				UDP:       p.UDP,
				IPv6:      p.IPv6,
			},
		)
	}
	d := dataplane.Desired{
		Network:       c.Network,
		Paths:         paths,
		Unavailable:   unavailable,
		Selected:      selected,
		Fallback:      c.Policy.Fallback,
		BreakExisting: c.Policy.BreakExisting,
	}
	if continuityEnabled(c) {
		if n.Runtime.Continuity == nil {
			return nil, errors.New("continuity unavailable")
		}
		d.Continuity, e = n.Runtime.Continuity.Prepare(
			ctx,
			n.Runtime,
			c,
			carrierPaths,
			selected,
			nil,
		)
		if e != nil {
			return nil, e
		}
	}
	if model.SelectiveRouting(c) {
		if n.Runtime.Routing == nil {
			return nil, errors.New("selective routing unavailable")
		}
		d.Selective, e = n.Runtime.Routing.Prepare(ctx, c, carrierPaths, selected, nil)
		if e != nil {
			return nil, e
		}
	}
	if _, e := dataplane.Compile(d); e != nil {
		return nil, e
	}
	txn, e := n.Client.Prepare(ctx, d)
	if e != nil {
		return nil, e
	}
	if e = n.Runtime.Store.SaveCheckpoint(txn.ID, c); e != nil {
		_, _ = n.Client.Rollback(ctx, txn.ID)
		return nil, errors.New("configuration checkpoint could not be saved before apply")
	}
	// Only the current candidate checkpoint is needed now; the previous
	// confirmed configuration has its separate durable private snapshot.
	if e = n.Runtime.Store.PruneCheckpoints([]string{txn.ID}); e != nil {
		_, _ = n.Client.Rollback(ctx, txn.ID)
		return nil, errors.New("obsolete configuration checkpoints could not be pruned")
	}
	n.preparedRevision = c.Revision
	n.transaction = txn.ID
	n.timeout = time.Duration(timeout) * time.Second
	return toMap(txn), nil
}

func toMap(v any) map[string]any {
	b, _ := json.Marshal(v)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func (n *NetworkCoordinator) Action(
	ctx context.Context,
	id, action string,
) (map[string]any, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var txn helper.Transaction
	var e error
	switch action {
	case "apply":
		if n.transaction != id || n.preparedRevision != n.Runtime.Store.Get().Revision {
			return nil, errors.New("configuration changed; prepare again")
		}
		if continuityEnabled(n.Runtime.Store.Get()) {
			if n.Runtime.Continuity == nil {
				return nil, errors.New("continuity unavailable")
			}
			n.Runtime.Continuity.Refresh(ctx)
			n.Runtime.mu.Lock()
			selected := n.Runtime.decision.Selected
			n.Runtime.mu.Unlock()
			if selected != "" && !n.Runtime.Continuity.Ready(selected) {
				return nil, errors.New(
					"selected relay path is not ready; inspect continuity transports before applying",
				)
			}
		}
		txn, e = n.Client.Apply(ctx, id, n.timeout)
	case "confirm":
		if n.transaction != id || n.preparedRevision != n.Runtime.Store.Get().Revision {
			return nil, errors.New(
				"configuration changed or controller restarted; inspect and prepare again",
			)
		}
		txn, e = n.Client.Confirm(ctx, id)
		if e == nil {
			if e = n.Runtime.Store.SaveConfirmed(n.Runtime.Store.Get()); e != nil {
				return nil, errors.New(
					"network confirmed; configuration checkpoint could not be finalized",
				)
			}
			n.confirmedRevision = n.preparedRevision
			_ = n.Runtime.Store.PruneCheckpoints([]string{id})
		}
	case "rollback":
		txn, e = n.Client.Rollback(ctx, id)
		n.confirmedRevision = 0
	default:
		return nil, errors.New("unknown action")
	}
	if e != nil {
		return nil, e
	}
	if action == "confirm" || action == "rollback" {
		n.refreshRetained(ctx)
		if n.Runtime.Routing != nil {
			state, err := n.Client.Status(ctx)
			if err == nil && (state.Committed == nil || state.Committed.Selective == nil) {
				_ = n.Runtime.Routing.Close(ctx)
				_ = n.Runtime.Adapters.Stop(ctx, dataplane.SelectiveSourceID)
			}
		}
		if n.Runtime.Continuity != nil {
			state, err := n.Client.Status(ctx)
			if err == nil && (state.Committed == nil || state.Committed.Continuity == nil) {
				_ = n.Runtime.Continuity.Close(ctx)
				_ = n.Runtime.Adapters.Stop(ctx, adapter.ContinuitySourceID)
			}
		}
	}
	return toMap(txn), nil
}

func (n *NetworkCoordinator) Status(ctx context.Context, id string) (map[string]any, error) {
	s, e := n.Client.Status(ctx)
	if e != nil {
		return nil, e
	}
	if s.Transaction == nil || s.Transaction.ID != id {
		return nil, errors.New("transaction not found")
	}
	return toMap(s.Transaction), nil
}

func (n *NetworkCoordinator) Current(ctx context.Context) (map[string]any, error) {
	s, e := n.Client.Status(ctx)
	if e != nil {
		return nil, e
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	effective := effectiveRoutingDesired(s)
	out := map[string]any{
		"applied": effective != nil && !s.Guarded,
		"guarded": s.Guarded,
		"emergency_direct": effective != nil && effective.Selective != nil &&
			(s.SelectiveEmergency || s.SelectiveEmergencyPending) &&
			!s.MaintenanceHold &&
			s.MaintenanceJob == "",
		"confirmed_for_current_config": n.confirmedRevision == n.Runtime.Store.Get().Revision,
		"last_error":                   n.lastError,
		"maintenance_job":              s.MaintenanceJob,
		"maintenance_hold":             s.MaintenanceHold,
	}
	if s.MaintenanceHold {
		out["confirmed_for_current_config"] = false
		out["last_error"] = "maintenance_requires_confirmed_routing"
	}
	if effective != nil {
		out["selected"] = effective.Selected
		out["unavailable_sources"] = append([]string{}, effective.Unavailable...)
	}
	if s.Transaction != nil {
		out["transaction_id"] = s.Transaction.ID
		out["transaction_state"] = s.Transaction.State
		out["deadline"] = s.Transaction.Deadline
		out["flow_termination"] = s.Transaction.FlowTermination
		if s.Transaction.State == "confirmed" && s.Transaction.FlowTermination == "failed" {
			out["last_error"] = s.Transaction.ErrorCode
		}
	}
	return out, nil
}

// Apply switches packet ingress before confirmation promotes Candidate to
// Committed. Readiness and classification must describe that actual ingress;
// prepared or incomplete transitions continue to retain the committed policy.
func effectiveRoutingDesired(s helper.State) *dataplane.Desired {
	if s.Transaction != nil && s.Transaction.State == "applied" {
		return &s.Transaction.Candidate
	}
	return s.Committed
}

// Sync applies only choices inside the already-confirmed adapter allocation set.
// A modified configuration requires a fresh transaction; a restart restores only
// a private configuration snapshot that matches the helper journal.
func (n *NetworkCoordinator) Sync(ctx context.Context) {
	if n.Runtime.Continuity != nil {
		n.Runtime.Continuity.Refresh(ctx)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.initialized {
		if time.Now().Before(n.nextInitialize) {
			return
		}
		if n.initializeLocked(ctx) != nil {
			return
		}
	}
	c := n.Runtime.Store.Get()
	n.Runtime.mu.Lock()
	selected := n.Runtime.decision.Selected
	n.Runtime.mu.Unlock()
	s, e := n.Client.Status(ctx)
	if e != nil {
		n.lastError = "helper_unavailable"
		return
	}
	if s.MaintenanceJob != "" || s.MaintenanceHold {
		n.lastError = "maintenance_requires_confirmed_routing"
		return
	}
	effective := effectiveRoutingDesired(s)
	if effective != nil && effective.Selective != nil {
		// A draft configuration must not drive a committed selector. Continue
		// observing its classifier and preserve any journaled emergency state.
		if n.confirmedRevision != c.Revision ||
			s.Transaction != nil && s.Transaction.State == "applied" {
			selected = effective.Selected
		}
		if slices.Contains(effective.Unavailable, selected) {
			n.lastError = "recovered_source_requires_routing_prepare"
			return
		}
		if n.Runtime.Routing == nil || n.Runtime.Routing.Sync(ctx, s, selected) != nil {
			n.lastError = "selective_dispatcher_unavailable"
			return
		}
		if s.SelectiveEmergency || s.SelectiveEmergencyPending {
			n.lastError = "selective_emergency_direct"
			return
		}
		if s.Guarded {
			n.lastError = "selective_requires_confirmed_routing"
			return
		}
		if effective.Continuity != nil && (n.Runtime.Continuity == nil ||
			n.Runtime.Continuity.EnsureRunning(ctx) != nil ||
			n.Runtime.Continuity.Select(ctx, n.Runtime, selected) != nil) {
			n.lastError = "continuity_worker_unavailable"
			return
		}
		n.lastError = ""
		return
	}
	if n.Runtime.Routing != nil {
		_ = n.Runtime.Routing.Sync(ctx, s, selected)
	}
	if n.confirmedRevision != c.Revision {
		return
	}
	if s.Committed != nil && s.Committed.Continuity != nil {
		if s.Guarded {
			n.lastError = "continuity_requires_confirmed_routing"
			return
		}
		if n.Runtime.Continuity == nil || n.Runtime.Continuity.EnsureRunning(ctx) != nil ||
			n.Runtime.Continuity.Select(ctx, n.Runtime, selected) != nil {
			n.lastError = "continuity_worker_unavailable"
		} else {
			n.lastError = ""
		}
		return
	}
	if s.Committed == nil || (s.Committed.Selected == selected && !s.Guarded) {
		return
	}
	if slices.Contains(s.Committed.Unavailable, selected) {
		n.lastError = "recovered_source_requires_routing_prepare"
		return
	}
	if _, e = n.Client.Switch(ctx, selected); e != nil {
		n.lastError = "path_switch_failed"
	} else {
		n.lastError = ""
	}
}

// ValidateChange protects live and rollback engine allocations while configuration edits are staged.
func (n *NetworkCoordinator) ValidateChange(ctx context.Context, old, next model.Config) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	state, e := n.Client.Status(ctx)
	if e != nil {
		return errors.New("network state unavailable; retry before changing configuration")
	}
	if state.Transaction != nil {
		switch state.Transaction.State {
		case "prepared", "applying", "applied", "rolling-back":
			return errors.New(
				"confirm or roll back the pending network transaction before editing configuration",
			)
		}
	}
	if state.Committed != nil && state.Committed.Network.Enabled && !next.Network.Enabled {
		return errors.New(
			"active routing requires explicit decommission: use preserve-closed or restore-direct through trusted local access",
		)
	}
	if state.Committed != nil && state.Committed.Continuity != nil && continuityEnabled(next) {
		if !reflect.DeepEqual(state.Committed.Continuity.Config, *next.Continuity) ||
			!sameContinuitySources(old.Sources, next.Sources) {
			return errors.New(
				"disable and confirm continuity before changing its relay, limits or prepared sources",
			)
		}
	}
	retained := map[string]bool{}
	if state.Committed != nil {
		for _, p := range state.Committed.Paths {
			retained[p.SourceID] = true
		}
	}
	n.Runtime.retain(retained)
	if len(retained) == 0 {
		return nil
	}
	before := state.Committed.Network
	after := next.Network
	before.Enabled = after.Enabled
	if !reflect.DeepEqual(before, after) {
		return errors.New(
			"remove and confirm active routing paths before changing their DNS, IPv6 or interface settings",
		)
	}
	for id := range retained {
		a, known := n.Runtime.endpointFor(id)
		for _, b := range next.Sources {
			if b.ID == id && (!known || !sameSourceEndpoint(a, b)) {
				return errors.New(
					"remove and confirm this source from active routing before changing its connection settings",
				)
			}
		}
	}
	return nil
}

func (n *NetworkCoordinator) refreshRetained(ctx context.Context) {
	state, e := n.Client.Status(ctx)
	if e != nil {
		return
	}
	ids := map[string]bool{}
	if state.Committed != nil {
		for _, p := range state.Committed.Paths {
			ids[p.SourceID] = true
		}
	}
	n.Runtime.retain(ids)
}

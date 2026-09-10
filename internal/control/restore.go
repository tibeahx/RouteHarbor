package control

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/adapter"
	"github.com/tibeahx/RouteHarbor/internal/dataplane"
	"github.com/tibeahx/RouteHarbor/internal/dispatch"
	"github.com/tibeahx/RouteHarbor/internal/helper"
	"github.com/tibeahx/RouteHarbor/internal/model"
)

// Initialize restores confirmed marks and listener allocations before allowing
// scheduled probes. Failure leaves the API available and reports a stable error.
func (n *NetworkCoordinator) Initialize(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.initializeLocked(ctx)
}

func (n *NetworkCoordinator) initializeLocked(ctx context.Context) error {
	if n.initialized {
		return nil
	}
	n.Runtime.setPathBlock("restoring_network_paths")
	state, e := n.Client.Status(ctx)
	if e != nil {
		return n.restoreFailure("helper_unavailable")
	}
	if state.MaintenanceJob != "" {
		return n.restoreFailure("maintenance_active")
	}
	current := n.Runtime.Store.Get()
	confirmed := current
	if state.Committed != nil &&
		(len(state.Committed.Paths) > 0 || len(state.Committed.Unavailable) > 0 || state.Committed.Selective != nil) {
		found := false
		if state.Transaction != nil && state.Transaction.State == "confirmed" {
			if saved, ok, err := n.Runtime.Store.Checkpoint(state.Transaction.ID); err != nil {
				return n.restoreFailure("checkpoint_unreadable")
			} else if ok {
				confirmed = saved
				found = true
			}
		}
		if !found {
			if saved, ok, err := n.Runtime.Store.Confirmed(); err != nil {
				return n.restoreFailure("checkpoint_unreadable")
			} else if ok {
				confirmed = saved
				found = true
			}
		}
		if !found || !matchesDesired(confirmed, *state.Committed) {
			recovered, ok, err := n.maintenanceRollbackCheckpoint(state)
			if err != nil {
				return n.restoreFailure("maintenance_checkpoint_recovery_failed")
			}
			if !ok {
				return n.restoreFailure("confirmed_configuration_missing")
			}
			confirmed = recovered
		}
	}
	sources := map[string]model.Source{}
	allocations := map[string]adapter.Path{}
	retained := map[string]bool{}
	collect := func(c model.Config, d dataplane.Desired) error {
		byID := map[string]model.Source{}
		for _, s := range c.Sources {
			byID[s.ID] = s
		}
		for _, p := range d.Paths {
			s, ok := byID[p.SourceID]
			if !ok {
				return errors.New("restored source missing")
			}
			kind := s.Type
			if kind == "socks5" || kind == "http-connect" || kind == "sing-box" || kind == "xray" {
				kind = "tproxy"
			}
			if kind != p.Kind {
				return errors.New("restored source type mismatch")
			}
			a := adapter.Path{
				SourceID:        s.ID,
				Kind:            s.Type,
				Slot:            int(p.Slot),
				Mark:            adapter.Mark(int(p.Slot)),
				Queue:           uint16(21000 + p.Slot),
				TransparentPort: int(p.Port),
				DNSPort:         int(p.DNSPort),
				Interface:       p.Interface,
				UDP:             p.UDP,
				IPv6:            p.IPv6,
			}
			if old, exists := allocations[s.ID]; exists && old != a {
				return errors.New("restored source allocation conflict")
			}
			sources[s.ID] = s
			allocations[s.ID] = a
		}
		return nil
	}
	network := current.Network
	if state.Committed != nil {
		network = state.Committed.Network
		if e = collect(confirmed, *state.Committed); e != nil {
			return n.restoreFailure("committed_allocation_mismatch")
		}
		for _, p := range state.Committed.Paths {
			retained[p.SourceID] = true
		}
	}
	pending := state.Transaction != nil &&
		(state.Transaction.State == "prepared" || state.Transaction.State == "applying" || state.Transaction.State == "applied" || state.Transaction.State == "rolling-back")
	if pending {
		saved, ok, err := n.Runtime.Store.Checkpoint(state.Transaction.ID)
		if err != nil || !ok || !matchesDesired(saved, state.Transaction.Candidate) {
			return n.restoreFailure("pending_configuration_missing")
		}
		if len(allocations) > 0 && !reflect.DeepEqual(network, saved.Network) {
			return n.restoreFailure("pending_network_mismatch")
		}
		network = saved.Network
		if err = collect(saved, state.Transaction.Candidate); err != nil {
			return n.restoreFailure("pending_allocation_mismatch")
		}
		n.transaction = state.Transaction.ID
		n.preparedRevision = saved.Revision
		n.timeout = 120 * time.Second
	}
	if state.Committed != nil && state.Transaction != nil &&
		state.Transaction.State == "confirmed" &&
		matchesDesired(confirmed, *state.Committed) {
		if e = n.Runtime.Store.SaveConfirmed(confirmed); e != nil {
			return n.restoreFailure("confirmed_checkpoint_write_failed")
		}
	}
	if e = n.Runtime.Adapters.ConfigureNetwork(
		ctx,
		network.DNSResolver,
		network.IPv6 == "proxy",
	); e != nil {
		return n.restoreFailure("engine_teardown_failed")
	}
	list := []model.Source{}
	paths := []adapter.Path{}
	for id, s := range sources {
		list = append(list, s)
		paths = append(paths, allocations[id])
	}
	if e = n.Runtime.Adapters.RestoreAllocations(ctx, list, paths); e != nil {
		return n.restoreFailure("engine_input_restore_failed")
	}
	// If a later worker restore fails (for example while its optional package is
	// being installed), release this attempt's freshly recreated inputs. A retry
	// must not fail forever because RestoreAllocations requires an empty manager.
	restoreComplete := false
	defer func() {
		if restoreComplete {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if n.Runtime.Routing != nil {
			_ = n.Runtime.Routing.Close(cleanup)
		}
		if n.Runtime.Continuity != nil {
			_ = n.Runtime.Continuity.Close(cleanup)
		}
		_ = n.Runtime.Adapters.Close(cleanup)
	}()
	// DNS follows the effective helper-owned network, including after an offline
	// configuration edit. The current draft must not enable direct DNS for a
	// restored managed path.
	if prober, ok := n.Runtime.Prober.(interface{ ConfigureDNS(bool, string) }); ok {
		prober.ConfigureDNS(network.Enabled, network.DNSResolver)
	}
	n.Runtime.mu.Lock()
	n.Runtime.retained = retained
	for id, s := range sources {
		present := false
		for _, v := range current.Sources {
			if v.ID == id && v.Enabled && sameSourceEndpoint(s, v) {
				present = true
			}
		}
		if !present {
			n.Runtime.retired[id] = s
		}
	}
	n.Runtime.mu.Unlock()
	// Source-specific readiness is measured by probes; one missing engine does not
	// substitute another input or suppress probes for a healthy direct path.
	for _, s := range list {
		_ = n.Runtime.Adapters.Start(ctx, s)
	}
	// The old process's endpoint sockets cannot be restored. Recreate only the
	// exact helper-owned listener allocation; the journal's guard remains in
	// force until a new network transaction is confirmed.
	var continuityIntent *dataplane.ContinuityIntent
	continuityConfig := confirmed
	selected := ""
	if state.Committed != nil {
		continuityIntent = state.Committed.Continuity
		selected = state.Committed.Selected
	}
	if pending && state.Transaction.Candidate.Continuity != nil {
		continuityIntent = state.Transaction.Candidate.Continuity
		continuityConfig, _, _ = n.Runtime.Store.Checkpoint(state.Transaction.ID)
		selected = state.Transaction.Candidate.Selected
	}
	if continuityIntent != nil {
		if n.Runtime.Continuity == nil {
			return n.restoreFailure("continuity_worker_unavailable")
		}
		carrierPaths := []adapter.Path{}
		for _, source := range list {
			p, err := n.Runtime.Adapters.ProbePath(ctx, source)
			if err == nil {
				carrierPaths = append(carrierPaths, p)
			}
		}
		if _, err := n.Runtime.Continuity.Prepare(
			ctx,
			n.Runtime,
			continuityConfig,
			carrierPaths,
			selected,
			continuityIntent,
		); err != nil {
			return n.restoreFailure("continuity_input_restore_failed")
		}
	}
	// Restore both committed and staged classifiers. Prepare only recreates the
	// exact recorded listeners; the helper's journal continues to decide which
	// ingress is active, including a boot-time emergency-direct guard.
	restoreSelective := func(c model.Config, d dataplane.Desired) error {
		if d.Selective == nil {
			return nil
		}
		if n.Runtime.Routing == nil {
			return errors.New("selective dispatcher unavailable")
		}
		carriers := []adapter.Path{}
		for _, path := range d.Paths {
			source, ok := sources[path.SourceID]
			if !ok {
				return errors.New("selective source checkpoint missing")
			}
			prepared, err := n.Runtime.Adapters.ProbePath(ctx, source)
			if err != nil {
				return err
			}
			carriers = append(carriers, prepared)
		}
		_, err := n.Runtime.Routing.Prepare(ctx, c, carriers, d.Selected, d.Selective)
		return err
	}
	if state.Committed != nil {
		if err := restoreSelective(confirmed, *state.Committed); err != nil {
			return n.restoreFailure("selective_input_restore_failed")
		}
	}
	if pending {
		saved, _, _ := n.Runtime.Store.Checkpoint(state.Transaction.ID)
		if err := restoreSelective(saved, state.Transaction.Candidate); err != nil {
			return n.restoreFailure("selective_pending_restore_failed")
		}
	}
	n.lastError = ""
	n.Runtime.setPathBlock("")
	if state.Committed != nil &&
		(len(state.Committed.Paths) > 0 || len(state.Committed.Unavailable) > 0 || state.Committed.Selective != nil) &&
		reflect.DeepEqual(confirmed, current) {
		n.confirmedRevision = current.Revision
	}

	n.initialized = true
	restoreComplete = true
	return nil
}

// A maintenance recovery transaction can intentionally roll an existing direct
// fallback back to closed. Accept that one journal-proven policy change without
// weakening ordinary checkpoint matching or modifying the current draft.
func (n *NetworkCoordinator) maintenanceRollbackCheckpoint(
	state helper.State,
) (model.Config, bool, error) {
	t := state.Transaction
	if !state.MaintenanceHold || !state.Guarded || state.MaintenanceJob != "" ||
		state.Committed == nil || t == nil || t.State != "rolled-back" ||
		state.Committed.Selected != "" || state.Committed.Fallback != "closed" ||
		!reflect.DeepEqual(t.Rollback, *state.Committed) {
		return model.Config{}, false, nil
	}
	closed := t.Candidate
	closed.Selected = ""
	closed.Fallback = "closed"
	if !reflect.DeepEqual(closed, *state.Committed) {
		return model.Config{}, false, nil
	}
	saved, found, err := n.Runtime.Store.Checkpoint(t.ID)
	if err != nil || !found {
		return model.Config{}, false, err
	}
	if !matchesDesired(saved, t.Candidate) {
		return model.Config{}, false, nil
	}
	saved.Policy.Fallback = "closed"
	if !matchesDesired(saved, *state.Committed) {
		return model.Config{}, false, nil
	}
	if err := n.Runtime.Store.SaveConfirmed(saved); err != nil {
		return model.Config{}, false, err
	}
	return saved, true, nil
}

func (n *NetworkCoordinator) restoreFailure(code string) error {
	n.lastError = code
	n.nextInitialize = time.Now().Add(10 * time.Second)
	n.Runtime.setPathBlock(code)
	return errors.New(code)
}

func (r *Runtime) setPathBlock(code string) {
	r.mu.Lock()
	r.pathBlock = code
	r.mu.Unlock()
}

func matchesDesired(c model.Config, d dataplane.Desired) bool {
	if model.SelectiveRouting(c) != (d.Selective != nil) ||
		d.Selective != nil &&
			(d.Selective.PolicyHash != routingConfigHash(c) || d.Selective.FailurePolicy != c.Routing.FailurePolicy) {
		return false
	}
	if continuityEnabled(c) != (d.Continuity != nil) ||
		d.Continuity != nil && !reflect.DeepEqual(*c.Continuity, d.Continuity.Config) {
		return false
	}
	if !reflect.DeepEqual(c.Network, d.Network) || c.Policy.Fallback != d.Fallback ||
		c.Policy.BreakExisting != d.BreakExisting {
		return false
	}
	sources := map[string]model.Source{}
	for _, s := range c.Sources {
		if s.Enabled {
			sources[s.ID] = s
		}
	}
	if len(sources) != len(d.Paths)+len(d.Unavailable) {
		return false
	}
	seen := map[string]bool{}
	for _, id := range d.Unavailable {
		if _, exists := sources[id]; !exists || seen[id] || id == d.Selected {
			return false
		}
		seen[id] = true
	}
	for _, p := range d.Paths {
		s, ok := sources[p.SourceID]
		if !ok || seen[p.SourceID] {
			return false
		}
		seen[p.SourceID] = true
		kind := s.Type
		if kind == "sing-box" || kind == "xray" || kind == "socks5" || kind == "http-connect" {
			kind = "tproxy"
		}
		if p.Kind != kind {
			return false
		}
	}
	return true
}

// routingConfigHash binds private checkpoints to the public routing policy while
// bulk registry generations remain independently published outside the journal.
func routingConfigHash(c model.Config) string {
	if !model.SelectiveRouting(c) {
		return ""
	}
	return dispatch.PolicyHash(*c.Routing)
}

package control

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/dataplane"
	"github.com/tibeahx/OpenRHP/internal/model"
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
	current := n.Runtime.Store.Get()
	confirmed := current
	if state.Committed != nil &&
		(len(state.Committed.Paths) > 0 || len(state.Committed.Unavailable) > 0) {
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
			return n.restoreFailure("confirmed_configuration_missing")
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
	n.lastError = ""
	n.Runtime.setPathBlock("")
	if state.Committed != nil &&
		(len(state.Committed.Paths) > 0 || len(state.Committed.Unavailable) > 0) &&
		reflect.DeepEqual(confirmed, current) {
		n.confirmedRevision = current.Revision
	}

	n.initialized = true
	return nil
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

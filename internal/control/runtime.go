package control

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"reflect"
	"sync"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/config"
	"github.com/tibeahx/OpenRHP/internal/model"
	"github.com/tibeahx/OpenRHP/internal/probe"
	"github.com/tibeahx/OpenRHP/internal/selection"
)

type Prober interface {
	Run(
		context.Context,
		model.Source,
		[]model.Target,
		model.ProbeSettings,
		bool,
	) (model.Measurement, error)
}
type Runtime struct {
	Store          *config.Store
	Adapters       *adapter.Manager
	Prober         Prober
	Network        *NetworkCoordinator
	Continuity     *ContinuityControl
	Routing        *RoutingControl
	Journal        *Journal
	mu             sync.Mutex
	selector       *selection.Selector
	configRevision uint64
	decision       model.Decision
	events         []model.Decision
	active         map[string]bool
	probeCancels   map[string]context.CancelFunc
	retained       map[string]bool
	retired        map[string]model.Source
	pathBlock      string
	next           map[string]time.Time
	speedAt        map[string]time.Time
	currentConfig  model.Config
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
}

func New(store *config.Store, adapters *adapter.Manager, journal *Journal) *Runtime {
	ctx, cancel := context.WithCancel(context.Background())
	c := store.Get()
	s := selection.New(c.Policy)
	s.SetTargets(selectionTargets(c))
	s.SetHistoryLimit(c.Probes.HistoryLimit)
	runner := probe.NewRunner(adapters)
	runner.ConfigureDNS(c.Network.Enabled, c.Network.DNSResolver)
	return &Runtime{
		Store:          store,
		Adapters:       adapters,
		Prober:         runner,
		Journal:        journal,
		selector:       s,
		configRevision: c.Revision,
		currentConfig:  c,
		active:         map[string]bool{},
		probeCancels:   map[string]context.CancelFunc{},
		retained:       map[string]bool{},
		retired:        map[string]model.Source{},
		next:           map[string]time.Time{},
		speedAt:        map[string]time.Time{},
		ctx:            ctx,
		cancel:         cancel,
		events:         []model.Decision{},
	}
}

func (r *Runtime) Start() {
	r.wg.Go(func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-r.ctx.Done():
				return
			case now := <-t.C:
				r.tick(now)
				if r.Routing != nil {
					r.Routing.Tick(now)
				}
				if r.Network != nil {
					ctx, cancel := context.WithTimeout(r.ctx, 10*time.Second)
					r.Network.Sync(ctx)
					cancel()
				}
			}
		}
	})
}

func (r *Runtime) Close() {
	r.cancel()
	r.wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if r.Routing != nil {
		_ = r.Routing.Close(ctx)
	}
	if r.Continuity != nil {
		_ = r.Continuity.Close(ctx)
	}
	_ = r.Adapters.Close(ctx)
}

func (r *Runtime) Reload() {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.Store.Get()
	if c.Revision == r.configRevision {
		return
	}
	for _, cancel := range r.probeCancels {
		cancel()
	}
	ctx, cancel := context.WithTimeout(r.ctx, 10*time.Second)
	configureErr := r.Adapters.ConfigureNetwork(
		ctx,
		c.Network.DNSResolver,
		c.Network.IPv6 == "proxy",
	)
	cancel()
	if configureErr != nil {
		r.pathBlock = "engine_reconfiguration_failed"
		return
	}
	if r.pathBlock == "engine_reconfiguration_failed" {
		r.pathBlock = ""
	}
	if prober, ok := r.Prober.(interface{ ConfigureDNS(bool, string) }); ok {
		prober.ConfigureDNS(c.Network.Enabled, c.Network.DNSResolver)
	}
	r.selector = selection.New(c.Policy)
	r.selector.SetTargets(selectionTargets(c))
	r.selector.SetHistoryLimit(c.Probes.HistoryLimit)
	// Revoking/changing a source must discard its old prepared endpoint and metrics.
	for _, old := range r.currentConfig.Sources {
		keep := false
		for _, s := range c.Sources {
			if s.ID == old.ID && sameSourceEndpoint(s, old) && s.Enabled {
				keep = true
				break
			}
		}
		if !keep && r.retained[old.ID] {
			r.retired[old.ID] = old
		}
		if !keep && !r.retained[old.ID] {
			ctx, cancel := context.WithTimeout(r.ctx, 4*time.Second)
			_ = r.Adapters.Stop(ctx, old.ID)
			cancel()
		}
	}
	r.configRevision = c.Revision
	r.currentConfig = c
	r.next = map[string]time.Time{}
	r.speedAt = map[string]time.Time{}
	r.decision = model.Decision{}
}

func (r *Runtime) tick(now time.Time) {
	r.Reload()
	c := r.Store.Get()
	r.mu.Lock()
	r.evaluateLocked(c, now)
	r.mu.Unlock()
	if len(selectionTargets(c)) == 0 {
		return
	}
	launched := 0
	for _, s := range c.Sources {
		if launched >= c.Probes.Concurrency {
			break
		}
		if !s.Enabled {
			continue
		}
		r.mu.Lock()
		degradation := r.degradationSpeedDueLocked(s.ID, c, now)
		due := !now.Before(r.next[s.ID]) || degradation
		space := len(r.active) < c.Probes.Concurrency
		busy := r.active[s.ID]
		speed := degradation || r.speedAt[s.ID].IsZero() ||
			now.Sub(r.speedAt[s.ID]) >= time.Duration(c.Probes.SpeedIntervalSeconds)*time.Second
		r.mu.Unlock()
		if due && space && !busy {
			launched++
			r.wg.Add(1)
			go func(id string, speed bool) { defer r.wg.Done(); _, _ = r.Probe(r.ctx, id, speed) }(
				s.ID,
				speed,
			)
		}
	}
}

func (r *Runtime) Probe(ctx context.Context, id string, speed bool) (model.Measurement, error) {
	r.mu.Lock()
	blocked := r.pathBlock
	r.mu.Unlock()
	if blocked != "" {
		return model.Measurement{}, errors.New(blocked)
	}
	c := r.Store.Get()
	var source *model.Source
	for i := range c.Sources {
		if c.Sources[i].ID == id {
			s := c.Sources[i]
			source = &s
			break
		}
	}
	if source == nil || !source.Enabled {
		return model.Measurement{}, errors.New("source_missing_or_disabled")
	}
	if len(selectionTargets(c)) == 0 {
		return model.Measurement{}, errors.New("no_probe_targets")
	}
	r.mu.Lock()
	if r.pathBlock != "" {
		code := r.pathBlock
		r.mu.Unlock()
		return model.Measurement{}, errors.New(code)
	}
	if c.Revision != r.configRevision {
		r.mu.Unlock()
		return model.Measurement{}, errors.New("configuration_changed_before_probe")
	}
	if r.active[id] || len(r.active) >= c.Probes.Concurrency {
		r.mu.Unlock()
		return model.Measurement{}, ErrQueueFull
	}
	r.active[id] = true
	r.next[id] = time.Now().Add(time.Duration(c.Probes.OtherIntervalSeconds) * time.Second)
	probeCtx, cancel := context.WithCancel(ctx)
	r.probeCancels[id] = cancel
	r.mu.Unlock()
	defer func() { r.mu.Lock(); delete(r.active, id); delete(r.probeCancels, id); r.mu.Unlock() }()
	// Context cancellation from the server shutdown also terminates explicitly requested jobs.
	stop := context.AfterFunc(r.ctx, cancel)
	defer func() { stop(); cancel() }()
	var m model.Measurement
	e := r.Adapters.Start(probeCtx, *source)
	if e == nil {
		if continuityEnabled(c) {
			if r.Continuity == nil {
				e = errors.New("continuity unavailable")
			} else {
				m, e = r.Continuity.Probe(probeCtx, r, c, *source)
			}
		} else {
			m, e = r.Prober.Run(probeCtx, *source, c.Targets, c.Probes, speed)
		}
	}
	if e != nil && len(m.Resources) == 0 {
		m = model.Measurement{
			SourceID:  id,
			At:        time.Now().UTC(),
			Path:      source.Type,
			Resources: []model.ResourceResult{},
		}
		for _, t := range selectionTargets(c) {
			m.Resources = append(
				m.Resources,
				model.ResourceResult{
					TargetID:  t.ID,
					Required:  t.Required,
					ErrorCode: "path_unavailable",
				},
			)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Store.Get().Revision != c.Revision {
		return m, errors.New("configuration_changed_during_probe")
	}
	r.selector.Observe(m)
	r.evaluateLocked(c, time.Now())
	interval := c.Probes.OtherIntervalSeconds
	if r.decision.Selected == id {
		interval = c.Probes.ActiveIntervalSeconds
	}
	jitter := .85 + rand.Float64()*.3
	r.next[id] = time.Now().Add(time.Duration(float64(interval) * jitter * float64(time.Second)))
	if speed {
		r.speedAt[id] = time.Now()
	}
	return m, e
}

func (r *Runtime) evaluateLocked(c model.Config, now time.Time) {
	sources := c.Sources
	if model.SelectiveRouting(c) && !continuityEnabled(c) {
		sources = make([]model.Source, 0, len(c.Sources))
		for _, source := range c.Sources {
			if source.Type != "direct" {
				sources = append(sources, source)
			}
		}
	}
	d := r.selector.Evaluate(sources, now)
	r.decision = d
	if d.Changed {
		r.events = append(r.events, d)
		if len(r.events) > 64 {
			r.events = append([]model.Decision(nil), r.events[len(r.events)-64:]...)
		}
	}
}

func (r *Runtime) Status() map[string]any {
	c := r.Store.Get()
	continuityStatus := map[string]any{"status": "Disabled", "qualified": false}
	if r.Continuity != nil {
		continuityStatus = r.Continuity.Public()
	}
	continuityStatus["enabled"] = continuityEnabled(c)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evaluateLocked(c, time.Now())
	health := r.selector.Health(time.Now())
	events := append([]model.Decision{}, r.events...)
	return map[string]any{
		"continuity":                continuityStatus,
		"version":                   "0.1.0-dev",
		"project":                   "OpenRHP",
		"revision":                  c.Revision,
		"role":                      c.Role,
		"policy":                    c.Policy,
		"decision":                  r.decision,
		"health":                    health,
		"switches":                  events,
		"network_configured":        c.Network.Enabled,
		"probes_running":            len(r.active),
		"path_initialization_error": r.pathBlock,
	}
}

func (r *Runtime) History(id string) []model.Measurement {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.selector.History(id)
}

func (r *Runtime) EngineStatus() []adapter.Status {
	out := []adapter.Status{}
	for _, s := range r.Store.Get().Sources {
		out = append(out, r.Adapters.Status(s.ID))
	}
	return out
}

func (r *Runtime) SnapshotJSON() []byte {
	b, _ := json.Marshal(r.Status())
	return b
}

func sameSourceEndpoint(a, b model.Source) bool {
	return a.ID == b.ID && a.Type == b.Type && reflect.DeepEqual(a.Settings, b.Settings)
}

// retain delays teardown of removed sources until a network confirmation has removed their live and rollback allocations.
func (r *Runtime) retain(ids map[string]bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.retained = ids
	current := r.Store.Get()
	configured := map[string]bool{}
	for _, s := range current.Sources {
		if s.Enabled {
			configured[s.ID] = true
		}
	}
	for id := range r.retired {
		if !configured[id] && !ids[id] {
			ctx, cancel := context.WithTimeout(r.ctx, 4*time.Second)
			_ = r.Adapters.Stop(ctx, id)
			cancel()
			delete(r.retired, id)
		}
	}
}

func (r *Runtime) endpointFor(id string) (model.Source, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.retired[id]; ok {
		return s, true
	}
	for _, s := range r.currentConfig.Sources {
		if s.ID == id {
			return s, true
		}
	}
	return model.Source{}, false
}

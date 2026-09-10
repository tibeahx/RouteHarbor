// Package selection makes deterministic path decisions from independent probe
// measurements. It never mutates routes or infers Wi-Fi health from WAN probes.
package selection

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/model"
)

const alpha = 0.3

type observation struct {
	health         model.SourceHealth
	history        []model.Measurement
	failedRequired int
	fullFailure    bool
	needsRecovery  bool
	speedAt        time.Time
	lossAt         time.Time
}

type Selector struct {
	mu              sync.Mutex
	policy          model.Policy
	sources         map[string]*observation
	required        map[string]bool
	targetSignature string
	historyLimit    int
	selected        string
	selectedAt      time.Time
	lastSwitch      time.Time
	candidate       string
	confirmations   int
	candidateAt     time.Time
}

func New(policy model.Policy) *Selector {
	s := &Selector{
		sources:      make(map[string]*observation),
		required:     make(map[string]bool),
		historyLimit: 32,
	}
	s.policy = safePolicy(policy)
	return s
}

// Invalid modes/fallbacks fail closed even if a caller bypassed config.Validate.
func safePolicy(p model.Policy) model.Policy {
	if p.Mode != "auto" && p.Mode != "manual" {
		p.Mode = "off"
	}
	if p.Fallback != "direct" {
		p.Fallback = "closed"
	}
	if p.Confirmations < 1 {
		p.Confirmations = 3
	}
	if p.FailureConfirmations < 1 {
		p.FailureConfirmations = 3
	}
	if p.RecoveryConfirmations < 1 {
		p.RecoveryConfirmations = 3
	}
	if p.StaleAfterSeconds < 1 {
		p.StaleAfterSeconds = 90
	}
	if p.MinDwellSeconds < 0 {
		p.MinDwellSeconds = 0
	}
	if p.CooldownSeconds < 0 {
		p.CooldownSeconds = 0
	}
	if !finite(p.ImprovementPercent) || p.ImprovementPercent < 1 {
		p.ImprovementPercent = 20
	}
	return p
}

func (s *Selector) Configure(policy model.Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policy = safePolicy(policy)
	s.clearCandidate()
}

// SetTargets invalidates measurements when resource policy changes: an old
// response cannot prove accessibility of a newly required resource.
func (s *Selector) SetTargets(targets []model.Target) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make(map[string]bool)
	for _, t := range targets {
		if t.Required {
			next[t.ID] = true
		}
	}
	signature, _ := json.Marshal(targets)
	if string(signature) != s.targetSignature {
		s.sources = make(map[string]*observation)
		s.clearCandidate()
	}
	s.targetSignature = string(signature)
	s.required = next
}

func (s *Selector) SetHistoryLimit(limit int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit < 1 {
		limit = 1
	}
	if limit > 256 {
		limit = 256
	}
	s.historyLimit = limit
	for _, o := range s.sources {
		if len(o.history) > limit {
			o.history = append([]model.Measurement(nil), o.history[len(o.history)-limit:]...)
		}
	}
}

// Observe accepts one complete cycle. Repeated/out-of-order cycles never count
// as extra confirmation; invalid numeric telemetry cannot poison the EWMA.
func (s *Selector) Observe(m model.Measurement) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m.SourceID == "" || len(m.SourceID) > 64 || m.At.IsZero() || len(m.Resources) == 0 {
		return
	}
	seen := make(map[string]bool)
	for _, r := range m.Resources {
		if r.TargetID == "" || seen[r.TargetID] || !finite(r.LatencyMS) || r.LatencyMS < 0 ||
			r.Bytes < 0 ||
			(r.SpeedBPS != nil && (!finite(*r.SpeedBPS) || *r.SpeedBPS < 0)) {
			return
		}
		seen[r.TargetID] = true
	}
	if m.PacketLoss != nil && (!finite(*m.PacketLoss) || *m.PacketLoss < 0 || *m.PacketLoss > 1) {
		return
	}
	o := s.sources[m.SourceID]
	if o != nil && !m.At.After(o.health.LastAt) {
		return
	}
	if o == nil {
		o = &observation{health: model.SourceHealth{SourceID: m.SourceID, State: "unknown"}}
		s.sources[m.SourceID] = o
	}
	m = cloneMeasurement(m)
	o.history = append(o.history, m)
	if len(o.history) > s.historyLimit {
		o.history = append([]model.Measurement(nil), o.history[len(o.history)-s.historyLimit:]...)
	}
	succeeded, failedRequired, measured := 0, 0, 0
	var latency, speed float64
	for _, r := range m.Resources {
		if r.Success {
			succeeded++
			latency += r.LatencyMS
			if r.SpeedBPS != nil {
				speed += *r.SpeedBPS
				measured++
			}
		}
		if !r.Success && (r.Required || s.required[r.TargetID]) {
			failedRequired++
		}
	}
	for id := range s.required {
		if !seen[id] {
			failedRequired++
		}
	}
	first := o.health.LastAt.IsZero()
	o.health.SuccessRate = smooth(
		o.health.SuccessRate,
		float64(succeeded)/float64(len(m.Resources)),
		first,
	)
	if succeeded > 0 {
		o.health.LatencyMS = smooth(
			o.health.LatencyMS,
			latency/float64(succeeded),
			first || o.health.LatencyMS == 0,
		)
	}
	if measured > 0 {
		value := speed / float64(measured)
		if o.health.SpeedBPS != nil {
			value = smooth(*o.health.SpeedBPS, value, false)
		}
		o.health.SpeedBPS = &value
		o.speedAt = m.At
	}
	if m.PacketLoss != nil {
		value := *m.PacketLoss
		if o.health.PacketLoss != nil {
			value = smooth(*o.health.PacketLoss, value, false)
		}
		o.health.PacketLoss = &value
		o.lossAt = m.At
	}
	o.failedRequired = failedRequired
	o.fullFailure = succeeded == 0
	o.health.LastAt = m.At
	o.health.Resources = cloneResources(m.Resources)
	if failedRequired > 0 || o.fullFailure {
		o.health.ConsecutiveFailures++
		o.health.ConsecutiveSuccesses = 0
		if o.fullFailure || o.health.ConsecutiveFailures >= s.policy.FailureConfirmations {
			o.needsRecovery = true
		}
	} else {
		o.health.ConsecutiveSuccesses++
		o.health.ConsecutiveFailures = 0
		if o.health.ConsecutiveSuccesses >= s.policy.RecoveryConfirmations {
			o.needsRecovery = false
		}
	}
}

func (s *Selector) health(o *observation, now time.Time) model.SourceHealth {
	h := cloneHealth(o.health)
	age := now.Sub(h.LastAt)
	switch {
	case age < 0:
		h.State = "unknown"
	case age > time.Duration(s.policy.StaleAfterSeconds)*time.Second:
		h.State = "stale"
	case o.fullFailure || o.health.ConsecutiveFailures >= s.policy.FailureConfirmations:
		h.State = "unhealthy"
	case o.failedRequired > 0:
		h.State = "degraded"
	case o.needsRecovery:
		h.State = "recovering"
	default:
		h.State = "healthy"
	}
	// Speed checks are intentionally less frequent than light checks, but light
	// checks cannot keep old throughput/loss evidence alive forever.
	metricTTL := max(time.Duration(s.policy.StaleAfterSeconds)*10*time.Second, 5*time.Minute)
	if now.Sub(o.speedAt) > metricTTL {
		h.SpeedBPS = nil
	}
	if now.Sub(o.lossAt) > time.Duration(s.policy.StaleAfterSeconds)*time.Second {
		h.PacketLoss = nil
	}
	return h
}

func (s *Selector) Health(now time.Time) []model.SourceHealth {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.SourceHealth, 0, len(s.sources))
	for _, o := range s.sources {
		out = append(out, s.health(o, now))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SourceID < out[j].SourceID })
	return out
}

func (s *Selector) History(sourceID string) []model.Measurement {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := []model.Measurement{}
	if o := s.sources[sourceID]; o != nil {
		for _, m := range o.history {
			result = append(result, cloneMeasurement(m))
		}
	}
	return result
}

func (s *Selector) Evaluate(sources []model.Source, now time.Time) model.Decision {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := s.selected
	decision := func(selected, state, reason string) model.Decision {
		changed := selected != previous
		if changed {
			s.selected = selected
			s.selectedAt = now
			s.lastSwitch = now
			s.clearCandidate()
		}
		return model.Decision{
			At:       now,
			Previous: previous,
			Selected: selected,
			Changed:  changed,
			State:    state,
			Reason:   reason,
		}
	}
	if s.policy.Mode == "off" {
		return decision("", "off", "Automatic and manual selection are disabled")
	}
	available := make(map[string]model.Source)
	for _, source := range sources {
		available[source.ID] = source
	}
	for id := range s.sources {
		if _, exists := available[id]; !exists {
			delete(s.sources, id)
		}
	}
	h := make(map[string]model.SourceHealth)
	for id, o := range s.sources {
		h[id] = s.health(o, now)
	}
	healthy := func(id string) bool {
		source, exists := available[id]
		return exists && source.Enabled && h[id].State == "healthy"
	}
	fallback := func(reason string) model.Decision {
		if s.policy.Fallback == "direct" {
			var ids []string
			for id, src := range available {
				if src.Type == "direct" && healthy(id) {
					ids = append(ids, id)
				}
			}
			sort.Strings(ids)
			if len(ids) > 0 {
				return decision(
					ids[0],
					"fallback",
					reason+"; explicitly permitted direct fallback passed fresh resource checks",
				)
			}
			return decision(
				"",
				"unavailable",
				reason+"; direct fallback has no freshly verified source",
			)
		}
		return decision("", "unavailable", reason+"; fallback policy is closed")
	}
	if s.policy.Mode == "manual" {
		if healthy(s.policy.Pinned) {
			return decision(
				s.policy.Pinned,
				"manual",
				"The pinned source passed fresh required-resource checks",
			)
		}
		return fallback("The pinned source is disabled, unverified, stale, or unhealthy")
	}
	var candidates []string
	for id, src := range available {
		if src.Auto && healthy(id) {
			candidates = append(candidates, id)
		}
	}
	sort.Strings(candidates)
	best := ""
	for _, id := range candidates {
		if best == "" || better(h[id], h[best], 0) {
			best = id
		}
	}
	current, exists := available[previous]
	currentAllowed := exists && current.Enabled && current.Auto
	currentHealth := h[previous]
	currentUsable := currentAllowed &&
		(currentHealth.State == "healthy" || currentHealth.State == "degraded")
	if !currentUsable {
		if best == "" {
			return fallback("No eligible source has fresh successful resource checks")
		}
		reason := "Initial eligible source passed fresh required-resource checks"
		if previous != "" {
			reason = "Current source is disabled, excluded, stale, or failed required resources; verified replacement selected without normal dwell"
		}
		return decision(best, "selected", reason)
	}
	if best == "" || best == previous ||
		!better(h[best], currentHealth, s.policy.ImprovementPercent) {
		s.clearCandidate()
		if currentHealth.State == "degraded" {
			return decision(
				previous,
				"degraded",
				fmt.Sprintf(
					"Current source failed %d required resources in %d consecutive checks; awaiting failure confirmation",
					s.sources[previous].failedRequired,
					currentHealth.ConsecutiveFailures,
				),
			)
		}
		return decision(
			previous,
			"selected",
			"Current source remains eligible; no confirmed superior candidate",
		)
	}
	if s.candidate != best {
		s.clearCandidate()
		s.candidate = best
	}
	if h[best].LastAt.After(s.candidateAt) {
		s.confirmations++
		s.candidateAt = h[best].LastAt
	}
	if s.confirmations < s.policy.Confirmations {
		return decision(
			previous,
			"selected",
			fmt.Sprintf(
				"Candidate advantage confirmed in %d of %d fresh checks",
				s.confirmations,
				s.policy.Confirmations,
			),
		)
	}
	if now.Sub(s.selectedAt) < time.Duration(s.policy.MinDwellSeconds)*time.Second {
		return decision(
			previous,
			"selected",
			"Candidate is better; minimum channel dwell is still active",
		)
	}
	if now.Sub(s.lastSwitch) < time.Duration(s.policy.CooldownSeconds)*time.Second {
		return decision(
			previous,
			"selected",
			"Candidate is better; switch cooldown is still active",
		)
	}
	return decision(
		best,
		"selected",
		fmt.Sprintf(
			"Candidate sustained at least %.0f%% quality advantage across %d fresh checks",
			s.policy.ImprovementPercent,
			s.confirmations,
		),
	)
}

func better(a, b model.SourceHealth, improvement float64) bool {
	quality := func(h model.SourceHealth) float64 {
		q := h.SuccessRate / (1 + h.LatencyMS/1000)
		if h.PacketLoss != nil {
			q /= 1 + 4*(*h.PacketLoss)
		}
		return q
	}
	qa, qb := quality(a), quality(b)
	if a.SpeedBPS != nil && b.SpeedBPS != nil {
		qa *= *a.SpeedBPS
		qb *= *b.SpeedBPS
	}
	return qa > qb*(1+improvement/100)
}

func (s *Selector) clearCandidate() {
	s.candidate = ""
	s.confirmations = 0
	s.candidateAt = time.Time{}
}

func finite(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0)
}

func smooth(old, next float64, first bool) float64 {
	if first {
		return next
	}
	return alpha*next + (1-alpha)*old
}

func copyFloat(v *float64) *float64 {
	if v == nil {
		return nil
	}
	copy := *v
	return &copy
}

func cloneResources(resources []model.ResourceResult) []model.ResourceResult {
	out := append([]model.ResourceResult(nil), resources...)
	for i := range out {
		out[i].SpeedBPS = copyFloat(out[i].SpeedBPS)
	}
	return out
}

func cloneMeasurement(m model.Measurement) model.Measurement {
	m.Resources = cloneResources(m.Resources)
	m.PacketLoss = copyFloat(m.PacketLoss)
	return m
}

func cloneHealth(h model.SourceHealth) model.SourceHealth {
	h.Resources = cloneResources(h.Resources)
	h.SpeedBPS = copyFloat(h.SpeedBPS)
	h.PacketLoss = copyFloat(h.PacketLoss)
	return h
}

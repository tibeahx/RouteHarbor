package control

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/tibeahx/OpenRHP/internal/model"
)

func seedDegradation(r *Runtime, id string, now time.Time, latestLatency float64, failed bool) {
	for i, latency := range []float64{20, 24, 22, latestLatency} {
		r.selector.Observe(
			model.Measurement{
				SourceID: id,
				At:       now.Add(time.Duration(i-4) * time.Second),
				Resources: []model.ResourceResult{
					{
						TargetID:  "web",
						Required:  true,
						Success:   !failed || i != 3,
						LatencyMS: latency,
						Bytes:     100,
					},
				},
			},
		)
	}
	r.speedAt[id] = now.Add(-2 * time.Minute)
	r.next[id] = now.Add(time.Hour)
}

func TestDegradationSpeedRequiresFreshEvidenceAndCooldown(t *testing.T) {
	for _, scenario := range []string{"latency", "required-failure", "cooldown", "already-measured", "stale", "unknown-loss", "ordinary-jitter", "no-baseline", "measured-loss"} {
		t.Run(scenario, func(t *testing.T) {
			r := runtimeFixture(t)
			now := time.Now()
			c := r.Store.Get()
			latency := 250.0
			if scenario == "ordinary-jitter" || scenario == "unknown-loss" ||
				scenario == "measured-loss" {
				latency = 40
			}
			seedDegradation(r, "direct", now, latency, scenario == "required-failure")
			switch scenario {
			case "cooldown":
				r.speedAt["direct"] = now.Add(-30 * time.Second)
			case "already-measured":
				r.speedAt["direct"] = now
			case "stale":
				now = now.Add(time.Duration(c.Policy.StaleAfterSeconds+1) * time.Second)
			case "no-baseline":
				r.selector.SetTargets(nil)
				r.selector.SetTargets(c.Targets)
			case "measured-loss":
				loss := 0.01
				r.selector.Observe(
					model.Measurement{
						SourceID:   "direct",
						At:         now.Add(-500 * time.Millisecond),
						PacketLoss: &loss,
						Resources: []model.ResourceResult{
							{TargetID: "web", Required: true, Success: true, LatencyMS: 40},
						},
					},
				)
				loss = 0.2
				r.selector.Observe(
					model.Measurement{
						SourceID:   "direct",
						At:         now,
						PacketLoss: &loss,
						Resources: []model.ResourceResult{
							{TargetID: "web", Required: true, Success: true, LatencyMS: 40},
						},
					},
				)
			}
			want := scenario == "latency" || scenario == "required-failure" ||
				scenario == "measured-loss"
			if got := r.degradationSpeedDueLocked("direct", c, now); got != want {
				t.Fatalf("speed trigger=%v, expected %v", got, want)
			}
		})
	}
}

type scheduledProbe struct {
	id       string
	speed    bool
	settings model.ProbeSettings
	targets  []model.Target
}
type schedulerProber struct {
	calls   chan scheduledProbe
	release <-chan struct{}
}

func (p schedulerProber) Run(
	ctx context.Context,
	source model.Source,
	targets []model.Target,
	settings model.ProbeSettings,
	speed bool,
) (model.Measurement, error) {
	p.calls <- scheduledProbe{source.ID, speed, settings, targets}
	if p.release != nil {
		select {
		case <-p.release:
		case <-ctx.Done():
			return model.Measurement{}, ctx.Err()
		}
	}
	return model.Measurement{
		SourceID: source.ID,
		At:       time.Now(),
		Resources: []model.ResourceResult{
			{TargetID: "web", Required: true, Success: true, LatencyMS: 20, Bytes: 100},
		},
	}, nil
}

func nextScheduled(t *testing.T, calls <-chan scheduledProbe) scheduledProbe {
	t.Helper()
	select {
	case call := <-calls:
		return call
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not launch bounded speed probe")
		return scheduledProbe{}
	}
}

func waitIdle(t *testing.T, r *Runtime) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		idle := len(r.active) == 0
		r.mu.Unlock()
		if idle {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("probe did not finish")
}

func TestSuspectedDegradationBypassesLightScheduleButKeepsLimits(t *testing.T) {
	r := runtimeFixture(t)
	now := time.Now()
	seedDegradation(r, "direct", now, 250, false)
	calls := make(chan scheduledProbe, 2)
	r.Prober = schedulerProber{calls: calls}
	r.tick(now)
	call := nextScheduled(t, calls)
	c := r.Store.Get()
	if !call.speed || call.id != "direct" || call.settings != c.Probes || len(call.targets) != 1 ||
		call.targets[0].MaxBytes != 1024 {
		t.Fatal("speed probe bypassed configured probe limits")
	}
	waitIdle(t, r)
	r.mu.Lock()
	r.next["direct"] = now.Add(time.Hour)
	r.selector.Observe(
		model.Measurement{
			SourceID: "direct",
			At:       now.Add(time.Second),
			Resources: []model.ResourceResult{
				{TargetID: "web", Required: true, Success: false, LatencyMS: 300},
			},
		},
	)
	if r.degradationSpeedDueLocked("direct", c, now.Add(2*time.Second)) {
		r.mu.Unlock()
		t.Fatal("new degraded light sample caused a repeated speed burst inside cooldown")
	}
	r.mu.Unlock()
}

func TestDegradationSpeedSharesGlobalConcurrencyBudget(t *testing.T) {
	r := runtimeFixture(t)
	c := r.Store.Get()
	c.Probes.Concurrency = 1
	c.Sources = append(
		c.Sources,
		model.Source{
			ID:       "other",
			Name:     "Other",
			Type:     "direct",
			Enabled:  true,
			Settings: json.RawMessage(`{}`),
		},
	)
	if _, err := r.Store.Replace(c.Revision, c); err != nil {
		t.Fatal(err)
	}
	r.Reload()
	now := time.Now()
	seedDegradation(r, "direct", now, 250, false)
	seedDegradation(r, "other", now, 250, false)
	calls := make(chan scheduledProbe, 3)
	release := make(chan struct{})
	r.Prober = schedulerProber{calls: calls, release: release}
	r.tick(now)
	first := nextScheduled(t, calls)
	if !first.speed {
		t.Fatal("first degradation probe not a speed check")
	}
	r.tick(now.Add(time.Second))
	r.mu.Lock()
	active := len(r.active)
	r.mu.Unlock()
	if active != 1 {
		t.Fatal("degradation probes exceeded global concurrency")
	}
	select {
	case <-calls:
		t.Fatal("second probe ran while budget was exhausted")
	default:
	}
	close(release)
	waitIdle(t, r)
	r.tick(now.Add(2 * time.Second))
	second := nextScheduled(t, calls)
	if !second.speed || second.id == first.id {
		t.Fatal("waiting source was not serviced after budget became available")
	}
	waitIdle(t, r)
}

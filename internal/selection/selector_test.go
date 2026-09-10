package selection

import (
	"math"
	"sync"
	"testing"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/model"
)

func policy() model.Policy {
	return model.Policy{
		Mode:                  "auto",
		Fallback:              "closed",
		ImprovementPercent:    20,
		Confirmations:         3,
		FailureConfirmations:  3,
		RecoveryConfirmations: 3,
		MinDwellSeconds:       10,
		CooldownSeconds:       10,
		StaleAfterSeconds:     90,
	}
}

func source(id string) model.Source {
	return model.Source{ID: id, Name: id, Type: "socks5", Enabled: true, Auto: true}
}

func measure(id string, at time.Time, speed float64) model.Measurement {
	return model.Measurement{
		SourceID: id,
		At:       at,
		Path:     "isolated-" + id,
		Resources: []model.ResourceResult{
			{
				TargetID:  "required",
				Required:  true,
				Success:   true,
				LatencyMS: 20,
				SpeedBPS:  &speed,
				Bytes:     1024,
			},
		},
	}
}

func epoch() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}

func setup() (*Selector, []model.Source, time.Time) {
	s := New(policy())
	return s, []model.Source{source("a"), source("b")}, epoch()
}

func pickA(t *testing.T, s *Selector, sources []model.Source, now time.Time) {
	t.Helper()
	s.Observe(measure("a", now, 1000))
	s.Observe(measure("b", now, 500))
	if d := s.Evaluate(sources, now); d.Selected != "a" {
		t.Fatalf("initial selection: %+v", d)
	}
}

func TestSustainedFasterSourceNeedsFreshConfirmations(t *testing.T) {
	s, sources, now := setup()
	pickA(t, s, sources, now)
	now = now.Add(11 * time.Second)
	s.Observe(measure("b", now, 10000))
	for range 20 {
		if d := s.Evaluate(sources, now); d.Selected != "a" {
			t.Fatalf("polls count as measurements: %+v", d)
		}
	}
	for i := range 2 {
		now = now.Add(time.Second)
		s.Observe(measure("b", now, 10000))
		d := s.Evaluate(sources, now)
		if i == 0 && d.Selected != "a" {
			t.Fatal("switched before three measurements")
		}
		if i == 1 && (!d.Changed || d.Selected != "b") {
			t.Fatalf("superior channel not selected: %+v", d)
		}
	}
}

func TestDwellAndCooldownAreIndependent(t *testing.T) {
	for _, gate := range []string{"dwell", "cooldown"} {
		t.Run(gate, func(t *testing.T) {
			s, sources, now := setup()
			p := policy()
			p.MinDwellSeconds = 0
			p.CooldownSeconds = 0
			if gate == "dwell" {
				p.MinDwellSeconds = 30
			} else {
				p.CooldownSeconds = 30
			}
			s.Configure(p)
			pickA(t, s, sources, now)
			for i := 1; i <= 3; i++ {
				at := now.Add(time.Duration(i) * time.Second)
				s.Observe(measure("b", at, 10000))
				if d := s.Evaluate(sources, at); d.Selected != "a" {
					t.Fatalf("%s bypassed: %+v", gate, d)
				}
			}
			if d := s.Evaluate(sources, now.Add(31*time.Second)); d.Selected != "b" {
				t.Fatalf("expired %s still blocked: %+v", gate, d)
			}
		})
	}
}

func TestOneLatencySpikeDoesNotFlap(t *testing.T) {
	s, sources, now := setup()
	pickA(t, s, sources, now)
	now = now.Add(11 * time.Second)
	m := measure("a", now, 1000)
	m.Resources[0].LatencyMS = 6000
	s.Observe(m)
	if d := s.Evaluate(sources, now); d.Selected != "a" {
		t.Fatalf("single latency spike switched: %+v", d)
	}
	for range 10 {
		now = now.Add(time.Second)
		s.Observe(measure("a", now, 1000))
		s.Observe(measure("b", now, 500))
		if d := s.Evaluate(sources, now); d.Selected != "a" {
			t.Fatalf("recovered channel flapped: %+v", d)
		}
	}
}

func TestFullFailureExpeditesRegardlessOfTimers(t *testing.T) {
	s, sources, now := setup()
	p := policy()
	p.MinDwellSeconds = 3600
	p.CooldownSeconds = 3600
	s.Configure(p)
	pickA(t, s, sources, now)
	now = now.Add(time.Second)
	m := measure("a", now, 0)
	m.Resources[0].Success = false
	s.Observe(m)
	d := s.Evaluate(sources, now)
	if d.Selected != "b" || !d.Changed {
		t.Fatalf("full failure did not expedite: %+v", d)
	}
}

func TestPartialRequiredFailureNeedsConfirmationAndRecovery(t *testing.T) {
	s, sources, now := setup()
	p := policy()
	p.MinDwellSeconds = 3600
	p.CooldownSeconds = 3600
	s.Configure(p)
	pickA(t, s, sources, now)
	for i := 1; i <= 3; i++ {
		now = now.Add(time.Second)
		m := measure("a", now, 1000)
		m.Resources[0].Success = false
		m.Resources = append(
			m.Resources,
			model.ResourceResult{TargetID: "optional", Success: true, LatencyMS: 20},
		)
		s.Observe(m)
		d := s.Evaluate(sources, now)
		if i < 3 && d.Selected != "a" {
			t.Fatal("partial error switched before confirmation")
		}
		if i == 3 && d.Selected != "b" {
			t.Fatalf("confirmed required failure not replaced: %+v", d)
		}
	}
	for i := 1; i <= 3; i++ {
		now = now.Add(time.Second)
		s.Observe(measure("a", now, 10000))
		h := s.Health(now)
		state := ""
		for _, v := range h {
			if v.SourceID == "a" {
				state = v.State
			}
		}
		if i < 3 && state != "recovering" {
			t.Fatalf("early recovery: %s", state)
		}
		if i == 3 && state != "healthy" {
			t.Fatalf("recovery failed: %s", state)
		}
	}
}

func TestStaleAndFutureMeasurementsAreNotHealthy(t *testing.T) {
	s, sources, now := setup()
	pickA(t, s, sources, now)
	d := s.Evaluate(sources, now.Add(91*time.Second))
	if d.Selected != "" || d.State != "unavailable" {
		t.Fatalf("stale source retained: %+v", d)
	}
	s.Observe(measure("b", now.Add(time.Hour), 500))
	d = s.Evaluate(sources, now.Add(92*time.Second))
	if d.Selected != "" {
		t.Fatal("future measurement treated as healthy")
	}
}

func TestNoHealthyCandidatesClosedAndExplicitDirectFallback(t *testing.T) {
	for _, fallback := range []string{"closed", "direct"} {
		t.Run(fallback, func(t *testing.T) {
			s, sources, now := setup()
			p := policy()
			p.Fallback = fallback
			s.Configure(p)
			direct := source("direct")
			direct.Type = "direct"
			direct.Auto = false
			sources = append(sources, direct)
			if d := s.Evaluate(sources, now); d.Selected != "" || d.State != "unavailable" {
				t.Fatal("unprobed fallback trusted")
			}
			s.Observe(measure("direct", now, 100))
			d := s.Evaluate(sources, now)
			if fallback == "direct" && (d.Selected != "direct" || d.State != "fallback") {
				t.Fatalf("explicit healthy direct unavailable: %+v", d)
			}
			if fallback == "closed" && d.Selected != "" {
				t.Fatal("closed policy leaked direct")
			}
			sources[2].Enabled = false
			if d := s.Evaluate(sources, now); d.Selected != "" {
				t.Fatal("disabled direct used")
			}
		})
	}
}

func TestManualAndAutoExclusions(t *testing.T) {
	s, sources, now := setup()
	sources[0].Auto = false
	s.Observe(measure("a", now, 10000))
	s.Observe(measure("b", now, 500))
	if d := s.Evaluate(sources, now); d.Selected != "b" {
		t.Fatal("auto-excluded source selected")
	}
	p := policy()
	p.Mode = "manual"
	p.Pinned = "a"
	s.Configure(p)
	if d := s.Evaluate(sources, now); d.Selected != "a" || d.State != "manual" {
		t.Fatalf("manual source not pinned: %+v", d)
	}
	sources[0].Enabled = false
	if d := s.Evaluate(sources, now); d.Selected != "" {
		t.Fatal("disabled manual source remained selected")
	}
	p.Mode = "unknown"
	s.Configure(p)
	if d := s.Evaluate(sources, now); d.Selected != "" || d.State != "off" {
		t.Fatal("unknown mode enabled selection")
	}
}

func TestCompleteRequiredResourceSetAndPolicyChanges(t *testing.T) {
	s, sources, now := setup()
	targets := []model.Target{
		{ID: "required", Required: true, URL: "https://a.example"},
		{ID: "another", Required: true, URL: "https://b.example"},
	}
	s.SetTargets(targets)
	s.Observe(measure("a", now, 1000))
	if d := s.Evaluate(sources, now); d.Selected != "" {
		t.Fatal("omitted required resource accepted")
	}
	m := measure("b", now, 500)
	m.Resources[0].Required = false
	m.Resources = append(
		m.Resources,
		model.ResourceResult{TargetID: "another", Success: true, LatencyMS: 20},
	)
	s.Observe(m)
	if d := s.Evaluate(sources, now); d.Selected != "b" {
		t.Fatalf("complete required set not accepted: %+v", d)
	}
	targets[0].URL = "https://changed.example"
	s.SetTargets(targets)
	if d := s.Evaluate(sources, now); d.Selected != "" {
		t.Fatal("changed target inherited previous URL health")
	}
}

func TestUnknownTelemetryIsNotZeroAndMeasuredLossIsSeparate(t *testing.T) {
	s, sources, now := setup()
	m := measure("a", now, 100)
	m.Resources[0].SpeedBPS = nil
	s.Observe(m)
	h := s.Health(now)[0]
	if h.SpeedBPS != nil || h.PacketLoss != nil {
		t.Fatal("unknown telemetry presented as zero")
	}
	now = now.Add(time.Second)
	m = measure("a", now, 100)
	m.Resources[0].Success = false
	s.Observe(m)
	h = s.Health(now)[0]
	if h.PacketLoss != nil {
		t.Fatal("HTTP error reported as packet loss")
	}
	s = New(policy())
	loss := 0.4
	m = measure("a", now, 100)
	m.PacketLoss = &loss
	s.Observe(m)
	m = measure("b", now, 100)
	s.Observe(m)
	if d := s.Evaluate(sources, now); d.Selected != "b" {
		t.Fatalf("real packet loss ignored: %+v", d)
	}
}

func TestHistoriesBoundedAndCopiesDetached(t *testing.T) {
	s, _, now := setup()
	s.SetHistoryLimit(4)
	for i := range 20 {
		s.Observe(measure("a", now.Add(time.Duration(i)*time.Second), 100))
	}
	history := s.History("a")
	if len(history) != 4 {
		t.Fatalf("history length %d", len(history))
	}
	if !history[0].At.Equal(now.Add(16 * time.Second)) {
		t.Fatal("history is not latest window")
	}
	history[0].Resources[0].TargetID = "mutated"
	*history[0].Resources[0].SpeedBPS = 99999
	h := s.Health(now.Add(20 * time.Second))
	*h[0].SpeedBPS = 11111
	if s.History("a")[0].Resources[0].TargetID == "mutated" ||
		*s.Health(now.Add(20 * time.Second))[0].SpeedBPS != 100 {
		t.Fatal("external mutation corrupted selector")
	}
}

func TestOldThroughputExpiresDespiteFreshLightChecks(t *testing.T) {
	s, _, now := setup()
	s.Observe(measure("a", now, 1000))
	for i := 1; i <= 16; i++ {
		m := measure("a", now.Add(time.Duration(i)*time.Minute), 0)
		m.Resources[0].SpeedBPS = nil
		s.Observe(m)
	}
	h := s.Health(now.Add(16 * time.Minute))[0]
	if h.State != "healthy" || h.SpeedBPS != nil {
		t.Fatalf("old speed retained by light checks: %+v", h)
	}
}

func TestRejectInvalidOrRepeatedTelemetry(t *testing.T) {
	s, _, now := setup()
	s.Observe(measure("a", now, 1000))
	for _, value := range []float64{-1, math.NaN(), math.Inf(1)} {
		m := measure("a", now.Add(time.Second), value)
		s.Observe(m)
	}
	m := measure("a", now.Add(time.Second), 1000)
	m.Resources = append(m.Resources, m.Resources[0])
	s.Observe(m)
	m = measure("a", now.Add(-time.Second), 1000)
	s.Observe(m)
	m = measure("a", now, 1000)
	s.Observe(m)
	if len(s.History("a")) != 1 {
		t.Fatal("invalid or repeated cycle recorded")
	}
}

func TestConcurrentObserveEvaluateAndRead(t *testing.T) {
	s, sources, now := setup()
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 1; i <= 100; i++ {
				at := now.Add(time.Duration(i) * time.Millisecond)
				s.Observe(measure(sources[worker%2].ID, at, 100))
				s.Evaluate(sources, at)
				s.Health(at)
				s.History("a")
			}
		}(worker)
	}
	wg.Wait()
}

func FuzzSelectorTelemetry(f *testing.F) {
	f.Add(float64(10), float64(100), float64(0), true)
	f.Add(float64(-1), math.Inf(1), math.NaN(), false)
	f.Fuzz(func(t *testing.T, latency, speed, loss float64, success bool) {
		s, sources, now := setup()
		m := measure("a", now, speed)
		m.Resources[0].LatencyMS = latency
		m.Resources[0].Success = success
		m.PacketLoss = &loss
		s.Observe(m)
		d := s.Evaluate(sources, now)
		if d.Selected != "" && d.Selected != "a" {
			t.Fatal("selected nonexistent measurement")
		}
		for _, h := range s.Health(now) {
			if !finite(h.LatencyMS) || !finite(h.SuccessRate) {
				t.Fatal("invalid telemetry poisoned state")
			}
		}
	})
}

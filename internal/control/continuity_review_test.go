package control

import (
	"testing"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/adapter"
	"github.com/tibeahx/RouteHarbor/internal/config"
	"github.com/tibeahx/RouteHarbor/internal/model"
	"github.com/tibeahx/RouteHarbor/internal/selection"
)

func TestContinuityStandbyPrefersFreshHealthyOverStaleFastPath(t *testing.T) {
	s := selection.New(config.Defaults().Policy)
	observe := func(id string, at time.Time, speed float64) {
		s.Observe(
			model.Measurement{
				SourceID: id,
				At:       at,
				Resources: []model.ResourceResult{
					{
						TargetID:  "relay",
						Required:  true,
						Success:   true,
						LatencyMS: 10,
						SpeedBPS:  &speed,
					},
				},
			},
		)
	}
	now := time.Now()
	observe("stale-fast", now.Add(-2*time.Minute), 1e9)
	observe("fresh", now, 1e8)
	r := &Runtime{
		selector: s,
		currentConfig: model.Config{
			Sources: []model.Source{
				{ID: "active", Enabled: true, Auto: true},
				{ID: "stale-fast", Enabled: true, Auto: true},
				{ID: "fresh", Enabled: true, Auto: true},
			},
		},
	}
	got := r.continuityStandby(
		"active",
		[]adapter.Path{{SourceID: "active"}, {SourceID: "stale-fast"}, {SourceID: "fresh"}},
	)
	if got != "fresh" {
		t.Fatalf("fresh healthy standby bypassed by obsolete measurement: %s", got)
	}
	r.currentConfig.Sources[2].Auto = false
	if got := r.continuityStandby(
		"active",
		[]adapter.Path{{SourceID: "active"}, {SourceID: "stale-fast"}, {SourceID: "fresh"}},
	); got != "" {
		t.Fatalf("automatically selected excluded or stale source: %s", got)
	}
}

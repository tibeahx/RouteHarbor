package control

import (
	"slices"
	"sort"
	"time"

	"github.com/tibeahx/OpenRHP/internal/model"
)

// degradationSpeedDueLocked only changes when the next bounded speed check is
// due. It never switches a route or substitutes HTTP failures for packet loss.
func (r *Runtime) degradationSpeedDueLocked(id string, c model.Config, now time.Time) bool {
	lastSpeed := r.speedAt[id]
	interval := c.Probes.OtherIntervalSeconds
	if r.decision.Selected == id {
		interval = c.Probes.ActiveIntervalSeconds
	}
	cooldown := max(time.Minute, 2*time.Duration(interval)*time.Second)
	if lastSpeed.IsZero() || now.Sub(lastSpeed) < cooldown {
		return false
	}
	history := r.selector.History(id)
	if len(history) == 0 {
		return false
	}
	latest := history[len(history)-1]
	if !latest.At.After(lastSpeed) || latest.At.After(now) ||
		now.Sub(latest.At) > time.Duration(c.Policy.StaleAfterSeconds)*time.Second {
		return false
	}
	required := make(map[string]bool)
	for _, target := range c.Targets {
		if target.Required {
			required[target.ID] = true
		}
	}
	succeeded := 0
	for _, result := range latest.Resources {
		if result.Success {
			succeeded++
			delete(required, result.TargetID)
		} else if result.Required {
			return true
		}
	}
	if len(required) > 0 || succeeded == 0 {
		return true
	}
	previous := history[max(0, len(history)-5) : len(history)-1]
	for _, result := range latest.Resources {
		if !result.Success {
			continue
		}
		baseline := []float64{}
		for _, measurement := range previous {
			for _, old := range measurement.Resources {
				if old.TargetID == result.TargetID && old.Success && old.LatencyMS > 0 {
					baseline = append(baseline, old.LatencyMS)
				}
			}
		}
		if len(baseline) < 2 {
			continue
		}
		sort.Float64s(baseline)
		median := baseline[len(baseline)/2]
		if result.LatencyMS >= median*2 && result.LatencyMS-median >= 100 {
			return true
		}
	}
	if latest.PacketLoss != nil {
		for _, measurement := range slices.Backward(previous) {
			if measurement.PacketLoss != nil {
				return *latest.PacketLoss-*measurement.PacketLoss >= 0.1
			}
		}
	}
	return false
}

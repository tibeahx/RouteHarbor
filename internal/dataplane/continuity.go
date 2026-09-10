package dataplane

import (
	"encoding/hex"
	"errors"
	"net/netip"

	"github.com/tibeahx/RouteHarbor/internal/model"
	"github.com/tibeahx/RouteHarbor/internal/platform"
)

const ContinuitySourceID = "__continuity"

// ContinuityIntent keeps the stable LAN endpoint separate from the underlying
// source allocations. Switching carriers does not change this routing intent.
type ContinuityIntent struct {
	Config model.ContinuityConfig `json:"config"`
	Path   Path                   `json:"path"`
}

func materializeContinuity(d Desired) (Desired, error) {
	c := d.Continuity
	if c == nil {
		return d, nil
	}
	a, err := netip.ParseAddrPort(c.Config.RelayAddress)
	pin, pinErr := hex.DecodeString(c.Config.RelayFingerprint)
	if !c.Config.Enabled || err != nil || a.Port() == 0 || !platform.PublicAddress(a.Addr()) ||
		pinErr != nil ||
		len(pin) != 32 ||
		d.Fallback != "closed" ||
		d.BreakExisting {
		return d, errors.New(
			"invalid_continuity: explicit trusted relay and closed session policy required",
		)
	}
	p := c.Path
	if p.SourceID != ContinuitySourceID || p.Kind != "tproxy" || !p.UDP || p.Interface != "" ||
		p.Slot == 0 ||
		p.Slot > MaxPaths ||
		p.Port < 1024 ||
		(d.Network.IPv6 == "proxy" && !p.IPv6) ||
		(d.Network.DNS == "selected-path" && p.DNSPort < 1024) {
		return d, errors.New("invalid_continuity: invalid stable interception allocation")
	}
	for _, path := range d.Paths {
		if path.SourceID == ContinuitySourceID || path.Slot == p.Slot {
			return d, errors.New("invalid_continuity: source allocation collision")
		}
	}
	for _, id := range d.Unavailable {
		if id == ContinuitySourceID {
			return d, errors.New("invalid_continuity: reserved source identity")
		}
	}
	if d.Selected != "" {
		found := false
		for _, path := range d.Paths {
			if path.SourceID == d.Selected {
				found = true
			}
		}
		if !found {
			return d, errors.New("invalid_continuity: preferred source is not prepared")
		}
	}
	d.Paths = append(append([]Path(nil), d.Paths...), p)
	d.Selected = ContinuitySourceID
	return d, nil
}

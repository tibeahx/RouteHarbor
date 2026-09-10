package helper

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"

	"github.com/tibeahx/RouteHarbor/internal/dataplane"
)

const (
	selectiveSyntheticPriority = 29910
	selectiveInterfacePriority = 26000
)

type selectiveGuardRule struct {
	family, priority int
	destination      string
	mark             uint32
}

func selectiveGuardRules(p *dataplane.Plan) []selectiveGuardRule {
	if p == nil || p.Desired.Selective == nil {
		return nil
	}
	s := p.Desired.Selective
	out := []selectiveGuardRule{
		{4, selectiveSyntheticPriority, s.FakeIPv4, 0},
		{6, selectiveSyntheticPriority, s.FakeIPv6, 0},
	}
	for _, path := range p.Desired.Paths {
		if path.Kind != "interface" {
			continue
		}
		for _, family := range []int{4, 6} {
			if family == 6 && p.Desired.Network.IPv6 == "block" {
				continue
			}
			out = append(
				out,
				selectiveGuardRule{
					family,
					selectiveInterfacePriority + int(path.Slot),
					"",
					dataplane.Mark(path.Slot),
				},
			)
		}
	}
	return out
}

func (g selectiveGuardRule) matches(r ipRule) bool {
	if r.Unsupported || r.Priority != g.priority || r.Action != "blackhole" || r.UIDStart != nil ||
		r.UIDEnd != nil ||
		r.IPProto != "" ||
		r.DPort != 0 ||
		r.IIF != "" ||
		r.IIFName != "" ||
		len(r.Table) != 0 ||
		r.Destination != g.destination {
		return false
	}
	if g.mark == 0 {
		return len(r.FWMark) == 0 && len(r.FWMask) == 0
	}
	return number(r.FWMark) == uint64(g.mark) && number(r.FWMask) == uint64(dataplane.MarkMask)
}

func selectiveRuleAllowed(family int, r ipRule, p *dataplane.Plan) bool {
	for _, g := range selectiveGuardRules(p) {
		if g.family == family && g.matches(r) {
			return true
		}
	}
	return false
}

func (g selectiveGuardRule) args(action string) []string {
	args := []string{
		"-" + strconv.Itoa(g.family),
		"rule",
		action,
		"priority",
		strconv.Itoa(g.priority),
	}
	if g.destination != "" {
		args = append(args, "to", g.destination)
	}
	if g.mark != 0 {
		args = append(args, "fwmark", fmt.Sprintf("0x%08x/0xffff0000", g.mark))
	}
	return append(args, "blackhole")
}

func (b *NetworkBackend) applySelectiveGuards(
	ctx context.Context,
	p dataplane.Plan,
	old *dataplane.Plan,
) error {
	return b.applySelectiveGuardRules(ctx, selectiveGuardRules(&p), old)
}

func (b *NetworkBackend) applySelectiveGuardRules(
	ctx context.Context,
	guards []selectiveGuardRule,
	old *dataplane.Plan,
) error {
	for _, g := range guards {
		rules, err := b.rules(ctx, g.family)
		if err != nil {
			return err
		}
		found := false
		for _, r := range rules {
			if r.Priority == g.priority {
				if !selectiveRuleAllowed(g.family, r, old) {
					return errors.New(
						"ownership_conflict: selective guard priority belongs to another owner",
					)
				}
				found = g.matches(r)
			}
		}
		if !found {
			if _, err = b.Runner.Run(ctx, b.IPBinary, g.args("add"), nil); err != nil {
				return errors.New("selective_guard_failed")
			}
		}
	}
	return nil
}

// Completed emergency mode keeps only synthetic destination protection. Network
// services may flush policy rules after the early boot guard has run; restoring
// these exact owned rules does not reset DNS, rewrite a journal or touch bypass.
func (b *NetworkBackend) EnsureSelectiveEmergencyGuards(
	ctx context.Context,
	d dataplane.Desired,
) error {
	if d.Selective == nil || d.Selective.FailurePolicy != "direct" {
		return errors.New("selective_failure_policy_required")
	}
	p, err := dataplane.Compile(d)
	if err != nil {
		return err
	}
	var guards []selectiveGuardRule
	for _, g := range selectiveGuardRules(&p) {
		if g.destination != "" {
			guards = append(guards, g)
		}
	}
	return b.applySelectiveGuardRules(ctx, guards, &p)
}

func (b *NetworkBackend) cleanupSelectiveGuards(
	ctx context.Context,
	p, old *dataplane.Plan,
	retainSynthetic bool,
) error {
	next := selectiveGuardRules(p)
	for _, g := range selectiveGuardRules(old) {
		keep := retainSynthetic && g.destination != ""
		for _, v := range next {
			if v == g {
				keep = true
			}
		}
		if keep {
			continue
		}
		rules, err := b.rules(ctx, g.family)
		if err != nil {
			return err
		}
		for _, r := range rules {
			if g.matches(r) {
				if _, err = b.Runner.Run(ctx, b.IPBinary, g.args("del"), nil); err != nil {
					return errors.New("selective_guard_cleanup_failed")
				}
			}
		}
	}
	return nil
}

func validateSelectivePrefixes(p dataplane.Plan, interfaces []string) error {
	if p.Desired.Selective == nil {
		return nil
	}
	fake := []netip.Prefix{
		netip.MustParsePrefix(p.Desired.Selective.FakeIPv4),
		netip.MustParsePrefix(p.Desired.Selective.FakeIPv6),
	}
	for _, raw := range interfaces {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			continue
		}
		for _, f := range fake {
			if f.Overlaps(prefix) {
				return errors.New(
					"selective_prefix_conflict: fake IP overlaps a LAN or tunnel subnet",
				)
			}
		}
	}
	return nil
}

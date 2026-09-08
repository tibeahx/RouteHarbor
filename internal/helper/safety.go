package helper

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"

	"github.com/tibeahx/OpenRHP/internal/dataplane"
	"github.com/tibeahx/OpenRHP/internal/model"
)

const (
	safetyTable    = 20999
	safetyPriority = 30000
)

type safetyLocalRoute struct {
	family int
	prefix string
	device string
}

// Recovery may own guards from both sides of an interrupted policy change.
// These networks come only from the root-owned journal, never a request field.
func safetyNetworks(p *dataplane.Plan) []model.Network {
	if p == nil {
		return nil
	}
	out := append([]model.Network(nil), p.SafetyNetworks...)
	if p.Desired.Fallback == "closed" {
		out = append(out, p.Desired.Network)
	}
	return out
}

func addSafetyOwner(p *dataplane.Plan, network model.Network) {
	p.SafetyNetworks = append(p.SafetyNetworks, network)
}

func safetyRuleAllowed(rule ipRule, old *dataplane.Plan) bool {
	if rule.Unsupported || number(rule.Table) != safetyTable || len(rule.FWMark) != 0 ||
		len(rule.FWMask) != 0 {
		return false
	}
	iif := rule.IIF
	if iif == "" {
		iif = rule.IIFName
	}
	for _, network := range safetyNetworks(old) {
		for index, dev := range network.LANInterfaces {
			if iif == dev && rule.Priority == safetyPriority+index {
				return true
			}
		}
	}
	return false
}

func ownedSafetyLocalRoutes(p *dataplane.Plan) []safetyLocalRoute {
	routes := []safetyLocalRoute{}
	seen := map[safetyLocalRoute]bool{}
	for _, network := range safetyNetworks(p) {
		candidate := dataplane.Plan{Desired: dataplane.Desired{Network: network}}
		for _, route := range safetyLocalRoutes(candidate) {
			if !seen[route] {
				seen[route] = true
				routes = append(routes, route)
			}
		}
	}
	return routes
}

func safetyLocalRoutes(p dataplane.Plan) []safetyLocalRoute {
	result := []safetyLocalRoute{}
	for _, prefix := range p.Desired.Network.LocalPrefixes {
		wanted, _ := netip.ParsePrefix(prefix)
		for _, device := range p.Desired.Network.LANInterfaces {
			iface, err := net.InterfaceByName(device)
			if err != nil {
				continue
			}
			addresses, err := iface.Addrs()
			if err != nil {
				continue
			}
			found := false
			for _, raw := range addresses {
				a, err := netip.ParsePrefix(raw.String())
				if err != nil {
					continue
				}
				if a.Addr().BitLen() == wanted.Addr().BitLen() && a.Bits() <= wanted.Bits() &&
					a.Masked().Contains(wanted.Addr()) {
					family := 4
					if wanted.Addr().Is6() {
						family = 6
					}
					result = append(result, safetyLocalRoute{family, wanted.String(), device})
					found = true
					break
				}
			}
			if found {
				break
			}
		}
	}
	return result
}

func (b *NetworkBackend) checkSafety(
	ctx context.Context,
	p dataplane.Plan,
	old *dataplane.Plan,
) error {
	allowed := ownedSafetyLocalRoutes(old)
	owned := len(safetyNetworks(old)) > 0
	for _, family := range []int{4, 6} {
		entries, err := b.routeEntries(ctx, family)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if number(entry.Table) != safetyTable {
				continue
			}
			if !owned {
				return errors.New("ownership_conflict: safety route table belongs to another owner")
			}
			if entry.Type == "blackhole" && entry.Dst == "default" {
				continue
			}
			match := false
			for _, a := range allowed {
				if a.family == family && entry.Dst == a.prefix && entry.Dev == a.device &&
					entry.Gateway == "" {
					match = true
				}
			}
			if !match {
				return errors.New("ownership_conflict: safety route table contains a foreign route")
			}
		}
	}
	return nil
}

// applySafety installs a routing guard that survives nft flush and fw4 stop. Only
// packets with an explicitly permitted source mark can bypass its blackhole.
// Kernel-local management traffic retains the standard priority-0 local lookup.
func (b *NetworkBackend) applySafety(
	ctx context.Context,
	p dataplane.Plan,
	old *dataplane.Plan,
) error {
	if err := b.checkSafety(ctx, p, old); err != nil {
		return err
	}
	if p.Desired.Fallback == "closed" {
		for _, family := range []int{4, 6} {
			if _, err := b.Runner.Run(
				ctx,
				b.IPBinary,
				[]string{
					"-" + strconv.Itoa(family),
					"route",
					"replace",
					"blackhole",
					"default",
					"table",
					strconv.Itoa(safetyTable),
				},
				nil,
			); err != nil {
				return errors.New("safety_route_failed")
			}
			for _, route := range safetyLocalRoutes(p) {
				if route.family != family {
					continue
				}
				if _, err := b.Runner.Run(
					ctx,
					b.IPBinary,
					[]string{
						"-" + strconv.Itoa(family),
						"route",
						"replace",
						route.prefix,
						"dev",
						route.device,
						"table",
						strconv.Itoa(safetyTable),
					},
					nil,
				); err != nil {
					return errors.New("safety_route_failed")
				}
			}
			rules, err := b.rules(ctx, family)
			if err != nil {
				return err
			}
			for index, device := range p.Desired.Network.LANInterfaces {
				priority := safetyPriority + index
				found := false
				for _, r := range rules {
					if r.Priority == priority {
						if (r.IIF != device && r.IIFName != device) ||
							number(r.Table) != safetyTable ||
							number(r.FWMark) != 0 ||
							number(r.FWMask) != 0 {
							return errors.New(
								"ownership_conflict: safety rule priority is occupied",
							)
						}
						found = true
					}
				}
				if !found {
					if _, err = b.Runner.Run(
						ctx,
						b.IPBinary,
						[]string{
							"-" + strconv.Itoa(family),
							"rule",
							"add",
							"priority",
							strconv.Itoa(priority),
							"iif",
							device,
							"lookup",
							strconv.Itoa(safetyTable),
						},
						nil,
					); err != nil {
						return errors.New("safety_rule_failed")
					}
				}
			}
		}
	}
	// Old local routes and interfaces remain blocked until the new nft policy is
	// installed; cleanup is done separately after the successful nft transaction.
	return nil
}

func (b *NetworkBackend) cleanupSafety(
	ctx context.Context,
	p dataplane.Plan,
	old *dataplane.Plan,
) error {
	if len(safetyNetworks(old)) == 0 {
		return nil
	}
	for _, family := range []int{4, 6} {
		rules, err := b.rules(ctx, family)
		if err != nil {
			return err
		}
		entries, err := b.routeEntries(ctx, family)
		if err != nil {
			return err
		}
		// Iterate the actual rules once even if multiple journal states owned
		// the same guard. Never delete a priority based only on its number.
		for _, rule := range rules {
			if !safetyRuleAllowed(rule, old) {
				continue
			}
			device := rule.IIF
			if device == "" {
				device = rule.IIFName
			}
			keep := false
			if p.Desired.Fallback == "closed" {
				for index, dev := range p.Desired.Network.LANInterfaces {
					if device == dev && rule.Priority == safetyPriority+index {
						keep = true
					}
				}
			}
			if !keep {
				if _, err := b.Runner.Run(
					ctx,
					b.IPBinary,
					[]string{
						"-" + strconv.Itoa(family),
						"rule",
						"del",
						"priority",
						strconv.Itoa(rule.Priority),
						"iif",
						device,
						"lookup",
						strconv.Itoa(safetyTable),
					},
					nil,
				); err != nil {
					return errors.New("safety_cleanup_failed")
				}
			}
		}
		oldRoutes := ownedSafetyLocalRoutes(old)
		newRoutes := safetyLocalRoutes(p)
		for _, r := range oldRoutes {
			if r.family != family {
				continue
			}
			keep := false
			if p.Desired.Fallback == "closed" {
				for _, next := range newRoutes {
					if next == r {
						keep = true
					}
				}
			}
			exists := false
			for _, entry := range entries {
				if number(entry.Table) == safetyTable && entry.Dst == r.prefix &&
					entry.Dev == r.device {
					exists = true
				}
			}
			if !keep && exists {
				if _, err := b.Runner.Run(
					ctx,
					b.IPBinary,
					[]string{
						"-" + strconv.Itoa(family),
						"route",
						"del",
						r.prefix,
						"dev",
						r.device,
						"table",
						strconv.Itoa(safetyTable),
					},
					nil,
				); err != nil {
					return errors.New("safety_cleanup_failed")
				}
			}
		}
		blackholeExists := false
		for _, entry := range entries {
			if number(entry.Table) == safetyTable && entry.Type == "blackhole" &&
				entry.Dst == "default" {
				blackholeExists = true
			}
		}
		if p.Desired.Fallback != "closed" && blackholeExists {
			if _, err := b.Runner.Run(
				ctx,
				b.IPBinary,
				[]string{
					"-" + strconv.Itoa(family),
					"route",
					"del",
					"blackhole",
					"default",
					"table",
					strconv.Itoa(safetyTable),
				},
				nil,
			); err != nil {
				return errors.New("safety_cleanup_failed")
			}
		}
	}
	return nil
}

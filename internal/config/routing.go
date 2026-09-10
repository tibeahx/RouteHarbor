package config

import (
	"fmt"
	"net/netip"
	"net/url"

	"github.com/tibeahx/RouteHarbor/internal/model"
	"github.com/tibeahx/RouteHarbor/internal/routing"
)

// RoutingDefaults applies only to new installations. Decode never inserts it in
// an existing file, so old confirmed configurations retain all-traffic routing.
func RoutingDefaults() *model.RoutingConfig {
	return &model.RoutingConfig{
		Mode:          "selective",
		FailurePolicy: "direct",
		Registry:      model.RoutingRegistry{Enabled: true, Provider: "antifilter"},
		Detection:     model.RoutingDetection{ControlTargetIDs: []string{}},
		Exceptions:    []model.RoutingRule{},
	}
}

// ValidRoutingDomain accepts canonical DNS names, not URLs, IP literals, wildcard
// syntax or Unicode lookalikes. International names use their ASCII A-label form.
func ValidRoutingDomain(domain string) bool {
	canonical, err := routing.CanonicalDomain(domain)
	return err == nil && canonical == domain && !routing.LocalDomain(domain)
}

func validateRouting(c model.Config) error {
	p := c.Routing
	if p == nil {
		return nil
	}
	bad := func(field, reason string) error { return fmt.Errorf("routing.%s: %s", field, reason) }
	if p.Mode != "selective" && p.Mode != "legacy-all" {
		return bad("mode", "must be selective or legacy-all")
	}
	if p.FailurePolicy != "direct" {
		return bad("failure_policy", "must explicitly permit emergency direct")
	}
	if p.Registry.Provider != "antifilter" {
		return bad("registry.provider", "must be antifilter")
	}
	if len(p.Exceptions) > 4096 {
		return bad("exceptions", "exceeds 4096 rule limit")
	}
	seen := map[string]bool{}
	for _, rule := range p.Exceptions {
		if rule.Action != "direct" && rule.Action != "bypass" {
			return bad("exceptions", "action must be direct or bypass")
		}
		if (rule.Domain == "") == (rule.CIDR == "") {
			return bad("exceptions", "each rule requires exactly one domain or CIDR")
		}
		key := rule.Action + ":" + rule.Domain + ":" + rule.CIDR + fmt.Sprint(
			rule.IncludeSubdomains,
		)
		if seen[key] {
			return bad("exceptions", "duplicate rule")
		}
		seen[key] = true
		if rule.Domain != "" && !ValidRoutingDomain(rule.Domain) {
			return bad(
				"exceptions",
				"domain must be a canonical public DNS name; subdomains require an explicit flag",
			)
		}
		if rule.CIDR != "" {
			prefix, err := routing.CanonicalPrefix(rule.CIDR)
			ip, ipErr := netip.ParseAddr(rule.CIDR)
			canonical := prefix.String() == rule.CIDR || (ipErr == nil && ip.String() == rule.CIDR)
			if err != nil || !canonical || rule.IncludeSubdomains {
				return bad(
					"exceptions",
					"IP or CIDR must be canonical and public without subdomain matching",
				)
			}
		}
	}
	if len(p.Detection.ControlTargetIDs) > 64 {
		return bad("detection.control_target_ids", "exceeds 64 control resource limit")
	}
	ids := map[string]bool{}
	for _, id := range p.Detection.ControlTargetIDs {
		if ids[id] {
			return bad("detection.control_target_ids", "duplicate control target")
		}
		ids[id] = true
		found := false
		for _, target := range c.Targets {
			if target.ID == id {
				parsed, err := url.Parse(target.URL)
				if err != nil || parsed.Scheme != "https" ||
					parsed.Port() != "" && parsed.Port() != "443" {
					return bad(
						"detection.control_target_ids",
						"control resources must use HTTPS on port 443",
					)
				}
				found = true
				break
			}
		}
		if !found {
			return bad(
				"detection.control_target_ids",
				"must reference configured HTTPS probe resources",
			)
		}
	}
	if p.Detection.Enabled && len(ids) == 0 {
		return bad(
			"detection.control_target_ids",
			"automatic detection requires an explicitly configured control resource",
		)
	}
	if p.Mode == "selective" {
		if c.Policy.BreakExisting {
			return bad(
				"mode",
				"selective routing requires break_existing=false to preserve ordinary connections",
			)
		}
		if c.Policy.Fallback != "closed" {
			return bad(
				"mode",
				"selective routing requires closed bypass fallback; emergency direct is a separate classifier failure policy",
			)
		}
		if c.Policy.Mode == "manual" && (c.Continuity == nil || !c.Continuity.Enabled) {
			for _, s := range c.Sources {
				if s.ID == c.Policy.Pinned && s.Type == "direct" {
					return bad("mode", "direct cannot be selected as a bypass method")
				}
			}
		}
	}
	return nil
}

// RedactRouting deliberately copies only public configuration; DNS observations
// and detector history are never part of this representation.
func RedactRouting(p *model.RoutingConfig) *model.RoutingConfig {
	if p == nil {
		return nil
	}
	out := &model.RoutingConfig{
		Mode:          p.Mode,
		FailurePolicy: p.FailurePolicy,
		Registry: model.RoutingRegistry{
			Enabled:  p.Registry.Enabled,
			Provider: p.Registry.Provider,
		},
		Detection: model.RoutingDetection{
			Enabled:          p.Detection.Enabled,
			ControlTargetIDs: append([]string{}, p.Detection.ControlTargetIDs...),
		},
		Exceptions: []model.RoutingRule{},
	}
	for _, r := range p.Exceptions {
		out.Exceptions = append(
			out.Exceptions,
			model.RoutingRule{
				Action:            r.Action,
				Domain:            r.Domain,
				IncludeSubdomains: r.IncludeSubdomains,
				CIDR:              r.CIDR,
			},
		)
	}
	return out
}

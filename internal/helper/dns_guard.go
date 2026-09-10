package helper

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/tibeahx/OpenRHP/internal/dataplane"
)

// DNSGuardIdentity is read only from the private routing journal, never a request.
// The account and trusted executable are bound before any rule is installed.
type DNSGuardIdentity struct {
	UID          uint32 `json:"uid"`
	GID          uint32 `json:"gid"`
	BinarySHA256 string `json:"binary_sha256"`
	InitSHA256   string `json:"init_sha256"`
}

func (d DNSGuardIdentity) valid() bool {
	if d.UID == 0 || d.GID == 0 || d.UID > 1<<31-1 || d.GID > 1<<31-1 {
		return false
	}
	for _, hash := range []string{d.BinarySHA256, d.InitSHA256} {
		if len(hash) != 64 {
			return false
		}
		if _, err := hex.DecodeString(hash); err != nil {
			return false
		}
	}
	return true
}

func attachDNSGuard(p *dataplane.Plan, s *State) {
	p.IngressDevices = append([]string(nil), s.Ingress...)
	if s.DNSGuard != nil {
		p.DNSGuardUID = s.DNSGuard.UID
	}
}

func (m *Manager) prepareDNSIdentity(ctx context.Context, s *State) error {
	b, ok := m.backend.(*NetworkBackend)
	if !ok || b.DNSIdentity == nil {
		return nil
	}
	identity, err := b.DNSIdentity(ctx)
	if err != nil {
		return m.dnsIdentityFailure(ctx, s, err)
	}
	if !identity.valid() {
		return errors.New("dns_guard_unavailable: DNS service ownership is not verifiable")
	}
	if s.DNSGuard != nil {
		if *s.DNSGuard != identity {
			return m.dnsIdentityFailure(
				ctx,
				s,
				errors.New(
					"dns_guard_identity_changed: previous protection retained; restore the trusted DNS service or explicitly decommission routing",
				),
			)
		}
		return nil
	}
	// Saving ownership before mutation makes a partially installed rule replayable.
	// No DNS rule is removed by ordinary configuration changes or rollback.
	s.DNSGuard = &identity
	return m.save(s)
}

const dnsGuardPriority = 29900

func hasDNSSelectors(r ipRule) bool {
	return r.UIDStart != nil || r.UIDEnd != nil || r.IPProto != "" || r.DPort != 0 || r.Action != ""
}

func dnsRuleAllowed(r ipRule, owner *dataplane.Plan) bool {
	if owner == nil || owner.DNSGuardUID == 0 || r.Unsupported || r.Destination != "" ||
		r.UIDStart == nil ||
		r.UIDEnd == nil ||
		*r.UIDStart != owner.DNSGuardUID ||
		*r.UIDEnd != owner.DNSGuardUID ||
		r.Action != "blackhole" ||
		r.DPort != 53 ||
		len(r.Table) != 0 ||
		len(r.FWMark) != 0 ||
		len(r.FWMask) != 0 ||
		r.IIF != "" ||
		r.IIFName != "" {
		return false
	}
	return r.Priority == dnsGuardPriority && (r.IPProto == "tcp" || r.IPProto == "ipproto-6") ||
		r.Priority == dnsGuardPriority+1 && (r.IPProto == "udp" || r.IPProto == "ipproto-17")
}

func dnsRuleArgs(family int, action string, uid uint32, offset int) []string {
	protocol := "6"
	if offset == 1 {
		protocol = "17"
	}
	user := strconv.FormatUint(uint64(uid), 10)
	return []string{
		"-" + strconv.Itoa(family),
		"rule",
		action,
		"priority",
		strconv.Itoa(dnsGuardPriority + offset),
		"uidrange",
		user + "-" + user,
		"ipproto",
		protocol,
		"dport",
		"53",
		"blackhole",
	}
}

func (b *NetworkBackend) applyDNSGuard(
	ctx context.Context,
	p dataplane.Plan,
	old *dataplane.Plan,
) error {
	if p.DNSGuardUID == 0 || p.Desired.Selective != nil {
		return nil
	}
	for _, family := range []int{4, 6} {
		rules, err := b.rules(ctx, family)
		if err != nil {
			return err
		}
		for offset := 0; offset < 2; offset++ {
			found := false
			for _, r := range rules {
				if r.Priority != dnsGuardPriority+offset {
					continue
				}
				if !dnsRuleAllowed(r, old) {
					return errors.New(
						"ownership_conflict: DNS guard rule priority belongs to another owner",
					)
				}
				found = true
			}
			if !found {
				if _, err = b.Runner.Run(
					ctx,
					b.IPBinary,
					dnsRuleArgs(family, "add", p.DNSGuardUID, offset),
					nil,
				); err != nil {
					return errors.New(
						"dns_guard_unavailable: kernel rejected the dedicated DNS owner routing guard",
					)
				}
			}
		}
	}
	return nil
}

func (b *NetworkBackend) removeDNSGuard(ctx context.Context, p dataplane.Plan) error {
	if p.DNSGuardUID == 0 {
		return nil
	}
	for _, family := range []int{4, 6} {
		rules, err := b.rules(ctx, family)
		if err != nil {
			return err
		}
		for _, r := range rules {
			if dnsRuleAllowed(r, &p) {
				if _, err = b.Runner.Run(
					ctx,
					b.IPBinary,
					dnsRuleArgs(family, "del", p.DNSGuardUID, r.Priority-dnsGuardPriority),
					nil,
				); err != nil {
					return errors.New("dns_guard_cleanup_failed")
				}
			}
		}
	}
	return nil
}

func (m *Manager) dnsIdentityFailure(ctx context.Context, s *State, cause error) error {
	if s.Committed != nil {
		if err := m.quarantineLocked(ctx, s); err != nil {
			return errors.New(
				"dns_guard_unverified: DNS identity failed and quarantine requires recovery",
			)
		}
	}
	return cause
}

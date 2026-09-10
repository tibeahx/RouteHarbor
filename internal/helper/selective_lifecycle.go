package helper

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tibeahx/OpenRHP/internal/dataplane"
	"github.com/tibeahx/OpenRHP/internal/dispatch"
	"github.com/tibeahx/OpenRHP/internal/routing"
)

// EmergencyDirect honors only the explicit selective failure policy. It removes
// exact journal-owned rules, keeps synthetic destination rejection, and leaves
// all unrelated firewall/routing policy untouched.
func (b *NetworkBackend) EmergencyDirect(ctx context.Context, p dataplane.Plan) error {
	if p.Desired.Selective == nil || p.Desired.Selective.FailurePolicy != "direct" {
		return errors.New("selective_failure_policy_required")
	}
	if err := b.checkTables(ctx); err != nil {
		return err
	}
	if err := b.checkRoutes(ctx, p, &p); err != nil {
		return err
	}
	if err := b.checkSafety(ctx, p, &p); err != nil {
		return err
	}
	batch, err := dataplane.EmergencyDirectNFT(p.Desired)
	if err != nil {
		return err
	}
	if _, err = b.Runner.Run(
		ctx,
		b.NFTBinary,
		[]string{"--check", "--file", "-"},
		[]byte(batch+p.GuardNFT),
	); err != nil {
		return errors.New("selective_emergency_check_failed")
	}
	// Kernel rules survive an nft flush and never permit stale FakeIP on WAN.
	if err = b.applySelectiveGuards(ctx, p, &p); err != nil {
		return err
	}
	if err = b.saveGuard(p); err != nil {
		return err
	}
	if _, err = b.Runner.Run(
		ctx,
		b.NFTBinary,
		[]string{"--file", "-"},
		[]byte(batch+p.GuardNFT),
	); err != nil {
		return errors.New("selective_emergency_apply_failed")
	}
	for _, r := range p.Routes {
		if err = b.removeRoute(ctx, r); err != nil {
			return err
		}
	}
	if err = b.removeDNSGuard(ctx, p); err != nil {
		return err
	}
	direct := p
	direct.Desired.Fallback = "direct"
	direct.SafetyNetworks = nil
	if err = b.cleanupSafety(ctx, direct, &p); err != nil {
		return err
	}
	if err = b.cleanupSelectiveGuards(ctx, nil, &p, true); err != nil {
		return err
	}
	// DNS redirects are conntrack NAT state: clearing only the dispatcher slot
	// also restores DNS for applications that reuse an existing UDP socket.
	return b.ResetFlowTracking(ctx, p.Desired.Selective.Path.Slot)
}

type selectiveEmergencyBackend interface {
	EmergencyDirect(context.Context, dataplane.Plan) error
}

func (m *Manager) selectiveEmergencyLocked(
	ctx context.Context,
	s *State,
	d dataplane.Desired,
) error {
	if s.MaintenanceHold || s.MaintenanceJob != "" {
		return ErrMaintenanceActive
	}
	if d.Selective == nil || d.Selective.FailurePolicy != "direct" {
		return errors.New("selective_failure_policy_required")
	}
	b, ok := m.backend.(selectiveEmergencyBackend)
	if !ok {
		return errors.New("selective_emergency_unavailable")
	}
	p, err := dataplane.Compile(d)
	if err != nil {
		return err
	}
	attachDNSGuard(&p, s)
	if s.Guarded {
		addSafetyOwner(&p, d.Network)
	}
	if t := s.Transaction; t != nil && active(t) && t.State != "prepared" && t.Previous != nil {
		prior, err := dataplane.Compile(*t.Previous)
		if err != nil {
			return err
		}
		if prior.Desired.Fallback == "closed" && prior.Desired.Selective == nil {
			addSafetyOwner(&p, prior.Desired.Network)
		}
		for _, r := range prior.Routes {
			if !containsRoute(p.Routes, r) {
				p.Routes = append(p.Routes, r)
			}
		}
	}
	// Persist authorization/state before touching the network, so boot retries an
	// interrupted recovery. This flag is cleared only by a new successful apply.
	s.SelectiveEmergency = true
	s.SelectiveEmergencyPending = true
	if err = m.save(s); err != nil {
		return err
	}
	if err = b.EmergencyDirect(ctx, p); err != nil {
		return err
	}
	s.Guarded = false
	s.SelectiveEmergencyPending = false
	return m.save(s)
}

func (m *Manager) SelectiveEmergency(
	ctx context.Context,
) error {
	return m.selectiveEmergency(ctx, "")
}

// SelectiveEmergencyFor cannot act on a replacement transaction after a slow
// health check raced a newly confirmed network policy.
func (m *Manager) SelectiveEmergencyFor(ctx context.Context, transaction string) error {
	if !validTransactionID(transaction) {
		return errors.New("invalid_transaction_identity")
	}
	return m.selectiveEmergency(ctx, transaction)
}

func (m *Manager) selectiveEmergency(ctx context.Context, transaction string) error {
	return m.locked(func(s *State) error {
		if transaction != "" &&
			(s.Transaction == nil || s.Transaction.ID != transaction || s.Transaction.State != "confirmed" && s.Transaction.State != "rolled-back" && s.Transaction.State != "prepared" && s.Transaction.State != "failed") {
			return nil
		}
		if transaction != "" && s.SelectiveEmergency && !s.SelectiveEmergencyPending {
			if s.MaintenanceHold || s.MaintenanceJob != "" {
				return ErrMaintenanceActive
			}
			// An already completed recovery is monitored by the guard-only path.
			// Repeated repair failures must not reset DNS or rewrite its journal.
			return nil
		}
		d := s.Committed
		if s.Transaction != nil && active(s.Transaction) && s.Transaction.State != "prepared" {
			d = &s.Transaction.Candidate
		}
		if d == nil {
			return nil
		}
		return m.selectiveEmergencyLocked(ctx, s, *d)
	})
}

// SelectiveHealth performs local-only probes; it never depends on the registry,
// bypass source or the WAN being healthy. The reserved DNS name must receive
// a synthetic answer from the engine through the frontend, without external DNS.
func SelectiveHealth(ctx context.Context, d dataplane.Desired) error {
	if d.Selective == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(
		ctx,
		"tcp",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(int(d.Selective.Path.Port))),
	)
	// The classifier rejects this loopback destination immediately. Its reset
	// can win the connect-completion race on OpenWrt: that still proves the
	// listener answered. DNS below must independently prove engine service.
	if err != nil && !errors.Is(err, syscall.ECONNRESET) {
		return errors.New("selective_dispatcher_unavailable")
	}
	if conn != nil {
		_ = conn.Close()
	}
	conn, err = dialer.DialContext(
		ctx,
		"udp",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(int(d.Selective.DNSFrontPort))),
	)
	if err != nil {
		return errors.New("selective_dns_unavailable")
	}
	defer func() { _ = conn.Close() }()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	query := make([]byte, 12)
	if _, err = rand.Read(query[:2]); err != nil {
		return err
	}
	query[2] = 1
	binary.BigEndian.PutUint16(query[4:6], 1)
	query = append(query, 14)
	query = append(query, []byte("openrhp-health")...)
	query = append(query, 7)
	query = append(query, []byte("invalid")...)
	query = append(query, 0, 0, 1, 0, 1)
	if _, err = conn.Write(query); err != nil {
		return errors.New("selective_dns_unavailable")
	}
	response := make([]byte, 512)
	n, err := conn.Read(response)
	pool := netip.MustParsePrefix(dispatch.FakePoolIPv4(d.Selective.FakePool))
	if err != nil || !routing.ValidDNSHealthResponse(query, response[:n], pool) {
		return errors.New("selective_dns_unavailable")
	}
	return nil
}

// WatchSelectiveOnce is driven by the independent watchdog process after
// transaction confirmation. false means no active selective classifier remains.
// The caller debounces consecutive failures before invoking SelectiveEmergency.
func (m *Manager) WatchSelectiveOnce(ctx context.Context) (bool, error) {
	return m.watchSelectiveOnce(ctx, "")
}

// A detached monitor must not operate on a replacement transaction after its
// original status read raced a newly prepared or confirmed policy.
func (m *Manager) WatchSelectiveOnceFor(ctx context.Context, transaction string) (bool, error) {
	if !validTransactionID(transaction) {
		return false, errors.New("invalid_transaction_identity")
	}
	return m.watchSelectiveOnce(ctx, transaction)
}

func (m *Manager) watchSelectiveOnce(ctx context.Context, transaction string) (bool, error) {
	s, err := m.Status()
	if err != nil {
		return true, err
	}
	if transaction != "" && (s.Transaction == nil || s.Transaction.ID != transaction) {
		return false, nil
	}
	if s.MaintenanceHold || s.MaintenanceJob != "" || s.Committed == nil ||
		s.Committed.Selective == nil {
		return false, nil
	}
	if active(s.Transaction) && s.Transaction.State != "prepared" {
		return true, nil
	}
	if s.SelectiveEmergencyPending {
		return true, errors.New("selective_emergency_pending")
	}
	if s.SelectiveEmergency {
		id := ""
		if s.Transaction != nil {
			id = s.Transaction.ID
		}
		watch := true
		err := m.locked(func(current *State) error {
			currentID := ""
			if current.Transaction != nil {
				currentID = current.Transaction.ID
			}
			if id != currentID || current.MaintenanceHold || current.MaintenanceJob != "" ||
				current.Committed == nil ||
				current.Committed.Selective == nil {
				watch = false
				return nil
			}
			if !current.SelectiveEmergency || current.SelectiveEmergencyPending ||
				active(current.Transaction) && current.Transaction.State != "prepared" {
				return nil
			}
			backend, ok := m.backend.(interface {
				EnsureSelectiveEmergencyGuards(context.Context, dataplane.Desired) error
			})
			if !ok {
				return errors.New("selective_emergency_guard_unavailable")
			}
			return backend.EnsureSelectiveEmergencyGuards(ctx, *current.Committed)
		})
		return watch, err
	}
	if b, ok := m.backend.(interface {
		CheckSelectiveHealth(context.Context, dataplane.Desired) error
	}); ok {
		if err := b.CheckSelectiveHealth(ctx, *s.Committed); err != nil {
			return true, err
		}
	}
	return true, SelectiveHealth(ctx, *s.Committed)
}

func (b *NetworkBackend) CheckSelectiveHealth(ctx context.Context, d dataplane.Desired) error {
	if d.Selective == nil {
		return nil
	}
	// A running process alone is insufficient after fw4/nft replacement. Verify
	// the dispatcher table and the local routing allocation before reporting live.
	raw, err := b.Runner.Run(
		ctx,
		b.NFTBinary,
		[]string{"list", "chain", "inet", dataplane.Table, "dispatch"},
		nil,
	)
	if err != nil ||
		!strings.Contains(
			string(raw),
			"tproxy ip to 127.0.0.1:"+strconv.Itoa(int(d.Selective.Path.Port)),
		) {
		return errors.New("selective_classifier_rules_unavailable")
	}
	raw, err = b.Runner.Run(
		ctx,
		b.NFTBinary,
		[]string{"list", "chain", "inet", dataplane.Table, "dns"},
		nil,
	)
	if err != nil ||
		!strings.Contains(
			string(raw),
			"redirect to :"+strconv.Itoa(int(d.Selective.DNSFrontPort)),
		) {
		return errors.New("selective_dns_rules_unavailable")
	}
	p, err := dataplane.Compile(d)
	if err != nil {
		return err
	}
	for _, r := range p.Routes {
		if r.Mark != dataplane.Mark(d.Selective.Path.Slot) {
			continue
		}
		present, err := b.ruleExists(ctx, r)
		if err != nil || !present {
			return errors.New("selective_classifier_route_unavailable")
		}
		entries, err := b.routeEntries(ctx, r.Family)
		if err != nil {
			return err
		}
		found := false
		for _, entry := range entries {
			if routeEntryMatches(entry, r) {
				found = true
			}
		}
		if !found {
			return errors.New("selective_classifier_route_unavailable")
		}
	}
	return nil
}

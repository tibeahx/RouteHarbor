package helper

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/dataplane"
)

func selectiveDesired() dataplane.Desired {
	d := testDesired()
	d.Paths = []dataplane.Path{
		{
			SourceID:  "tunnel",
			Kind:      "interface",
			Slot:      4,
			Interface: "tunnel0",
			UDP:       true,
			IPv6:      true,
		},
	}
	d.Selected = "tunnel"
	d.Selective = &dataplane.SelectiveIntent{
		Path: dataplane.Path{
			SourceID: dataplane.SelectiveSourceID,
			Kind:     "tproxy",
			Slot:     250,
			Port:     12250,
			IPv6:     true,
			UDP:      true,
		},
		DNSFrontPort:  12550,
		FakeIPv4:      dataplane.DefaultFakeIPv4,
		FakeIPv6:      dataplane.DefaultFakeIPv6,
		FailurePolicy: "direct",
		PolicyHash:    strings.Repeat("a", 64),
		Snapshot: dataplane.SelectiveSnapshotRef{
			Generation: 1,
			SHA256:     strings.Repeat("a", 64),
		},
	}
	return d
}

type emergencyMemory struct {
	memoryBackend
	emergencies int
}

func (b *emergencyMemory) EmergencyDirect(context.Context, dataplane.Plan) error {
	b.emergencies++
	return nil
}
func (b *emergencyMemory) CheckQuarantine(context.Context, dataplane.Plan) error { return nil }
func (b *emergencyMemory) Quarantine(context.Context, dataplane.Plan) error      { return nil }
func TestSelectiveBootReplaysApprovedDirectAndRespectsHold(t *testing.T) {
	b := &emergencyMemory{}
	m := testManager(t, b, &testWatchdog{})
	ctx := context.Background()
	d := selectiveDesired()
	tx, err := m.Prepare(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Apply(ctx, tx.ID, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Confirm(tx.ID); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewManager(m.dir, b, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.BootGuard(ctx); err != nil {
		t.Fatal(err)
	}
	s, err := restarted.Status()
	if err != nil || !s.SelectiveEmergency || b.emergencies != 1 || s.Guarded {
		t.Fatalf("state=%+v emergency=%d err=%v", s, b.emergencies, err)
	}
	if err = restarted.locked(
		func(s *State) error { s.MaintenanceHold = true; return restarted.save(s) },
	); err != nil {
		t.Fatal(err)
	}
	if err = restarted.SelectiveEmergency(ctx); !errors.Is(err, ErrMaintenanceActive) {
		t.Fatal("maintenance was reopened", err)
	}
	if err = restarted.BootGuard(ctx); err != nil {
		t.Fatal(err)
	}
	if b.emergencies != 1 {
		t.Fatal("boot overrides maintenance hold")
	}
}

func TestSelectiveRulesRequireExactOwnership(t *testing.T) {
	p, err := dataplane.Compile(selectiveDesired())
	if err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		raw     string
		family  int
		allowed bool
	}{
		{`{"priority":29910,"src":"all","dst":"198.18.0.0/15","action":"blackhole"}`, 4, true},
		{
			`{"priority":29910,"src":"all","dst":"198.18.0.0","dstlen":15,"action":"blackhole"}`,
			4,
			true,
		},
		{
			`{"priority":29910,"src":"all","dst":"198.18.0.0","dstlen":14,"action":"blackhole"}`,
			4,
			false,
		},
		{`{"priority":29910,"src":"all","dst":"198.18.0.0/15","action":"blackhole"}`, 6, false},
		{`{"priority":29910,"src":"all","dst":"10.0.0.0/8","action":"blackhole"}`, 4, false},
		{
			`{"priority":26004,"src":"all","fwmark":"0x4f040000","fwmask":"0xffff0000","action":"blackhole"}`,
			4,
			true,
		},
		{
			`{"priority":26004,"src":"all","dst":"1.1.1.1","fwmark":"0x4f040000","fwmask":"0xffff0000","action":"blackhole"}`,
			4,
			false,
		},
	}
	for _, row := range rows {
		var rule ipRule
		if err = json.Unmarshal([]byte(row.raw), &rule); err != nil {
			t.Fatal(err)
		}
		if selectiveRuleAllowed(row.family, rule, &p) != row.allowed {
			t.Fatal(row.raw)
		}
	}
	if len(safetyNetworks(&p)) != 0 {
		t.Fatal("selective intent installs global LAN blackhole")
	}
	if err = validateSelectivePrefixes(p, []string{"fd66:6f70:656e:1::/64"}); err == nil {
		t.Fatal("tunnel overlap accepted")
	}
}

func TestSelectiveHealthUsesLocalReservedDNS(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tcp.Close() }()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udp.Close() }()
	d := selectiveDesired()
	d.Selective.Path.Port = uint16(tcp.Addr().(*net.TCPAddr).Port)
	d.Selective.DNSFrontPort = uint16(udp.LocalAddr().(*net.UDPAddr).Port)
	accepted := make(chan struct{})
	go func() {
		conn, e := tcp.Accept()
		if e == nil {
			_ = conn.Close()
		}
		close(accepted)
	}()
	queried := make(chan string, 1)
	go func() {
		buf := make([]byte, 512)
		n, peer, e := udp.ReadFrom(buf)
		if e != nil {
			return
		}
		queried <- string(buf[12:n])
		buf[2] |= 0x80
		buf[7] = 1
		answer := append(buf[:n], 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 18, 0, 1)
		_, _ = udp.WriteTo(answer, peer)
	}()
	if err = SelectiveHealth(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	<-accepted
	if q := <-queried; !strings.Contains(q, "routeharbor-health") {
		t.Fatal("health query could depend on external WAN", q)
	}
	_ = udp.Close()
	if err = SelectiveHealth(context.Background(), d); err == nil {
		t.Fatal("DNS outage reported healthy")
	}
}

func TestSelectiveWatchdogCannotReopenReplacementTransaction(t *testing.T) {
	b := &emergencyMemory{}
	m := testManager(t, b, &testWatchdog{})
	ctx := context.Background()
	tx, err := m.Prepare(ctx, selectiveDesired())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Apply(ctx, tx.ID, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Confirm(tx.ID); err != nil {
		t.Fatal(err)
	}
	if err = m.SelectiveEmergencyFor(ctx, strings.Repeat("f", 32)); err != nil {
		t.Fatal(err)
	}
	s, _ := m.Status()
	if s.SelectiveEmergency || b.emergencies != 0 {
		t.Fatal("stale health check opened a replacement policy")
	}
	if err = m.SelectiveEmergencyFor(ctx, tx.ID); err != nil {
		t.Fatal(err)
	}
	if b.emergencies != 1 {
		t.Fatal("matching watchdog failed")
	}
}

func TestSelectiveRollbackWithoutBypassKeepsDirectAndWatchdog(t *testing.T) {
	ctx := context.Background()
	b := &emergencyMemory{}
	m := testManager(t, b, &testWatchdog{})
	d := selectiveDesired()
	d.Selected = ""
	first, err := m.Prepare(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Apply(ctx, first.ID, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Confirm(first.ID); err != nil {
		t.Fatal(err)
	}
	next, err := m.Prepare(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Apply(ctx, next.ID, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Rollback(ctx, next.ID); err != nil {
		t.Fatal(err)
	}
	state, err := m.Status()
	if err != nil || state.Guarded || state.Committed == nil || state.Committed.Selective == nil ||
		state.Committed.Selected != "" {
		t.Fatal("selective rollback disabled ordinary direct", state, err)
	}
	if err = m.SelectiveEmergencyFor(ctx, next.ID); err != nil {
		t.Fatal(err)
	}
	state, err = m.Status()
	if err != nil || !state.SelectiveEmergency || b.emergencies != 1 {
		t.Fatal("rolled-back selective profile lost watchdog recovery", state, err)
	}
}

func TestSelectivePreparedWatchdogHandoverFailureRetainsJournal(t *testing.T) {
	ctx := context.Background()
	b := &emergencyMemory{}
	w := &testWatchdog{}
	m := testManager(t, b, w)
	d := selectiveDesired()
	first, err := m.Prepare(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Apply(ctx, first.ID, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Confirm(first.ID); err != nil {
		t.Fatal(err)
	}
	w.err = errors.New("injected prepared watchdog failure")
	if _, err = m.Prepare(ctx, d); err == nil {
		t.Fatal("missing prepared monitor accepted")
	}
	state, err := m.Status()
	if err != nil || state.Transaction.ID != first.ID || state.Transaction.State != "confirmed" ||
		state.SelectiveEmergency {
		t.Fatal("failed handover replaced monitored journal", state, err)
	}
	if err = m.SelectiveEmergencyFor(ctx, first.ID); err != nil {
		t.Fatal(err)
	}
	if b.emergencies != 1 {
		t.Fatal("original monitor lost authority")
	}
}

func TestSelectiveRollbackPreservesPreviousEmergency(t *testing.T) {
	for _, failApply := range []bool{false, true} {
		t.Run(
			map[bool]string{false: "explicit-rollback", true: "apply-failure"}[failApply],
			func(t *testing.T) {
				ctx := context.Background()
				b := &emergencyMemory{}
				m := testManager(t, b, &testWatchdog{})
				d := selectiveDesired()
				first, err := m.Prepare(ctx, d)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = m.Apply(ctx, first.ID, 30*time.Second); err != nil {
					t.Fatal(err)
				}
				if _, err = m.Confirm(first.ID); err != nil {
					t.Fatal(err)
				}
				if err = m.SelectiveEmergency(ctx); err != nil {
					t.Fatal(err)
				}
				next, err := m.Prepare(ctx, d)
				if err != nil || !next.PreviousSelectiveEmergency {
					t.Fatal("previous emergency not journaled", next, err)
				}
				b.failNext = failApply
				_, err = m.Apply(ctx, next.ID, 30*time.Second)
				if failApply && err == nil {
					t.Fatal("injected apply failure ignored")
				}
				if !failApply {
					if err != nil {
						t.Fatal(err)
					}
					if _, err = m.Rollback(ctx, next.ID); err != nil {
						t.Fatal(err)
					}
				}
				state, err := m.Status()
				if err != nil || state.Transaction.State != "rolled-back" ||
					!state.SelectiveEmergency ||
					state.SelectiveEmergencyPending ||
					state.Guarded ||
					b.emergencies != 2 {
					t.Fatal("rollback reactivated emergency classifier", state, b.emergencies, err)
				}
			},
		)
	}
}

func TestSelectivePreparedDispatcherUsesDistinctSlotAndPool(t *testing.T) {
	ctx := context.Background()
	b := &emergencyMemory{}
	m := testManager(t, b, &testWatchdog{})
	d := selectiveDesired()
	first, err := m.Prepare(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Apply(ctx, first.ID, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Confirm(first.ID); err != nil {
		t.Fatal(err)
	}
	next := selectiveDesired()
	next.Selective.Path.Slot = 249
	next.Selective.Path.Port--
	next.Selective.DNSFrontPort--
	if _, err = m.Prepare(ctx, next); err == nil {
		t.Fatal("overlapping prepared FakeIP pools accepted")
	}
	next.Selective.FakePool = 1
	tx, err := m.Prepare(ctx, next)
	if err != nil {
		t.Fatal("isolated staged dispatcher rejected", err)
	}
	if tx.Rollback.Selective.Path.Slot != 250 || tx.Candidate.Selective.Path.Slot != 249 {
		t.Fatal("rollback lost previous classifier allocation", tx)
	}
}

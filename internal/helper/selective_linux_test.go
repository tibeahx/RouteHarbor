//go:build linux

package helper

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/dataplane"
)

// This test changes only the explicitly isolated Docker namespace guarded by
// requireNetLab. It exercises actual kernel nft syntax and routing fallthrough.
func TestLinuxSelectiveEmergencyAndNativeGuards(t *testing.T) {
	prepareLab(t)
	b := labBackend()
	ctx := context.Background()
	d := selectiveDesired()
	p, err := dataplane.Compile(d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, g := range selectiveGuardRules(&p) {
			_ = exec.Command("/sbin/ip", g.args("del")...).Run()
		}
		for _, r := range p.Routes {
			_ = b.removeRoute(ctx, r)
		}
	})
	p.DNSGuardUID = 45055
	if err = b.Check(ctx, p); err != nil {
		t.Fatal("selective kernel preflight", err)
	}
	if err = b.Apply(ctx, p, nil); err != nil {
		t.Fatal("selective apply", err)
	}
	if err = b.CheckSelectiveHealth(ctx, d); err != nil {
		t.Fatal("live classifier rules", err)
	}
	legacy := p
	legacy.Desired.Selective = nil
	if err = b.applyDNSGuard(ctx, legacy, nil); err != nil {
		t.Fatal("legacy DNS guard fixture", err)
	}
	out := string(labCommand(t, "/sbin/ip", "-4", "route", "get", "1.1.1.1"))
	if !strings.Contains(out, "outside0") {
		t.Fatal("ordinary direct unavailable", out)
	}
	out = string(labCommand(t, "/sbin/ip", "-4", "route", "get", "1.1.1.1", "mark", "0x4f040000"))
	if !strings.Contains(out, "tunnel0") {
		t.Fatal("native path binding missing", out)
	}
	labCommand(t, "/sbin/ip", "link", "del", "tunnel0")
	if err = exec.Command("/sbin/ip", "-4", "route", "get", "1.1.1.1", "mark", "0x4f040000").
		Run(); err == nil {
		t.Fatal("dead native path fell through to WAN")
	}
	// Synthetic guards and tunnel mark fallthrough protection survive nft loss.
	labCommand(t, "/usr/sbin/nft", "flush", "ruleset")
	if err = b.CheckSelectiveHealth(ctx, d); err == nil {
		t.Fatal("missing classifier rules reported healthy")
	}
	for _, fake := range []struct{ family, address string }{{"-4", "198.18.0.1"}, {"-6", "fd66:6f70:656e::1"}} {
		if err = exec.Command("/sbin/ip", fake.family, "route", "get", fake.address).
			Run(); err == nil {
			t.Fatal("synthetic destination reached WAN after nft flush", fake.address)
		}
	}
	// Model a reused DNS UDP flow and an unrelated application flow. Only the
	// classifier-owned NAT state may be removed during emergency recovery.
	conntrack, err := conntrackBinary()
	if err != nil {
		t.Fatal(err)
	}
	for i, mark := range []string{"0x4ffa0000", "0x12340000"} {
		labCommand(
			t,
			conntrack,
			"--create",
			"--proto",
			"udp",
			"--orig-src",
			"10.44.0.2",
			"--orig-dst",
			"10.44.0.1",
			"--sport",
			strconv.Itoa(40550+i),
			"--dport",
			"53",
			"--timeout",
			"120",
			"--mark",
			mark,
		)
	}
	defer func() { _ = exec.Command(conntrack, "--delete", "--proto", "udp", "--sport", "40551").Run() }()
	if err = b.EmergencyDirect(ctx, p); err != nil {
		t.Fatal(
			"emergency direct",
			err,
			string(labCommand(t, "/sbin/ip", "-4", "-j", "rule", "show")),
			string(labCommand(t, "/sbin/ip", "-6", "-j", "rule", "show")),
		)
	}
	if present, e := runConntrack(
		ctx,
		conntrack,
		"--dump",
		"ipv4",
		dataplane.Mark(250),
	); e != nil ||
		present {
		t.Fatal("emergency retained classifier DNS NAT state", e)
	}
	if out, e := exec.Command(conntrack, "--dump", "--mark", "0x12340000/0xffff0000").
		Output(); e != nil ||
		len(out) == 0 {
		t.Fatal("emergency removed foreign connection state", e)
	}
	out = string(labCommand(t, "/sbin/ip", "-4", "route", "get", "1.1.1.1"))
	if !strings.Contains(out, "outside0") {
		t.Fatal(out)
	}
	for _, family := range []int{4, 6} {
		rules, err := b.rules(ctx, family)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rules {
			if dnsRuleAllowed(r, &p) {
				t.Fatal("emergency retained DNS UID blackhole")
			}
		}
	}
	rules := string(labCommand(t, "/usr/sbin/nft", "list", "ruleset"))
	if strings.Contains(rules, "tproxy") || strings.Contains(rules, "redirect") ||
		!strings.Contains(rules, "198.18.0.0/15 drop") {
		t.Fatal("emergency failed to restore ordinary DNS/WAN", rules)
	}
	if err = exec.Command("/sbin/ip", "-4", "route", "get", "198.18.0.1").Run(); err == nil {
		t.Fatal("emergency removed synthetic quarantine")
	}
}

func TestLinuxSelectiveWatchdogChild(t *testing.T) {
	if os.Getenv("ROUTEHARBOR_SELECTIVE_CHILD") != "1" {
		t.Skip("isolated child only")
	}
	requireNetLab(t)
	d := selectiveDesired()
	tcp, err := net.Listen("tcp", "127.0.0.1:12250")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tcp.Close() }()
	udp, err := net.ListenPacket("udp", "127.0.0.1:12550")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udp.Close() }()
	go func() {
		for {
			conn, e := tcp.Accept()
			if e != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	go func() {
		for {
			buf := make([]byte, 512)
			n, peer, e := udp.ReadFrom(buf)
			if e != nil {
				return
			}
			if n < 12 {
				continue
			}
			buf[2] |= 0x80
			buf[7] = 1
			response := append(buf[:n:n], 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 18, 0, 2)
			_, _ = udp.WriteTo(response, peer)
		}
	}()
	dir := os.Getenv("ROUTEHARBOR_SELECTIVE_STATE")
	m, err := NewManager(
		dir,
		labBackend(),
		ProcessWatchdog{Binary: "/usr/libexec/routeharbor-helper", StateDir: dir},
	)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := m.Prepare(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Apply(context.Background(), tx.ID, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Confirm(tx.ID); err != nil {
		t.Fatal(err)
	}
	if mode := os.Getenv("ROUTEHARBOR_SELECTIVE_WATCH_MODE"); mode != "confirmed" {
		next, e := m.Prepare(context.Background(), d)
		if e != nil {
			t.Fatal(e)
		}
		if mode == "rolled-back" {
			if _, e = m.Rollback(context.Background(), next.ID); e != nil {
				t.Fatal(e)
			}
		}
	}
	if err = os.WriteFile(
		os.Getenv("ROUTEHARBOR_SELECTIVE_READY"),
		[]byte("ready"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	select {}
}

func TestLinuxSelectiveDetachedWatchdogAfterHelperDeath(t *testing.T) {
	for _, mode := range []string{"confirmed", "prepared", "rolled-back"} {
		t.Run(mode, func(t *testing.T) { selectiveDetachedWatchdog(t, mode) })
	}
}

func selectiveDetachedWatchdog(t *testing.T, mode string) {
	prepareLab(t)
	dir := filepath.Join(t.TempDir(), "state")
	ready := filepath.Join(t.TempDir(), "ready")
	child := exec.Command(os.Args[0], "-test.run=^TestLinuxSelectiveWatchdogChild$", "-test.v")
	child.Env = append(
		os.Environ(),
		"ROUTEHARBOR_SELECTIVE_CHILD=1",
		"ROUTEHARBOR_SELECTIVE_STATE="+dir,
		"ROUTEHARBOR_SELECTIVE_READY="+ready,
		"ROUTEHARBOR_SELECTIVE_WATCH_MODE="+mode,
	)
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill() }()
	deadline := time.Now().Add(8 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("selective child did not confirm")
		}
		time.Sleep(25 * time.Millisecond)
	}
	// Let the detached watchdog observe the live classifier before the owner dies.
	time.Sleep(1500 * time.Millisecond)
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	m, err := NewManager(dir, labBackend(), nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		s, err := m.Status()
		if err == nil && s.SelectiveEmergency {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("detached selective watchdog did not restore direct", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// State is saved before mutations: wait for the actual emergency rules too.
	for {
		out, err := exec.Command("/usr/sbin/nft", "list", "table", "inet", dataplane.Table).Output()
		if err == nil && !strings.Contains(string(out), "tproxy") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(
				"emergency intent did not reach kernel",
				m.SelectiveEmergency(context.Background()),
			)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if out := string(
		labCommand(t, "/sbin/ip", "-4", "route", "get", "1.1.1.1"),
	); !strings.Contains(
		out,
		"outside0",
	) {
		t.Fatal("WAN not restored", out)
	}
	p, err := dataplane.Compile(selectiveDesired())
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range selectiveGuardRules(&p) {
		_ = exec.Command("/sbin/ip", g.args("del")...).Run()
	}
}

func TestLinuxSelectiveMigrationRemovesLegacyGlobalBlackhole(t *testing.T) {
	prepareLab(t)
	ctx := context.Background()
	b := labBackend()
	old, err := dataplane.Compile(testDesired())
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Apply(ctx, old, nil); err != nil {
		t.Fatal(err)
	}
	next, err := dataplane.Compile(selectiveDesired())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, g := range selectiveGuardRules(&next) {
			_ = exec.Command("/sbin/ip", g.args("del")...).Run()
		}
		for _, r := range next.Routes {
			_ = b.removeRoute(ctx, r)
		}
	}()
	if err = b.Apply(ctx, next, &old); err != nil {
		t.Fatal("legacy migration", err)
	}
	out := string(
		labCommand(
			t,
			"/sbin/ip",
			"-4",
			"route",
			"get",
			"1.1.1.1",
			"from",
			"10.44.0.2",
			"iif",
			"home0",
		),
	)
	if !strings.Contains(out, "outside0") {
		t.Fatal("unmarked ordinary WAN remained globally blackholed", out)
	}
	for _, family := range []int{4, 6} {
		entries, err := b.routeEntries(ctx, family)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if number(e.Table) == safetyTable {
				t.Fatal("legacy global safety table survived selective migration", e)
			}
		}
	}
}

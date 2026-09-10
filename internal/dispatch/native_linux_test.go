//go:build linux

package dispatch

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tibeahx/OpenRHP/internal/dataplane"
	"github.com/tibeahx/OpenRHP/internal/routing"
)

func requireDispatcherLab(t *testing.T) {
	t.Helper()
	if os.Getenv("OPENRHP_DISPATCH_LAB") != "1" {
		t.Skip("requires isolated pinned-engine Linux lab")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil || os.Geteuid() != 0 {
		t.Fatal("dispatcher lab requires isolated container root")
	}
	out, err := exec.Command("/usr/bin/sing-box", "version").Output()
	if err != nil || !strings.HasPrefix(string(out), "sing-box version 1.14.0\n") {
		t.Fatal("pinned sing-box 1.14.0 required", err, string(out))
	}
}

func TestDispatcherNativeConfigChecks(t *testing.T) {
	requireDispatcherLab(t)
	for _, kind := range []string{"interface", "packet-engine", "socks5", "http-connect", "sing-box", "xray"} {
		for _, ipv6 := range []bool{false, true} {
			name := kind + "-ipv4"
			if ipv6 {
				name = kind + "-dual"
			}
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				rules := filepath.Join(dir, "rules.json")
				if err := os.WriteFile(
					rules,
					[]byte(
						`{"version":4,"rules":[{"domain":["blocked.example","blocked-v6.example"]},{"ip_cidr":["11.0.0.98/32","2606:4700:100::98/128"]}]}`,
					),
					0o600,
				); err != nil {
					t.Fatal(err)
				}
				raw, err := Generate(
					dispatcherFixture(ipv6, kind),
					Files{RuleSet: rules, Cache: filepath.Join(dir, "cache.db")},
					strings.Repeat("a", 32),
				)
				if err != nil {
					t.Fatal(err)
				}
				config := filepath.Join(dir, "config.json")
				if err = os.WriteFile(config, raw, 0o600); err != nil {
					t.Fatal(err)
				}
				out, err := exec.Command("/usr/bin/sing-box", "check", "-c", config).
					CombinedOutput()
				if err != nil {
					t.Fatal("pinned engine rejected typed configuration", err, string(out))
				}
			})
		}
	}
}

func labExec(t *testing.T, name string, args ...string) []byte {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v: %s", name, args, err, out)
	}
	return out
}
func labIP(t *testing.T, args ...string) { t.Helper(); labExec(t, "/sbin/ip", args...) }
func labNSIP(t *testing.T, ns string, args ...string) {
	t.Helper()
	labIP(t, append([]string{"-n", ns}, args...)...)
}

func labDNSQuery(domain string, typ uint16) []byte {
	q := make([]byte, 12)
	q[0] = 0x73
	q[1] = 0x41
	q[2] = 1
	q[5] = 1
	for _, label := range strings.Split(domain, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0, byte(typ>>8), byte(typ), 0, 1)
}

func labDNSAnswer(q []byte) []byte {
	if len(q) < 17 {
		return nil
	}
	end := 12
	for end < len(q) && q[end] != 0 {
		end += int(q[end]) + 1
	}
	if end+5 > len(q) {
		return nil
	}
	end++
	typ := binary.BigEndian.Uint16(q[end : end+2])
	end += 4
	out := append([]byte(nil), q[:end]...)
	out[2] = 0x81
	out[3] = 0x80
	out[6] = 0
	out[7] = 1
	out[8] = 0
	out[9] = 0
	out[10] = 0
	out[11] = 0
	address := net.ParseIP("11.0.0.99").To4()
	if typ == 1 && strings.Contains(string(q[:end]), "-v6") {
		out[7] = 0
		return out
	}
	if typ == 28 {
		address = net.ParseIP("2606:4700:100::99").To16()
	} else if typ != 1 {
		out[7] = 0
		return out
	}
	out = append(out, 0xc0, 0x0c, byte(typ>>8), byte(typ), 0, 1, 0, 0, 0, 60, 0, byte(len(address)))
	return append(out, address...)
}

func TestDispatcherLabService(t *testing.T) {
	if os.Getenv("OPENRHP_DISPATCH_SERVICE") != "1" {
		t.Skip("namespace service child")
	}
	dns, err := net.Listen("tcp4", "11.0.0.53:53")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dns.Close() }()
	go func() {
		for {
			c, e := dns.Accept()
			if e != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				for {
					head := make([]byte, 2)
					if _, e := io.ReadFull(c, head); e != nil {
						return
					}
					q := make([]byte, int(binary.BigEndian.Uint16(head)))
					if _, e := io.ReadFull(c, q); e != nil {
						return
					}
					reply := labDNSAnswer(q)
					binary.BigEndian.PutUint16(head, uint16(len(reply)))
					_, _ = c.Write(append(head, reply...))
				}
			}()
		}
	}()
	for _, family := range []string{"4", "6"} {
		address := "0.0.0.0:18080"
		if family == "6" {
			address = "[::]:18080"
		}
		l, err := net.Listen("tcp"+family, address)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }()
		go func() {
			for {
				c, e := l.Accept()
				if e != nil {
					return
				}
				go func() {
					defer func() { _ = c.Close() }()
					buf := make([]byte, 1)
					for {
						if _, err := c.Read(buf); err != nil {
							return
						}
						host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
						if _, err := c.Write([]byte(host + "\n")); err != nil {
							return
						}
					}
				}()
			}
		}()
		udpAddresses := []string{"11.0.0.99:18080", "11.0.0.98:18080"}
		if family == "6" {
			udpAddresses = []string{"[2606:4700:100::99]:18080", "[2606:4700:100::98]:18080"}
		}
		for _, udpAddress := range udpAddresses {
			p, err := net.ListenPacket("udp"+family, udpAddress)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = p.Close() }()
			go func() {
				for {
					buf := make([]byte, 2048)
					_, peer, e := p.ReadFrom(buf)
					if e != nil {
						return
					}
					host, _, _ := net.SplitHostPort(peer.String())
					_, _ = p.WriteTo([]byte(host), peer)
				}
			}()
		}
	}
	if err = os.WriteFile(os.Getenv("OPENRHP_DISPATCH_READY"), []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {}
}

func TestDispatcherLabClient(t *testing.T) {
	if os.Getenv("OPENRHP_DISPATCH_CLIENT") != "1" {
		t.Skip("namespace client child")
	}
	domain, network, want := os.Getenv(
		"OPENRHP_DISPATCH_DOMAIN",
	), os.Getenv(
		"OPENRHP_DISPATCH_NETWORK",
	), os.Getenv(
		"OPENRHP_DISPATCH_EXPECT",
	)
	ip := domain
	if net.ParseIP(domain) == nil {
		typ := uint16(1)
		if strings.HasSuffix(network, "6") {
			typ = 28
		}
		c, err := net.DialTimeout("udp4", "10.77.0.1:53", time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, err = c.Write(labDNSQuery(domain, typ))
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		_ = c.Close()
		if err != nil {
			t.Fatal("managed DNS", err)
		}
		reply := buf[:n]
		size := 4
		if typ == 28 {
			size = 16
		}
		if n < 12+size || binary.BigEndian.Uint16(reply[6:8]) != 1 {
			t.Fatalf("unexpected DNS answer %x", reply)
		}
		ip = net.IP(reply[n-size:]).String()
		fake := netip.MustParsePrefix(FakeIPv4)
		if typ == 28 {
			fake = netip.MustParsePrefix(FakeIPv6)
		}
		parsed, err := netip.ParseAddr(ip)
		if err != nil || !fake.Contains(parsed) {
			t.Fatal("managed DNS did not return FakeIP", ip)
		}
	}
	c, err := net.DialTimeout(network, net.JoinHostPort(ip, "18080"), 3*time.Second)
	if err != nil {
		if want == "blocked" {
			return
		}
		t.Fatal("LAN dial", domain, network, ip, err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = c.Write([]byte("x")); err != nil {
		if want == "blocked" {
			return
		}
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if want == "blocked" {
		if err == nil {
			t.Fatal("failed bypass escaped", string(buf[:n]))
		}
		return
	}
	if err != nil {
		t.Fatal("LAN response", domain, network, ip, err)
	}
	if got := strings.TrimSpace(string(buf[:n])); got != want {
		t.Fatalf("%s %s: expected egress %s got %s", domain, network, want, got)
	}
	if ready := os.Getenv("OPENRHP_DISPATCH_HOLD_READY"); ready != "" {
		if err = os.WriteFile(ready, []byte("connected"), 0o600); err != nil {
			t.Fatal(err)
		}
		resume := os.Getenv("OPENRHP_DISPATCH_HOLD_RESUME")
		deadline := time.Now().Add(60 * time.Second)
		for {
			if _, e := os.Stat(resume); e == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("held connection resume missing")
			}
			time.Sleep(20 * time.Millisecond)
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = c.Write([]byte("x")); err != nil {
			t.Fatal("held direct socket interrupted", err)
		}
		n, err = c.Read(buf)
		if err != nil || strings.TrimSpace(string(buf[:n])) != want {
			t.Fatal("held direct socket changed route or failed", err, string(buf[:n]))
		}
		t.Log("same direct TCP socket survived every bypass selector switch and rule reload")
	}
	t.Logf("%s %s fake=%s egress=%s", domain, network, ip, want)
}

func TestDispatcherSameIPDomainIsolation(t *testing.T) {
	requireDispatcherLab(t)
	for _, ns := range []string{"dispatch-client", "dispatch-server"} {
		labIP(t, "netns", "add", ns)
		defer func() { _ = exec.Command("/sbin/ip", "netns", "del", ns).Run() }()
		labNSIP(t, ns, "link", "set", "lo", "up")
	}
	for _, link := range []struct{ host, peer, ns string }{{"lan0", "client0", "dispatch-client"}, {"wan0", "server0", "dispatch-server"}, {"vpn0", "server1", "dispatch-server"}} {
		labIP(t, "link", "add", link.host, "type", "veth", "peer", "name", link.peer)
		defer func() { _ = exec.Command("/sbin/ip", "link", "del", link.host).Run() }()
		labIP(t, "link", "set", link.peer, "netns", link.ns)
		labIP(t, "link", "set", link.host, "up")
		labNSIP(t, link.ns, "link", "set", link.peer, "up")
	}
	for _, a := range []struct{ dev, addr string }{{"lan0", "10.77.0.1/24"}, {"lan0", "fd77::1/64"}, {"wan0", "11.0.0.1/24"}, {"wan0", "2606:4700:100::1/64"}, {"vpn0", "12.0.0.1/24"}, {"vpn0", "2606:4700:200::1/64"}} {
		args := []string{"addr", "add", a.addr, "dev", a.dev}
		if strings.Contains(a.addr, ":") {
			args = append(args, "nodad")
		}
		labIP(t, args...)
	}
	for _, a := range []struct{ ns, dev, addr string }{{"dispatch-client", "client0", "10.77.0.2/24"}, {"dispatch-client", "client0", "fd77::2/64"}, {"dispatch-server", "server0", "11.0.0.99/24"}, {"dispatch-server", "server0", "11.0.0.53/24"}, {"dispatch-server", "server0", "11.0.0.98/24"}, {"dispatch-server", "server0", "2606:4700:100::98/64"}, {"dispatch-server", "server0", "2606:4700:100::99/64"}, {"dispatch-server", "server1", "12.0.0.2/24"}, {"dispatch-server", "server1", "2606:4700:200::2/64"}} {
		args := []string{"addr", "add", a.addr, "dev", a.dev}
		if strings.Contains(a.addr, ":") {
			args = append(args, "nodad")
		}
		labNSIP(t, a.ns, args...)
	}
	labNSIP(t, "dispatch-client", "route", "add", "default", "via", "10.77.0.1")
	labNSIP(t, "dispatch-client", "-6", "route", "add", "default", "via", "fd77::1")
	// A tunnel is point-to-point; these permanent neighbor entries model its
	// underlay-independent destination reachability on the veth fixture.
	serverMAC := strings.TrimSpace(
		string(
			labExec(
				t,
				"/sbin/ip",
				"netns",
				"exec",
				"dispatch-server",
				"cat",
				"/sys/class/net/server1/address",
			),
		),
	)
	labIP(
		t,
		"neigh",
		"replace",
		"11.0.0.99",
		"lladdr",
		serverMAC,
		"nud",
		"permanent",
		"dev",
		"vpn0",
	)
	labIP(
		t,
		"neigh",
		"replace",
		"11.0.0.98",
		"lladdr",
		serverMAC,
		"nud",
		"permanent",
		"dev",
		"vpn0",
	)
	labIP(
		t,
		"-6",
		"neigh",
		"replace",
		"2606:4700:100::98",
		"lladdr",
		serverMAC,
		"nud",
		"permanent",
		"dev",
		"vpn0",
	)
	labIP(
		t,
		"neigh",
		"replace",
		"11.0.0.53",
		"lladdr",
		serverMAC,
		"nud",
		"permanent",
		"dev",
		"vpn0",
	)
	labIP(
		t,
		"-6",
		"neigh",
		"replace",
		"2606:4700:100::99",
		"lladdr",
		serverMAC,
		"nud",
		"permanent",
		"dev",
		"vpn0",
	)
	labExec(
		t,
		"/bin/sh",
		"-c",
		"echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter; echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter; echo 0 > /proc/sys/net/ipv4/conf/vpn0/rp_filter; echo 1 > /proc/sys/net/ipv4/ip_forward; echo 1 > /proc/sys/net/ipv6/conf/all/forwarding",
	)
	dir := t.TempDir()
	ready := filepath.Join(dir, "ready")
	service := exec.Command(
		"/sbin/ip",
		"netns",
		"exec",
		"dispatch-server",
		os.Args[0],
		"-test.run=^TestDispatcherLabService$",
		"-test.v",
	)
	service.Env = append(
		os.Environ(),
		"OPENRHP_DISPATCH_SERVICE=1",
		"OPENRHP_DISPATCH_READY="+ready,
	)
	service.Stdout = os.Stdout
	service.Stderr = os.Stderr
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = service.Process.Kill(); _ = service.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("DNS/echo fixture did not start")
		}
		time.Sleep(25 * time.Millisecond)
	}
	s := dispatcherFixture(true, "interface")
	s.Network.LocalPrefixes = append(s.Network.LocalPrefixes, "fd77::/64")
	nfq := labSourceFixtures(t, dir, &s)
	rules := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(
		rules,
		[]byte(
			`{"version":4,"rules":[{"domain":["blocked.example","blocked-v6.example"]},{"ip_cidr":["11.0.0.98/32","2606:4700:100::98/128"]}]}`,
		),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	raw, err := Generate(
		s,
		Files{RuleSet: rules, Cache: filepath.Join(dir, "cache.db")},
		strings.Repeat("a", 32),
	)
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "config.json")
	if err = os.WriteFile(config, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	engine := exec.Command("/usr/bin/sing-box", "run", "-c", config)
	engine.Stdout = os.Stdout
	engine.Stderr = os.Stderr
	if err = engine.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = engine.Process.Kill(); _ = engine.Wait() }()
	deadline = time.Now().Add(5 * time.Second)
	for {
		conn, e := net.DialTimeout("tcp", "127.0.0.1:13250", 100*time.Millisecond)
		if e == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("dispatcher did not start")
		}
		time.Sleep(25 * time.Millisecond)
	}
	front := routing.DNSProxy{
		LocalDNS:    "127.0.0.1:53",
		ExternalDNS: "127.0.0.1:13250",
		AllowedClients: []netip.Prefix{
			netip.MustParsePrefix("10.77.0.0/24"),
			netip.MustParsePrefix("fd77::/64"),
		},
	}
	udp, err := net.ListenPacket("udp4", "0.0.0.0:14250")
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp4", "0.0.0.0:14250")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = front.Serve(ctx, udp, tcp) }()
	intent := dataplane.Desired{
		Network: s.Network,
		Paths: []dataplane.Path{
			{
				SourceID:  s.Selected,
				Kind:      "interface",
				Slot:      4,
				Interface: "vpn0",
				IPv6:      true,
				UDP:       true,
			},
		},
		Selected: s.Selected,
		Fallback: "closed",
		Selective: &dataplane.SelectiveIntent{
			Path: dataplane.Path{
				SourceID: dataplane.SelectiveSourceID,
				Kind:     "tproxy",
				Slot:     250,
				Port:     11250,
				IPv6:     true,
				UDP:      true,
			},
			DNSFrontPort:  14250,
			FakeIPv4:      FakeIPv4,
			FakeIPv6:      FakeIPv6,
			FailurePolicy: "direct",
			PolicyHash:    strings.Repeat("a", 64),
			Snapshot: dataplane.SelectiveSnapshotRef{
				Generation: 1,
				SHA256:     strings.Repeat("a", 64),
			},
		},
	}
	for _, source := range s.Sources[1:] {
		kind := source.Kind
		if kind != "packet-engine" && kind != "interface" {
			kind = "tproxy"
		}
		intent.Paths = append(
			intent.Paths,
			dataplane.Path{
				SourceID: source.SourceID,
				Kind:     kind,
				Slot:     uint16(source.Slot),
				Port:     uint16(source.TransparentPort),
				IPv6:     source.IPv6,
				UDP:      source.UDP,
			},
		)
	}
	plan, err := dataplane.Compile(intent)
	if err != nil {
		t.Fatal(err)
	}
	plan, err = dataplane.WithRouterAddresses(
		plan,
		[]netip.Addr{
			netip.MustParseAddr("10.77.0.1"),
			netip.MustParseAddr("fd77::1"),
			netip.MustParseAddr("11.0.0.1"),
			netip.MustParseAddr("12.0.0.1"),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range plan.Routes {
		family := "-" + strconv.Itoa(r.Family)
		args := []string{family, "route", "add", "table", strconv.Itoa(r.Table)}
		if r.Local {
			args = append(args, "local")
		}
		args = append(args, "default", "dev", r.Device)
		if r.Table != 254 {
			labIP(t, args...)
		}
		labIP(
			t,
			family,
			"rule",
			"add",
			"priority",
			strconv.Itoa(r.Priority),
			"fwmark",
			fmt.Sprintf("0x%08x/0xffff0000", r.Mark),
			"lookup",
			strconv.Itoa(r.Table),
		)
	}
	nft := exec.Command("/usr/sbin/nft", "--file", "-")
	nft.Stdin = strings.NewReader(
		strings.Replace(plan.NFT, "queue num 21009", "counter queue num 21009", 1),
	)
	if out, err := nft.CombinedOutput(); err != nil {
		t.Fatal("selective nft", err, string(out))
	}
	runClient := func(domain, network, want string) {
		t.Helper()
		cmd := exec.Command(
			"/sbin/ip",
			"netns",
			"exec",
			"dispatch-client",
			os.Args[0],
			"-test.run=^TestDispatcherLabClient$",
			"-test.v",
		)
		cmd.Env = append(
			os.Environ(),
			"OPENRHP_DISPATCH_CLIENT=1",
			"OPENRHP_DISPATCH_DOMAIN="+domain,
			"OPENRHP_DISPATCH_NETWORK="+network,
			"OPENRHP_DISPATCH_EXPECT="+want,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Log(
				string(labExec(t, "/sbin/ip", "-6", "addr", "show")),
				string(labExec(t, "/sbin/ip", "-6", "rule", "show")),
				string(labExec(t, "/sbin/ip", "-6", "neigh", "show")),
				string(labExec(t, "/sbin/ip", "-n", "dispatch-client", "-6", "addr", "show")),
				string(labExec(t, "/usr/sbin/nft", "list", "table", "inet", "openrhp")),
				string(labExec(t, "/usr/bin/ss", "-lnpt")),
			)
			t.Fatal("actual LAN dispatch", domain, network, err, string(out))
		}
		t.Log(strings.TrimSpace(string(out)))
	}
	for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		direct, bypass := "11.0.0.1", "12.0.0.1"
		if strings.HasSuffix(network, "6") {
			direct, bypass = "2606:4700:100::1", "2606:4700:200::1"
		}
		allowed, blocked := "allowed.example", "blocked.example"
		if strings.HasSuffix(network, "6") {
			allowed, blocked = "allowed-v6.example", "blocked-v6.example"
		}
		runClient(allowed, network, direct)
		runClient(blocked, network, bypass)
	}
	for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		directIP, listedIP, direct, bypass := "11.0.0.99", "11.0.0.98", "11.0.0.1", "12.0.0.1"
		if strings.HasSuffix(network, "6") {
			directIP, listedIP, direct, bypass = "2606:4700:100::99", "2606:4700:100::98", "2606:4700:100::1", "2606:4700:200::1"
		}
		runClient(directIP, network, direct)
		runClient(listedIP, network, bypass)
	}
	holdReady, holdResume := filepath.Join(dir, "hold-ready"), filepath.Join(dir, "hold-resume")
	hold := exec.Command(
		"/sbin/ip",
		"netns",
		"exec",
		"dispatch-client",
		os.Args[0],
		"-test.run=^TestDispatcherLabClient$",
		"-test.v",
	)
	hold.Env = append(
		os.Environ(),
		"OPENRHP_DISPATCH_CLIENT=1",
		"OPENRHP_DISPATCH_DOMAIN=allowed.example",
		"OPENRHP_DISPATCH_NETWORK=tcp4",
		"OPENRHP_DISPATCH_EXPECT=11.0.0.1",
		"OPENRHP_DISPATCH_HOLD_READY="+holdReady,
		"OPENRHP_DISPATCH_HOLD_RESUME="+holdResume,
	)
	hold.Stdout, hold.Stderr = os.Stdout, os.Stderr
	if err = hold.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hold.Process.Kill(); _ = hold.Wait() }()
	deadline = time.Now().Add(5 * time.Second)
	for {
		if _, e := os.Stat(holdReady); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("held direct socket did not open")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Every supported source kind composes with the permanent dispatcher.
	for _, source := range s.Sources[1:] {
		labSelect(t, source.Slot)
		for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
			allowed, blocked, direct, bypass := "allowed.example", "blocked.example", "11.0.0.1", "11.0.0.99"
			if strings.HasSuffix(network, "6") {
				allowed, blocked, direct, bypass = "allowed-v6.example", "blocked-v6.example", "2606:4700:100::1", "2606:4700:100::99"
			}
			if source.Kind == "packet-engine" {
				bypass = direct
			}
			if source.Kind == "http-connect" && strings.HasPrefix(network, "udp") {
				bypass = "blocked"
			}
			runClient(allowed, network, direct)
			runClient(blocked, network, bypass)
		}
	}
	queueRules := string(labExec(t, "/usr/sbin/nft", "list", "chain", "inet", "openrhp", "output"))
	if !strings.Contains(queueRules, "queue to 21009") ||
		strings.Contains(queueRules, "counter packets 0 bytes 0 queue to 21009") {
		t.Fatal("packet path did not enter actual NFQUEUE", queueRules)
	}
	if err = nfq.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = nfq.Wait()
	runClient("allowed.example", "tcp4", "11.0.0.1")
	runClient("blocked.example", "tcp4", "blocked")
	runClient("blocked.example", "udp4", "blocked")
	labSelect(t, 4)
	labPublish(t, rules, true)
	time.Sleep(500 * time.Millisecond)
	runClient("allowed.example", "tcp4", "12.0.0.1")
	labPublish(t, rules, false)
	time.Sleep(500 * time.Millisecond)
	runClient("allowed.example", "tcp4", "11.0.0.1")
	if err = os.WriteFile(holdResume, []byte("resume"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = hold.Wait(); err != nil {
		t.Fatal("held direct TCP failed", err)
	}
	labIP(t, "link", "del", "vpn0")
	runClient("allowed.example", "tcp4", "11.0.0.1")
	runClient("blocked.example", "tcp4", "blocked")
}

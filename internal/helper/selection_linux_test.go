//go:build linux

package helper

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/dataplane"
	"github.com/tibeahx/RouteHarbor/internal/platform"
)

type selectionRecordingRunner struct{ mutations []string }

func (r *selectionRecordingRunner) Run(
	ctx context.Context,
	binary string,
	args []string,
	input []byte,
) ([]byte, error) {
	if strings.Contains(strings.Join(args, " "), "--file") &&
		!strings.Contains(strings.Join(args, " "), "--check") {
		r.mutations = append(r.mutations, string(input))
	}
	if binary == "/sbin/ip" && !strings.Contains(strings.Join(args, " "), "show") {
		return nil, fmt.Errorf("selection attempted route mutation: %v", args)
	}
	return labRunner{}.Run(ctx, binary, args, input)
}

func TestLinuxAtomicSelectionRetainsFailedTunnel(t *testing.T) {
	prepareLab(t)
	b := labBackend()
	d := testDesired()
	d.Paths = append(
		d.Paths,
		dataplane.Path{
			SourceID:  "old",
			Kind:      "interface",
			Slot:      4,
			Interface: "tunnel0",
			UDP:       true,
		},
	)
	d.Selected = "old"
	old, err := dataplane.Compile(d)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Apply(context.Background(), old, nil); err != nil {
		t.Fatal(err)
	}
	labCommand(t, "/sbin/ip", "link", "del", "tunnel0")
	d.Selected = "b"
	next, err := dataplane.Compile(d)
	if err != nil {
		t.Fatal(err)
	}
	detect := b.Detect
	b.Detect = func(ctx context.Context) platform.Report {
		r := detect(ctx)
		for i := range r.Interfaces {
			if r.Interfaces[i].Device == "tunnel0" {
				r.Interfaces[i].Up = false
			}
		}
		return r
	}
	record := &selectionRecordingRunner{}
	b.Runner = record
	if err = b.ApplySelection(context.Background(), next, old); err != nil {
		t.Fatal(err)
	}
	if len(record.mutations) != 1 ||
		!strings.HasPrefix(record.mutations[0], "flush chain inet routeharbor select_flow\n") ||
		strings.Contains(record.mutations[0], "guard") {
		t.Fatal("not a single atomic classifier mutation", record.mutations)
	}
	table := string(labCommand(t, "/usr/sbin/nft", "list", "table", "inet", dataplane.Table))
	if !strings.Contains(table, "0x4f020000") || !strings.Contains(table, `oifname "tunnel0"`) {
		t.Fatal("retained flow protection disappeared", table)
	}
	if _, err := exec.Command("/usr/sbin/nft", "list", "table", "inet", dataplane.GuardTable).
		Output(); err == nil {
		t.Fatal("selection installed a drop guard")
	}
}

func TestLinuxDNSAffinityAcrossMixedSelections(t *testing.T) {
	prepareLab(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const namespace = "routeharbor-dns-affinity"
	_ = exec.Command("/sbin/ip", "netns", "del", namespace).Run()
	defer func() { _ = exec.Command("/sbin/ip", "netns", "del", namespace).Run() }()
	labCommand(t, "/sbin/ip", "link", "del", "home0")
	labCommand(t, "/sbin/ip", "netns", "add", namespace)
	labCommand(t, "/sbin/ip", "link", "add", "home0", "type", "veth", "peer", "name", "dns-peer")
	labCommand(t, "/sbin/ip", "link", "set", "dns-peer", "netns", namespace)
	labCommand(t, "/sbin/ip", "address", "add", "10.44.0.1/24", "dev", "home0")
	labCommand(t, "/sbin/ip", "link", "set", "home0", "up")
	labCommand(t, "/sbin/ip", "link", "set", "lo", "up")
	labCommand(t, "/sbin/ip", "address", "add", "8.8.8.8/32", "dev", "lo")
	defer func() { _ = exec.Command("/sbin/ip", "address", "del", "8.8.8.8/32", "dev", "lo").Run() }()
	for _, args := range [][]string{{"address", "add", "10.44.0.2/24", "dev", "dns-peer"}, {"link", "set", "dns-peer", "up"}, {"link", "set", "lo", "up"}} {
		labCommand(
			t,
			"/sbin/ip",
			append([]string{"netns", "exec", namespace, "/sbin/ip"}, args...)...)
	}
	type arrival struct{ owner, protocol, payload string }
	arrivals := make(chan arrival, 32)
	listen := func(owner, address string, transparent bool) {
		lc := net.ListenConfig{}
		if transparent {
			lc.Control = func(_, _ string, raw syscall.RawConn) error {
				var sockErr error
				err := raw.Control(
					func(fd uintptr) { sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1) },
				)
				if err != nil {
					return err
				}
				return sockErr
			}
		}
		tcp, err := lc.Listen(ctx, "tcp4", address)
		if err != nil {
			t.Fatal(err)
		}
		deferClose := func(c io.Closer) { t.Cleanup(func() { _ = c.Close() }) }
		deferClose(tcp)
		udp, err := lc.ListenPacket(ctx, "udp4", address)
		if err != nil {
			t.Fatal(err)
		}
		deferClose(udp)
		go func() {
			buf := make([]byte, 100)
			for {
				n, _, err := udp.ReadFrom(buf)
				if err != nil {
					return
				}
				arrivals <- arrival{owner, "udp", string(buf[:n])}
			}
		}()
		go func() {
			for {
				conn, err := tcp.Accept()
				if err != nil {
					return
				}
				go func() {
					defer func() { _ = conn.Close() }()
					scanner := bufio.NewScanner(conn)
					for scanner.Scan() {
						arrivals <- arrival{owner, "tcp", scanner.Text()}
					}
				}()
			}
		}()
	}
	listen("a", "0.0.0.0:14003", true)
	listen("b", "0.0.0.0:14010", true)
	listen("native", "8.8.8.8:53", false)
	d := testDesired()
	d.Network.DNS, d.Network.DNSResolver = "selected-path", "8.8.8.8"
	d.Paths = []dataplane.Path{
		{SourceID: "a", Kind: "tproxy", Slot: 3, Port: 12003, DNSPort: 14003, UDP: true},
		{SourceID: "b", Kind: "tproxy", Slot: 10, Port: 12010, DNSPort: 14010, UDP: true},
		{SourceID: "native", Kind: "direct", Slot: 2, UDP: true},
	}
	current, err := dataplane.Compile(d)
	if err != nil {
		t.Fatal(err)
	}
	b := labBackend()
	if err = b.Check(ctx, current); err != nil {
		t.Fatal(err)
	}
	if err = b.Apply(ctx, current, nil); err != nil {
		t.Fatal(err)
	}
	newClient := func() io.WriteCloser {
		code := "import socket,sys\nt=socket.socket();t.settimeout(3);t.connect(('10.44.0.1',53))\nu=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.connect(('10.44.0.1',53))\nfor line in sys.stdin:\n p=line.strip().encode();t.sendall(p+b'\\n');u.send(p)\n"
		cmd := exec.CommandContext(
			ctx,
			"/sbin/ip",
			"netns",
			"exec",
			namespace,
			"python3",
			"-c",
			code,
		)
		input, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err = cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = input.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
		return input
	}
	send := func(client io.Writer, owner, payload string) {
		if _, err := fmt.Fprintln(client, payload); err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for len(seen) < 2 {
			select {
			case got := <-arrivals:
				if got.owner != owner || got.payload != payload || seen[got.protocol] {
					t.Fatalf("DNS session moved/duplicated: %+v wanted %s/%s", got, owner, payload)
				}
				seen[got.protocol] = true
			case <-time.After(4 * time.Second):
				t.Fatalf("DNS flow stalled: %s %s; received %v", owner, payload, seen)
			}
		}
	}
	switchTo := func(id string) {
		d.Selected = id
		next, err := dataplane.Compile(d)
		if err != nil {
			t.Fatal(err)
		}
		if err = b.ApplySelection(ctx, next, current); err != nil {
			t.Fatal(err)
		}
		current = next
	}
	a := newClient()
	send(a, "a", "first")
	switchTo("b")
	send(a, "a", "old-after-b")
	c := newClient()
	send(c, "b", "second")
	switchTo("native")
	send(a, "a", "old-after-native")
	send(c, "b", "second-after-native")
	n := newClient()
	send(n, "native", "native-new")
	switchTo("a")
	send(n, "native", "native-after-proxy")
	send(c, "b", "second-after-proxy")
}

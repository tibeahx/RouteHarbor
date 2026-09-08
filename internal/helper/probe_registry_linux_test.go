//go:build linux

package helper

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/tibeahx/OpenRHP/internal/dataplane"
	"github.com/tibeahx/OpenRHP/internal/platform"
)

func TestLinuxFirstUseNativeProbeRegistration(t *testing.T) {
	requireNetLab(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	namespace := "openrhp-probe-origin"
	_ = exec.Command("/sbin/ip", "netns", "del", namespace).Run()
	_ = exec.Command("/sbin/ip", "link", "del", "probe-veth").Run()
	defer func() { _ = exec.Command("/sbin/ip", "netns", "del", namespace).Run() }()
	defer func() { _ = exec.Command("/sbin/ip", "link", "del", "probe-veth").Run() }()
	defer func() { _ = exec.Command("/sbin/ip", "link", "del", "probe-tun").Run() }()
	labCommand(t, "/sbin/ip", "netns", "add", namespace)
	labCommand(
		t,
		"/sbin/ip",
		"link",
		"add",
		"probe-veth",
		"type",
		"veth",
		"peer",
		"name",
		"probe-peer",
	)
	labCommand(t, "/sbin/ip", "link", "set", "probe-peer", "netns", namespace)
	labCommand(t, "/sbin/ip", "addr", "add", "10.230.0.1/24", "dev", "probe-veth")
	labCommand(t, "/sbin/ip", "link", "set", "probe-veth", "up")
	ns := func(args ...string) {
		all := append([]string{"netns", "exec", namespace, "/sbin/ip"}, args...)
		labCommand(t, "/sbin/ip", all...)
	}
	ns("addr", "add", "10.230.0.2/24", "dev", "probe-peer")
	ns("link", "set", "probe-peer", "up")
	ns("link", "set", "lo", "up")
	ns("addr", "add", "1.1.1.1/32", "dev", "lo")
	ns("addr", "add", "8.8.8.8/32", "dev", "lo")
	labCommand(
		t,
		"/sbin/ip",
		"route",
		"add",
		"1.1.1.1/32",
		"via",
		"10.230.0.2",
		"dev",
		"probe-veth",
	)
	labCommand(
		t,
		"/sbin/ip",
		"tunnel",
		"add",
		"probe-tun",
		"mode",
		"gre",
		"local",
		"10.230.0.1",
		"remote",
		"10.230.0.2",
		"dev",
		"probe-veth",
	)
	labCommand(t, "/sbin/ip", "addr", "add", "10.231.0.1/30", "dev", "probe-tun")
	labCommand(t, "/sbin/ip", "link", "set", "probe-tun", "up")
	ns(
		"tunnel",
		"add",
		"probe-tun",
		"mode",
		"gre",
		"local",
		"10.230.0.2",
		"remote",
		"10.230.0.1",
		"dev",
		"probe-peer",
	)
	ns("addr", "add", "10.231.0.2/30", "dev", "probe-tun")
	ns("link", "set", "probe-tun", "up")
	labCommand(t, "/sbin/ip", "route", "add", "8.8.8.8/32", "via", "10.231.0.2", "dev", "probe-tun")
	code := "import socket\ns=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',443));s.listen()\nwhile True:\n c,a=s.accept();c.sendall(b'native-probe-origin');c.close()"
	origin := exec.Command("/sbin/ip", "netns", "exec", namespace, "python3", "-c", code)
	if e := origin.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = origin.Process.Kill(); _ = origin.Wait() }()
	manager := testManager(t, &memoryBackend{}, &testWatchdog{})
	socket := filepath.Join(t.TempDir(), "helper.sock")
	server := &Server{Manager: manager, AllowedUID: uint32(os.Geteuid()), SocketPath: socket}
	server.inspectProbeTunnel = func(ctx context.Context, name string) error {
		raw, e := exec.CommandContext(ctx, "/sbin/ip", "-details", "-json", "link", "show", "dev", name).
			Output()
		if e != nil {
			return e
		}
		return validateTunnelEvidence(
			name,
			[]platform.Interface{{Device: name, Protocol: "gre", Up: true}},
			raw,
		)
	}
	serving := make(chan error, 1)
	go func() { serving <- server.Serve(ctx) }()
	defer func() { cancel(); <-serving }()
	client := &Client{SocketPath: socket, ExpectedUID: 0}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, e := os.Stat(socket); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("helper did not serve")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, p := range []struct {
		id, kind, device, address, local string
		slot                             int
	}{{"first-direct", "direct", "", "1.1.1.1:443", "10.230.0.1", 201}, {"first-tunnel", "interface", "probe-tun", "8.8.8.8:443", "10.231.0.1", 202}} {
		if e := client.RegisterProbe(ctx, p.id, p.kind, p.slot, p.device); e != nil {
			t.Fatal("first-use registration", e)
		}
		bounded, stop := context.WithTimeout(ctx, 3*time.Second)
		var conn net.Conn
		var e error
		for {
			conn, e = client.DialProbe(bounded, p.id, p.address)
			if e == nil {
				break
			}
			if bounded.Err() != nil {
				stop()
				t.Fatal("first-use registered path", e)
			}
			time.Sleep(20 * time.Millisecond)
		}
		data, e := io.ReadAll(conn)
		if e != nil || string(data) != "native-probe-origin" {
			t.Fatal("source did not reach isolated origin", string(data), e)
		}
		if conn.LocalAddr().(*net.TCPAddr).IP.String() != p.local {
			t.Fatal("source left through wrong interface", conn.LocalAddr())
		}
		raw, err := conn.(*net.TCPConn).SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		mark := 0
		var socketErr error
		if err = raw.Control(func(fd uintptr) {
			mark, socketErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK)
		}); err != nil {
			t.Fatal(err)
		}
		if socketErr != nil {
			t.Fatal(socketErr)
		}
		if uint32(mark) != dataplane.Mark(uint16(p.slot)) {
			t.Fatal("received FD lost independent source mark", mark)
		}
		_ = conn.Close()
		stop()
		if e := client.UnregisterProbe(ctx, p.id); e != nil {
			t.Fatal(e)
		}
		if conn, e := client.DialProbe(ctx, p.id, p.address); e == nil {
			_ = conn.Close()
			t.Fatal("unregistered source could dial")
		}
	}
	if e := client.RegisterProbe(ctx, "physical", "interface", 203, "probe-veth"); e == nil {
		t.Fatal("physical uplink accepted as tunnel")
	}
	state, e := manager.Status()
	if e != nil || state.Committed != nil || state.Transaction != nil {
		t.Fatal("registration created network transaction", e)
	}
}

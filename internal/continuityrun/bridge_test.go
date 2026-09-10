package continuityrun

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/dispatch"
)

func testBridge(t *testing.T) (dispatch.Bridge, string, <-chan string) {
	t.Helper()
	gateway, targets := testGateway(t)
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	b := dispatch.Bridge{
		Port:     l.Addr().(*net.TCPAddr).Port,
		Username: strings.Repeat("ab", 16),
		Password: strings.Repeat("cd", 32),
	}
	go func() { defer close(done); serveBridge(ctx, gateway, l, b, make(chan struct{}, 8)) }()
	t.Cleanup(func() { cancel(); _ = l.Close(); <-done })
	return b, l.Addr().String(), targets
}

func bridgeLogin(t *testing.T, address string, b dispatch.Bridge) net.Conn {
	t.Helper()
	c, e := net.DialTimeout("tcp", address, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, e = c.Write([]byte{5, 1, 2}); e != nil {
		t.Fatal(e)
	}
	var h [2]byte
	if _, e = io.ReadFull(c, h[:]); e != nil || h != [2]byte{5, 2} {
		t.Fatal(h, e)
	}
	auth := append([]byte{1, byte(len(b.Username))}, []byte(b.Username)...)
	auth = append(auth, byte(len(b.Password)))
	auth = append(auth, []byte(b.Password)...)
	if _, e = c.Write(auth); e != nil {
		t.Fatal(e)
	}
	if _, e = io.ReadFull(c, h[:]); e != nil || h != [2]byte{1, 0} {
		t.Fatal(h, e)
	}
	return c
}

func bridgeRequest(
	t *testing.T,
	c net.Conn,
	command byte,
	destination netip.AddrPort,
) (byte, netip.AddrPort) {
	t.Helper()
	if _, e := c.Write(append([]byte{5, command, 0}, bridgeAddress(destination)...)); e != nil {
		t.Fatal(e)
	}
	var h [4]byte
	if _, e := io.ReadFull(c, h[:]); e != nil {
		t.Fatal(e)
	}
	if h[0] != 5 || h[2] != 0 {
		t.Fatal(h)
	}
	a, e := readBridgeAddress(c, h[3])
	if e != nil {
		t.Fatal(e)
	}
	return h[1], a
}

func TestBridgeAuthenticatedTCPAndIPv6PreserveRelayDestination(t *testing.T) {
	b, address, targets := testBridge(t)
	for _, destination := range []string{"9.9.9.9:443", "[2606:4700:4700::1111]:443"} {
		c := bridgeLogin(t, address, b)
		status, _ := bridgeRequest(t, c, 1, netip.MustParseAddrPort(destination))
		if status != 0 {
			t.Fatal(status)
		}
		payload := []byte("through-private-relay")
		if _, e := c.Write(payload); e != nil {
			t.Fatal(e)
		}
		reply := make([]byte, len(payload))
		if _, e := io.ReadFull(c, reply); e != nil || !bytes.Equal(reply, payload) {
			t.Fatal(string(reply), e)
		}
		select {
		case got := <-targets:
			if got != "tcp "+destination {
				t.Fatal(got)
			}
		case <-time.After(time.Second):
			t.Fatal("relay not opened")
		}
		_ = c.Close()
	}
}

func TestBridgeRejectsNoAuthenticationAndBadCredentials(t *testing.T) {
	b, address, targets := testBridge(t)
	for _, auth := range []bool{false, true} {
		c, e := net.Dial("tcp", address)
		if e != nil {
			t.Fatal(e)
		}
		_ = c.SetDeadline(time.Now().Add(time.Second))
		if !auth {
			_, _ = c.Write([]byte{5, 1, 0})
			var h [2]byte
			if _, e = io.ReadFull(c, h[:]); e != nil || h != [2]byte{5, 255} {
				t.Fatal(h, e)
			}
		} else {
			_, _ = c.Write([]byte{5, 1, 2})
			var h [2]byte
			_, _ = io.ReadFull(c, h[:])
			_, _ = c.Write(
				append(append([]byte{1, byte(len(b.Username))}, []byte(b.Username)...), 1, 'x'),
			)
			if _, e = io.ReadFull(c, h[:]); e != nil || h != [2]byte{1, 1} {
				t.Fatal(h, e)
			}
		}
		_ = c.Close()
	}
	select {
	case target := <-targets:
		t.Fatal("unauthenticated relay target", target)
	default:
	}
}

func TestBridgeRejectsPrivateDomainAndUnsupportedRequests(t *testing.T) {
	b, address, targets := testBridge(t)
	for _, destination := range []string{"127.0.0.1:22", "10.0.0.1:443", "169.254.169.254:80", "[::1]:443", "[2001:db8::1]:443", "8.8.8.8:0"} {
		c := bridgeLogin(t, address, b)
		status, _ := bridgeRequest(t, c, 1, netip.MustParseAddrPort(destination))
		if status != 2 {
			t.Fatal(destination, status)
		}
		_ = c.Close()
	}
	c := bridgeLogin(t, address, b)
	_, _ = c.Write(
		[]byte{5, 1, 0, 3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0, 80},
	)
	var reply [10]byte
	if _, e := io.ReadFull(c, reply[:]); e != nil || reply[1] != 8 {
		t.Fatal(reply, e)
	}
	_ = c.Close()
	c = bridgeLogin(t, address, b)
	status, _ := bridgeRequest(t, c, 2, netip.MustParseAddrPort("8.8.8.8:443"))
	if status != 7 {
		t.Fatal(status)
	}
	select {
	case target := <-targets:
		t.Fatal("forbidden target opened", target)
	default:
	}
}

func TestBridgeUDPAssociationBoundariesSourcePinningAndCleanup(t *testing.T) {
	b, address, targets := testBridge(t)
	c := bridgeLogin(t, address, b)
	status, bound := bridgeRequest(t, c, 3, netip.MustParseAddrPort("0.0.0.0:0"))
	if status != 0 || !bound.Addr().IsLoopback() || bound.Port() == 0 {
		t.Fatal(status, bound)
	}
	u, e := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(bound))
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = u.Close() }()
	destination := netip.MustParseAddrPort("9.9.9.9:443")
	for _, payload := range [][]byte{[]byte("udp-one"), bytes.Repeat([]byte{0x42}, 1400)} {
		packet := append([]byte{0, 0, 0}, bridgeAddress(destination)...)
		packet = append(packet, payload...)
		if _, e = u.Write(packet); e != nil {
			t.Fatal(e)
		}
		_ = u.SetReadDeadline(time.Now().Add(3 * time.Second))
		reply := make([]byte, 2048)
		n, e := u.Read(reply)
		if e != nil || !bytes.Equal(packet, reply[:n]) {
			t.Fatal("UDP framing changed", n, e)
		}
	}
	select {
	case got := <-targets:
		if got != "udp 9.9.9.9:443" {
			t.Fatal(got)
		}
	case <-time.After(time.Second):
		t.Fatal("UDP relay target missing")
	}
	other, e := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(bound))
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = other.Close() }()
	packet := append([]byte{0, 0, 0}, bridgeAddress(netip.MustParseAddrPort("8.8.8.8:443"))...)
	packet = append(packet, 'x')
	_, _ = other.Write(packet)
	_ = other.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, e = other.Read(make([]byte, 1024)); e == nil {
		t.Fatal("unowned datagram accepted")
	}
	for _, bad := range [][]byte{append([]byte{0, 0, 1}, bridgeAddress(destination)...), append([]byte{0, 0, 0}, bridgeAddress(netip.MustParseAddrPort("10.0.0.1:80"))...), {0, 0, 0, 3, 1, 'x', 0, 80}} {
		_, _ = u.Write(bad)
	}
	_ = u.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, e = u.Read(make([]byte, 2048)); e == nil {
		t.Fatal("fragment/private/domain datagram accepted")
	}
	_ = c.Close()
	time.Sleep(20 * time.Millisecond)
	_, _ = u.Write(append(append([]byte{0, 0, 0}, bridgeAddress(destination)...), 'x'))
	_ = u.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, e = u.Read(make([]byte, 2048)); e == nil {
		t.Fatal("association survived control close")
	}
	select {
	case got := <-targets:
		t.Fatal("extra UDP mapping opened", got)
	default:
	}
}

func TestBridgeRejectsOutsideLoopbackBeforeHandshake(t *testing.T) {
	g, targets := testGateway(t)
	l := newMemoryListener()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); serveBridge(ctx, g, l, dispatch.Bridge{}, make(chan struct{}, 1)) }()
	defer func() { cancel(); _ = l.Close(); <-done }()
	client, accepted := acceptedPair(t, "192.168.1.2:1234", "127.0.0.1:8443")
	defer func() { _ = client.Close() }()
	l.conns <- accepted
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, e := client.Read(make([]byte, 1)); e == nil {
		t.Fatal("LAN bridge client accepted")
	}
	select {
	case target := <-targets:
		t.Fatal(target)
	default:
	}
}

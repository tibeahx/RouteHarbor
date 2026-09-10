package continuityrun

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/config"
	"github.com/tibeahx/RouteHarbor/internal/continuity"
	"github.com/tibeahx/RouteHarbor/internal/helper"
	"github.com/tibeahx/RouteHarbor/internal/model"
	"github.com/tibeahx/RouteHarbor/internal/node"
)

// These fixtures carry real mutually authenticated TLS over in-memory sockets.
// Address-aware accepted connections verify worker forwarding decisions, not
// kernel interception, privilege separation, or physical cutover performance.
type memoryListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newMemoryListener() *memoryListener {
	return &memoryListener{conns: make(chan net.Conn, 8), closed: make(chan struct{})}
}

func (l *memoryListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *memoryListener) Close() error { l.once.Do(func() { close(l.closed) }); return nil }

func (*memoryListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443} }

func (l *memoryListener) dial(ctx context.Context) (net.Conn, error) {
	a, b := net.Pipe()
	select {
	case l.conns <- b:
		return a, nil
	case <-ctx.Done():
		_ = a.Close()
		_ = b.Close()
		return nil, ctx.Err()
	case <-l.closed:
		_ = a.Close()
		_ = b.Close()
		return nil, net.ErrClosed
	}
}

type acceptedConn struct {
	net.Conn
	remote, local net.Addr
}

func (c *acceptedConn) RemoteAddr() net.Addr { return c.remote }
func (c *acceptedConn) LocalAddr() net.Addr  { return c.local }
func acceptedPair(t *testing.T, remote, local string) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	r, err := net.ResolveTCPAddr("tcp", remote)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.ResolveTCPAddr("tcp", local)
	if err != nil {
		t.Fatal(err)
	}
	return a, &acceptedConn{Conn: b, remote: r, local: l}
}

func testGateway(t *testing.T) (*continuity.Gateway, <-chan string) {
	t.Helper()
	gatewayIdentity, err := node.LoadIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	relayIdentity, err := node.LoadIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := continuity.ClientTLS(gatewayIdentity.Certificate, relayIdentity.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, err := continuity.ServerTLS(
		relayIdentity.Certificate,
		[]string{gatewayIdentity.Fingerprint},
	)
	if err != nil {
		t.Fatal(err)
	}
	targets := make(chan string, 8)
	relay, err := continuity.NewRelay(
		continuity.RelayConfig{
			TLSConfig: serverTLS,
			DialTarget: func(ctx context.Context, network, address string) (net.Conn, error) {
				a, b := net.Pipe()
				select {
				case targets <- network + " " + address:
				case <-ctx.Done():
					_ = a.Close()
					_ = b.Close()
					return nil, ctx.Err()
				}
				go func() { defer func() { _ = b.Close() }(); _, _ = io.Copy(b, b) }()
				return a, nil
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	listener := newMemoryListener()
	done := make(chan struct{})
	go func() { defer close(done); _ = relay.Serve(listener) }()
	gateway, err := continuity.NewGateway(continuity.GatewayConfig{TLSConfig: clientTLS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Close(); _ = relay.Close(); _ = listener.Close(); <-done })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := gateway.AddPath(ctx, "first", listener.dial); err != nil {
		t.Fatal(err)
	}
	return gateway, targets
}

func TestLimitsRetainDefaultFlowAndControlBounds(t *testing.T) {
	c := config.ContinuityDefaults()
	got := Limits(c)
	expected := continuity.DefaultLimits()
	expected.BufferBytes = (32 << 20) - (2 << 20) - model.ContinuityFixedReserveBytes
	expected.UDPReserveBytes = 2 << 20
	if got != expected {
		t.Fatal("worker default budget changed", got)
	}
	c.BufferBytes = 8 << 20
	c.UDPReserveBytes = 1 << 20
	c.DisconnectedGraceSeconds = 7
	got = Limits(c)
	if got.BufferBytes != 7<<20 || got.UDPReserveBytes != 512<<10 ||
		got.DisconnectedGrace != 7*time.Second ||
		got.MaxTCP != 512 ||
		got.MaxUDP != 256 ||
		got.ControlBytes != 256<<10 ||
		got.FlowBytes != 2<<20 {
		t.Fatal("public overrides changed unrelated bounds", got)
	}
	if _, err := got.Normalize(); err != nil {
		t.Fatal(err)
	}
}

func TestLANClientRequiresExplicitMatchingPrefix(t *testing.T) {
	c := model.Network{LocalPrefixes: []string{"192.168.1.0/24", "fd00:1::/64", "malformed"}}
	for _, test := range []struct {
		address string
		want    bool
	}{{"192.168.1.2", true}, {"::ffff:192.168.1.2", true}, {"fd00:1::2", true}, {"192.168.2.2", false}, {"8.8.8.8", false}, {"fd00:2::2", false}, {"0.0.0.0", false}, {"224.0.0.1", false}, {"::", false}, {"ff02::1", false}} {
		t.Run(test.address, func(t *testing.T) {
			if got := LANClient(c, netip.MustParseAddr(test.address)); got != test.want {
				t.Fatal(got, test.want)
			}
		})
	}
	if LANClient(model.Network{}, netip.MustParseAddr("192.168.1.2")) ||
		LANClient(c, netip.Addr{}) {
		t.Fatal("unknown LAN admitted")
	}
}

func TestServeTCPPreservesOriginalDestinationAndDNSPolicy(t *testing.T) {
	for _, dns := range []bool{false, true} {
		t.Run(map[bool]string{false: "transparent", true: "dns"}[dns], func(t *testing.T) {
			gateway, targets := testGateway(t)
			listener := newMemoryListener()
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			r := helper.ContinuityWorkerRequest{
				Network: model.Network{
					LocalPrefixes: []string{"192.168.1.0/24"},
					DNSResolver:   "8.8.8.8",
				},
			}
			go func() { defer close(done); serveTCP(ctx, gateway, listener, r, dns, make(chan struct{}, 2)) }()
			t.Cleanup(func() { cancel(); _ = listener.Close(); <-done })
			client, accepted := acceptedPair(t, "192.168.1.2:42100", "9.9.9.9:443")
			defer func() { _ = client.Close() }()
			listener.conns <- accepted
			_ = client.SetDeadline(time.Now().Add(3 * time.Second))
			payload := []byte("worker-target-integrity")
			if _, err := client.Write(payload); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, len(payload))
			if _, err := io.ReadFull(client, reply); err != nil || !bytes.Equal(reply, payload) {
				t.Fatal("payload changed", err)
			}
			want := "tcp 9.9.9.9:443"
			if dns {
				want = "tcp 8.8.8.8:53"
			}
			select {
			case target := <-targets:
				if target != want {
					t.Fatal("original destination/policy lost", target, want)
				}
			case <-time.After(time.Second):
				t.Fatal("relay did not receive target")
			}
		})
	}
}

func TestServeTCPRejectsOutsideLANAndBoundedAdmission(t *testing.T) {
	gateway, targets := testGateway(t)
	listener := newMemoryListener()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	r := helper.ContinuityWorkerRequest{
		Network: model.Network{LocalPrefixes: []string{"192.168.1.0/24"}},
	}
	slots := make(chan struct{}, 1)
	go func() { defer close(done); serveTCP(ctx, gateway, listener, r, false, slots) }()
	defer func() { cancel(); _ = listener.Close(); <-done }()
	outside, accepted := acceptedPair(t, "203.0.113.2:42000", "9.9.9.9:443")
	defer func() { _ = outside.Close() }()
	listener.conns <- accepted
	_ = outside.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := outside.Read(b[:]); err != io.EOF {
		t.Fatal("outside LAN client not closed", err)
	}
	select {
	case destination := <-targets:
		t.Fatal("outside LAN reached relay", destination)
	default:
	}
	// Occupy the only admission slot without relying on flow scheduling timing.
	slots <- struct{}{}
	excess, accepted := acceptedPair(t, "192.168.1.2:42001", "9.9.9.9:443")
	defer func() { _ = excess.Close() }()
	listener.conns <- accepted
	_ = excess.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := excess.Read(b[:]); err != io.EOF {
		t.Fatal("excess client was not rejected", err)
	}
	if gateway.Snapshot().TCPFlows != 0 {
		t.Fatal("rejected clients allocated logical flows")
	}
}

type datagramLease struct {
	writes [][]byte
	closed bool
}

func (c *datagramLease) Read([]byte) (int, error) { return 0, io.EOF }
func (c *datagramLease) Write(b []byte) (int, error) {
	if c.closed {
		return 0, net.ErrClosed
	}
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}
func (c *datagramLease) Close() error                   { c.closed = true; return nil }
func (*datagramLease) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*datagramLease) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (*datagramLease) SetDeadline(time.Time) error      { return nil }
func (*datagramLease) SetReadDeadline(time.Time) error  { return nil }
func (*datagramLease) SetWriteDeadline(time.Time) error { return nil }

type fakeUDPSender struct {
	err                        error
	keys, destinations, closed []string
	payloads                   [][]byte
}

func (s *fakeUDPSender) SendUDP(
	_ context.Context,
	key, destination string,
	payload []byte,
	deliver func([]byte) error,
) error {
	s.keys = append(s.keys, key)
	s.destinations = append(s.destinations, destination)
	s.payloads = append(s.payloads, append([]byte(nil), payload...))
	if s.err != nil {
		return s.err
	}
	return deliver(payload)
}
func (s *fakeUDPSender) CloseUDP(key string) { s.closed = append(s.closed, key) }

type fakeUDPOpener struct {
	remote, original []string
	leases           []*datagramLease
}

func (o *fakeUDPOpener) ContinuityUDPReply(
	_ context.Context,
	remote, original string,
) (net.Conn, error) {
	o.remote = append(o.remote, remote)
	o.original = append(o.original, original)
	c := &datagramLease{}
	o.leases = append(o.leases, c)
	return c, nil
}

func TestUDPTemporaryPressurePreservesExistingMappingAndDatagrams(t *testing.T) {
	sender, opener := &fakeUDPSender{}, &fakeUDPOpener{}
	mappings := map[string]*udpMapping{}
	remote, original := netip.MustParseAddrPort(
		"192.168.1.2:43000",
	), netip.MustParseAddrPort(
		"9.9.9.9:443",
	)
	payloads := [][]byte{{1, 0, 2}, {}, {3, 4, 5, 6}}
	send := func(payload []byte) error {
		return forwardUDP(
			context.Background(),
			sender,
			opener,
			mappings,
			model.Network{},
			false,
			remote,
			original,
			payload,
			time.Now(),
		)
	}
	if err := send(payloads[0]); err != nil {
		t.Fatal(err)
	}
	sender.err = continuity.ErrCapacity
	if err := send([]byte("dropped")); err != continuity.ErrCapacity {
		t.Fatal(err)
	}
	if len(opener.leases) != 1 || opener.leases[0].closed || len(sender.closed) != 0 ||
		len(mappings) != 1 {
		t.Fatal("buffer pressure destroyed established UDP identity")
	}
	sender.err = nil
	for _, payload := range payloads[1:] {
		if err := send(payload); err != nil {
			t.Fatal(err)
		}
	}
	if len(opener.leases) != 1 || len(opener.leases[0].writes) != len(payloads) {
		t.Fatal("reply lease changed or datagrams merged")
	}
	for i, payload := range payloads {
		if !bytes.Equal(opener.leases[0].writes[i], payload) {
			t.Fatal("datagram payload/boundary changed", i)
		}
	}
	sender.err = net.ErrClosed
	if err := send(
		[]byte("closed"),
	); err != net.ErrClosed || !opener.leases[0].closed || len(mappings) != 0 ||
		len(sender.closed) != 1 {
		t.Fatal("terminal error did not clean mapping", err)
	}
}

func TestUDPRejectedNewMappingReleasesLeaseAndEmptyFlow(t *testing.T) {
	sender, opener := &fakeUDPSender{err: continuity.ErrCapacity}, &fakeUDPOpener{}
	mappings := map[string]*udpMapping{}
	err := forwardUDP(
		context.Background(),
		sender,
		opener,
		mappings,
		model.Network{},
		false,
		netip.MustParseAddrPort("192.168.1.2:43000"),
		netip.MustParseAddrPort("9.9.9.9:443"),
		[]byte("new"),
		time.Now(),
	)
	if err != continuity.ErrCapacity || len(mappings) != 0 || len(sender.closed) != 1 ||
		len(opener.leases) != 1 ||
		!opener.leases[0].closed {
		t.Fatal("rejected new mapping retained resources", err)
	}
}

func TestUDPDNSChangesRelayTargetPreservingOriginalReplyTuple(t *testing.T) {
	sender, opener := &fakeUDPSender{}, &fakeUDPOpener{}
	mappings := map[string]*udpMapping{}
	remote, original := netip.MustParseAddrPort(
		"192.168.1.2:43000",
	), netip.MustParseAddrPort(
		"9.9.9.9:53",
	)
	query := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	err := forwardUDP(
		context.Background(),
		sender,
		opener,
		mappings,
		model.Network{DNSResolver: "8.8.8.8"},
		true,
		remote,
		original,
		query,
		time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if sender.destinations[0] != "8.8.8.8:53" || opener.remote[0] != remote.String() ||
		opener.original[0] != original.String() {
		t.Fatal("DNS resolver leaked into client reply identity")
	}
	if len(opener.leases[0].writes) != 1 || !bytes.Equal(opener.leases[0].writes[0], query) {
		t.Fatal("DNS datagram content changed")
	}
}

func TestUDPMappingCountBoundAvoidsOpeningExcessLeases(t *testing.T) {
	sender, opener := &fakeUDPSender{}, &fakeUDPOpener{}
	mappings := map[string]*udpMapping{}
	for i := range continuity.DefaultLimits().MaxUDP {
		mappings[netip.AddrPortFrom(netip.MustParseAddr("192.168.1.2"), uint16(i+1024)).String()] = &udpMapping{}
	}
	err := forwardUDP(
		context.Background(),
		sender,
		opener,
		mappings,
		model.Network{},
		false,
		netip.MustParseAddrPort("192.168.1.2:43000"),
		netip.MustParseAddrPort("9.9.9.9:443"),
		[]byte("excess"),
		time.Now(),
	)
	if err != continuity.ErrCapacity || len(opener.leases) != 0 || len(sender.keys) != 0 {
		t.Fatal("excess mapping acquired resources", err)
	}
}

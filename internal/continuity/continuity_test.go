package continuity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "continuity fixture"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

type testPath struct {
	address string
	mu      sync.Mutex
	conns   []*faultConn
	dead    atomic.Bool
}
type faultConn struct {
	net.Conn
	blackhole atomic.Bool
	oneWay    atomic.Bool
	closed    chan struct{}
	once      sync.Once
}

func (c *faultConn) Write(b []byte) (int, error) {
	if c.blackhole.Load() || c.oneWay.Load() {
		return len(b), nil
	}
	return c.Conn.Write(b)
}

func (c *faultConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if c.blackhole.Load() {
		<-c.closed
		return 0, net.ErrClosed
	}
	return n, err
}
func (c *faultConn) Close() error { c.once.Do(func() { close(c.closed) }); return c.Conn.Close() }
func (p *testPath) dial(ctx context.Context) (net.Conn, error) {
	if p.dead.Load() {
		return nil, errors.New("test path unavailable")
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", p.address)
	if err != nil {
		return nil, err
	}
	f := &faultConn{Conn: c, closed: make(chan struct{})}
	p.mu.Lock()
	p.conns = append(p.conns, f)
	p.mu.Unlock()
	return f, nil
}

func (p *testPath) fail(mode string, laneOnly bool) {
	p.dead.Store(true)
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, c := range p.conns {
		if laneOnly && i%CarriersPerPath != 1 {
			continue
		}
		switch mode {
		case "blackhole":
			c.blackhole.Store(true)
		case "oneway":
			c.oneWay.Store(true)
		default:
			_ = c.Close()
		}
	}
}

type fixture struct {
	g        *Gateway
	r        *Relay
	paths    [2]*testPath
	tls      *tls.Config
	dialed   atomic.Int64
	udpMu    sync.Mutex
	udpPorts []string
}

func newFixture(t *testing.T, l Limits) *fixture {
	t.Helper()
	return newFixtureProfiles(t, l, l)
}

func newFixtureProfiles(t *testing.T, serverLimits, gatewayLimits Limits) *fixture {
	t.Helper()
	server, client := testCert(t), testCert(t)
	st, err := ServerTLS(server, []string{CertificateFingerprint(client.Leaf)})
	if err != nil {
		t.Fatal(err)
	}
	ct, err := ClientTLS(client, CertificateFingerprint(server.Leaf))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{tls: ct}
	r, err := NewRelay(
		RelayConfig{
			TLSConfig: st,
			Limits:    serverLimits,
			DialTarget: func(ctx context.Context, network, address string) (net.Conn, error) {
				f.dialed.Add(1)
				c, e := (&net.Dialer{}).DialContext(ctx, network, address)
				if e == nil && network == "udp" {
					f.udpMu.Lock()
					f.udpPorts = append(f.udpPorts, c.LocalAddr().String())
					f.udpMu.Unlock()
				}
				return c, e
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	f.r = r
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = r.Serve(listener) }()
	g, err := NewGateway(GatewayConfig{TLSConfig: ct, Limits: gatewayLimits})
	if err != nil {
		t.Fatal(err)
	}
	f.g = g
	t.Cleanup(func() { _ = g.Close(); _ = r.Close() })
	for i, name := range []string{"alpha", "beta"} {
		p := &testPath{address: listener.Addr().String()}
		f.paths[i] = p
		if err = g.AddPath(context.Background(), name, p.dial); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func tcpPair(t *testing.T) (net.Conn, *net.TCPConn) {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ch := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); ch <- c }()
	c, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	server := <-ch
	_ = l.Close()
	t.Cleanup(func() { _ = c.Close(); _ = server.Close() })
	return server, c.(*net.TCPConn)
}

func tcpEcho(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() { defer func() { _ = c.Close() }(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr().String()
}

func exchange(t *testing.T, c net.Conn, payload []byte) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan error, 1)
	go func() { done <- writeAll(c, payload) }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("stream changed across carrier switch")
	}
}

func eventually(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

func TestTLSCarrierFailoverKeepsTCPAndHalfClose(t *testing.T) {
	for _, mode := range []string{"reset", "blackhole", "oneway"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, Limits{})
			gateway, client := tcpPair(t)
			done := make(chan error, 1)
			go func() { done <- f.g.ServeTCP(context.Background(), gateway, tcpEcho(t)) }()
			payload := bytes.Repeat([]byte("a retained TCP session\x00"), 16000)
			exchange(t, client, payload)
			f.paths[0].fail(mode, false)
			exchange(t, client, payload)
			if n := f.dialed.Load(); n != 1 {
				t.Fatalf("target socket recreated: %d", n)
			}
			eventually(t, func() bool { return f.g.Snapshot().ActivePath == "beta" })
			if err := client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
			b := make([]byte, 1)
			if n, err := client.Read(b); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("half-close not propagated: n=%d err=%v", n, err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("flow did not close")
			}
		})
	}
}

func TestDataCarrierFailureDetectedWithControlAlive(t *testing.T) {
	f := newFixture(t, Limits{})
	gateway, client := tcpPair(t)
	destination := tcpEcho(t)
	go func() { _ = f.g.ServeTCP(context.Background(), gateway, destination) }()
	exchange(t, client, []byte("before"))
	f.paths[0].fail("oneway", true)
	exchange(t, client, bytes.Repeat([]byte("after"), 4000))
	eventually(t, func() bool { return f.g.Snapshot().ActivePath == "beta" })
	f.g.p.mu.Lock()
	control := f.g.p.paths["alpha"][5]
	stillAlive := control != nil && !control.closed
	f.g.p.mu.Unlock()
	if !stillAlive {
		t.Fatal("test did not isolate data carrier failure")
	}
}

func TestPreferredPathMovesBothDirectionsWithoutReopening(t *testing.T) {
	f := newFixture(t, Limits{})
	gateway, client := tcpPair(t)
	destination := tcpEcho(t)
	go func() { _ = f.g.ServeTCP(context.Background(), gateway, destination) }()
	exchange(t, client, []byte("before selection"))
	if err := f.g.SetPreferred("beta"); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool {
		snapshots := f.r.Snapshots()
		return len(snapshots) == 1 && snapshots[0].ActivePath == "beta"
	})
	exchange(t, client, []byte("after selection"))
	if f.dialed.Load() != 1 {
		t.Fatal("ordinary selection recreated target")
	}
	if err := f.g.Close(); err != nil {
		t.Fatal(err)
	}
	if s := f.g.Snapshot(); s.QueueBytes != 0 || s.ControlQueueBytes != 0 {
		t.Fatalf("queues not released: %+v", s)
	}
}

func TestRelayRestartRefusesExistingGeneration(t *testing.T) {
	f := newFixture(t, Limits{})
	gateway, client := tcpPair(t)
	destination := tcpEcho(t)
	done := make(chan error, 1)
	go func() { done <- f.g.ServeTCP(context.Background(), gateway, destination) }()
	exchange(t, client, []byte("old application session"))
	address := f.paths[0].address
	tlsConfig := f.r.tls
	if err := f.r.Close(); err != nil {
		t.Fatal(err)
	}
	newRelay, err := NewRelay(
		RelayConfig{
			TLSConfig: tlsConfig,
			DialTarget: func(context.Context, string, string) (net.Conn, error) {
				t.Error("application target replayed after relay restart")
				return nil, ErrDestination
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = newRelay.Close() }()
	l, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = newRelay.Serve(l) }()
	select {
	case err = <-done:
		if !errors.Is(err, ErrGeneration) {
			t.Fatalf("generation loss was not explicit: %v", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("old session remained after generation changed")
	}
	if len(newRelay.Snapshots()) != 0 {
		t.Fatal("new relay recreated old session")
	}
	if !errors.Is(f.g.TerminalError(), ErrGeneration) ||
		f.g.Snapshot().DegradedReason != "relay_generation_lost" {
		t.Fatal("generation loss was not sticky and observable")
	}
	if err = f.g.SendUDP(
		context.Background(),
		"after-restart",
		"8.8.8.8:53",
		[]byte("new"),
		func([]byte) error { return nil },
	); !errors.Is(
		err,
		ErrGeneration,
	) {
		t.Fatal("terminal gateway accepted a new mapping")
	}
}

func TestNegotiatesSmallerFlowWindow(t *testing.T) {
	for _, serverSmall := range []bool{false, true} {
		t.Run(fmt.Sprint(serverSmall), func(t *testing.T) {
			server, gateway := DefaultLimits(), DefaultLimits()
			server.FlowBytes = 32 << 10
			gateway.FlowBytes = 16 << 10
			if serverSmall {
				server.FlowBytes, gateway.FlowBytes = gateway.FlowBytes, server.FlowBytes
			}
			f := newFixtureProfiles(t, server, gateway)
			accepted, client := tcpPair(t)
			destination := tcpEcho(t)
			go func() { _ = f.g.ServeTCP(context.Background(), accepted, destination) }()
			exchange(t, client, bytes.Repeat([]byte("negotiated bounded stream"), 16000))
			f.g.p.mu.Lock()
			window := f.g.p.limits.FlowBytes
			f.g.p.mu.Unlock()
			if window != 16<<10 {
				t.Fatal("did not negotiate smaller window")
			}
		})
	}
}

func TestPerIdentitySessionQuota(t *testing.T) {
	f := newFixture(t, Limits{})
	second, err := NewGateway(GatewayConfig{TLSConfig: f.tls})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	if err = second.AddPath(context.Background(), "second", f.paths[0].dial); err != nil {
		t.Fatal(err)
	}
	third, err := NewGateway(GatewayConfig{TLSConfig: f.tls})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = third.Close() }()
	if err = third.AddPath(context.Background(), "third", f.paths[0].dial); err == nil {
		t.Fatal("one identity exhausted relay with unbounded sessions")
	}
	if len(f.r.Snapshots()) != 2 {
		t.Fatal("unexpected per-identity session count")
	}
}

func TestUDPAdmissionAndMinimumScratchBudget(t *testing.T) {
	cert := testCert(t)
	tlsConfig, err := ClientTLS(cert, CertificateFingerprint(cert.Leaf))
	if err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.UDPReserveBytes = 128 << 10
	if _, err = NewGateway(GatewayConfig{TLSConfig: tlsConfig, Limits: limits}); err == nil {
		t.Fatal("accepted UDP budget too small for a complete datagram")
	}
	limits = DefaultLimits()
	limits.MaxUDP = 1
	g, err := NewGateway(GatewayConfig{TLSConfig: tlsConfig, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	deliver := func([]byte) error { return nil }
	if err = g.SendUDP(
		context.Background(),
		"first",
		"8.8.8.8:53",
		[]byte("first"),
		deliver,
	); err != nil {
		t.Fatal(err)
	}
	if err = g.SendUDP(
		context.Background(),
		"second",
		"8.8.8.8:53",
		[]byte("second"),
		deliver,
	); !errors.Is(
		err,
		ErrCapacity,
	) {
		t.Fatal("UDP admission quota was not enforced")
	}
}

type writeGateConn struct {
	net.Conn
	release   <-chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *writeGateConn) Write(b []byte) (int, error) {
	select {
	case <-c.release:
		return c.Conn.Write(b)
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *writeGateConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func (c *writeGateConn) CloseWrite() error {
	return c.Conn.(*net.TCPConn).CloseWrite()
}

func TestSlowReceiverAppliesWindowWithoutFailingHealthyPaths(t *testing.T) {
	limits := DefaultLimits()
	limits.FlowBytes = 16 << 10
	f := newFixture(t, limits)
	accepted, client := tcpPair(t)
	// Block application delivery deterministically while keeping real TCP/TLS
	// carriers. Tiny kernel socket buffers also introduce OS-specific TCP
	// window-update delays after the application resumes reading.
	release := make(chan struct{})
	blocked := &writeGateConn{Conn: accepted, release: release, closed: make(chan struct{})}
	t.Cleanup(func() { _ = blocked.Close() })
	destination := tcpEcho(t)
	go func() { _ = f.g.ServeTCP(context.Background(), blocked, destination) }()
	payload := bytes.Repeat([]byte("backpressure preserves bytes"), 10000)
	written := make(chan error, 1)
	go func() { written <- writeAll(client, payload) }()
	eventually(t, func() bool {
		f.g.p.mu.Lock()
		defer f.g.p.mu.Unlock()
		for _, flow := range f.g.p.flows {
			if flow.recvBytes >= limits.FlowBytes-segmentOverhead*2 {
				return true
			}
		}
		return false
	})
	time.Sleep(150 * time.Millisecond)
	s := f.g.Snapshot()
	if s.Switches != 0 || len(s.Paths) != 2 || !s.Paths[0].Ready || !s.Paths[1].Ready {
		t.Fatalf("flow control falsely failed healthy carriers: %+v", s)
	}
	close(release)
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(payload))
	if received, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("received %d/%d bytes: %v", received, len(payload), err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("backpressure changed payload")
	}
}

func TestUDPKeepsMappingOnOrdinaryPreferenceChange(t *testing.T) {
	f := newFixture(t, Limits{})
	target, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = target.Close() }()
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, e := target.ReadFrom(b)
			if e != nil {
				return
			}
			_, _ = target.WriteTo(b[:n], a)
		}
	}()
	replies := make(chan []byte, 4)
	deliver := func(b []byte) error { replies <- append([]byte(nil), b...); return nil }
	for _, name := range []string{"alpha", "beta", "alpha", "beta"} {
		if err = f.g.SetPreferred(name); err != nil {
			t.Fatal(err)
		}
		body := []byte(name)
		if err = f.g.SendUDP(
			context.Background(),
			"stable",
			target.LocalAddr().String(),
			body,
			deliver,
		); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-replies:
			if !bytes.Equal(got, body) {
				t.Fatal("UDP response changed")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("UDP response lost after ordinary selection")
		}
	}
	if f.dialed.Load() != 1 {
		t.Fatal("UDP socket recreated on preference change")
	}
}

func TestCloseRetriesAfterCarrierFailure(t *testing.T) {
	f := newFixture(t, Limits{})
	if err := f.g.SendUDP(
		context.Background(),
		"mapping",
		"127.0.0.1:9",
		[]byte("open"),
		func([]byte) error { return nil },
	); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return f.dialed.Load() == 1 })
	f.paths[0].fail("blackhole", false)
	f.g.CloseUDP("mapping")
	eventually(
		t,
		func() bool { snapshots := f.r.Snapshots(); return len(snapshots) == 1 && snapshots[0].UDPFlows == 0 },
	)
	f.g.p.mu.Lock()
	remaining := len(f.g.p.closing)
	f.g.p.mu.Unlock()
	if remaining > 1 {
		t.Fatal("close retry state is unbounded")
	}
}

func TestUDPKeepsTargetMappingAcrossFailover(t *testing.T) {
	f := newFixture(t, Limits{})
	target, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = target.Close() }()
	go func() {
		b := make([]byte, 65535)
		for {
			n, addr, e := target.ReadFrom(b)
			if e != nil {
				return
			}
			_, _ = target.WriteTo(b[:n], addr)
		}
	}()
	replies := make(chan []byte, 20)
	deliver := func(b []byte) error { replies <- append([]byte(nil), b...); return nil }
	for i := 0; i < 20; i++ {
		if i == 10 {
			f.paths[0].fail("reset", false)
		}
		body := bytes.Repeat([]byte{byte(i)}, 1200)
		if err = f.g.SendUDP(
			context.Background(),
			"lan-tuple",
			target.LocalAddr().String(),
			body,
			deliver,
		); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-replies:
			if !bytes.Equal(got, body) {
				t.Fatal("UDP boundary or contents changed")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("datagram lost")
		}
	}
	if n := f.dialed.Load(); n != 1 {
		t.Fatalf("UDP target mapping recreated: %d", n)
	}
	f.udpMu.Lock()
	defer f.udpMu.Unlock()
	if len(f.udpPorts) != 1 {
		t.Fatal("UDP external port changed")
	}
	f.g.CloseUDP("lan-tuple")
}

func TestPinnedIdentityAndProbe(t *testing.T) {
	f := newFixture(t, Limits{})
	probe, err := ProbeRelay(context.Background(), f.tls, f.paths[0].dial)
	if err != nil || probe.Bytes != 2*chunkSize || probe.Duration <= 0 {
		t.Fatalf("invalid authenticated probe: %+v %v", probe, err)
	}
	imposter := testCert(t)
	wrong, err := ClientTLS(imposter, CertificateFingerprint(imposter.Leaf))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ProbeRelay(context.Background(), wrong, f.paths[0].dial); err == nil {
		t.Fatal("untrusted identity accepted")
	}
	if _, err = NewGateway(
		GatewayConfig{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}},
	); err == nil {
		t.Fatal("missing pin accepted")
	}
	if _, err = ClientTLS(imposter, ""); err == nil {
		t.Fatal("missing fingerprint accepted")
	}
}

func TestQueuesBoundedAndUDPExpiresWhileDisconnected(t *testing.T) {
	l := DefaultLimits()
	l.BufferBytes = 256 << 10
	l.UDPReserveBytes = 64 << 10
	l.FlowBytes = 32 << 10
	p := newPeer(l, "test", "generation", false, nil)
	defer func() { _ = p.close() }()
	g := &Gateway{p: p, paths: make(map[string]gatewayPath)}
	var capacity bool
	for i := 0; i < 100; i++ {
		err := g.SendUDP(
			context.Background(),
			"key",
			"8.8.8.8:53",
			make([]byte, 1200),
			func([]byte) error { return nil },
		)
		if errors.Is(err, ErrCapacity) {
			capacity = true
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !capacity {
		t.Fatal("UDP queue was not bounded")
	}
	s := g.Snapshot()
	if s.QueueBytes > l.BufferBytes || s.UDPQueueBytes > l.UDPReserveBytes {
		t.Fatal("queue budget exceeded")
	}
	// Datagrams have distinct enqueue timestamps. Seeing the first expiration
	// does not mean a later datagram has already crossed its replay deadline.
	eventually(t, func() bool {
		snapshot := g.Snapshot()
		return snapshot.ExpiredUDP > 0 && snapshot.UDPQueueBytes == flowOverhead
	})
	if g.Snapshot().Qualified {
		t.Fatal("unmeasured link claimed qualified")
	}
}

func TestReceiverDeduplicatesAfterWriteBeforeACK(t *testing.T) {
	l := DefaultLimits()
	p := newPeer(l, "test", "generation", false, nil)
	defer func() { _ = p.close() }()
	var delivered bytes.Buffer
	var mu sync.Mutex
	p.mu.Lock()
	f, err := p.newFlow(1, "8.8.8.8:443", false)
	if err != nil {
		t.Fatal(err)
	}
	f.opened = true
	f.deliver = func(b []byte) error { mu.Lock(); defer mu.Unlock(); _, e := delivered.Write(b); return e }
	p.startFlow(f)
	c := &carrier{p: p, control: make(chan queued), data: make(chan queued)}
	p.mu.Unlock()
	frame := frame{kind: frameData, flow: 1, offset: 0, data: []byte("execute exactly once")}
	p.handle(c, frame)
	eventually(
		t,
		func() bool { mu.Lock(); defer mu.Unlock(); return delivered.Len() == len(frame.data) },
	)
	p.handle(c, frame)
	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if delivered.String() != string(frame.data) {
		t.Fatal("replay delivered bytes twice")
	}
}

func TestUDPReplayDeduplicatesAndBoundsWindow(t *testing.T) {
	var w datagramWindow
	for _, n := range []uint64{1, 3, 2, 4097, 9000} {
		if w.contains(n) {
			t.Fatalf("unseen datagram %d", n)
		}
		w.add(n)
		if !w.contains(n) {
			t.Fatal("missing duplicate")
		}
	}
	if !w.contains(1) {
		t.Fatal("ancient replay accepted")
	}
	w.add(^uint64(0) - 1)
	w.add(^uint64(0))
	if !w.contains(^uint64(0)) {
		t.Fatal("maximum sequence not deduplicated")
	}
}

func TestDestinationPolicy(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "::1", "::ffff:192.168.1.1", "169.254.169.254", "100.64.0.1", "64:ff9b::a00:1", "2002:0a00:1::", "2001:db8::1"} {
		if publicAddress(netip.MustParseAddr(ip)) {
			t.Errorf("forbidden destination accepted: %s", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		if !publicAddress(netip.MustParseAddr(ip)) {
			t.Errorf("public destination rejected: %s", ip)
		}
	}
	for _, dest := range []string{"host:0", "host:65536", "host:00443", "host:https", "host:443garbage", "missing-port"} {
		if validDestination(dest) == nil {
			t.Errorf("invalid target accepted: %s", dest)
		}
	}
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(b []byte) (int, error) {
	if len(b) > 3 {
		b = b[:3]
	}
	return w.Buffer.Write(b)
}

func TestWirePartialWrites(t *testing.T) {
	w := &shortWriter{}
	want := frame{kind: frameData, flow: 13, offset: 100, value: 200, data: []byte("payload")}
	if err := writeFrame(w, want); err != nil {
		t.Fatal(err)
	}
	got, err := readFrame(&w.Buffer)
	if err != nil || got.kind != want.kind || got.flow != want.flow || got.offset != want.offset ||
		got.value != want.value ||
		!bytes.Equal(got.data, want.data) {
		t.Fatalf("wire mismatch: %+v %v", got, err)
	}
}

func FuzzReadFrame(f *testing.F) {
	var b bytes.Buffer
	_ = writeFrame(&b, frame{kind: frameData, flow: 1, data: []byte("seed")})
	f.Add(b.Bytes())
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := readFrame(bytes.NewReader(b))
		if err == nil && len(m.data) > maxPayload {
			t.Fatal("unbounded frame")
		}
	})
}

func FuzzDatagramSequenceWindow(f *testing.F) {
	f.Add(uint64(1), uint64(2))
	f.Add(^uint64(0)-1, ^uint64(0))
	f.Add(uint64(8192), uint64(1))
	f.Fuzz(func(t *testing.T, a, b uint64) {
		var w datagramWindow
		for _, n := range []uint64{a, b} {
			if n == 0 {
				continue
			}
			w.add(n)
			if !w.contains(n) {
				t.Fatal("recorded sequence was not deduplicated")
			}
		}
	})
}

// Package continuityrun connects the unprivileged continuity engine to typed,
// inherited helper resources. It never changes LAN routing during a path switch.
package continuityrun

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/continuity"
	"github.com/tibeahx/OpenRHP/internal/helper"
	"github.com/tibeahx/OpenRHP/internal/model"
	"github.com/tibeahx/OpenRHP/internal/probe"
)

func Limits(c model.ContinuityConfig) continuity.Limits {
	l := continuity.DefaultLimits()
	l.BufferBytes = c.BufferBytes - c.UDPReserveBytes/2 - model.ContinuityFixedReserveBytes
	l.UDPReserveBytes = c.UDPReserveBytes / 2
	l.DisconnectedGrace = time.Duration(c.DisconnectedGraceSeconds) * time.Second
	return l
}

// SourceTransport opens only the configured relay using the prepared source.
// ProxyURL is used by control probes; private workers use an owned local engine.
func SourceTransport(
	ctx context.Context,
	c *helper.Client,
	p adapter.Path,
	relay string,
) (net.Conn, error) {
	proxy := p.ProxyURL
	if p.ProxyPort != 0 {
		proxy = &url.URL{
			Scheme: "socks5",
			Host:   net.JoinHostPort("127.0.0.1", strconv.Itoa(p.ProxyPort)),
		}
	}
	if proxy != nil {
		return probe.OpenRelayTransport(ctx, proxy, relay)
	}
	if c == nil {
		return nil, errors.New("relay helper unavailable")
	}
	return c.DialContinuity(ctx, p.SourceID)
}

func LANClient(network model.Network, address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
		return false
	}
	for _, raw := range network.LocalPrefixes {
		p, e := netip.ParsePrefix(raw)
		if e == nil && p.Contains(address) {
			return true
		}
	}
	return false
}

type udpMapping struct {
	conn net.Conn
	last time.Time
}

// RunWorker requires the fixed inherited descriptor contract of the helper.
func RunWorker(ctx context.Context) error {
	if os.Geteuid() == 0 {
		return errors.New("continuity worker must be unprivileged")
	}
	life := os.NewFile(3, "continuity-life")
	status := os.NewFile(4, "continuity-status")
	input := os.NewFile(5, "continuity-config")
	commands := os.NewFile(6, "continuity-commands")
	if life == nil || status == nil || input == nil || commands == nil {
		return errors.New("missing continuity descriptors")
	}
	defer func() { _ = life.Close() }()
	defer func() { _ = status.Close() }()
	defer func() { _ = input.Close() }()
	defer func() { _ = commands.Close() }()
	raw, e := io.ReadAll(io.LimitReader(input, helper.MaxRequestBytes+1))
	if e != nil {
		return errors.New("invalid continuity input")
	}
	var r helper.ContinuityWorkerRequest
	if len(raw) > helper.MaxRequestBytes || helper.DecodeStrict(raw, &r) != nil ||
		helper.ValidateContinuityWorker(r) != nil {
		return errors.New("invalid continuity configuration")
	}
	if !strings.HasPrefix(r.HelperSocket, "/") {
		return errors.New("invalid helper socket")
	}
	cert, e := tls.X509KeyPair([]byte(r.Certificate), []byte(r.PrivateKey))
	if e != nil {
		return errors.New("invalid worker identity")
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil {
		return errors.New("invalid worker certificate")
	}
	tlsConfig, e := continuity.ClientTLS(cert, r.Config.RelayFingerprint)
	if e != nil {
		return e
	}
	g, e := continuity.NewGateway(
		continuity.GatewayConfig{TLSConfig: tlsConfig, Limits: Limits(r.Config)},
	)
	if e != nil {
		return e
	}
	defer func() { _ = g.Close() }()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { var b [1]byte; _, _ = life.Read(b[:]); cancel() }()
	client := &helper.Client{SocketPath: r.HelperSocket, ExpectedUID: 0}
	var listeners []io.Closer
	var wg sync.WaitGroup
	defer func() {
		cancel()
		for _, l := range listeners {
			_ = l.Close()
		}
		_ = commands.Close()
		wg.Wait()
	}()
	maxListeners := 4
	if r.Path.IPv6 {
		maxListeners = 8
	}
	if r.Path.DNSPort == 0 {
		maxListeners /= 2
	}
	if r.Bridge != nil {
		maxListeners++
	}
	if len(r.Listeners) != maxListeners {
		return errors.New("invalid continuity listeners")
	}
	tcpSlots := make(chan struct{}, continuity.DefaultLimits().MaxTCP)
	for i, spec := range r.Listeners {
		if spec.FD != 7+i {
			return errors.New("invalid continuity descriptor")
		}
		if spec.Bridge && (r.Bridge == nil || i != 0 || spec.Network != "tcp4" || spec.DNS) ||
			!spec.Bridge && r.Bridge != nil && i == 0 {
			return errors.New("invalid continuity bridge descriptor")
		}
		f := os.NewFile(uintptr(spec.FD), "continuity-listener")
		if f == nil {
			return errors.New("missing continuity listener")
		}
		if strings.HasPrefix(spec.Network, "tcp") {
			l, err := net.FileListener(f)
			_ = f.Close()
			if err != nil {
				return errors.New("invalid continuity listener")
			}
			listeners = append(listeners, l)
			if spec.Bridge {
				address, err := netip.ParseAddrPort(l.Addr().String())
				if err != nil || !address.Addr().IsLoopback() ||
					int(address.Port()) != r.Bridge.Port {
					return errors.New("invalid continuity bridge listener")
				}
				wg.Go(func() { serveBridge(ctx, g, l, *r.Bridge, tcpSlots) })
			} else {
				wg.Go(func() { serveTCP(ctx, g, l, r, spec.DNS, tcpSlots) })
			}
		} else if strings.HasPrefix(spec.Network, "udp") {
			p, err := net.FilePacketConn(f)
			_ = f.Close()
			if err != nil {
				return errors.New("invalid continuity listener")
			}
			u, ok := p.(*net.UDPConn)
			if !ok {
				_ = p.Close()
				return errors.New("invalid continuity datagram listener")
			}
			listeners = append(listeners, u)
			wg.Go(func() { serveUDP(ctx, g, client, u, r, spec.DNS) })
		} else {
			_ = f.Close()
			return errors.New("invalid continuity listener network")
		}
	}
	// Readiness acknowledges owned LAN sockets. Path readiness is separately
	// reported per carrier; no TLS/qualification status is inferred from this line.
	if _, e = io.WriteString(status, "ready\n"); e != nil {
		return e
	}
	choices := make(chan helper.ContinuityRequest, 1)
	choices <- helper.ContinuityRequest{Action: "select", SourceID: r.Preferred, Standby: r.Standby}
	wg.Go(func() {
		scan := bufio.NewScanner(commands)
		scan.Buffer(make([]byte, 1024), 4096)
		for scan.Scan() {
			var choice helper.ContinuityRequest
			if helper.DecodeStrict(scan.Bytes(), &choice) != nil || choice.Action != "select" {
				cancel()
				return
			}
			select {
			case choices <- choice:
			case <-ctx.Done():
				return
			}
		}
		cancel()
	})
	wg.Go(func() { managePaths(ctx, g, client, r, choices) })
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		snapshot := helper.ContinuityStatus{
			Snapshot:    g.Snapshot(),
			Running:     true,
			Fingerprint: continuity.CertificateFingerprint(leaf),
		}
		snapshot.QueueBytes += model.ContinuityFixedReserveBytes
		if e = json.NewEncoder(status).Encode(snapshot); e != nil {
			return errors.New("continuity status owner lost")
		}
		if snapshot.DegradedReason == "relay_generation_lost" {
			return errors.New("relay session state lost")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func managePaths(
	ctx context.Context,
	g *continuity.Gateway,
	client *helper.Client,
	r helper.ContinuityWorkerRequest,
	choices <-chan helper.ContinuityRequest,
) {
	known := map[string]adapter.Path{}
	for _, p := range r.Sources {
		known[p.SourceID] = p
	}
	connected := map[string]bool{}
	var primary, standby, lastPreferred string
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case choice := <-choices:
			if _, ok := known[choice.SourceID]; choice.SourceID != "" && !ok {
				continue
			}
			if _, ok := known[choice.Standby]; choice.Standby != "" && !ok {
				continue
			}
			primary, standby = choice.SourceID, choice.Standby
		case <-ticker.C:
		}
		if primary == "" {
			for id := range connected {
				g.RemovePath(id)
				delete(connected, id)
			}
			lastPreferred = ""
			continue
		}
		// Keep the current active path until its replacement is completely ready.
		active := g.Snapshot().ActivePath
		for id := range connected {
			if id != primary && id != standby && id != active {
				g.RemovePath(id)
				delete(connected, id)
			}
		}
		for _, id := range []string{primary, standby} {
			if id == "" || connected[id] {
				continue
			}
			if len(connected) >= 2 {
				for old := range connected {
					if old != active {
						g.RemovePath(old)
						delete(connected, old)
						break
					}
				}
			}
			if len(connected) >= 2 {
				continue
			}
			path := known[id]
			bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
			err := g.AddPath(bounded, id, func(c context.Context) (net.Conn, error) {
				return SourceTransport(c, client, path, r.Config.RelayAddress)
			})
			cancel()
			if err == nil {
				connected[id] = true
			}
			if id == primary && connected[id] && primary != lastPreferred {
				if g.SetPreferred(primary) == nil {
					lastPreferred = primary
					active = primary
				}
			}
		}
		// Do not force an emergency-failed path back to primary on each poll.
		if connected[primary] && primary != lastPreferred {
			if g.SetPreferred(primary) == nil {
				lastPreferred = primary
			}
		}
		for id := range connected {
			if id != primary && id != standby && id != g.Snapshot().ActivePath {
				g.RemovePath(id)
				delete(connected, id)
			}
		}
	}
}

func serveTCP(
	ctx context.Context,
	g *continuity.Gateway,
	l net.Listener,
	r helper.ContinuityWorkerRequest,
	dns bool,
	slots chan struct{},
) {
	for {
		c, e := l.Accept()
		if e != nil {
			return
		}
		remote, e := netip.ParseAddrPort(c.RemoteAddr().String())
		if e != nil || !LANClient(r.Network, remote.Addr()) {
			_ = c.Close()
			continue
		}
		destination := c.LocalAddr().String()
		if dns {
			destination = net.JoinHostPort(r.Network.DNSResolver, "53")
		}
		select {
		case slots <- struct{}{}:
			go func() { defer func() { <-slots }(); _ = g.ServeTCP(ctx, c, destination) }()
		default:
			_ = c.Close()
		}
	}
}

func serveUDP(
	ctx context.Context,
	g *continuity.Gateway,
	client *helper.Client,
	u *net.UDPConn,
	r helper.ContinuityWorkerRequest,
	dns bool,
) {
	// A single reader owns the mapping table; delivery uses connected socket
	// writes, which are safe concurrently with expiry/close. The engine enforces
	// the session-wide mapping and memory quotas across all listeners.
	mappings := map[string]*udpMapping{}
	defer func() {
		for key, m := range mappings {
			g.CloseUDP(key)
			_ = m.conn.Close()
		}
	}()
	buf := make([]byte, 65535)
	oob := make([]byte, 256)
	for {
		_ = u.SetReadDeadline(time.Now().Add(time.Second))
		n, on, flags, remote, e := u.ReadMsgUDPAddrPort(buf, oob)
		now := time.Now()
		for key, m := range mappings {
			if now.Sub(m.last) >= 120*time.Second {
				g.CloseUDP(key)
				_ = m.conn.Close()
				delete(mappings, key)
			}
		}
		if e != nil {
			if ctx.Err() != nil {
				return
			}
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		if flags != 0 || !LANClient(r.Network, remote.Addr()) {
			continue
		}
		original, e := originalDestination(oob[:on])
		if e != nil {
			continue
		}
		_ = forwardUDP(ctx, g, client, mappings, r.Network, dns, remote, original, buf[:n], now)
	}
}

type udpForwarder interface {
	SendUDP(context.Context, string, string, []byte, func([]byte) error) error
	CloseUDP(string)
}

type udpReplyOpener interface {
	ContinuityUDPReply(context.Context, string, string) (net.Conn, error)
}

// forwardUDP preserves an established reply lease and relay socket when the
// bounded sender drops a datagram under pressure. A rejected new mapping is
// cleaned up so empty leases cannot crowd out established UDP sessions.
func forwardUDP(
	ctx context.Context,
	sender udpForwarder,
	opener udpReplyOpener,
	mappings map[string]*udpMapping,
	network model.Network,
	dns bool,
	remote, original netip.AddrPort,
	payload []byte,
	now time.Time,
) error {
	destination := original.String()
	if dns {
		destination = net.JoinHostPort(network.DNSResolver, "53")
	}
	key := remote.String() + "|" + original.String()
	m := mappings[key]
	created := m == nil
	if created {
		if len(mappings) >= continuity.DefaultLimits().MaxUDP {
			return continuity.ErrCapacity
		}
		bounded, cancel := context.WithTimeout(ctx, time.Second)
		reply, err := opener.ContinuityUDPReply(bounded, remote.String(), original.String())
		cancel()
		if err != nil {
			return err
		}
		m = &udpMapping{conn: reply}
		mappings[key] = m
	}
	m.last = now
	err := sender.SendUDP(ctx, key, destination, payload, func(reply []byte) error {
		_, err := m.conn.Write(reply)
		return err
	})
	if err != nil && (created || !errors.Is(err, continuity.ErrCapacity)) {
		// SendUDP can allocate a flow before discovering payload-buffer pressure;
		// CloseUDP also releases that empty flow when a new mapping was rejected.
		sender.CloseUDP(key)
		_ = m.conn.Close()
		delete(mappings, key)
	}
	return err
}

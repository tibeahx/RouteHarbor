package continuity

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

type Relay struct {
	mu         sync.Mutex
	tls        *tls.Config
	limits     Limits
	maxClients int
	dial       TargetDialFunc
	generation string
	sessions   map[string]*peer
	listeners  map[net.Listener]bool
	pending    map[net.Conn]bool
	closed     bool
	wg         sync.WaitGroup
	stop       chan struct{}
}

func NewRelay(c RelayConfig) (*Relay, error) {
	if !validTLS(c.TLSConfig, true) {
		return nil, errors.New("pinned mutually authenticated TLS 1.3 required")
	}
	l, err := c.Limits.normalized()
	if err != nil {
		return nil, err
	}
	if c.MaxClients == 0 {
		c.MaxClients = 16
	}
	if c.MaxClients < 1 || c.MaxClients > 256 {
		return nil, errors.New("invalid relay client limit")
	}
	if c.DialTarget == nil {
		c.DialTarget = dialPublicTarget
	}
	r := &Relay{
		tls:        c.TLSConfig.Clone(),
		limits:     l,
		maxClients: c.MaxClients,
		dial:       c.DialTarget,
		generation: randomID(),
		sessions:   make(map[string]*peer),
		listeners:  make(map[net.Listener]bool),
		pending:    make(map[net.Conn]bool),
		stop:       make(chan struct{}),
	}
	r.wg.Add(1)
	go r.reap()
	return r, nil
}

func (r *Relay) Serve(listener net.Listener) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return ErrClosed
	}
	r.listeners[listener] = true
	r.mu.Unlock()
	defer func() { r.mu.Lock(); delete(r.listeners, listener); r.mu.Unlock() }()
	for {
		conn, err := listener.Accept()
		if err != nil {
			r.mu.Lock()
			closed := r.closed
			r.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		r.mu.Lock()
		if r.closed || len(r.pending) >= r.maxClients*CarriersPerPath*2 {
			r.mu.Unlock()
			_ = conn.Close()
			continue
		}
		r.pending[conn] = true
		r.wg.Add(1)
		r.mu.Unlock()
		go r.accept(conn)
	}
}

func (r *Relay) accept(raw net.Conn) {
	start := time.Now()
	defer r.wg.Done()
	defer func() { r.mu.Lock(); delete(r.pending, raw); r.mu.Unlock() }()
	conn := tls.Server(raw, r.tls)
	attached := false
	defer func() {
		if !attached {
			_ = conn.Close()
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := conn.Handshake(); err != nil {
		return
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return
	}
	var h hello
	if err := readJSON(conn, &h); err != nil || h.Version != 1 {
		return
	}
	if h.Lane == -1 && h.Path == "probe" && h.Session == "" {
		if writeJSON(conn, welcome{Generation: r.generation}) != nil {
			return
		}
		f, err := readFrame(conn)
		if err != nil || f.kind != framePing || len(f.data) != chunkSize {
			return
		}
		_ = writeFrame(conn, frame{kind: framePong, data: f.data})
		return
	}
	id, err := hex.DecodeString(h.Session)
	if err != nil || len(id) != 16 || !pathName.MatchString(h.Path) || h.Lane < 0 ||
		h.Lane >= CarriersPerPath {
		return
	}
	if h.Generation != "" && h.Generation != r.generation {
		_ = writeJSON(conn, welcome{Error: "generation"})
		return
	}
	key := CertificateFingerprint(state.PeerCertificates[0]) + ":" + h.Session
	remoteLimits, err := h.Limits.normalized()
	if err != nil {
		_ = writeJSON(conn, welcome{Error: "limits"})
		return
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	p := r.sessions[key]
	if p == nil {
		if h.Generation != "" {
			r.mu.Unlock()
			_ = writeJSON(conn, welcome{Error: "generation"})
			return
		}
		if len(r.sessions) >= r.maxClients {
			r.mu.Unlock()
			_ = writeJSON(conn, welcome{Error: "capacity"})
			return
		}
		identitySessions := 0
		for existingKey := range r.sessions {
			if existingKey[:64] == key[:64] {
				identitySessions++
			}
		}
		if identitySessions >= 2 {
			r.mu.Unlock()
			_ = writeJSON(conn, welcome{Error: "capacity"})
			return
		}
		limits := r.limits
		if remoteLimits.FlowBytes < limits.FlowBytes {
			limits.FlowBytes = remoteLimits.FlowBytes
		}
		p = newPeer(limits, h.Session, r.generation, true, r.dial)
		r.sessions[key] = p
	}
	r.mu.Unlock()
	if err = writeJSON(
		conn,
		welcome{Generation: r.generation, FlowBytes: p.limits.FlowBytes},
	); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	if err = p.addCarrier(h.Path, h.Lane, conn, time.Since(start)); err != nil {
		return
	}
	attached = true
}

func (r *Relay) reap() {
	defer r.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.stop:
			return
		case now := <-ticker.C:
			r.mu.Lock()
			var expired []*peer
			for key, p := range r.sessions {
				p.mu.Lock()
				empty := p.active == "" && now.Sub(p.lastReady) >= p.limits.DisconnectedGrace
				p.mu.Unlock()
				if empty {
					delete(r.sessions, key)
					expired = append(expired, p)
				}
			}
			r.mu.Unlock()
			for _, p := range expired {
				_ = p.close()
			}
		}
	}
}

func (r *Relay) Close() error {
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		close(r.stop)
		for l := range r.listeners {
			_ = l.Close()
		}
		for c := range r.pending {
			_ = c.Close()
		}
	}
	sessions := make([]*peer, 0, len(r.sessions))
	for _, p := range r.sessions {
		sessions = append(sessions, p)
	}
	r.mu.Unlock()
	for _, p := range sessions {
		_ = p.close()
	}
	r.wg.Wait()
	return nil
}

func (r *Relay) Snapshots() []Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Snapshot, 0, len(r.sessions))
	for _, p := range r.sessions {
		out = append(out, p.snapshot())
	}
	return out
}

// Resolve first, validate every returned address, and then dial one numeric
// address. DNS rebinding cannot replace the checked destination during dialing.
func dialPublicTarget(ctx context.Context, network, destination string) (net.Conn, error) {
	if err := validDestination(destination); err != nil {
		return nil, err
	}
	host, port, _ := net.SplitHostPort(destination)
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		return nil, ErrDestination
	}
	local := make(map[netip.Addr]bool)
	if addresses, e := net.InterfaceAddrs(); e == nil {
		for _, a := range addresses {
			if prefix, e := netip.ParsePrefix(a.String()); e == nil {
				local[prefix.Addr().Unmap()] = true
			}
		}
	}
	for _, addr := range addrs {
		if !publicAddress(addr) || local[addr.Unmap()] {
			return nil, ErrDestination
		}
	}
	dialer := net.Dialer{}
	for _, addr := range addrs {
		conn, e := dialer.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
		if e == nil {
			return conn, nil
		}
	}
	return nil, errors.New("relay target connection failed")
}

var deniedPrefixes = []netip.Prefix{
	netip.MustParsePrefix(
		"0.0.0.0/8",
	),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix(
		"::/96",
	),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func publicAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range deniedPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

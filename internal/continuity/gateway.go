package continuity

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sync"
	"time"
)

var pathName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

type gatewayPath struct {
	cancel context.CancelFunc
	dial   DialFunc
}
type Gateway struct {
	p      *peer
	tls    *tls.Config
	mu     sync.Mutex
	paths  map[string]gatewayPath
	wg     sync.WaitGroup
	closed bool
	// Initial session creation is serialized, so a relay restart can never be
	// mistaken for a new empty session by concurrent standby reconnections.
	connectMu sync.Mutex
}

func NewGateway(c GatewayConfig) (*Gateway, error) {
	if !validTLS(c.TLSConfig, false) {
		return nil, errors.New("pinned mutual TLS 1.3 configuration required")
	}
	l, err := c.Limits.normalized()
	if err != nil {
		return nil, err
	}
	return &Gateway{
		p:     newPeer(l, randomID(), "", false, nil),
		tls:   c.TLSConfig.Clone(),
		paths: make(map[string]gatewayPath),
	}, nil
}

// AddPath establishes all six connections before returning. Failed carriers are
// subsequently reconnected in the background. The supplied dialer must bind the
// connection to the named source and the configured relay; it must not fall back
// to an unselected direct route.
func (g *Gateway) AddPath(ctx context.Context, name string, dial DialFunc) error {
	if !pathName.MatchString(name) || dial == nil {
		return errors.New("invalid continuity path")
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return ErrClosed
	}
	if _, ok := g.paths[name]; ok {
		g.mu.Unlock()
		return errors.New("continuity path already exists")
	}
	if len(g.paths) >= 2 {
		g.mu.Unlock()
		return ErrCapacity
	}
	pctx, cancel := context.WithCancel(g.p.ctx)
	g.paths[name] = gatewayPath{cancel, dial}
	g.mu.Unlock()
	connectCtx, connectCancel := context.WithCancel(ctx)
	stopCancel := context.AfterFunc(pctx, connectCancel)
	defer stopCancel()
	defer connectCancel()
	for lane := 0; lane < CarriersPerPath; lane++ {
		if err := g.connect(connectCtx, name, lane, dial); err != nil {
			g.RemovePath(name)
			return err
		}
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		g.RemovePath(name)
		return ErrClosed
	}
	g.wg.Add(1)
	g.mu.Unlock()
	go g.maintain(pctx, name, dial)
	return nil
}

func (g *Gateway) connect(ctx context.Context, name string, lane int, dial DialFunc) error {
	g.connectMu.Lock()
	defer g.connectMu.Unlock()
	if err := g.TerminalError(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := time.Now()
	raw, err := dial(ctx)
	if err != nil {
		return errors.New("relay path connection failed")
	}
	t := tls.Client(raw, g.tls)
	success := false
	defer func() {
		if !success {
			_ = t.Close()
		}
	}()
	if err = t.HandshakeContext(ctx); err != nil {
		return errors.New("relay identity or TLS handshake failed")
	}
	g.p.mu.Lock()
	h := hello{
		Version:    1,
		Session:    g.p.session,
		Generation: g.p.generation,
		Path:       name,
		Lane:       lane,
		Limits:     g.p.limits,
	}
	g.p.mu.Unlock()
	_ = t.SetDeadline(time.Now().Add(5 * time.Second))
	if err = writeJSON(t, h); err != nil {
		return errors.New("relay session handshake failed")
	}
	var w welcome
	if err = readJSON(t, &w); err != nil {
		return errors.New("relay session handshake failed")
	}
	if w.Error != "" {
		if w.Error == "generation" {
			g.p.mu.Lock()
			g.p.terminalErr = ErrGeneration
			for _, f := range g.p.flows {
				g.p.closeFlow(f, ErrGeneration, false)
			}
			for _, carriers := range g.p.paths {
				for _, carrier := range carriers {
					if carrier != nil {
						g.p.closeCarrier(carrier)
					}
				}
			}
			g.p.selectPath(time.Now())
			g.p.mu.Unlock()
			return ErrGeneration
		}
		return errors.New("relay rejected session")
	}
	if len(w.Generation) != 32 {
		return errors.New("invalid relay generation")
	}
	g.p.mu.Lock()
	if w.FlowBytes < 16<<10 || w.FlowBytes > g.p.limits.FlowBytes ||
		g.p.generation != "" && w.FlowBytes != g.p.limits.FlowBytes {
		g.p.mu.Unlock()
		return errors.New("invalid relay flow window")
	}
	if g.p.generation != "" && g.p.generation != w.Generation {
		g.p.mu.Unlock()
		return ErrGeneration
	}
	g.p.generation = w.Generation
	g.p.limits.FlowBytes = w.FlowBytes
	g.p.mu.Unlock()
	_ = t.SetDeadline(time.Time{})
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, exists := g.paths[name]; g.closed || !exists || ctx.Err() != nil {
		return ErrClosed
	}
	if err = g.p.addCarrier(name, lane, t, time.Since(start)); err != nil {
		return err
	}
	success = true
	return nil
}

func (g *Gateway) maintain(ctx context.Context, name string, dial DialFunc) {
	defer g.wg.Done()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for lane := 0; lane < CarriersPerPath; lane++ {
				g.p.mu.Lock()
				cs, exists := g.p.paths[name]
				ready := exists && cs[lane] != nil && !cs[lane].closed
				g.p.mu.Unlock()
				if !ready {
					if err := g.connect(ctx, name, lane, dial); errors.Is(err, ErrGeneration) {
						return
					}
				}
			}
		}
	}
}

func (g *Gateway) RemovePath(name string) {
	g.mu.Lock()
	path, ok := g.paths[name]
	if ok {
		path.cancel()
		delete(g.paths, name)
	}
	g.mu.Unlock()
	g.p.mu.Lock()
	if cs, exists := g.p.paths[name]; exists {
		for _, c := range cs {
			if c != nil {
				g.p.closeCarrier(c)
			}
		}
		delete(g.p.paths, name)
	}
	g.p.selectPath(time.Now())
	g.p.mu.Unlock()
}

func (g *Gateway) SetPreferred(name string) error {
	g.p.mu.Lock()
	defer g.p.mu.Unlock()
	if g.p.closed {
		return ErrClosed
	}
	if g.p.terminalErr != nil {
		return g.p.terminalErr
	}
	if !g.p.ready(name) {
		return ErrNoPath
	}
	g.p.preferred = name
	if g.p.active != name {
		g.p.active = name
		g.p.switches++
		g.p.switchedAt = time.Now()
	}
	return nil
}

// ServeTCP takes ownership of an already accepted transparent TCP connection.
// Its target-side socket belongs to the relay session, never to a carrier.
func (g *Gateway) ServeTCP(ctx context.Context, client net.Conn, destination string) error {
	if client == nil {
		return errors.New("missing TCP connection")
	}
	if err := validDestination(destination); err != nil {
		_ = client.Close()
		return err
	}
	g.p.mu.Lock()
	if g.p.closed {
		g.p.mu.Unlock()
		_ = client.Close()
		return ErrClosed
	}
	if g.p.terminalErr != nil {
		err := g.p.terminalErr
		g.p.mu.Unlock()
		_ = client.Close()
		return err
	}
	g.p.nextID++
	f, err := g.p.newFlow(g.p.nextID, destination, false)
	if err != nil {
		g.p.mu.Unlock()
		_ = client.Close()
		return err
	}
	f.conn = client
	g.p.startFlow(f)
	g.p.mu.Unlock()
	select {
	case <-ctx.Done():
		g.p.mu.Lock()
		g.p.closeFlow(f, ctx.Err(), true)
		g.p.mu.Unlock()
	case <-f.done:
	}
	g.p.mu.Lock()
	err = f.err
	g.p.mu.Unlock()
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// SendUDP retains a stable mapping for key and destination until CloseUDP or the
// idle timeout. deliver is serialized for that mapping and must return promptly;
// it must not call Close synchronously. Payload bytes are copied into bounded RAM.
func (g *Gateway) SendUDP(
	ctx context.Context,
	key, destination string,
	payload []byte,
	deliver func([]byte) error,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if key == "" || len(key) > 256 || deliver == nil || len(payload) > maxPayload {
		return errors.New("invalid UDP mapping")
	}
	if err := validDestination(destination); err != nil {
		return err
	}
	g.p.mu.Lock()
	defer g.p.mu.Unlock()
	if g.p.closed {
		return ErrClosed
	}
	if g.p.terminalErr != nil {
		return g.p.terminalErr
	}
	f := g.p.flows[g.p.keys[key]]
	if f == nil {
		g.p.nextID++
		var err error
		f, err = g.p.newFlow(g.p.nextID, destination, true)
		if err != nil {
			return err
		}
		f.deliver = deliver
		g.p.keys[key] = f.id
		g.p.startFlow(f)
	} else if f.destination != destination {
		return errors.New("UDP mapping destination changed")
	}
	cost := int64(len(payload)) + segmentOverhead
	if !g.p.reserve(true, true, cost) {
		g.p.dropped++
		return ErrCapacity
	}
	f.next++
	now := time.Now()
	f.lastActive = now
	s := &segment{
		f: frame{
			kind:   frameUDP,
			flow:   f.id,
			offset: f.next,
			value:  uint64(now.UnixNano()),
			data:   append([]byte(nil), payload...),
		},
		cost:    cost,
		owned:   true,
		sending: true,
		udp:     true,
	}
	f.pending = append(f.pending, s)
	f.sendBytes += cost
	return nil
}

func (g *Gateway) CloseUDP(key string) {
	g.p.mu.Lock()
	defer g.p.mu.Unlock()
	if f := g.p.flows[g.p.keys[key]]; f != nil {
		g.p.closeFlow(f, nil, true)
	}
}
func (g *Gateway) Snapshot() Snapshot { return g.p.snapshot() }

// TerminalError identifies a lost relay generation. A supervisor may create a
// fresh Gateway for new LAN connections; the old sockets are never replayed.
func (g *Gateway) TerminalError() error { g.p.mu.Lock(); defer g.p.mu.Unlock(); return g.p.terminalErr }

func (g *Gateway) Close() error {
	g.mu.Lock()
	if !g.closed {
		g.closed = true
		for _, path := range g.paths {
			path.cancel()
		}
	}
	g.mu.Unlock()
	err := g.p.close()
	g.wg.Wait()
	return err
}

func validDestination(destination string) error {
	host, port, err := net.SplitHostPort(destination)
	if err != nil || host == "" || port == "" || len(destination) > 300 {
		return ErrDestination
	}
	var n int
	if _, err = fmt.Sscanf(
		port,
		"%d",
		&n,
	); err != nil || n < 1 || n > 65535 ||
		fmt.Sprint(n) != port {
		return ErrDestination
	}
	return nil
}

type ProbeResult struct {
	RTT      time.Duration
	Bytes    int64
	Duration time.Duration
}

// ProbeRelay tests the authenticated carrier, without creating a logical session.
// The short echo provides a reachability sample, not throughput qualification.
func ProbeRelay(ctx context.Context, tlsConfig *tls.Config, dial DialFunc) (ProbeResult, error) {
	var result ProbeResult
	if !validTLS(tlsConfig, false) || dial == nil {
		return result, errors.New("pinned TLS relay probe required")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := time.Now()
	raw, err := dial(ctx)
	if err != nil {
		return result, errors.New("relay probe connection failed")
	}
	conn := tls.Client(raw, tlsConfig)
	defer func() { _ = conn.Close() }()
	if err = conn.HandshakeContext(ctx); err != nil {
		return result, errors.New("relay probe identity failed")
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err = writeJSON(conn, hello{Version: 1, Path: "probe", Lane: -1}); err != nil {
		return result, err
	}
	var w welcome
	if err = readJSON(conn, &w); err != nil || w.Error != "" {
		return result, errors.New("relay probe rejected")
	}
	result.RTT = time.Since(start)
	start = time.Now()
	payload := make([]byte, chunkSize)
	if err = writeFrame(conn, frame{kind: framePing, data: payload}); err != nil {
		return result, err
	}
	f, err := readFrame(conn)
	if err != nil || f.kind != framePong || len(f.data) != len(payload) {
		return result, errors.New("relay probe echo failed")
	}
	result.Duration = time.Since(start)
	result.Bytes = int64(len(payload)) * 2
	return result, nil
}

package continuityrun

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tibeahx/OpenRHP/internal/continuity"
	"github.com/tibeahx/OpenRHP/internal/dispatch"
	"github.com/tibeahx/OpenRHP/internal/platform"
)

var bridgeAssociation atomic.Uint64

// serveBridge exposes only an inherited loopback socket. Authentication is
// mandatory even on loopback; configuration and credentials never enter status.
func serveBridge(
	ctx context.Context,
	g *continuity.Gateway,
	l net.Listener,
	b dispatch.Bridge,
	slots chan struct{},
) {
	for {
		c, e := l.Accept()
		if e != nil {
			return
		}
		remote, e := netip.ParseAddrPort(c.RemoteAddr().String())
		if e != nil || !remote.Addr().IsLoopback() {
			_ = c.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		go func() {
			defer func() { <-slots }()
			defer func() { _ = c.Close() }()
			closeOnCancel := context.AfterFunc(ctx, func() { _ = c.Close() })
			defer closeOnCancel()
			handleBridge(ctx, g, c, b)
		}()
	}
}

func handleBridge(ctx context.Context, g *continuity.Gateway, c net.Conn, b dispatch.Bridge) {
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	var h [2]byte
	if _, e := io.ReadFull(c, h[:]); e != nil || h[0] != 5 || h[1] == 0 {
		return
	}
	methods := make([]byte, int(h[1]))
	if _, e := io.ReadFull(c, methods); e != nil {
		return
	}
	auth := false
	for _, method := range methods {
		auth = auth || method == 2
	}
	if !auth {
		_, _ = c.Write([]byte{5, 255})
		return
	}
	if _, e := c.Write([]byte{5, 2}); e != nil {
		return
	}
	if _, e := io.ReadFull(c, h[:]); e != nil || h[0] != 1 || h[1] == 0 {
		return
	}
	user := make([]byte, int(h[1]))
	if _, e := io.ReadFull(c, user); e != nil {
		return
	}
	var size [1]byte
	if _, e := io.ReadFull(c, size[:]); e != nil || size[0] == 0 {
		return
	}
	password := make([]byte, int(size[0]))
	if _, e := io.ReadFull(c, password); e != nil {
		return
	}
	valid := subtle.ConstantTimeCompare(
		user,
		[]byte(b.Username),
	) & subtle.ConstantTimeCompare(
		password,
		[]byte(b.Password),
	)
	if valid != 1 {
		_, _ = c.Write([]byte{1, 1})
		return
	}
	if _, e := c.Write([]byte{1, 0}); e != nil {
		return
	}
	var request [4]byte
	if _, e := io.ReadFull(c, request[:]); e != nil || request[0] != 5 || request[2] != 0 {
		return
	}
	address, e := readBridgeAddress(c, request[3])
	if e != nil {
		_ = writeBridgeReply(c, 8, netip.AddrPort{})
		return
	}
	switch request[1] {
	case 1:
		if address.Port() == 0 || !platform.PublicAddress(address.Addr()) {
			_ = writeBridgeReply(c, 2, netip.AddrPort{})
			return
		}
		flowCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		ready := &bridgeTCPConn{Conn: c}
		timer := time.AfterFunc(10*time.Second, func() { cancel(); _ = c.Close() })
		defer timer.Stop()
		ready.open = func() error {
			timer.Stop()
			if e := writeBridgeReply(c, 0, netip.MustParseAddrPort("127.0.0.1:0")); e != nil {
				return e
			}
			return c.SetDeadline(time.Time{})
		}
		// Gateway reads/writes the endpoint only after relay frameOpened. This
		// wrapper therefore acknowledges CONNECT after the real remote open.
		_ = g.ServeTCP(flowCtx, ready, address.String())
	case 3:
		if !address.Addr().IsUnspecified() && !address.Addr().IsLoopback() {
			_ = writeBridgeReply(c, 2, netip.AddrPort{})
			return
		}
		serveBridgeUDP(ctx, g, c, address)
	default:
		_ = writeBridgeReply(c, 7, netip.AddrPort{})
	}
}

type bridgeTCPConn struct {
	net.Conn
	once sync.Once
	open func() error
	err  error
}

func (c *bridgeTCPConn) opened() error { c.once.Do(func() { c.err = c.open() }); return c.err }
func (c *bridgeTCPConn) Read(p []byte) (int, error) {
	if e := c.opened(); e != nil {
		return 0, e
	}
	return c.Conn.Read(p)
}

func (c *bridgeTCPConn) Write(p []byte) (int, error) {
	if e := c.opened(); e != nil {
		return 0, e
	}
	return c.Conn.Write(p)
}

func (c *bridgeTCPConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return nil
}

func readBridgeAddress(r io.Reader, typ byte) (netip.AddrPort, error) {
	n := 4
	if typ == 4 {
		n = 16
	} else if typ != 1 {
		return netip.AddrPort{}, errors.New("bridge requires numeric destination")
	}
	raw := make([]byte, n+2)
	if _, e := io.ReadFull(r, raw); e != nil {
		return netip.AddrPort{}, e
	}
	ip, ok := netip.AddrFromSlice(raw[:n])
	if !ok || ip.Is4In6() {
		return netip.AddrPort{}, errors.New("invalid bridge address")
	}
	return netip.AddrPortFrom(ip, binary.BigEndian.Uint16(raw[n:])), nil
}

func bridgeAddress(a netip.AddrPort) []byte {
	out := []byte{}
	ip := a.Addr()
	if !ip.IsValid() {
		ip = netip.IPv4Unspecified()
	}
	if ip.Is4() {
		v := ip.As4()
		out = append(out, 1)
		out = append(out, v[:]...)
	} else {
		v := ip.As16()
		out = append(out, 4)
		out = append(out, v[:]...)
	}
	return append(out, byte(a.Port()>>8), byte(a.Port()))
}

func writeBridgeReply(c net.Conn, status byte, address netip.AddrPort) error {
	_, e := c.Write(append([]byte{5, status, 0}, bridgeAddress(address)...))
	return e
}

// Each authenticated TCP association owns one private UDP socket. Datagram
// source is pinned on its first packet (or constrained by the client's requested
// port), fragments and domains are rejected, and all relay mappings expire.
func serveBridgeUDP(
	ctx context.Context,
	g *continuity.Gateway,
	c net.Conn,
	requested netip.AddrPort,
) {
	u, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		_ = writeBridgeReply(c, 1, netip.AddrPort{})
		return
	}
	defer func() { _ = u.Close() }()
	address, e := netip.ParseAddrPort(u.LocalAddr().String())
	if e != nil {
		return
	}
	if e = writeBridgeReply(c, 0, address); e != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = u.Close(); _ = c.Close() })
	defer stop()
	go func() { var b [1]byte; _, _ = c.Read(b[:]); cancel() }()
	id := strconv.FormatUint(bridgeAssociation.Add(1), 10)
	mappings := map[string]time.Time{}
	defer func() {
		for key := range mappings {
			g.CloseUDP(key)
		}
	}()
	var client netip.AddrPort
	buffer := make([]byte, 65535)
	for {
		_ = u.SetReadDeadline(time.Now().Add(time.Second))
		n, remote, e := u.ReadFromUDPAddrPort(buffer)
		now := time.Now()
		for key, last := range mappings {
			if now.Sub(last) >= 120*time.Second {
				g.CloseUDP(key)
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
		if !remote.Addr().IsLoopback() ||
			requested.Port() != 0 && remote.Port() != requested.Port() ||
			client.IsValid() && remote != client ||
			n < 4 ||
			buffer[0] != 0 ||
			buffer[1] != 0 ||
			buffer[2] != 0 {
			continue
		}
		reader := &bridgeSliceReader{data: buffer[4:n]}
		destination, e := readBridgeAddress(reader, buffer[3])
		if e != nil || destination.Port() == 0 || !platform.PublicAddress(destination.Addr()) {
			continue
		}
		if !client.IsValid() {
			client = remote
		}
		key := "socks:" + id + ":" + destination.String()
		_, exists := mappings[key]
		if !exists && len(mappings) >= continuity.DefaultLimits().MaxUDP {
			continue
		}
		payload := reader.data
		replyClient := client
		replyDestination := destination
		e = g.SendUDP(ctx, key, destination.String(), payload, func(reply []byte) error {
			out := append([]byte{0, 0, 0}, bridgeAddress(replyDestination)...)
			out = append(out, reply...)
			_ = u.SetWriteDeadline(time.Now().Add(time.Second))
			_, err := u.WriteToUDPAddrPort(out, replyClient)
			return err
		})
		if e == nil {
			mappings[key] = now
		} else if !exists || !errors.Is(e, continuity.ErrCapacity) {
			g.CloseUDP(key)
			delete(mappings, key)
		}
	}
}

type bridgeSliceReader struct{ data []byte }

func (r *bridgeSliceReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

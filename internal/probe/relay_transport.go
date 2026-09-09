package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"time"
)

// OpenRelayTransport is deliberately separate from probe requests. The caller
// supplies the configured relay and a concrete source proxy, never a URL from a
// target being probed. Native paths use the helper's fixed relay capability.
func OpenRelayTransport(ctx context.Context, proxy *url.URL, relay string) (net.Conn, error) {
	a, e := netip.ParseAddrPort(relay)
	if e != nil || a.Port() == 0 || !PublicIP(a.Addr()) || proxy == nil {
		return nil, errors.New("invalid relay transport")
	}
	if proxy.Scheme != "socks5" && proxy.Scheme != "http" {
		return nil, errors.New("unsupported relay transport")
	}
	var d net.Dialer
	c, e := d.DialContext(ctx, "tcp", proxy.Host)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			_ = c.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	if deadline, yes := ctx.Deadline(); yes {
		_ = c.SetDeadline(deadline)
	} else {
		_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	}
	if proxy.Scheme == "socks5" {
		e = socksConnect(c, proxy, a.Addr(), int(a.Port()))
	} else {
		e = httpConnect(c, proxy, net.JoinHostPort(a.Addr().String(), strconv.Itoa(int(a.Port()))))
	}
	if e != nil {
		return nil, e
	}
	_ = c.SetDeadline(time.Time{})
	ok = true
	return c, nil
}

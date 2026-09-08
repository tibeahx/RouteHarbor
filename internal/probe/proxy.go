package probe

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

func (r *Runner) proxyDial(ctx context.Context, proxy *url.URL, address string) (net.Conn, error) {
	host, portText, e := net.SplitHostPort(address)
	if e != nil {
		return nil, errors.New("invalid probe destination")
	}
	ip, e := netip.ParseAddr(host)
	if e != nil || !PublicIP(ip) {
		return nil, errors.New("proxy destination must be a pinned public IP")
	}
	port, e := strconv.Atoi(portText)
	if e != nil || (port != 443 && port != 53) {
		return nil, errors.New("invalid probe port")
	}
	conn, e := r.dial(ctx, proxy.Host)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	if deadline, yes := ctx.Deadline(); yes {
		_ = conn.SetDeadline(deadline)
	}
	switch proxy.Scheme {
	case "socks5":
		e = socksConnect(conn, proxy, ip, port)
	case "http":
		e = httpConnect(conn, proxy, address)
	default:
		e = errors.New("unsupported proxy type")
	}
	if e != nil {
		return nil, e
	}
	ok = true
	return conn, nil
}

func socksConnect(conn net.Conn, proxy *url.URL, ip netip.Addr, port int) error {
	method := byte(0)
	if proxy.User != nil {
		method = 2
	}
	if _, e := conn.Write([]byte{5, 1, method}); e != nil {
		return e
	}
	var reply [2]byte
	if _, e := io.ReadFull(conn, reply[:]); e != nil {
		return e
	}
	if reply[0] != 5 || reply[1] != method {
		return errors.New("SOCKS authentication method rejected")
	}
	if method == 2 {
		user := proxy.User.Username()
		pass, _ := proxy.User.Password()
		if len(user) > 255 || len(pass) > 255 {
			return errors.New("SOCKS credentials exceed limits")
		}
		payload := []byte{1, byte(len(user))}
		payload = append(payload, []byte(user)...)
		payload = append(payload, byte(len(pass)))
		payload = append(payload, []byte(pass)...)
		if _, e := conn.Write(payload); e != nil {
			return e
		}
		if _, e := io.ReadFull(conn, reply[:]); e != nil {
			return e
		}
		if reply != [2]byte{1, 0} {
			return errors.New("SOCKS authentication failed")
		}
	}
	payload := []byte{5, 1, 0}
	ip = ip.Unmap()
	if ip.Is4() {
		payload = append(payload, 1)
		v := ip.As4()
		payload = append(payload, v[:]...)
	} else {
		payload = append(payload, 4)
		v := ip.As16()
		payload = append(payload, v[:]...)
	}
	payload = binary.BigEndian.AppendUint16(payload, uint16(port))
	if _, e := conn.Write(payload); e != nil {
		return e
	}
	var h [4]byte
	if _, e := io.ReadFull(conn, h[:]); e != nil {
		return e
	}
	if h[0] != 5 || h[1] != 0 || h[2] != 0 {
		return errors.New("SOCKS connection refused")
	}
	n := 0
	switch h[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		var b [1]byte
		if _, e := io.ReadFull(conn, b[:]); e != nil {
			return e
		}
		n = int(b[0])
	default:
		return errors.New("invalid SOCKS response")
	}
	_, e := io.CopyN(io.Discard, conn, int64(n+2))
	return e
}

// Reading CONNECT headers one byte at a time avoids consuming any bytes from the TLS tunnel.
func httpConnect(conn net.Conn, proxy *url.URL, address string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", address, address)
	if proxy.User != nil {
		password, _ := proxy.User.Password()
		token := base64.StdEncoding.EncodeToString([]byte(proxy.User.Username() + ":" + password))
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", token)
	}
	b.WriteString("\r\n")
	if _, e := io.WriteString(conn, b.String()); e != nil {
		return e
	}
	header := make([]byte, 0, 512)
	for len(header) < 8192 {
		var c [1]byte
		if _, e := io.ReadFull(conn, c[:]); e != nil {
			return e
		}
		header = append(header, c[0])
		n := len(header)
		if n >= 4 && string(header[n-4:]) == "\r\n\r\n" {
			line, _, _ := bufio.NewReader(strings.NewReader(string(header))).ReadLine()
			fields := strings.Fields(string(line))
			if len(fields) < 2 || (fields[0] != "HTTP/1.1" && fields[0] != "HTTP/1.0") ||
				fields[1] != "200" {
				return errors.New("HTTP CONNECT refused")
			}
			return nil
		}
	}
	return errors.New("HTTP CONNECT response headers exceed limit")
}

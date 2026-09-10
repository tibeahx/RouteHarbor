package routing

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	DNSHealthName = "openrhp-health.invalid"
	MaxDNSMessage = 65535
)

// DNSProxy is an unprivileged DNS front end. Its upstreams must be explicit
// numeric loopback endpoints; ExternalDNS must be the dispatcher's FakeIP DNS,
// and LocalDNS the original dnsmasq listener. Observe receives only external
// canonical names, in memory. It must enqueue without blocking or logging names.
type DNSProxy struct {
	LocalDNS       string
	ExternalDNS    string
	AllowedClients []netip.Prefix
	LocalSuffixes  []string
	Observe        func(string)
	Timeout        time.Duration
	MaxConcurrent  int
	// Query is an in-process test injection, never accepted over a public API.
	Query func(context.Context, string, string, []byte) ([]byte, error)
}
type dnsQuestion struct {
	name  string
	typ   uint16
	class uint16
	end   int
}

func (p *DNSProxy) Validate() error {
	for _, s := range []string{p.LocalDNS, p.ExternalDNS} {
		a, e := netip.ParseAddrPort(s)
		if e != nil || !a.Addr().IsLoopback() || a.Port() == 0 || a.Addr().Zone() != "" {
			return errors.New("DNS upstream must be an explicit loopback endpoint")
		}
	}
	if p.LocalDNS == p.ExternalDNS {
		return errors.New("local and FakeIP DNS upstreams must differ")
	}
	if p.MaxConcurrent < 0 || p.MaxConcurrent > 256 || p.Timeout < 0 || p.Timeout > 30*time.Second {
		return errors.New("invalid DNS limits")
	}
	for _, prefix := range p.AllowedClients {
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Bits() == 0 {
			return errors.New("invalid DNS client prefix")
		}
	}
	for _, s := range p.LocalSuffixes {
		if _, e := CanonicalDomain(s); e != nil {
			return e
		}
	}
	return nil
}

func (p *DNSProxy) timeout() time.Duration {
	if p.Timeout == 0 {
		return 5 * time.Second
	}
	return p.Timeout
}

func (p *DNSProxy) local(q dnsQuestion) bool {
	if q.typ == 12 || LocalDomain(q.name) {
		return true
	}
	for _, suffix := range p.LocalSuffixes {
		s, _ := CanonicalDomain(suffix)
		if q.name == s || strings.HasSuffix(q.name, "."+s) {
			return true
		}
	}
	return false
}

func parseDNSQuestion(message []byte, response bool) (dnsQuestion, error) {
	var q dnsQuestion
	if len(message) < 12 || len(message) > MaxDNSMessage || message[2]&0x78 != 0 ||
		(message[2]&0x80 != 0) != response ||
		binary.BigEndian.Uint16(message[4:6]) != 1 {
		return q, errors.New("invalid DNS message")
	}
	name, next, e := dnsName(message, 12)
	if e != nil || next+4 > len(message) {
		return q, errors.New("invalid DNS question")
	}
	q = dnsQuestion{
		name,
		binary.BigEndian.Uint16(message[next:]),
		binary.BigEndian.Uint16(message[next+2:]),
		next + 4,
	}
	if q.class != 1 {
		return q, errors.New("unsupported DNS class")
	}
	return q, nil
}

func dnsName(message []byte, offset int) (string, int, error) {
	var labels []string
	end := -1
	total := 0
	visits := map[int]bool{}
	for hops := 0; hops < 128; hops++ {
		if offset >= len(message) || visits[offset] {
			return "", 0, errors.New("invalid DNS name")
		}
		visits[offset] = true
		n := int(message[offset])
		offset++
		if n == 0 {
			if end < 0 {
				end = offset
			}
			return strings.ToLower(strings.Join(labels, ".")), end, nil
		}
		if n&0xc0 == 0xc0 {
			if offset >= len(message) {
				break
			}
			ptr := (n&0x3f)<<8 | int(message[offset])
			if end < 0 {
				end = offset + 1
			}
			offset = ptr
			continue
		}
		if n > 63 || offset+n > len(message) {
			break
		}
		total += n + 1
		if total > 254 {
			break
		}
		label := message[offset : offset+n]
		for _, c := range label {
			if c < 33 || c > 126 || c == '.' || c == '\\' {
				return "", 0, errors.New("invalid DNS label")
			}
		}
		labels = append(labels, string(label))
		offset += n
	}
	return "", 0, errors.New("invalid DNS name")
}

func dnsEmpty(request []byte, q dnsQuestion, rcode byte) []byte {
	// Re-encode an uncompressed question, so a question compression pointer cannot
	// refer into an additional record removed from this synthetic response.
	out := make([]byte, 12)
	copy(out[:2], request[:2])
	out[2] = 0x80 | (request[2] & 1)
	out[3] = 0x80 | rcode
	binary.BigEndian.PutUint16(out[4:6], 1)
	if q.name != "" {
		for _, label := range strings.Split(q.name, ".") {
			out = append(out, byte(len(label)))
			out = append(out, label...)
		}
	}
	out = append(out, 0, byte(q.typ>>8), byte(q.typ), 0, 1)
	return out
}

func (p *DNSProxy) Exchange(ctx context.Context, network string, request []byte) ([]byte, error) {
	if e := p.Validate(); e != nil {
		return nil, e
	}
	if network != "udp" && network != "tcp" {
		return nil, errors.New("invalid DNS transport")
	}
	q, e := parseDNSQuestion(request, false)
	if e != nil {
		return nil, e
	}
	if binary.BigEndian.Uint16(request[6:8]) != 0 || binary.BigEndian.Uint16(request[8:10]) != 0 {
		return nil, errors.New("DNS request contains answer or authority records")
	}
	local := p.local(q)
	if !local && (q.typ == 64 || q.typ == 65) {
		return dnsEmpty(request, q, 0), nil
	}
	endpoint := p.ExternalDNS
	if local {
		endpoint = p.LocalDNS
	} else if p.Observe != nil && q.name != DNSHealthName {
		if name, e := CanonicalDomain(q.name); e == nil && !LocalDomain(name) {
			p.Observe(name)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	query := p.Query
	if query == nil {
		query = exchangeDNS
	}
	response, e := query(ctx, network, endpoint, request)
	if e != nil {
		return nil, errors.New("DNS upstream unavailable")
	}
	got, e := parseDNSQuestion(response, true)
	if e != nil || response[0] != request[0] || response[1] != request[1] || got.name != q.name ||
		got.typ != q.typ ||
		got.class != q.class {
		return nil, errors.New("DNS upstream returned mismatched response")
	}
	// Synthetic DNS cannot assert validation of the original public DNSSEC chain.
	if !local {
		response = append([]byte{}, response...)
		response[3] &= ^byte(0x20)
	}
	return response, nil
}

// ValidDNSHealthResponse requires a real answer from the local FakeIP engine.
// An open socket, a frontend-only reply, SERVFAIL or an address from another
// staged pool cannot attest that this classifier's DNS is serving requests.
func ValidDNSHealthResponse(request, response []byte, pool netip.Prefix) bool {
	want, e := parseDNSQuestion(request, false)
	if e != nil || want.name != DNSHealthName || want.typ != 1 || !pool.IsValid() {
		return false
	}
	got, e := parseDNSQuestion(response, true)
	if e != nil || response[0] != request[0] || response[1] != request[1] ||
		got.name != want.name || got.typ != 1 || response[2]&2 != 0 || response[3]&15 != 0 ||
		binary.BigEndian.Uint16(
			response[6:8],
		) != 1 || binary.BigEndian.Uint16(response[8:10]) != 0 ||
		binary.BigEndian.Uint16(response[10:12]) != 0 {
		return false
	}
	name, offset, e := dnsName(response, got.end)
	if e != nil || name != DNSHealthName || offset+14 != len(response) {
		return false
	}
	rr := response[offset:]
	if binary.BigEndian.Uint16(rr[:2]) != 1 || binary.BigEndian.Uint16(rr[2:4]) != 1 ||
		binary.BigEndian.Uint16(rr[8:10]) != 4 {
		return false
	}
	return pool.Contains(netip.AddrFrom4([4]byte(rr[10:14])))
}

func exchangeDNS(ctx context.Context, network, endpoint string, request []byte) ([]byte, error) {
	d := net.Dialer{}
	conn, e := d.DialContext(ctx, network, endpoint)
	if e != nil {
		return nil, e
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if network == "tcp" {
		frame := make([]byte, 2+len(request))
		binary.BigEndian.PutUint16(frame, uint16(len(request)))
		copy(frame[2:], request)
		if _, e = conn.Write(frame); e != nil {
			return nil, e
		}
		var header [2]byte
		if _, e = io.ReadFull(conn, header[:]); e != nil {
			return nil, e
		}
		n := int(binary.BigEndian.Uint16(header[:]))
		if n < 12 {
			return nil, errors.New("invalid DNS frame")
		}
		response := make([]byte, n)
		_, e = io.ReadFull(conn, response)
		return response, e
	}
	if _, e = conn.Write(request); e != nil {
		return nil, e
	}
	response := make([]byte, MaxDNSMessage)
	n, e := conn.Read(response)
	if e != nil {
		return nil, e
	}
	return response[:n], nil
}

func (p *DNSProxy) allowed(address net.Addr) bool {
	host, _, e := net.SplitHostPort(address.String())
	if e != nil {
		return false
	}
	ip, e := netip.ParseAddr(host)
	if e != nil {
		return false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() {
		return true
	}
	for _, prefix := range p.AllowedClients {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// Serve owns both sockets and closes them on cancellation or listener failure.
// UDP requests and TCP connections share a hard concurrency bound. Client names
// and packets are neither logged nor persisted; excess work is dropped.
func (p *DNSProxy) Serve(ctx context.Context, packet net.PacketConn, listener net.Listener) error {
	if e := p.Validate(); e != nil {
		return e
	}
	if packet == nil || listener == nil {
		return errors.New("DNS requires UDP and TCP listeners")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() { _ = packet.Close() }()
	defer func() { _ = listener.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = packet.Close(); _ = listener.Close() })
	defer stop()
	limit := p.MaxConcurrent
	if limit == 0 {
		limit = 64
	}
	slots := make(chan struct{}, limit)
	var workers sync.WaitGroup
	defer workers.Wait()
	errorsCh := make(chan error, 2)
	go func() {
		for {
			buffer := make([]byte, 4097)
			n, client, e := packet.ReadFrom(buffer)
			if e != nil {
				errorsCh <- e
				return
			}
			if n > 4096 || !p.allowed(client) {
				continue
			}
			select {
			case slots <- struct{}{}:
			default:
				continue
			}
			request := buffer[:n]
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-slots }()
				response, e := p.Exchange(ctx, "udp", request)
				if e != nil {
					if q, e := parseDNSQuestion(request, false); e == nil {
						response = dnsEmpty(request, q, 2)
					}
				}
				if len(response) > 4096 {
					if q, e := parseDNSQuestion(request, false); e == nil {
						response = dnsEmpty(request, q, 0)
						response[2] |= 2
					}
				}
				if len(response) > 0 {
					_, _ = packet.WriteTo(response, client)
				}
			}()
		}
	}()
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				errorsCh <- e
				return
			}
			if !p.allowed(conn.RemoteAddr()) {
				_ = conn.Close()
				continue
			}
			select {
			case slots <- struct{}{}:
			default:
				_ = conn.Close()
				continue
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-slots }()
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(p.timeout()))
				closeOnCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
				defer closeOnCancel()
				var header [2]byte
				if _, e := io.ReadFull(conn, header[:]); e != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(header[:]))
				if n < 12 {
					return
				}
				request := make([]byte, n)
				if _, e := io.ReadFull(conn, request); e != nil {
					return
				}
				response, e := p.Exchange(ctx, "tcp", request)
				if e != nil {
					if q, e := parseDNSQuestion(request, false); e == nil {
						response = dnsEmpty(request, q, 2)
					}
				}
				if len(response) == 0 {
					return
				}
				frame := make([]byte, 2+len(response))
				binary.BigEndian.PutUint16(frame, uint16(len(response)))
				copy(frame[2:], response)
				_, _ = conn.Write(frame)
			}()
		}
	}()
	e := <-errorsCh
	cancel()
	_ = packet.Close()
	_ = listener.Close()
	<-errorsCh
	if ctx.Err() != nil && (errors.Is(e, net.ErrClosed) || errors.Is(e, context.Canceled)) {
		return nil
	}
	return e
}

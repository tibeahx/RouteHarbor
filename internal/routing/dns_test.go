package routing

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func dnsRequest(name string, typ uint16) []byte {
	h := make([]byte, 12)
	h[0] = 0x42
	h[2] = 1
	binary.BigEndian.PutUint16(h[4:6], 1)
	for _, part := range strings.Split(name, ".") {
		h = append(h, byte(len(part)))
		h = append(h, part...)
	}
	return append(h, 0, byte(typ>>8), byte(typ), 0, 1)
}

func TestDNSDelegationSuppressionAndHealth(t *testing.T) {
	var endpoint string
	observed := []string{}
	p := DNSProxy{
		LocalDNS:      "127.0.0.1:53",
		ExternalDNS:   "127.0.0.1:1053",
		LocalSuffixes: []string{"internal.example"},
		Observe:       func(s string) { observed = append(observed, s) },
		Query: func(ctx context.Context, network, address string, request []byte) ([]byte, error) {
			endpoint = address
			q, e := parseDNSQuestion(request, false)
			if e != nil {
				return nil, e
			}
			response := dnsEmpty(request, q, 0)
			response[3] |= 0x20
			return response, nil
		},
	}
	for _, tc := range []struct {
		name string
		typ  uint16
		want string
	}{{"router.lan", 1, p.LocalDNS}, {"printer.internal.example", 1, p.LocalDNS}, {"1.1.168.192.in-addr.arpa", 12, p.LocalDNS}, {"www.example", 1, p.ExternalDNS}, {"www.example", 28, p.ExternalDNS}, {"www.example", 64, ""}, {"www.example", 65, ""}, {DNSHealthName, 1, p.ExternalDNS}} {
		endpoint = ""
		response, e := p.Exchange(context.Background(), "udp", dnsRequest(tc.name, tc.typ))
		if e != nil || endpoint != tc.want {
			t.Fatalf("%s/%d: endpoint=%s err=%v", tc.name, tc.typ, endpoint, e)
		}
		if tc.want != p.LocalDNS && response[3]&0x20 != 0 {
			t.Fatal("external synthetic reply asserts DNSSEC validation")
		}
	}
	if len(observed) != 2 || observed[0] != "www.example" {
		t.Fatal(observed)
	}
	p.Query = func(ctx context.Context, network, address string, request []byte) ([]byte, error) {
		q, _ := parseDNSQuestion(request, false)
		v := dnsEmpty(request, q, 0)
		v[0]++
		return v, nil
	}
	if _, e := p.Exchange(context.Background(), "tcp", dnsRequest("www.example", 1)); e == nil {
		t.Fatal("mismatched reply accepted")
	}
	p.ExternalDNS = "8.8.8.8:53"
	if e := p.Validate(); e == nil {
		t.Fatal("external upstream accepted")
	}
}

func startDNSEcho(t *testing.T) (string, func()) {
	t.Helper()
	tcp, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	udp, e := net.ListenPacket("udp", tcp.Addr().String())
	if e != nil {
		_ = tcp.Close()
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			buf := make([]byte, 4096)
			n, a, e := udp.ReadFrom(buf)
			if e != nil {
				return
			}
			q, e := parseDNSQuestion(buf[:n], false)
			if e == nil {
				_, _ = udp.WriteTo(dnsEmpty(buf[:n], q, 0), a)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			c, e := tcp.Accept()
			if e != nil {
				return
			}
			func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				var h [2]byte
				if _, e := io.ReadFull(c, h[:]); e != nil {
					return
				}
				buf := make([]byte, binary.BigEndian.Uint16(h[:]))
				if _, e := io.ReadFull(c, buf); e != nil {
					return
				}
				q, e := parseDNSQuestion(buf, false)
				if e != nil {
					return
				}
				v := dnsEmpty(buf, q, 0)
				binary.BigEndian.PutUint16(h[:], uint16(len(v)))
				_, _ = c.Write(append(h[:], v...))
			}()
		}
	}()
	return tcp.Addr().String(), func() { _ = tcp.Close(); _ = udp.Close(); wg.Wait() }
}

func TestDNSRealUDPAndTCPBoundedServer(t *testing.T) {
	local, closeLocal := startDNSEcho(t)
	defer closeLocal()
	external, closeExternal := startDNSEcho(t)
	defer closeExternal()
	tcp, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	udp, e := net.ListenPacket("udp", tcp.Addr().String())
	if e != nil {
		_ = tcp.Close()
		t.Fatal(e)
	}
	p := DNSProxy{
		LocalDNS:       local,
		ExternalDNS:    external,
		MaxConcurrent:  2,
		Timeout:        time.Second,
		AllowedClients: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.Serve(ctx, udp, tcp) }()
	for _, network := range []string{"udp", "tcp"} {
		ctx, stop := context.WithTimeout(context.Background(), time.Second)
		v, e := exchangeDNS(ctx, network, tcp.Addr().String(), dnsRequest("www.example", 1))
		stop()
		if e != nil {
			t.Fatal(network, e)
		}
		if _, e := parseDNSQuestion(v, true); e != nil {
			t.Fatal(e)
		}
	}
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DNS server failed to stop")
	}
	if p.allowed(&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 5353}) {
		t.Fatal("unknown client accepted")
	}
}

func FuzzDNSQuestion(f *testing.F) {
	f.Add(dnsRequest("www.example", 1))
	f.Add([]byte{0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		q, e := parseDNSQuestion(b, false)
		if e == nil {
			v := dnsEmpty(b, q, 0)
			if _, e := parseDNSQuestion(v, true); e != nil {
				t.Fatal("synthetic question invalid", e)
			}
		}
	})
}

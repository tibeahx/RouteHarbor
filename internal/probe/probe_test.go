package probe

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/model"
)

type fixedResolver []netip.Addr

func (r fixedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r, nil
}

type fixedPaths struct{ p adapter.Path }

func (f fixedPaths) ProbePath(
	context.Context,
	model.Source,
) (adapter.Path, error) {
	return f.p, nil
}

func defaultSettings() model.ProbeSettings {
	return model.ProbeSettings{Concurrency: 2, TimeoutSeconds: 2}
}

func target() model.Target {
	return model.Target{
		ID:          "web",
		URL:         "https://example.com/",
		Required:    true,
		MaxBytes:    1024,
		StatusCodes: []int{200},
	}
}

func testRunner(t *testing.T, handler http.Handler) (*Runner, *httptest.Server) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	r := NewRunner(fixedPaths{adapter.Path{SourceID: "direct", Kind: "direct"}})
	r.Resolver = fixedResolver{netip.MustParseAddr("93.184.216.34")}
	r.TLSConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	r.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "93.184.216.34:443" {
			t.Errorf("not pinned: %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}
	t.Cleanup(srv.Close)
	return r, srv
}

func TestPublicIPIncludesIPv6AndMappedAddresses(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.169.254", "192.0.2.1", "198.19.0.1", "224.0.0.1", "::1", "::ffff:127.0.0.1", "::ffff:192.168.1.1", "fe80::1", "fe80::1%eth0", "fc00::1", "64:ff9b::a00:1", "2002:a00:1::", "2001:db8::1"} {
		if PublicIP(netip.MustParseAddr(s)) {
			t.Errorf("accepted %s", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"} {
		if !PublicIP(netip.MustParseAddr(s)) {
			t.Errorf("rejected public %s", s)
		}
	}
}

func TestProbeBoundedAndUnknownTelemetry(t *testing.T) {
	r, _ := testRunner(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Host != "example.com" {
			t.Error("lost original TLS/HTTP hostname")
		}
		// The bounded client intentionally closes before consuming this response.
		_, _ = io.WriteString(w, strings.Repeat("x", 1024*128))
	}))
	m, e := r.Run(
		context.Background(),
		model.Source{ID: "direct"},
		[]model.Target{target()},
		defaultSettings(),
		false,
	)
	if e != nil {
		t.Fatal(e)
	}
	v := m.Resources[0]
	if !v.Success || v.Bytes != 1024 || v.SpeedBPS != nil || m.PacketLoss != nil {
		t.Fatalf("incorrect measurement %#v", m)
	}
	m, e = r.Run(
		context.Background(),
		model.Source{ID: "direct"},
		[]model.Target{target()},
		defaultSettings(),
		true,
	)
	if e != nil || m.Resources[0].SpeedBPS == nil || *m.Resources[0].SpeedBPS <= 0 {
		t.Fatalf("speed absent %#v %v", m, e)
	}
}

func TestRejectsRedirectAndDNSRebinding(t *testing.T) {
	var calls atomic.Int32
	r, _ := testRunner(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		http.Redirect(w, req, "http://127.0.0.1/admin", http.StatusFound)
	}))
	m, e := r.Run(
		context.Background(),
		model.Source{ID: "direct"},
		[]model.Target{target()},
		defaultSettings(),
		false,
	)
	if e != nil {
		t.Fatal(e)
	}
	if m.Resources[0].ErrorCode != "redirect_rejected" || calls.Load() != 1 {
		t.Fatal(m)
	}
	r.Resolver = fixedResolver{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("::ffff:127.0.0.1"),
	}
	m, e = r.Run(
		context.Background(),
		model.Source{ID: "direct"},
		[]model.Target{target()},
		defaultSettings(),
		false,
	)
	if e != nil {
		t.Fatal(e)
	}
	if m.Resources[0].ErrorCode != "target_dns_rejected" || calls.Load() != 1 {
		t.Fatal("DNS rebinding reached network", m)
	}
}

func TestConcurrencyAcrossSources(t *testing.T) {
	var active, peak atomic.Int32
	r, _ := testRunner(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		n := active.Add(1)
		defer active.Add(-1)
		for n > peak.Load() {
			old := peak.Load()
			if n <= old || peak.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		if _, e := io.WriteString(w, "ok"); e != nil {
			t.Error(e)
		}
	}))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := r.Run(
				context.Background(),
				model.Source{ID: "direct"},
				[]model.Target{target()},
				defaultSettings(),
				false,
			)
			if e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if peak.Load() > 2 {
		t.Fatal("global probe concurrency exceeded", peak.Load())
	}
}

func TestProxyDestinationsAreNumeric(t *testing.T) {
	for _, scheme := range []string{"socks5", "http"} {
		t.Run(scheme, func(t *testing.T) {
			client, server := net.Pipe()
			defer func() { _ = client.Close() }()
			done := make(chan string, 1)
			go func() {
				defer func() { _ = server.Close() }()
				if scheme == "socks5" {
					var hello [3]byte
					if _, e := io.ReadFull(server, hello[:]); e != nil {
						done <- e.Error()
						return
					}
					if _, e := server.Write([]byte{5, 0}); e != nil {
						done <- e.Error()
						return
					}
					var req [10]byte
					if _, e := io.ReadFull(server, req[:]); e != nil {
						done <- e.Error()
						return
					}
					if req[3] != 1 {
						done <- "remote DNS used"
						return
					}
					if string(req[4:8]) != string([]byte{93, 184, 216, 34}) {
						done <- "wrong IP"
						return
					}
					if _, e := server.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); e != nil {
						done <- e.Error()
						return
					}
					done <- ""
				} else {
					buf := make([]byte, 256)
					n, e := server.Read(buf)
					if e != nil {
						done <- e.Error()
						return
					}
					if !strings.HasPrefix(
						string(buf[:n]),
						"CONNECT 93.184.216.34:443 HTTP/1.1\r\n",
					) {
						done <- "not numeric"
						return
					}
					if _, e := server.Write(
						[]byte("HTTP/1.1 200 Connection Established\r\n\r\n"),
					); e != nil {
						done <- e.Error()
						return
					}
					done <- ""
				}
			}()
			r := NewRunner(nil)
			r.DialContext = func(context.Context, string, string) (net.Conn, error) { return client, nil }
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			c, e := r.proxyDial(
				ctx,
				&url.URL{Scheme: scheme, Host: "proxy.example:1080"},
				"93.184.216.34:443",
			)
			if e != nil {
				t.Fatal(e)
			}
			_ = c.Close()
			if e := <-done; e != "" {
				t.Fatal(e)
			}
		})
	}
}

func TestIndependentProxyInputs(t *testing.T) {
	m := adapter.NewManager(t.TempDir())
	a := model.Source{
		ID:       "a",
		Type:     "socks5",
		Settings: json.RawMessage(`{"server":"127.0.0.1","server_port":12001}`),
	}
	b := model.Source{
		ID:       "b",
		Type:     "http-connect",
		Settings: json.RawMessage(`{"server":"127.0.0.1","server_port":12002}`),
	}
	p, _ := m.ProbePath(context.Background(), a)
	q, _ := m.ProbePath(context.Background(), b)
	if p.ProxyURL.Host == q.ProxyURL.Host || p.Mark == q.Mark {
		t.Fatal("candidate paths share active input")
	}
}

func TestInterfaceNeverFallsBackToDirect(t *testing.T) {
	r := NewRunner(fixedPaths{adapter.Path{SourceID: "wg", Kind: "interface", Interface: "wg0"}})
	called := false
	r.DialContext = func(context.Context, string, string) (net.Conn, error) { called = true; return nil, nil }
	if _, e := r.pathDial(
		context.Background(),
		adapter.Path{Kind: "interface"},
		"1.1.1.1:443",
	); e == nil ||
		called {
		t.Fatal("interface probe fell through to direct")
	}
}

var _ = tls.VersionTLS13

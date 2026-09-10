package probe

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
)

// Real TLS over net.Pipe independently verifies the control check without an
// external network, a listener, or a public control resource chosen by tests.
func TestControlTLSMemoryCertificatePinningAndNoApplicationRequest(t *testing.T) {
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	r := NewRunner(nil)
	r.Resolver = fixedResolver{netip.MustParseAddr("93.184.216.34")}
	r.TLSConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	var calls, bytesSent atomic.Int32
	done := make(chan struct{}, 4)
	r.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		calls.Add(1)
		if address != "93.184.216.34:443" {
			t.Errorf("control IP not pinned: %s", address)
		}
		a, b := net.Pipe()
		go func() {
			defer func() { _ = b.Close(); done <- struct{}{} }()
			server := tls.Server(
				b,
				&tls.Config{
					Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
					MinVersion:   tls.VersionTLS12,
				},
			)
			if e := server.HandshakeContext(ctx); e != nil {
				return
			}
			buf := make([]byte, 1024)
			n, _ := server.Read(buf)
			bytesSent.Add(int32(n))
		}()
		return a, nil
	}
	path := adapter.Path{Kind: "direct"}
	at, e := r.ControlTLS(context.Background(), target(), path, defaultSettings())
	if e != nil || at.IsZero() {
		t.Fatal(at, e)
	}
	<-done
	if calls.Load() != 1 || bytesSent.Load() != 0 {
		t.Fatal("control sent application data", calls.Load(), bytesSent.Load())
	}
	r.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if _, e = r.ControlTLS(context.Background(), target(), path, defaultSettings()); e == nil {
		t.Fatal("untrusted control certificate accepted")
	}
	<-done
	r.Resolver = fixedResolver{
		netip.MustParseAddr("93.184.216.34"),
		netip.MustParseAddr("127.0.0.1"),
	}
	if _, e = r.ControlTLS(context.Background(), target(), path, defaultSettings()); e == nil {
		t.Fatal("private DNS answer accepted")
	}
	if calls.Load() != 2 {
		t.Fatal("private answer reached network")
	}
}

func TestControlTLSExplicitLimitsAndSharedBudget(t *testing.T) {
	r := NewRunner(nil)
	path := adapter.Path{Kind: "direct"}
	for _, settings := range []struct{ timeout, concurrency int }{{0, 1}, {61, 1}, {1, 0}, {1, 33}} {
		s := defaultSettings()
		s.TimeoutSeconds = settings.timeout
		s.Concurrency = settings.concurrency
		if _, e := r.ControlTLS(context.Background(), target(), path, s); e == nil {
			t.Fatal("invalid control limits accepted", settings)
		}
	}
	for _, address := range []string{"http://example.com/", "https://example.com:8443/", "https://user:pass@example.com/", "https://127.0.0.1/"} {
		v := target()
		v.URL = address
		if _, e := r.ControlTLS(context.Background(), v, path, defaultSettings()); e == nil {
			t.Fatal("unsafe control target accepted")
		}
	}
	if e := r.acquire(context.Background(), 1); e != nil {
		t.Fatal(e)
	}
	defer r.release()
	settings := defaultSettings()
	settings.Concurrency = 1
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, e := r.ControlTLS(
		ctx,
		target(),
		path,
		settings,
	); !errors.Is(
		e,
		context.DeadlineExceeded,
	) {
		t.Fatal("control ignored shared probe budget", e)
	}
}

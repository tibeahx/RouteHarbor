package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/adapter"
)

type comparativeDial func(context.Context, string, string) (net.Conn, error)

func (d comparativeDial) DialProbe(ctx context.Context, source, address string) (net.Conn, error) {
	return d(ctx, source, address)
}

type comparativeResolver struct{ calls atomic.Int32 }

func (r *comparativeResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	if r.calls.Add(1)%2 == 1 {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

func TestComparativePinsAllAddressesAndDoesNotReplayHTTP(t *testing.T) {
	var requests atomic.Int32
	r, srv := testRunner(
		t,
		http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) { requests.Add(1) }),
	)
	r.Resolver = fixedResolver{
		netip.MustParseAddr("93.184.216.34"),
		netip.MustParseAddr("2606:4700:4700::1111"),
	}
	var direct, bypass atomic.Int32
	r.DialProbe = comparativeDial(
		func(ctx context.Context, source, address string) (net.Conn, error) {
			if address != "93.184.216.34:443" && address != "[2606:4700:4700::1111]:443" {
				t.Errorf("not pinned: %s", address)
			}
			if source == "direct" {
				direct.Add(1)
				return nil, errors.New("connection reset")
			}
			bypass.Add(1)
			return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
		},
	)
	round, e := r.Compare(
		context.Background(),
		"example.com",
		adapter.Path{SourceID: "direct", Kind: "direct"},
		adapter.Path{SourceID: "bypass", Kind: "direct"},
		defaultSettings(),
	)
	if e != nil || !round.Complete || round.DNSError || len(round.Addresses) != 2 {
		t.Fatal(round, e)
	}
	for _, a := range round.Addresses {
		if a.DirectSuccess || !a.BypassSuccess || a.CertificateError {
			t.Fatal(a)
		}
	}
	if direct.Load() != 2 || bypass.Load() != 2 || requests.Load() != 0 || round.ControlOK {
		t.Fatal(
			"incorrect comparative behavior",
			direct.Load(),
			bypass.Load(),
			requests.Load(),
			round,
		)
	}
}

func TestComparativeDNSMismatchPrivateAndCertificateRemainIndeterminate(t *testing.T) {
	r, _ := testRunner(t, http.NotFoundHandler())
	path := adapter.Path{Kind: "direct"}
	r.Resolver = &comparativeResolver{}
	if round, e := r.Compare(
		context.Background(),
		"example.com",
		path,
		path,
		defaultSettings(),
	); e != nil || !round.DNSError ||
		round.Complete {
		t.Fatal(round, e)
	}
	r.Resolver = fixedResolver{netip.MustParseAddr("127.0.0.1")}
	if round, e := r.Compare(
		context.Background(),
		"example.com",
		path,
		path,
		defaultSettings(),
	); e != nil || !round.DNSError ||
		round.Complete {
		t.Fatal(round, e)
	}
	r.Resolver = fixedResolver{netip.MustParseAddr("93.184.216.34")}
	r.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	round, e := r.Compare(context.Background(), "example.com", path, path, defaultSettings())
	if e != nil || !round.Complete || len(round.Addresses) != 1 ||
		!round.Addresses[0].CertificateError {
		t.Fatal(round, e)
	}
}

func TestComparativeSharesProbeConcurrencyBudget(t *testing.T) {
	r := NewRunner(nil)
	if e := r.acquire(context.Background(), 1); e != nil {
		t.Fatal(e)
	}
	defer r.release()
	settings := defaultSettings()
	settings.Concurrency = 1
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, e := r.Compare(
		ctx,
		"example.com",
		adapter.Path{Kind: "direct"},
		adapter.Path{Kind: "direct"},
		settings,
	); !errors.Is(
		e,
		context.DeadlineExceeded,
	) {
		t.Fatal("ignored global probe budget", e)
	}
}

func TestControlTLSUsesExplicitTargetWithoutHTTPAndRejectsUnsafeAnswers(t *testing.T) {
	var requests atomic.Int32
	r, _ := testRunner(
		t,
		http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) { requests.Add(1) }),
	)
	path := adapter.Path{Kind: "direct"}
	at, e := r.ControlTLS(context.Background(), target(), path, defaultSettings())
	if e != nil || at.IsZero() || time.Since(at) > time.Second || requests.Load() != 0 {
		t.Fatal(at, e, requests.Load())
	}
	r.Resolver = fixedResolver{
		netip.MustParseAddr("93.184.216.34"),
		netip.MustParseAddr("192.168.1.1"),
	}
	if _, e := r.ControlTLS(context.Background(), target(), path, defaultSettings()); e == nil {
		t.Fatal("mixed unsafe control DNS accepted")
	}
	bad := target()
	bad.URL = "https://example.com:8443/"
	if _, e := r.ControlTLS(context.Background(), bad, path, defaultSettings()); e == nil {
		t.Fatal("non-443 control accepted")
	}
	r.Resolver = fixedResolver{netip.MustParseAddr("93.184.216.34")}
	r.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if _, e := r.ControlTLS(context.Background(), target(), path, defaultSettings()); e == nil {
		t.Fatal("invalid control certificate accepted")
	}
}

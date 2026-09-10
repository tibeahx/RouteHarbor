package routing

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/platform"
)

const (
	RegistryProvider   = "antifilter"
	RegistryProvenance = "Antifilter: third-party publication of registry data"
	registryHost       = "antifilter.download"
)

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// RegistryFetcher only downloads the two explicit provider lists. There is no
// user-supplied URL, environment proxy, redirect, URL-list, resolved-IP list or
// summarized /24 fallback. Every resolved address is checked before dialing.
type RegistryFetcher struct {
	Resolver Resolver
	// Transport is a test-only injection point. Production must leave it nil.
	Transport http.RoundTripper
}

func (f RegistryFetcher) Fetch(
	ctx context.Context,
	generation uint64,
	now time.Time,
) (Snapshot, error) {
	s := Snapshot{Generation: generation, CreatedAt: now.UTC()}
	domains, rejected, e := f.fetchList(ctx, "domains.lst", true)
	if e != nil {
		return Snapshot{}, e
	}
	cidrs, _, e := f.fetchList(ctx, "subnet.lst", false)
	if e != nil {
		return Snapshot{}, e
	}
	s.Domains = domains
	s.CIDRs = cidrs
	s.RejectedDomains = rejected
	return s, ValidateSnapshot(s)
}

func (f RegistryFetcher) fetchList(
	ctx context.Context,
	name string,
	domains bool,
) ([]string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	transport := f.Transport
	if transport == nil {
		r := f.Resolver
		if r == nil {
			r = net.DefaultResolver
		}
		addresses, e := r.LookupNetIP(ctx, "ip", registryHost)
		if e != nil || len(addresses) == 0 || len(addresses) > 64 {
			return nil, 0, errors.New("registry DNS resolution failed")
		}
		for _, a := range addresses {
			if !platform.PublicAddress(a) {
				return nil, 0, errors.New("registry DNS returned a prohibited address")
			}
		}
		pinned := addresses[0].Unmap()
		t := &http.Transport{
			Proxy:                  nil,
			DisableKeepAlives:      true,
			DisableCompression:     true,
			ResponseHeaderTimeout:  15 * time.Second,
			TLSHandshakeTimeout:    10 * time.Second,
			MaxResponseHeaderBytes: 16 << 10,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" || address != net.JoinHostPort(registryHost, "443") {
					return nil, errors.New("unexpected registry destination")
				}
				d := net.Dialer{Timeout: 15 * time.Second}
				return d.DialContext(ctx, "tcp", net.JoinHostPort(pinned.String(), "443"))
			},
		}
		defer t.CloseIdleConnections()
		transport = t
	}
	client := http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("registry redirects prohibited") },
	}
	req, e := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"https://"+registryHost+"/list/"+name,
		nil,
	)
	if e != nil {
		return nil, 0, errors.New("invalid registry request")
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "RouteHarbor registry updater")
	resp, e := client.Do(req)
	if e != nil {
		return nil, 0, errors.New("registry download failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || resp.ContentLength > MaxListBytes ||
		resp.Header.Get("Content-Encoding") != "" &&
			resp.Header.Get("Content-Encoding") != "identity" {
		return nil, 0, errors.New("registry response rejected")
	}
	var reader io.Reader = resp.Body
	if domains {
		return ParseRegistryDomains(reader)
	}
	values, err := ParseSubnets(reader)
	return values, 0, err
}

// Package probe measures independently routed HTTPS requests without retaining content.
package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/model"
	"github.com/tibeahx/OpenRHP/internal/platform"
)

type PathProvider interface {
	ProbePath(context.Context, model.Source) (adapter.Path, error)
}
type ProbeDialer interface {
	DialProbe(context.Context, string, string) (net.Conn, error)
}
type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

var errManagedResolverRequired = errors.New(
	"managed target DNS requires an explicit public resolver",
)

type dnsPolicy struct {
	managed  bool
	resolver string
}
type Runner struct {
	dnsMu     sync.RWMutex
	dnsPolicy dnsPolicy
	Paths     PathProvider
	DialProbe ProbeDialer
	Resolver  Resolver
	// DialContext and TLSConfig are injection points for deterministic local tests. Production leaves both nil.
	DialContext func(context.Context, string, string) (net.Conn, error)
	TLSConfig   *tls.Config
	mu          sync.Mutex
	running     int
	changed     chan struct{}
}

func NewRunner(paths PathProvider) *Runner {
	return &Runner{Paths: paths, Resolver: net.DefaultResolver, changed: make(chan struct{})}
}

// PublicIP uses the same address policy as the privileged probe sink.
func PublicIP(ip netip.Addr) bool {
	return platform.PublicAddress(ip)
}

func ValidateTarget(t model.Target) error {
	u, e := url.Parse(t.URL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" ||
		u.Opaque != "" ||
		len(t.URL) > 2048 ||
		strings.ContainsAny(t.URL, "\x00\r\n") {
		return errors.New("target must be an HTTPS URL without credentials or fragment")
	}
	hostname := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if hostname == "localhost" || strings.HasSuffix(hostname, ".localhost") ||
		strings.HasSuffix(hostname, ".local") {
		return errors.New("local probe hostnames are prohibited")
	}
	p := u.Port()
	if p != "" && p != "443" {
		return errors.New("probe targets must use HTTPS port 443")
	}
	if strings.Contains(u.Hostname(), "%") {
		return errors.New("scoped target addresses are prohibited")
	}
	if a, e := netip.ParseAddr(u.Hostname()); e == nil && !PublicIP(a) {
		return errors.New("probe target must be a public address")
	}
	if t.MaxBytes < 1 || t.MaxBytes > 8<<20 {
		return errors.New("target body budget must be 1 byte to 8 MiB")
	}
	if len(t.StatusCodes) == 0 || len(t.StatusCodes) > 16 {
		return errors.New("target requires expected HTTP status codes")
	}
	seen := map[int]bool{}
	for _, s := range t.StatusCodes {
		if seen[s] {
			return errors.New("duplicate expected HTTP status")
		}
		seen[s] = true
		if s < 200 || s > 599 {
			return errors.New("invalid expected HTTP status")
		}
	}
	return nil
}

func (r *Runner) resolve(
	ctx context.Context,
	u *url.URL,
	path adapter.Path,
	policy dnsPolicy,
) (netip.Addr, error) {
	if a, e := netip.ParseAddr(u.Hostname()); e == nil {
		if !PublicIP(a) {
			return netip.Addr{}, errors.New("unsafe address")
		}
		return a.Unmap(), nil
	}
	resolver := r.Resolver
	if policy.managed {
		ip, e := netip.ParseAddr(policy.resolver)
		if e != nil || !PublicIP(ip) {
			return netip.Addr{}, errManagedResolverRequired
		}
		destination := net.JoinHostPort(ip.Unmap().String(), "53")
		resolver = &net.Resolver{
			PreferGo:     true,
			StrictErrors: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return r.pathDial(ctx, path, destination)
			},
		}
	} else if resolver == nil {
		resolver = net.DefaultResolver
	}
	ips, e := resolver.LookupNetIP(ctx, "ip", u.Hostname())
	if e != nil || len(ips) == 0 || len(ips) > 64 {
		return netip.Addr{}, errors.New("DNS resolution failed")
	}
	for _, ip := range ips {
		if !PublicIP(ip) {
			return netip.Addr{}, errors.New("DNS returned a non-public address")
		}
	}
	return ips[0].Unmap(), nil
}

func (r *Runner) acquire(ctx context.Context, n int) error {
	for {
		r.mu.Lock()
		if r.changed == nil {
			r.changed = make(chan struct{})
		}
		if r.running < n {
			r.running++
			r.mu.Unlock()
			return nil
		}
		c := r.changed
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c:
		}
	}
}

func (r *Runner) release() {
	r.mu.Lock()
	r.running--
	close(r.changed)
	r.changed = make(chan struct{})
	r.mu.Unlock()
}

func (r *Runner) dial(ctx context.Context, address string) (net.Conn, error) {
	if r.DialContext != nil {
		return r.DialContext(ctx, "tcp", address)
	}
	d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: -1}
	return d.DialContext(ctx, "tcp", address)
}

func (r *Runner) pathDial(ctx context.Context, p adapter.Path, address string) (net.Conn, error) {
	switch p.Kind {
	case "socks5", "http-connect", "sing-box", "xray":
		if p.ProxyURL == nil {
			return nil, errors.New("source input unavailable")
		}
		return r.proxyDial(ctx, p.ProxyURL, address)
	case "interface", "packet-engine":
		if r.DialProbe == nil {
			return nil, errors.New("privileged source path unavailable")
		}
		return r.DialProbe.DialProbe(ctx, p.SourceID, address)
	case "direct":
		if r.DialProbe != nil {
			return r.DialProbe.DialProbe(ctx, p.SourceID, address)
		}
		return r.dial(ctx, address)
	default:
		return nil, errors.New("unsupported probe path")
	}
}

// Run validates and pins every target address before any connection, including proxy CONNECT/SOCKS requests.
// Parallel callers share one concurrency budget. Redirects are never followed. Missing loss/speed telemetry remains nil.
func (r *Runner) Run(
	ctx context.Context,
	s model.Source,
	targets []model.Target,
	settings model.ProbeSettings,
	speed bool,
) (model.Measurement, error) {
	m := model.Measurement{
		SourceID:  s.ID,
		At:        time.Now().UTC(),
		Resources: []model.ResourceResult{},
	}
	if len(targets) == 0 || len(targets) > 32 {
		return m, errors.New("between 1 and 32 probe targets required")
	}
	if settings.TimeoutSeconds < 1 || settings.TimeoutSeconds > 60 || settings.Concurrency < 1 ||
		settings.Concurrency > 32 {
		return m, errors.New("invalid probe timeout or concurrency")
	}
	if r.Paths == nil {
		return m, errors.New("source path provider is required")
	}
	p, e := r.Paths.ProbePath(ctx, s)
	if e != nil {
		return m, e
	}
	m.Path = p.Kind + ":" + p.SourceID
	for _, t := range targets {
		if e = ValidateTarget(t); e != nil {
			return m, e
		}
	}
	r.dnsMu.RLock()
	dns := r.dnsPolicy
	r.dnsMu.RUnlock()
	for _, t := range targets {
		if err := r.acquire(ctx, settings.Concurrency); err != nil {
			return m, err
		}
		result := r.resource(
			ctx,
			p,
			t,
			time.Duration(settings.TimeoutSeconds)*time.Second,
			speed,
			dns,
		)
		r.release()
		m.Resources = append(m.Resources, result)
	}
	return m, nil
}

func (r *Runner) resource(
	ctx context.Context,
	p adapter.Path,
	t model.Target,
	timeout time.Duration,
	speed bool,
	dns dnsPolicy,
) model.ResourceResult {
	result := model.ResourceResult{TargetID: t.ID, Required: t.Required}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	u, _ := url.Parse(t.URL)
	ip, e := r.resolve(ctx, u, p, dns)
	if e != nil {
		result.ErrorCode = "target_dns_rejected"
		if errors.Is(e, errManagedResolverRequired) {
			result.ErrorCode = "target_dns_resolver_required"
		}
		return result
	}
	address := net.JoinHostPort(ip.String(), "443")
	transport := &http.Transport{
		Proxy:                  nil,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 16 << 10,
		ResponseHeaderTimeout:  timeout,
		TLSHandshakeTimeout:    timeout,
		DisableCompression:     true,
	}
	transport.DialTLSContext = func(ctx context.Context, network, ignored string) (net.Conn, error) {
		conn, e := r.pathDial(ctx, p, address)
		if e != nil {
			return nil, e
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
		if r.TLSConfig != nil {
			cfg = r.TLSConfig.Clone()
			cfg.ServerName = u.Hostname()
			cfg.InsecureSkipVerify = false
		}
		secured := tls.Client(conn, cfg)
		if e = secured.HandshakeContext(ctx); e != nil {
			_ = conn.Close()
			return nil, e
		}
		return secured, nil
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport:     transport,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if e != nil {
		result.ErrorCode = "target_invalid"
		return result
	}
	req.Header.Set("User-Agent", "OpenRHP-Probe/1")
	req.Header.Set("Accept-Encoding", "identity")
	budget := t.MaxBytes
	if !speed && budget > 32<<10 {
		budget = 32 << 10
	}
	req.Header.Set("Range", "bytes=0-"+strconv.FormatInt(budget-1, 10))
	started := time.Now()
	response, e := client.Do(req)
	result.LatencyMS = float64(time.Since(started).Microseconds()) / 1000
	if e != nil {
		result.ErrorCode = "request_failed"
		return result
	}
	defer func() { _ = response.Body.Close() }()
	result.StatusCode = response.StatusCode
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		result.ErrorCode = "redirect_rejected"
		return result
	}
	expected := false
	for _, status := range t.StatusCodes {
		if response.StatusCode == status {
			expected = true
		}
	}
	count, e := io.Copy(io.Discard, io.LimitReader(response.Body, budget))
	result.Bytes = count
	if e != nil {
		result.ErrorCode = "body_read_failed"
		return result
	}
	if !expected {
		result.ErrorCode = "unexpected_status"
		return result
	}
	result.Success = true
	if speed && count > 0 {
		value := float64(count) * 8 / time.Since(started).Seconds()
		result.SpeedBPS = &value
	}
	return result
}

// ConfigureDNS is called by the controller on configuration changes. Each probe
// snapshots the policy, so parallel source lookups never share a mutable route.
func (r *Runner) ConfigureDNS(managed bool, resolver string) {
	r.dnsMu.Lock()
	r.dnsPolicy = dnsPolicy{managed: managed, resolver: resolver}
	r.dnsMu.Unlock()
}

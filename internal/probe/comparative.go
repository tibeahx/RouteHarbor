package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/model"
	"github.com/tibeahx/OpenRHP/internal/routing"
)

// ControlTLS checks an explicitly configured control target on the direct path,
// sharing the ordinary probe concurrency budget. It sends no HTTP request. A
// complete public DNS answer set and one verified TLS connection are required.
func (r *Runner) ControlTLS(
	ctx context.Context,
	target model.Target,
	direct adapter.Path,
	settings model.ProbeSettings,
) (time.Time, error) {
	return r.ControlTLSForFamilies(ctx, target, direct, settings, false, false)
}

// ControlTLSForFamilies requires fresh direct proof for each family used by the
// candidate. Working IPv4 cannot disguise a general IPv6 WAN outage.
func (r *Runner) ControlTLSForFamilies(
	ctx context.Context,
	target model.Target,
	direct adapter.Path,
	settings model.ProbeSettings,
	want4, want6 bool,
) (time.Time, error) {
	if ValidateTarget(target) != nil {
		return time.Time{}, errors.New("invalid direct control target")
	}
	if settings.TimeoutSeconds < 1 || settings.TimeoutSeconds > 60 || settings.Concurrency < 1 ||
		settings.Concurrency > 32 {
		return time.Time{}, errors.New("invalid control probe limits")
	}
	if e := r.acquire(ctx, settings.Concurrency); e != nil {
		return time.Time{}, e
	}
	defer r.release()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(settings.TimeoutSeconds)*time.Second)
	defer cancel()
	r.dnsMu.RLock()
	policy := r.dnsPolicy
	r.dnsMu.RUnlock()
	if !policy.managed && r.DialContext == nil {
		return time.Time{}, errors.New("control checks require managed public DNS")
	}
	u, _ := url.Parse(target.URL)
	domain := u.Hostname()
	ips, e := r.comparisonAddresses(ctx, domain, direct, policy)
	if e != nil {
		return time.Time{}, errors.New("control target DNS is indeterminate")
	}
	have4, have6 := false, false
	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		if ip.Is4() && have4 || ip.Is6() && have6 {
			continue
		}
		if ok, _ := r.comparisonTLS(ctx, domain, ip, direct, settings.TimeoutSeconds); ok {
			if ip.Is4() {
				have4 = true
			} else {
				have6 = true
			}
			if (!want4 || have4) && (!want6 || have6) {
				return time.Now().UTC(), nil
			}
		}
	}
	return time.Time{}, errors.New("direct control TLS unavailable")
}

// Compare performs TLS-only differential checks; it never repeats a user's HTTP
// request or sends an application body. The direct and bypass DNS answers must
// agree, every public answer is pinned, and every TLS handshake uses the same SNI
// and verification policy. ControlOK/ControlAt are left for the scheduler to fill
// from an independently configured direct control target.
func (r *Runner) Compare(
	ctx context.Context,
	domain string,
	direct, bypass adapter.Path,
	settings model.ProbeSettings,
) (routing.Round, error) {
	var result routing.Round
	domain, e := routing.CanonicalDomain(domain)
	if e != nil || routing.LocalDomain(domain) {
		return result, errors.New("comparative probe requires a public domain")
	}
	if settings.TimeoutSeconds < 1 || settings.TimeoutSeconds > 60 || settings.Concurrency < 1 ||
		settings.Concurrency > 32 {
		return result, errors.New("invalid comparative probe limits")
	}
	if e = r.acquire(ctx, settings.Concurrency); e != nil {
		return result, e
	}
	defer r.release()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Duration(settings.TimeoutSeconds)*time.Second)
	defer cancel()
	r.dnsMu.RLock()
	policy := r.dnsPolicy
	r.dnsMu.RUnlock()
	// A managed resolver is necessary to compare each source's DNS behavior.
	// The explicit Resolver injection is permitted only for deterministic tests.
	if !policy.managed && r.DialContext == nil {
		result.DNSError = true
		return result, errors.New("comparative checks require managed public DNS")
	}
	directIPs, e := r.comparisonAddresses(ctx, domain, direct, policy)
	if e != nil {
		result.DNSError = true
		return result, nil
	}
	bypassIPs, e := r.comparisonAddresses(ctx, domain, bypass, policy)
	if e != nil || !sameAddresses(directIPs, bypassIPs) {
		result.DNSError = true
		return result, nil
	}
	for _, ip := range bypassIPs {
		if ctx.Err() != nil {
			return result, nil
		}
		a := routing.AddressResult{IP: ip}
		a.DirectSuccess, a.CertificateError = r.comparisonTLS(
			ctx,
			domain,
			ip,
			direct,
			settings.TimeoutSeconds,
		)
		if ctx.Err() != nil {
			return result, nil
		}
		var cert bool
		a.BypassSuccess, cert = r.comparisonTLS(ctx, domain, ip, bypass, settings.TimeoutSeconds)
		a.CertificateError = a.CertificateError || cert
		result.Addresses = append(result.Addresses, a)
	}
	result.Complete = ctx.Err() == nil && len(result.Addresses) == len(bypassIPs)
	return result, nil
}

func sameAddresses(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (r *Runner) comparisonAddresses(
	ctx context.Context,
	domain string,
	path adapter.Path,
	policy dnsPolicy,
) ([]netip.Addr, error) {
	resolver := r.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if policy.managed {
		ip, e := netip.ParseAddr(policy.resolver)
		if e != nil || !PublicIP(ip) {
			return nil, errManagedResolverRequired
		}
		endpoint := net.JoinHostPort(ip.Unmap().String(), "53")
		resolver = &net.Resolver{
			PreferGo:     true,
			StrictErrors: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return r.pathDial(ctx, path, endpoint)
			},
		}
	}
	ips, e := resolver.LookupNetIP(ctx, "ip", domain)
	if e != nil || len(ips) == 0 || len(ips) > 64 {
		return nil, errors.New("comparative DNS resolution failed")
	}
	seen := map[netip.Addr]bool{}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if !PublicIP(ip) {
			return nil, errors.New("comparative DNS returned prohibited address")
		}
		ip = ip.Unmap()
		if !seen[ip] {
			out = append(out, ip)
			seen[ip] = true
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out, nil
}

func (r *Runner) comparisonTLS(
	ctx context.Context,
	domain string,
	ip netip.Addr,
	path adapter.Path,
	seconds int,
) (success, certificateError bool) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer cancel()
	conn, e := r.pathDial(ctx, path, net.JoinHostPort(ip.String(), "443"))
	if e != nil {
		return false, false
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	conf := &tls.Config{MinVersion: tls.VersionTLS12}
	if r.TLSConfig != nil {
		conf = r.TLSConfig.Clone()
	}
	conf.ServerName = domain
	tlsConn := tls.Client(conn, conf)
	e = tlsConn.HandshakeContext(ctx)
	if e == nil {
		return true, false
	}
	var verification *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	return false, errors.As(e, &verification) || errors.As(e, &unknown) || errors.As(e, &invalid) ||
		errors.As(e, &hostname)
}

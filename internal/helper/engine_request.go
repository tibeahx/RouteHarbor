package helper

import (
	"errors"
	"net/netip"

	"github.com/tibeahx/RouteHarbor/internal/adapter"
	"github.com/tibeahx/RouteHarbor/internal/model"
	"github.com/tibeahx/RouteHarbor/internal/platform"
)

// EngineRequest supplies one strict source and fixed loopback inputs. The helper
// regenerates all engine configuration and never reads an API-owned config file.
type EngineRequest struct {
	Source      model.Source `json:"source"`
	Path        adapter.Path `json:"path"`
	DNSResolver string       `json:"dns_resolver,omitempty"`
}

func ValidateEngineRequest(r EngineRequest) error {
	if e := adapter.ValidateSource(r.Source); e != nil {
		return errors.New("invalid_engine_source")
	}
	switch r.Source.Type {
	case "sing-box", "xray", "socks5", "http-connect":
	default:
		return errors.New("invalid_engine_source")
	}
	if adapter.RequireNumericEngineEndpoint(r.Source) != nil {
		return errors.New("engine_endpoint_not_pinned")
	}
	udp := r.Source.Type != "http-connect"
	if r.Source.Type == "sing-box" {
		var out adapter.SingOutbound
		_ = adapter.StrictDecode(r.Source.Settings, &out)
		udp = out.Type != "http"
	}
	if r.Path.UDP != udp {
		return errors.New("invalid_engine_capability")
	}
	p := r.Path
	if p.SourceID != r.Source.ID || p.Kind != r.Source.Type || p.Slot < 1 || p.Slot > 250 ||
		p.Mark != adapter.Mark(p.Slot) ||
		p.Queue != uint16(21000+p.Slot) ||
		p.Interface != "" ||
		p.ProxyURL != nil {
		return errors.New("invalid_engine_allocation")
	}
	seen := map[int]bool{}
	for _, port := range []int{p.ProxyPort, p.TransparentPort, p.DNSPort} {
		if port == 0 {
			continue
		}
		if port < 1024 || port > 65535 || seen[port] {
			return errors.New("invalid_engine_input")
		}
		seen[port] = true
	}
	if p.ProxyPort == 0 || p.TransparentPort == 0 {
		return errors.New("invalid_engine_input")
	}
	if p.DNSPort != 0 {
		ip, e := netip.ParseAddr(r.DNSResolver)
		if e != nil || !platform.PublicAddress(ip) {
			return errors.New("invalid_engine_resolver")
		}
	} else if r.DNSResolver != "" {
		return errors.New("invalid_engine_resolver")
	}
	// EngineConfig performs the remaining strict outbound and capability checks.
	p.DNSResolver = r.DNSResolver
	if _, e := adapter.EngineConfig(r.Source, p); e != nil {
		return errors.New("invalid_engine_config")
	}
	return nil
}

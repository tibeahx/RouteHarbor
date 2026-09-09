package helper

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/tibeahx/OpenRHP/internal/dataplane"
	"github.com/tibeahx/OpenRHP/internal/platform"
)

// NativeProbePath carries no user-controlled mark, address, routing rule or command.
type NativeProbePath struct {
	SourceID  string `json:"source_id"`
	Kind      string `json:"kind"`
	Slot      uint16 `json:"slot"`
	Interface string `json:"interface,omitempty"`
}
type nativeProbeRegistration struct {
	Path NativeProbePath
	Seen time.Time
}

func validateNativeProbe(p NativeProbePath) error {
	if validatePacketRequest(p.SourceID, int(p.Slot)) != nil {
		return errors.New("invalid_probe_path")
	}
	if p.Kind == "direct" && p.Interface == "" {
		return nil
	}
	if p.Kind == "interface" && platform.ValidInterfaceName(p.Interface) {
		return nil
	}
	return errors.New("invalid_probe_path")
}

func sameProbeAllocation(a, b dataplane.Path) bool {
	return a.SourceID == b.SourceID && a.Slot == b.Slot && a.Kind == b.Kind &&
		a.Interface == b.Interface
}

func probeAllocationConflict(a, b dataplane.Path) bool {
	return (a.SourceID == b.SourceID || a.Slot == b.Slot) && !sameProbeAllocation(a, b)
}

func (p NativeProbePath) path() dataplane.Path {
	return dataplane.Path{
		SourceID:  p.SourceID,
		Kind:      p.Kind,
		Slot:      p.Slot,
		Interface: p.Interface,
		UDP:       true,
	}
}

func (s *Server) expireNativeProbesLocked() {
	for id, r := range s.nativeProbes {
		if time.Since(r.Seen) > 90*time.Second {
			delete(s.nativeProbes, id)
		}
	}
}

// The registry mutex serializes native registration, packet startup and network
// prepare RPCs. Durable committed and pending allocations always outrank leases.
func (s *Server) validateProbeAllocationLocked(p dataplane.Path) error {
	s.expireNativeProbesLocked()
	for _, r := range s.nativeProbes {
		if probeAllocationConflict(p, r.Path.path()) {
			return errors.New("probe_allocation_conflict")
		}
	}
	for _, record := range s.engines {
		old := engineAllocation(record.Request)
		if probeAllocationConflict(p, old) ||
			p.SourceID == old.SourceID && p.Kind == "tproxy" &&
				(p.Port != old.Port || p.DNSPort != old.DNSPort) {
			return errors.New("probe_allocation_conflict")
		}
	}
	if s.Packet != nil {
		s.Packet.mu.Lock()
		conflict := false
		for id, r := range s.Packet.processes {
			if probeAllocationConflict(
				p,
				dataplane.Path{SourceID: id, Kind: "packet-engine", Slot: uint16(r.slot)},
			) {
				conflict = true
				break
			}
		}
		s.Packet.mu.Unlock()
		if conflict {
			return errors.New("probe_allocation_conflict")
		}
	}
	// Never hold the packet mutex while reading the transaction journal:
	// a concurrent backend preflight may hold that journal and inspect Packet.
	state, e := s.Manager.Status()
	if e != nil {
		return e
	}
	plans := []*dataplane.Desired{state.Committed}
	if active(state.Transaction) {
		plans = append(plans, &state.Transaction.Candidate, state.Transaction.Previous)
	}
	for _, plan := range plans {
		if plan == nil {
			continue
		}
		for _, old := range plan.Paths {
			if probeAllocationConflict(p, old) {
				return errors.New("probe_allocation_conflict")
			}
		}
	}
	return nil
}

func (s *Server) registerProbe(ctx context.Context, p NativeProbePath) error {
	if e := validateNativeProbe(p); e != nil {
		return e
	}
	if p.Kind == "interface" {
		inspect := s.inspectProbeTunnel
		if inspect == nil {
			inspect = inspectNativeProbeTunnel
		}
		if e := inspect(ctx, p.Interface); e != nil {
			return e
		}
	}
	s.probeMu.Lock()
	defer s.probeMu.Unlock()
	if e := s.validateProbeAllocationLocked(p.path()); e != nil {
		return e
	}
	if s.nativeProbes == nil {
		s.nativeProbes = map[string]nativeProbeRegistration{}
	}
	if _, exists := s.nativeProbes[p.SourceID]; !exists && len(s.nativeProbes) >= 250 {
		return errors.New("probe_resource_limit")
	}
	s.nativeProbes[p.SourceID] = nativeProbeRegistration{Path: p, Seen: time.Now()}
	return nil
}

func (s *Server) unregisterProbe(id string) error {
	if !packetSourceID.MatchString(id) {
		return errors.New("invalid_probe_path")
	}
	s.probeMu.Lock()
	defer s.probeMu.Unlock()
	delete(s.nativeProbes, id)
	return nil
}

func (s *Server) registeredProbe(id string) (dataplane.Path, bool) {
	s.probeMu.Lock()
	defer s.probeMu.Unlock()
	s.expireNativeProbesLocked()
	r, ok := s.nativeProbes[id]
	if ok {
		r.Seen = time.Now()
		s.nativeProbes[id] = r
	}
	return r.Path.path(), ok
}

func inspectNativeProbeTunnel(ctx context.Context, device string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	iface, e := net.InterfaceByName(device)
	if e != nil || iface.Flags&net.FlagUp == 0 {
		return errors.New("probe_interface_unavailable")
	}
	runner := platform.ProductionRunner{}
	raw, e := runner.Run(
		ctx,
		platform.UBusBinary(),
		[]string{"call", "network.interface", "dump"},
		nil,
	)
	if e != nil {
		return errors.New("probe_interface_unavailable")
	}
	interfaces, e := platform.ParseInterfaces(raw)
	if e != nil {
		return errors.New("probe_interface_unavailable")
	}
	raw, e = runner.Run(
		ctx,
		"/sbin/ip",
		[]string{"-details", "-json", "link", "show", "dev", device},
		nil,
	)
	if e != nil {
		return errors.New("probe_interface_unavailable")
	}
	return validateTunnelEvidence(device, interfaces, raw)
}

func validateTunnelEvidence(device string, interfaces []platform.Interface, raw []byte) error {
	observed := false
	for _, i := range interfaces {
		if i.Device == device && i.Up && i.Protocol != "static" && i.Protocol != "dhcp" &&
			i.Protocol != "dhcpv6" {
			observed = true
		}
	}
	var links []struct {
		IfName   string `json:"ifname"`
		LinkInfo struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
	}
	if !observed || json.Unmarshal(raw, &links) != nil || len(links) != 1 ||
		links[0].IfName != device {
		return errors.New("probe_interface_forbidden")
	}
	switch links[0].LinkInfo.Kind {
	case "wireguard", "tun", "gre", "gretap", "ip6gre", "ip6gretap", "ipip", "sit", "vti", "vti6":
		return nil
	}
	return errors.New("probe_interface_forbidden")
}

func (c *Client) RegisterProbe(
	ctx context.Context,
	id, kind string,
	slot int,
	device string,
) error {
	if slot < 1 || slot > 250 {
		return errors.New("invalid_probe_path")
	}
	_, e := c.call(
		ctx,
		Request{
			Operation: "register_probe",
			ProbePath: &NativeProbePath{
				SourceID:  id,
				Kind:      kind,
				Slot:      uint16(slot),
				Interface: device,
			},
		},
	)
	return e
}

func (c *Client) UnregisterProbe(ctx context.Context, id string) error {
	_, e := c.call(ctx, Request{Operation: "unregister_probe", SourceID: id})
	return e
}

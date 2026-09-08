package helper

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/tibeahx/OpenRHP/internal/dataplane"
	"github.com/tibeahx/OpenRHP/internal/platform"
)

func validateProbeAddress(address string) (netip.AddrPort, error) {
	a, e := netip.ParseAddrPort(address)
	if e != nil || (a.Port() != 443 && a.Port() != 53) || a.Addr().Zone() != "" {
		return a, errors.New("invalid_probe_address")
	}
	ip := a.Addr().Unmap()
	if !platform.PublicAddress(ip) {
		return a, errors.New("probe_address_forbidden")
	}
	return netip.AddrPortFrom(ip, a.Port()), nil
}

func (s *Server) probePath(sourceID string) (dataplane.Path, error) {
	if path, ok := s.registeredProbe(sourceID); ok {
		return path, nil
	}
	if s.Packet != nil {
		if slot, ok := s.Packet.Path(sourceID); ok {
			return dataplane.Path{
				SourceID: sourceID,
				Kind:     "packet-engine",
				Slot:     uint16(slot),
				UDP:      true,
			}, nil
		}
	}
	state, e := s.Manager.Status()
	if e != nil {
		return dataplane.Path{}, e
	}
	d := state.Committed
	if state.Transaction != nil && active(state.Transaction) {
		d = &state.Transaction.Candidate
	}
	if d == nil {
		return dataplane.Path{}, errors.New("probe_path_unprepared")
	}
	for _, p := range d.Paths {
		if p.SourceID == sourceID && p.Kind == "packet-engine" {
			return p, errors.New("probe_path_unprepared")
		}
		if p.SourceID == sourceID {
			if p.Kind != "direct" && p.Kind != "interface" && p.Kind != "packet-engine" {
				return p, errors.New("probe_path_unsupported")
			}
			return p, nil
		}
	}
	return dataplane.Path{}, errors.New("probe_path_unprepared")
}

func (s *Server) handleProbe(ctx context.Context, c *net.UnixConn, r Request) {
	address, e := validateProbeAddress(r.Address)
	if e != nil {
		writeResponse(c, Response{Error: safeError(e)})
		return
	}
	locals, _ := net.InterfaceAddrs()
	for _, local := range locals {
		prefix, err := netip.ParsePrefix(local.String())
		if err == nil && prefix.Addr().Unmap() == address.Addr() {
			writeResponse(c, Response{Error: "probe_address_forbidden"})
			return
		}
	}
	path, e := s.probePath(r.SourceID)
	if e != nil {
		writeResponse(c, Response{Error: safeError(e)})
		return
	}
	if path.Kind == "interface" {
		inspect := s.inspectProbeTunnel
		if inspect == nil {
			inspect = inspectNativeProbeTunnel
		}
		if e = inspect(ctx, path.Interface); e != nil {
			writeResponse(c, Response{Error: safeError(e)})
			return
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, e := dialMarked(
		ctx,
		path,
		net.JoinHostPort(address.Addr().String(), strconv.Itoa(int(address.Port()))),
	)
	if e != nil {
		writeResponse(c, Response{Error: "probe_connect_failed"})
		return
	}
	defer func() { _ = conn.Close() }()
	if e = sendConn(c, conn); e != nil {
		return
	}
}

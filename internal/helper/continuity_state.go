package helper

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/adapter"
	"github.com/tibeahx/RouteHarbor/internal/dataplane"
)

func validateContinuitySource(p adapter.Path) error {
	if p.Queue != uint16(21000+p.Slot) {
		return errors.New("invalid_continuity_source")
	}
	seen := map[int]bool{}
	for _, port := range []int{p.ProxyPort, p.TransparentPort, p.DNSPort} {
		if port == 0 {
			continue
		}
		if port < 1024 || port > 65535 || seen[port] {
			return errors.New("invalid_continuity_source")
		}
		seen[port] = true
	}
	switch p.Kind {
	case "direct", "interface", "packet-engine":
		if p.ProxyPort != 0 || p.TransparentPort != 0 || p.DNSPort != 0 {
			return errors.New("invalid_continuity_source")
		}
	case "sing-box", "xray", "socks5", "http-connect":
		if p.ProxyPort == 0 || p.TransparentPort == 0 || p.Interface != "" {
			return errors.New("invalid_continuity_source")
		}
	default:
		return errors.New("invalid_continuity_source")
	}
	return nil
}

func continuitySourceAllocation(p adapter.Path) dataplane.Path {
	kind := p.Kind
	if p.ProxyPort != 0 {
		kind = "tproxy"
	}
	return dataplane.Path{
		SourceID:  p.SourceID,
		Kind:      kind,
		Slot:      uint16(p.Slot),
		Port:      uint16(p.TransparentPort),
		DNSPort:   uint16(p.DNSPort),
		Interface: p.Interface,
		IPv6:      p.IPv6,
		UDP:       p.UDP,
	}
}

func sameContinuitySources(paths []dataplane.Path, sources []adapter.Path) bool {
	if len(paths) != len(sources) {
		return false
	}
	byID := map[string]dataplane.Path{}
	for _, p := range paths {
		byID[p.SourceID] = p
	}
	for _, p := range sources {
		if actual, ok := byID[p.SourceID]; !ok || actual != continuitySourceAllocation(p) {
			return false
		}
	}
	return true
}

func (s *Server) validateContinuitySourcesLocked(sources []adapter.Path) error {
	for _, p := range sources {
		allocation := continuitySourceAllocation(p)
		if err := s.validateProbeAllocationLocked(allocation); err != nil {
			return err
		}
		if p.ProxyPort != 0 {
			e := s.engines[p.SourceID]
			if e == nil || !e.ready {
				return errors.New("continuity_source_unowned")
			}
			select {
			case <-e.done:
				return errors.New("continuity_source_unavailable")
			default:
			}
			expected := e.Request.Path
			expected.DNSResolver = "" // Internal-only adapter annotation is absent from wire requests.
			p.DNSResolver = ""
			if !reflect.DeepEqual(expected, p) {
				return errors.New("continuity_source_mismatch")
			}
			continue
		}
		if p.Kind == "packet-engine" {
			if s.Packet == nil || !s.Packet.Running(p.SourceID, p.Slot) {
				return errors.New("continuity_source_unavailable")
			}
			continue
		}
		// A native source must have an independently registered lease or a durable
		// confirmed allocation. Caller-supplied source metadata alone grants nothing.
		registered := false
		if r, ok := s.nativeProbes[p.SourceID]; ok {
			registered = sameProbeAllocation(allocation, r.Path.path())
		}
		if !registered {
			state, err := s.Manager.Status()
			if err != nil {
				return err
			}
			if state.Committed != nil {
				for _, old := range state.Committed.Paths {
					if sameProbeAllocation(old, allocation) {
						registered = true
					}
				}
			}
		}
		if !registered {
			return errors.New("continuity_source_unowned")
		}
	}
	return nil
}

type continuityCommand struct {
	request ContinuityRequest
	result  chan error
}

func (r *continuityRegistration) sendCommand(ctx context.Context, request ContinuityRequest) error {
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	job := continuityCommand{request: request, result: make(chan error, 1)}
	select {
	case r.commands <- job:
	case <-r.done:
		return errors.New("continuity_unavailable")
	case <-bounded.Done():
		return errors.New("continuity_command_busy")
	}
	select {
	case err := <-job.result:
		return err
	case <-r.done:
		return errors.New("continuity_unavailable")
	case <-bounded.Done():
		return errors.New("continuity_command_timeout")
	}
}

func (r *continuityRegistration) writeCommands(pipe io.WriteCloser, life io.Closer) {
	// Only this goroutine writes to the bounded worker pipe. RPCs never hold the
	// status/registry lock while a slow or failed worker is consuming commands.
	for {
		select {
		case <-r.done:
			return
		case job := <-r.commands:
			deadline, ok := pipe.(interface{ SetWriteDeadline(time.Time) error })
			var err error
			if !ok {
				err = errors.New("continuity_command_deadline_unavailable")
			} else {
				err = deadline.SetWriteDeadline(time.Now().Add(time.Second))
			}
			if err == nil {
				err = json.NewEncoder(pipe).Encode(job.request)
			}
			job.result <- err
			if err != nil {
				_ = life.Close()
				return
			}
		}
	}
}

func (r *continuityRegistration) readStatus(reader *bufio.Reader, life io.Closer) {
	for {
		// ReadSlice never accumulates an unbounded line from a corrupted worker.
		line, err := reader.ReadSlice('\n')
		if err != nil || len(line) > MaxRequestBytes {
			_ = life.Close()
			return
		}
		var status ContinuityStatus
		if DecodeStrict(line, &status) != nil {
			_ = life.Close()
			return
		}
		r.mu.Lock()
		r.status = status
		r.mu.Unlock()
	}
}

// Configured relay dials cannot be redirected to a service on the router itself,
// including a public WAN address. No kernel addresses are returned to the caller.
func validateLiveContinuityRelay(address string) error {
	endpoint, err := netip.ParseAddrPort(address)
	if err != nil || endpoint.Addr().Is4In6() {
		return errors.New("continuity_relay_forbidden")
	}
	locals, err := net.InterfaceAddrs()
	if err != nil {
		return errors.New("continuity_relay_unavailable")
	}
	for _, local := range locals {
		prefix, e := netip.ParsePrefix(local.String())
		if e == nil && prefix.Addr().Unmap() == endpoint.Addr() {
			return errors.New("continuity_relay_forbidden")
		}
	}
	return nil
}

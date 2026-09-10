package adapter

import (
	"errors"
	"net"

	"github.com/tibeahx/RouteHarbor/internal/model"
)

const ContinuitySourceID = "__continuity"

// ReserveContinuity participates in the same mark and listener allocator as
// source engines. A restored allocation is never silently renumbered.
func (m *Manager) ReserveContinuity(restored *Path, ipv6, dns bool) (Path, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old := m.paths[ContinuitySourceID]; old != nil {
		if restored != nil && old.path != *restored {
			return Path{}, errors.New("continuity_restore_allocation_mismatch")
		}
		if old.path.Kind != "continuity" || old.path.IPv6 != ipv6 ||
			(old.path.DNSPort != 0) != dns {
			return Path{}, errors.New("continuity_allocation_requires_decommission")
		}
		return old.path, nil
	}
	used := map[int]bool{}
	for _, p := range m.paths {
		used[p.path.Slot] = true
	}
	for _, p := range m.restored {
		used[p.Slot] = true
	}
	slot := MaxActivePaths
	for slot > 0 && used[slot] {
		slot--
	}
	if restored != nil {
		slot = restored.Slot
	}
	if slot < 1 || slot > MaxActivePaths || used[slot] {
		return Path{}, errors.New("continuity_allocation_exhausted")
	}
	p := AllocatePath(ContinuitySourceID, "continuity", slot)
	p.IPv6, p.UDP = ipv6, true
	var ports []net.Listener
	var err error
	if restored != nil {
		if restored.SourceID != ContinuitySourceID || restored.Kind != "continuity" ||
			restored.IPv6 != ipv6 ||
			!restored.UDP ||
			restored.TransparentPort < 1024 ||
			(restored.DNSPort != 0) != dns {
			return Path{}, errors.New("continuity_restore_invalid")
		}
		p = *restored
		values := []int{p.TransparentPort}
		if dns {
			values = append(values, p.DNSPort)
		}
		ports, err = reserveFixedPorts(values)
	} else {
		count := 1
		if dns {
			count++
		}
		ports, err = reservePorts(count)
		if err == nil {
			p.TransparentPort = ports[0].Addr().(*net.TCPAddr).Port
			if dns {
				p.DNSPort = ports[1].Addr().(*net.TCPAddr).Port
			}
		}
	}
	if err != nil {
		return Path{}, errors.New("continuity_input_unavailable")
	}
	m.paths[ContinuitySourceID] = &prepared{
		source:       model.Source{ID: ContinuitySourceID, Type: "continuity", Enabled: true},
		path:         p,
		state:        "prepared",
		reservations: ports,
	}
	return p, nil
}

func (m *Manager) ReleaseContinuityInputs() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p := m.paths[ContinuitySourceID]; p != nil {
		releaseReservations(p)
	}
}

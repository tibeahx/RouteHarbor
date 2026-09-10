package adapter

import (
	"errors"
	"net"

	"github.com/tibeahx/RouteHarbor/internal/model"
)

const DispatcherSourceID = "__selective"

type DispatcherAllocation struct {
	FakePool     uint8 `json:"fake_pool"`
	Path         Path  `json:"path"`
	DNSFrontPort int   `json:"dns_front_port"`
	DirectPort   int   `json:"direct_port"`
	APIPort      int   `json:"api_port"`
}

// ReserveDispatcher shares the source allocator. Public ingress allocations are
// restored exactly; private engine inputs may be freshly allocated after restart.
func (m *Manager) ReserveDispatcher(
	restored *Path,
	front int,
	ipv6 bool,
) (DispatcherAllocation, error) {
	return m.ReserveDispatcherFor(DispatcherSourceID, restored, front, ipv6)
}

func (m *Manager) ReserveDispatcherFor(
	key string,
	restored *Path,
	front int,
	ipv6 bool,
) (DispatcherAllocation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.paths[key] != nil {
		return DispatcherAllocation{}, errors.New("dispatcher_already_reserved")
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
		return DispatcherAllocation{}, errors.New("dispatcher_allocation_exhausted")
	}
	p := AllocatePath(DispatcherSourceID, "dispatcher", slot)
	p.IPv6, p.UDP = ipv6, true
	var held []net.Listener
	if restored != nil {
		if restored.SourceID != DispatcherSourceID || restored.TransparentPort < 1024 ||
			front < 1024 {
			return DispatcherAllocation{}, errors.New("dispatcher_restore_invalid")
		}
		var err error
		held, err = reserveFixedPorts([]int{restored.TransparentPort, front})
		if err != nil {
			return DispatcherAllocation{}, err
		}
	}
	n := 6
	if restored != nil {
		n = 4
	}
	ports, err := reservePorts(n)
	if err != nil {
		for _, l := range held {
			_ = l.Close()
		}
		return DispatcherAllocation{}, err
	}
	if restored == nil {
		held = ports[:2]
		ports = ports[2:]
	}
	p.TransparentPort = held[0].Addr().(*net.TCPAddr).Port
	front = held[1].Addr().(*net.TCPAddr).Port
	p.ProxyPort = ports[0].Addr().(*net.TCPAddr).Port
	p.DNSPort = ports[1].Addr().(*net.TCPAddr).Port
	a := DispatcherAllocation{
		Path:         p,
		DNSFrontPort: front,
		DirectPort:   ports[2].Addr().(*net.TCPAddr).Port,
		APIPort:      ports[3].Addr().(*net.TCPAddr).Port,
	}
	m.paths[key] = &prepared{
		source:       model.Source{ID: DispatcherSourceID, Type: "dispatcher", Enabled: true},
		path:         p,
		state:        "prepared",
		reservations: append(held, ports...),
	}
	return a, nil
}

func (m *Manager) ReleaseDispatcherInputs() { m.ReleaseDispatcherInputsFor(DispatcherSourceID) }
func (m *Manager) ReleaseDispatcherInputsFor(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p := m.paths[key]; p != nil {
		releaseReservations(p)
	}
}

func (m *Manager) ForgetDispatcher() { m.ForgetDispatcherFor(DispatcherSourceID) }
func (m *Manager) ForgetDispatcherFor(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p := m.paths[key]; p != nil {
		releaseReservations(p)
		delete(m.paths, key)
	}
}

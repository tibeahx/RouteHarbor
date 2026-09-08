package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tibeahx/OpenRHP/internal/model"
	"github.com/tibeahx/OpenRHP/internal/platform"
)

const (
	MarkNamespace  uint32 = 0x4f000000
	MarkMask       uint32 = 0xffff0000
	MaxActivePaths        = 250 // finite routing and NFQUEUE resource allocation, not a saved-source limit
)

type Path struct {
	IPv6            bool     `json:"ipv6"`
	UDP             bool     `json:"udp"`
	SourceID        string   `json:"source_id"`
	Kind            string   `json:"kind"`
	ProxyURL        *url.URL `json:"-"`
	ProxyPort       int      `json:"proxy_port,omitempty"`
	DNSPort         int      `json:"dns_port,omitempty"`
	DNSResolver     string   `json:"-"`
	TransparentPort int      `json:"transparent_port,omitempty"`
	Interface       string   `json:"interface,omitempty"`
	Mark            uint32   `json:"mark"`
	Queue           uint16   `json:"queue,omitempty"`
	Slot            int      `json:"slot"`
}
type Status struct {
	SourceID  string `json:"source_id"`
	State     string `json:"state"`
	ErrorCode string `json:"error_code,omitempty"`
	Path      *Path  `json:"path,omitempty"`
}
type Adapter interface {
	Validate(model.Source) error
	Prepare(context.Context, model.Source) error
	Start(context.Context, model.Source) error
	Stop(context.Context, string) error
	ProbePath(context.Context, model.Source) (Path, error)
	Status(string) Status
}
type prepared struct {
	reservations []net.Listener
	engine       string
	engineSource model.Source
	managed      ManagedProcess
	source       model.Source
	path         Path
	config       string
	cmd          *exec.Cmd
	done         chan struct{}
	state        string
	errorCode    string
}
type ManagedProcess interface {
	Alive() bool
	Done() <-chan struct{}
	Close(context.Context) error
}
type ManagedEngineLauncher interface {
	StartEngine(context.Context, model.Source, Path) (ManagedProcess, error)
}
type NativeProbeLifecycle interface {
	RegisterProbe(context.Context, string, string, int, string) error
	UnregisterProbe(context.Context, string) error
}
type PacketLifecycle interface {
	StartPacket(context.Context, string, int) error
	StopPacket(context.Context, string) error
}

type Manager struct {
	ManagedEngines ManagedEngineLauncher
	NativeProbes   NativeProbeLifecycle
	Packet         PacketLifecycle
	DNSResolver    string
	LookupHost     func(context.Context, string) ([]string, error)
	// EnableTransparent requires sing-box to bridge external SOCKS/CONNECT sources into a LAN input. Set before first use.
	EnableTransparent bool
	EnableIPv6        bool
	lifecycle         sync.RWMutex
	mu                sync.Mutex
	runtimeDir        string
	paths             map[string]*prepared
	restored          map[string]Path
	// buildCommand is an internal test seam; production always uses the fixed, verified engine builder.
	buildCommand func(context.Context, string, string) (*exec.Cmd, error)
}

func NewManager(runtimeDir string) *Manager {
	return &Manager{
		runtimeDir: runtimeDir,
		paths:      make(map[string]*prepared),
		restored:   make(map[string]Path),
	}
}

func (m *Manager) Validate(s model.Source) error {
	return ValidateSource(s)
}

func Mark(slot int) uint32 {
	return MarkNamespace | uint32(slot)<<16
}

func AllocatePath(id, kind string, slot int) Path {
	return Path{
		SourceID: id,
		Kind:     kind,
		Slot:     slot,
		Mark:     Mark(slot),
		Queue:    uint16(21000 + slot),
		UDP:      kind != "http-connect",
	}
}

func reservePorts(count int) ([]net.Listener, error) {
	listeners := make([]net.Listener, 0, count)
	for i := 0; i < count; i++ {
		l, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			for _, open := range listeners {
				_ = open.Close()
			}
			return nil, e
		}
		listeners = append(listeners, l)
	}
	return listeners, nil
}

func releaseReservations(p *prepared) {
	for _, l := range p.reservations {
		_ = l.Close()
	}
	p.reservations = nil
}

// Prepare reserves local inputs, resolves only an explicitly configured engine endpoint, and writes a private generated config. It never starts a process or changes routes.
func (m *Manager) Prepare(ctx context.Context, s model.Source) error {
	m.lifecycle.RLock()
	defer m.lifecycle.RUnlock()
	return m.prepare(ctx, s)
}

func (m *Manager) prepare(ctx context.Context, s model.Source) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateSource(s); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if old := m.paths[s.ID]; old != nil {
		if old.source.Type == s.Type && bytes.Equal(old.source.Settings, s.Settings) {
			old.source = s
			if m.NativeProbes != nil && (s.Type == "direct" || s.Type == "interface") {
				return m.NativeProbes.RegisterProbe(
					ctx,
					s.ID,
					s.Type,
					old.path.Slot,
					old.path.Interface,
				)
			}
			return nil
		}
		return errors.New("stop source before changing its prepared settings")
	}
	used := map[int]bool{}
	for id, p := range m.restored {
		if id != s.ID {
			used[p.Slot] = true
		}
	}
	for _, p := range m.paths {
		used[p.path.Slot] = true
	}
	slot := 1
	for used[slot] {
		slot++
	}
	if previous, ok := m.restored[s.ID]; ok {
		slot = previous.Slot
	}
	if slot > MaxActivePaths {
		return errors.New("no free source routing slot; stop an unused source")
	}
	p := &prepared{source: s, path: AllocatePath(s.ID, s.Type, slot), state: "prepared"}
	p.path.IPv6 = m.EnableIPv6
	restored, restoring := m.restored[s.ID]
	if s.Type == "sing-box" {
		var o SingOutbound
		_ = StrictDecode(s.Settings, &o)
		p.path.UDP = o.Type != "http"
	}
	if s.Type == "sing-box" || s.Type == "xray" {
		p.engine = s.Type
	}
	if m.EnableTransparent && (s.Type == "socks5" || s.Type == "http-connect") {
		p.engine = "sing-box"
	}
	switch s.Type {
	case "socks5", "http-connect":
		var v ProxySettings
		_ = StrictDecode(s.Settings, &v)
		scheme := "socks5"
		if s.Type == "http-connect" {
			scheme = "http"
		}
		u := &url.URL{Scheme: scheme, Host: net.JoinHostPort(v.Server, strconv.Itoa(v.ServerPort))}
		if v.Username != "" {
			u.User = url.UserPassword(v.Username, v.Password)
		}
		p.path.ProxyURL = u
	case "interface":
		var v InterfaceSettings
		_ = StrictDecode(s.Settings, &v)
		p.path.Interface = v.Name
	}
	if p.engine != "" {
		count := 2
		if m.DNSResolver != "" {
			count = 3
		}
		var listeners []net.Listener
		var e error
		if restoring {
			count = 2
			if restored.DNSPort != 0 {
				count = 3
			}
			ports := []int{0, restored.TransparentPort}
			if count == 3 {
				ports = append(ports, restored.DNSPort)
			}
			listeners, e = reserveFixedPorts(ports)
		} else {
			listeners, e = reservePorts(count)
		}
		if e != nil {
			return errors.New("engine_input_conflict: could not reserve the source input ports")
		}
		p.reservations = listeners
		p.path.ProxyPort = listeners[0].Addr().(*net.TCPAddr).Port
		p.path.TransparentPort = listeners[1].Addr().(*net.TCPAddr).Port
		if count == 3 {
			p.path.DNSPort = listeners[2].Addr().(*net.TCPAddr).Port
			p.path.DNSResolver = m.DNSResolver
		}
		p.path.ProxyURL = &url.URL{
			Scheme: "socks5",
			Host:   net.JoinHostPort("127.0.0.1", strconv.Itoa(p.path.ProxyPort)),
		}
		defer func() {
			if m.paths[s.ID] != p {
				releaseReservations(p)
			}
		}()
	}

	if p.engine != "" {
		if m.runtimeDir == "" {
			return errors.New("engine runtime directory is required")
		}
		if err := os.MkdirAll(m.runtimeDir, 0o700); err != nil {
			return errors.New("cannot create engine runtime")
		}
		info, e := os.Lstat(m.runtimeDir)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0o077 != 0 {
			return errors.New("engine runtime directory must be private")
		}
		pinned, e := m.pinEndpoint(ctx, s)
		if e != nil {
			return e
		}
		p.engineSource = pinned
		raw, e := EngineConfig(pinned, p.path)
		if e != nil {
			return e
		}
		p.config = filepath.Join(m.runtimeDir, s.ID+".json")
		if e = writePrivate(p.config, raw); e != nil {
			return errors.New("could not write private engine configuration")
		}
	}
	if m.NativeProbes != nil && (s.Type == "direct" || s.Type == "interface") {
		if e := m.NativeProbes.RegisterProbe(
			ctx,
			s.ID,
			s.Type,
			p.path.Slot,
			p.path.Interface,
		); e != nil {
			return e
		}
	}
	m.paths[s.ID] = p
	return nil
}

func writePrivate(path string, raw []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".engine-*")
	if e != nil {
		return e
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if e = f.Chmod(0o600); e == nil {
		_, e = f.Write(raw)
	}
	if e == nil {
		e = f.Sync()
	}
	if c := f.Close(); e == nil {
		e = c
	}
	if e == nil {
		e = os.Rename(f.Name(), path)
	}
	return e
}

// Start runs only fixed installed engines, as the service user. No arbitrary executable or argv is imported.
func (m *Manager) Start(ctx context.Context, s model.Source) error {
	m.lifecycle.RLock()
	defer m.lifecycle.RUnlock()
	if e := m.prepare(ctx, s); e != nil {
		return e
	}
	m.mu.Lock()
	p := m.paths[s.ID]
	if p.managed != nil && !p.managed.Alive() {
		p.managed = nil
		p.state = "failed"
		p.errorCode = "engine_exited"
	}
	if p.state == "running" && s.Type != "packet-engine" {
		m.mu.Unlock()
		return nil
	}
	if s.Type == "packet-engine" && m.Packet != nil {
		slot := p.path.Slot
		m.mu.Unlock()
		if e := m.Packet.StartPacket(ctx, s.ID, slot); e != nil {
			return e
		}
		m.mu.Lock()
		if current := m.paths[s.ID]; current == p {
			p.state = "running"
		}
		m.mu.Unlock()
		return nil
	}
	if s.Type == "packet-engine" {
		p.state = "unavailable"
		p.errorCode = "privileged_packet_engine_required"
		m.mu.Unlock()
		return errors.New("packet engine requires the privileged helper and verified nfqws package")
	}
	if s.Type == "interface" {
		if _, e := net.InterfaceByName(p.path.Interface); e != nil {
			p.state = "unavailable"
			p.errorCode = "interface_missing"
			m.mu.Unlock()
			return errors.New("configured interface is unavailable")
		}
	}
	if p.engine == "" {
		p.state = "running"
		m.mu.Unlock()
		return nil
	}
	if m.ManagedEngines != nil {
		releaseReservations(p)
		process, e := m.ManagedEngines.StartEngine(ctx, p.engineSource, p.path)
		if e != nil {
			p.state = "failed"
			p.errorCode = "managed_engine_start_failed"
			m.mu.Unlock()
			return e
		}
		p.managed = process
		p.state = "running"
		p.errorCode = ""
		m.mu.Unlock()
		go func() {
			<-process.Done()
			m.mu.Lock()
			if p.managed == process {
				p.managed = nil
				p.state = "failed"
				p.errorCode = "engine_exited"
			}
			m.mu.Unlock()
		}()
		return nil
	}
	engine, config := p.engine, p.config
	build := m.buildCommand
	if build == nil {
		build = verifiedEngineCommand
	}
	if p.cmd != nil {
		cmd, done := p.cmd, p.done
		m.mu.Unlock()
		return m.waitEngineReady(ctx, p, cmd, done)
	}
	m.mu.Unlock()
	cmd, e := build(ctx, engine, config)
	if e != nil {
		m.mu.Lock()
		if m.paths[s.ID] == p && p.cmd == nil {
			p.state, p.errorCode = "failed", "engine_validation_failed"
			if strings.HasPrefix(e.Error(), "engine_missing:") {
				p.state, p.errorCode = "unavailable", "engine_missing"
			}
		}
		m.mu.Unlock()
		return e
	}
	m.mu.Lock()
	if m.paths[s.ID] != p {
		m.mu.Unlock()
		return errors.New("source stopped or changed during start")
	}
	if p.cmd != nil {
		cmd, done := p.cmd, p.done
		m.mu.Unlock()
		return m.waitEngineReady(ctx, p, cmd, done)
	}
	releaseReservations(p)
	if e := cmd.Start(); e != nil {
		p.state = "failed"
		p.errorCode = "engine_start_failed"
		m.mu.Unlock()
		return errors.New("engine failed to start")
	}
	done := make(chan struct{})
	p.cmd, p.done = cmd, done
	p.state, p.errorCode = "starting", ""
	m.mu.Unlock()
	go func() {
		_ = cmd.Wait()
		m.mu.Lock()
		// A waiter may outlive Stop and another generation. Only its own
		// process may clear state; close the captured generation's channel.
		if p.cmd == cmd {
			p.cmd, p.done = nil, nil
			p.state, p.errorCode = "failed", "engine_exited"
		}
		close(done)
		m.mu.Unlock()
	}()
	return m.waitEngineReady(ctx, p, cmd, done)
}

func verifiedEngineCommand(ctx context.Context, engine, config string) (*exec.Cmd, error) {
	binary := "/usr/bin/" + engine
	if _, e := os.Stat(binary); e != nil {
		return nil, errors.New("engine_missing: supported engine package is not installed")
	}
	if e := verifyEngine(ctx, engine, binary); e != nil {
		return nil, e
	}
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	args := []string{"check", "-c", config}
	if engine == "xray" {
		args = []string{"run", "-test", "-config", config}
	}
	check := exec.CommandContext(checkCtx, binary, args...)
	if e := check.Run(); e != nil {
		return nil, errors.New("generated engine configuration failed native validation")
	}
	args = []string{"run", "-c", config}
	if engine == "xray" {
		args = []string{"run", "-config", config}
	}
	cmd := exec.Command(binary, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	superviseEngine(cmd)
	return cmd, nil
}

func (m *Manager) waitEngineReady(
	ctx context.Context,
	p *prepared,
	cmd *exec.Cmd,
	done chan struct{},
) error {
	readyCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ports := []int{p.path.ProxyPort, p.path.TransparentPort}
	if p.path.DNSPort != 0 {
		ports = append(ports, p.path.DNSPort)
	}
	addresses := []string{}
	for i, port := range ports {
		addresses = append(addresses, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if p.path.IPv6 && i > 0 {
			addresses = append(addresses, net.JoinHostPort("::1", strconv.Itoa(port)))
		}
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		ready := true
		for _, address := range addresses {
			d := net.Dialer{Timeout: 50 * time.Millisecond}
			c, err := d.DialContext(readyCtx, "tcp", address)
			if err != nil {
				ready = false
				break
			}
			_ = c.Close()
		}
		if ready {
			m.mu.Lock()
			if m.paths[p.path.SourceID] == p && p.cmd == cmd {
				p.state, p.errorCode = "running", ""
				m.mu.Unlock()
				return nil
			}
			m.mu.Unlock()
			return errors.New("engine exited or source stopped during initialization")
		}
		select {
		case <-done:
			return errors.New("engine exited during initialization")
		case <-readyCtx.Done():
			m.mu.Lock()
			if p.cmd == cmd {
				_ = cmd.Process.Kill()
			}
			m.mu.Unlock()
			return errors.New("engine input did not become ready before startup deadline")
		case <-ticker.C:
		}
	}
}

func (m *Manager) Stop(ctx context.Context, id string) error {
	m.lifecycle.RLock()
	defer m.lifecycle.RUnlock()
	return m.stop(ctx, id)
}

func (m *Manager) stop(ctx context.Context, id string) error {
	m.mu.Lock()
	p := m.paths[id]
	if p == nil {
		delete(m.restored, id)
		m.mu.Unlock()
		return nil
	}
	delete(m.paths, id)
	delete(m.restored, id)
	releaseReservations(p)
	cmd, done, managed := p.cmd, p.done, p.managed
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(os.Interrupt)
	}
	m.mu.Unlock()
	if m.NativeProbes != nil && (p.source.Type == "direct" || p.source.Type == "interface") {
		if e := m.NativeProbes.UnregisterProbe(ctx, id); e != nil {
			return e
		}
	}
	if p.source.Type == "packet-engine" && m.Packet != nil {
		if e := m.Packet.StopPacket(ctx, id); e != nil {
			return e
		}
	}
	if managed != nil {
		if e := managed.Close(ctx); e != nil {
			return e
		}
	}
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			return ctx.Err()
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}
	if p.config != "" {
		_ = os.Remove(p.config)
	}
	return nil
}

func (m *Manager) ProbePath(ctx context.Context, s model.Source) (Path, error) {
	m.lifecycle.RLock()
	defer m.lifecycle.RUnlock()
	if e := m.prepare(ctx, s); e != nil {
		return Path{}, e
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.paths[s.ID]
	if p == nil {
		return Path{}, errors.New("source stopped during probe preparation")
	}
	path := p.path
	if path.ProxyURL != nil {
		u := *path.ProxyURL
		path.ProxyURL = &u
	}
	return path, nil
}

func (m *Manager) Status(id string) Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.paths[id]
	if p == nil {
		return Status{SourceID: id, State: "stopped"}
	}
	path := p.path
	path.ProxyURL = nil
	return Status{SourceID: id, State: p.state, ErrorCode: p.errorCode, Path: &path}
}

// EngineConfig produces only owned inputs plus exactly one validated outbound.
func EngineConfig(s model.Source, p Path) ([]byte, error) {
	if s.Type == "socks5" || s.Type == "http-connect" {
		if e := ValidateSource(s); e != nil {
			return nil, e
		}
		var v ProxySettings
		_ = StrictDecode(s.Settings, &v)
		kind := "socks"
		if s.Type == "http-connect" {
			kind = "http"
		}
		raw, _ := json.Marshal(
			SingOutbound{
				Type:       kind,
				Server:     v.Server,
				ServerPort: v.ServerPort,
				Username:   v.Username,
				Password:   v.Password,
			},
		)
		s.Type = "sing-box"
		s.Settings = raw
	}
	if err := ValidateSource(s); err != nil {
		return nil, err
	}
	if p.ProxyPort < 1 || p.TransparentPort < 1 {
		return nil, errors.New("allocated input ports required")
	}
	var out any
	switch s.Type {
	case "sing-box":
		var o SingOutbound
		_ = StrictDecode(s.Settings, &o)
		raw, _ := json.Marshal(o)
		var outbound map[string]any
		_ = json.Unmarshal(raw, &outbound)
		outbound["tag"] = "source"
		out = map[string]any{
			"log": map[string]any{"disabled": true},
			"inbounds": []any{
				map[string]any{
					"type":        "socks",
					"tag":         "probe",
					"listen":      "127.0.0.1",
					"listen_port": p.ProxyPort,
				},
				map[string]any{
					"type":        "tproxy",
					"tag":         "lan",
					"listen":      "127.0.0.1",
					"listen_port": p.TransparentPort,
					"network":     "tcp",
				},
			},
			"outbounds": []any{outbound},
			"route":     map[string]any{"final": "source"},
		}
	case "xray":
		var x XraySettings
		_ = StrictDecode(s.Settings, &x)
		o, e := normalizeXray(x)
		if e != nil {
			return nil, e
		}
		out = map[string]any{
			"log": map[string]any{"loglevel": "none"},
			"inbounds": []any{
				map[string]any{
					"listen":   "127.0.0.1",
					"port":     p.ProxyPort,
					"protocol": "socks",
					"settings": map[string]any{"auth": "noauth", "udp": true},
				},
				map[string]any{
					"listen":         "127.0.0.1",
					"port":           p.TransparentPort,
					"protocol":       "dokodemo-door",
					"settings":       map[string]any{"network": "tcp,udp", "followRedirect": true},
					"streamSettings": map[string]any{"sockopt": map[string]any{"tproxy": "tproxy"}},
				},
			},
			"outbounds": []any{o},
		}
	default:
		return nil, errors.New("source has no generated engine configuration")
	}
	if p.UDP && s.Type == "sing-box" {
		c := out.(map[string]any)
		in := c["inbounds"].([]any)
		delete(in[1].(map[string]any), "network")
	}
	if p.DNSPort != 0 {
		ip, e := netip.ParseAddr(p.DNSResolver)
		if e != nil || !platform.PublicAddress(ip) {
			return nil, errors.New("an explicit public DNS resolver IP is required")
		}
		config := out.(map[string]any)
		ins := config["inbounds"].([]any)
		if s.Type == "sing-box" {
			ins = append(
				ins,
				map[string]any{
					"type":        "direct",
					"tag":         "dns-input",
					"listen":      "127.0.0.1",
					"listen_port": p.DNSPort,
				},
			)
			config["dns"] = map[string]any{
				"servers": []any{
					map[string]any{
						"type":        "tcp",
						"tag":         "selected-dns",
						"server":      p.DNSResolver,
						"server_port": 53,
						"detour":      "source",
					},
				},
				"final": "selected-dns",
			}
			config["route"].(map[string]any)["rules"] = []any{
				map[string]any{"inbound": []string{"dns-input"}, "action": "hijack-dns"},
			}
		} else {
			ins = append(
				ins,
				map[string]any{
					"listen":   "127.0.0.1",
					"port":     p.DNSPort,
					"protocol": "dokodemo-door",
					"settings": map[string]any{
						"address": p.DNSResolver,
						"port":    53,
						"network": "tcp,udp",
					},
				},
			)
		}
		config["inbounds"] = ins
	}
	if p.IPv6 {
		config := out.(map[string]any)
		ins := config["inbounds"].([]any)
		extra := []any{}
		for index, inbound := range ins {
			if index == 0 {
				continue
			}
			original := inbound.(map[string]any)
			copy := map[string]any{}
			for k, v := range original {
				copy[k] = v
			}
			copy["listen"] = "::1"
			if tag, ok := copy["tag"].(string); ok {
				copy["tag"] = tag + "-v6"
			}
			extra = append(extra, copy)
		}
		config["inbounds"] = append(ins, extra...)
		if s.Type == "sing-box" && p.DNSPort != 0 {
			config["route"].(map[string]any)["rules"] = []any{
				map[string]any{
					"inbound": []string{"dns-input", "dns-input-v6"},
					"action":  "hijack-dns",
				},
			}
		}
	}
	return json.MarshalIndent(out, "", "  ")
}

// PacketArgs is a fixed audited strategy; settings never contribute arbitrary arguments.
func PacketArgs(slot int) ([]string, error) {
	if slot < 1 || slot > MaxActivePaths {
		return nil, errors.New("invalid queue allocation")
	}
	return []string{
		fmt.Sprintf("--qnum=%d", 21000+slot),
		fmt.Sprintf("--dpi-desync-fwmark=0x%x", Mark(slot)|0x8000),
		"--filter-tcp=443",
		"--dpi-desync=multisplit",
		"--dpi-desync-split-pos=1,midsld",
		"--dpi-desync-repeats=1",
	}, nil
}

// pinEndpoint resolves only the explicitly configured engine endpoint before startup.
// The generated engine receives an IP and retains the original TLS identity, preventing implicit bootstrap DNS in engine routing.
func (m *Manager) pinEndpoint(ctx context.Context, s model.Source) (model.Source, error) {
	var host string
	var sing *SingOutbound
	var proxy *ProxySettings
	var xray *XrayOutbound
	switch s.Type {
	case "sing-box":
		sing = &SingOutbound{}
		_ = StrictDecode(s.Settings, sing)
		host = sing.Server
	case "socks5", "http-connect":
		proxy = &ProxySettings{}
		_ = StrictDecode(s.Settings, proxy)
		host = proxy.Server
	case "xray":
		var settings XraySettings
		_ = StrictDecode(s.Settings, &settings)
		o, e := normalizeXray(settings)
		if e != nil {
			return s, e
		}
		xray = &o
		host = o.Settings.VNext[0].Address
	default:
		return s, nil
	}
	if net.ParseIP(host) != nil {
		return s, nil
	}
	lookup := m.LookupHost
	if lookup == nil {
		lookup = net.DefaultResolver.LookupHost
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ips, e := lookup(bounded, host)
	if e != nil || len(ips) == 0 {
		return s, errors.New(
			"engine_endpoint_dns_failed: could not resolve the configured engine endpoint",
		)
	}
	ip := ""
	for _, a := range ips {
		p := net.ParseIP(a)
		if p == nil {
			continue
		}
		if ip == "" || p.To4() != nil {
			ip = p.String()
		}
		if p.To4() != nil {
			break
		}
	}
	if ip == "" {
		return s, errors.New("engine_endpoint_dns_failed: no usable endpoint address")
	}
	var raw []byte
	if sing != nil {
		sing.Server = ip
		if sing.TLS != nil && sing.TLS.ServerName == "" {
			sing.TLS.ServerName = host
		}
		raw, _ = json.Marshal(sing)
	}
	if proxy != nil {
		proxy.Server = ip
		raw, _ = json.Marshal(proxy)
	}
	if xray != nil {
		xray.Settings.VNext[0].Address = ip
		if xray.Stream.TLS != nil && xray.Stream.TLS.ServerName == "" {
			xray.Stream.TLS.ServerName = host
		}
		raw, _ = json.Marshal(XraySettings{Outbound: xray})
	}
	s.Settings = raw
	return s, nil
}

// ConfigureNetwork replaces input requirements after the caller has established
// that no committed path depends on the old allocations.
func (m *Manager) ConfigureNetwork(ctx context.Context, dns string, ipv6 bool) error {
	m.lifecycle.Lock()
	defer m.lifecycle.Unlock()
	m.mu.Lock()
	if m.DNSResolver == dns && m.EnableIPv6 == ipv6 {
		m.mu.Unlock()
		return nil
	}
	ids := make([]string, 0, len(m.paths))
	for id := range m.paths {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	for _, id := range ids {
		if e := m.stop(ctx, id); e != nil {
			return e
		}
	}
	m.mu.Lock()
	m.DNSResolver, m.EnableIPv6 = dns, ipv6
	m.restored = make(map[string]Path)
	m.mu.Unlock()
	return nil
}

func (m *Manager) Close(ctx context.Context) error {
	m.lifecycle.Lock()
	defer m.lifecycle.Unlock()
	m.mu.Lock()
	ids := make([]string, 0, len(m.paths))
	for id := range m.paths {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	var first error
	for _, id := range ids {
		if e := m.stop(ctx, id); e != nil && first == nil {
			first = e
		}
	}
	return first
}

func reserveFixedPorts(ports []int) ([]net.Listener, error) {
	listeners := make([]net.Listener, 0, len(ports))
	for _, port := range ports {
		l, e := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if e != nil {
			for _, open := range listeners {
				_ = open.Close()
			}
			return nil, e
		}
		listeners = append(listeners, l)
	}
	return listeners, nil
}

// RestoreAllocations is called before the scheduler. It validates trusted helper
// intent against private source configuration, then reserves the same LAN ports
// and marks. It never takes over an occupied listener or changes network rules.
func (m *Manager) RestoreAllocations(
	ctx context.Context,
	sources []model.Source,
	allocations []Path,
) error {
	m.lifecycle.Lock()
	defer m.lifecycle.Unlock()
	byID := map[string]model.Source{}
	for _, s := range sources {
		if e := ValidateSource(s); e != nil {
			return e
		}
		if _, ok := byID[s.ID]; ok {
			return errors.New("duplicate restored source")
		}
		byID[s.ID] = s
	}
	slots := map[int]bool{}
	ports := map[int]bool{}
	restored := map[string]Path{}
	for _, p := range allocations {
		s, ok := byID[p.SourceID]
		if !ok || p.Kind != s.Type || p.Slot < 1 || p.Slot > MaxActivePaths || slots[p.Slot] {
			return errors.New(
				"restored source identity or slot does not match confirmed configuration",
			)
		}
		if _, ok := restored[p.SourceID]; ok {
			return errors.New("duplicate restored source allocation")
		}
		slots[p.Slot] = true
		engine := s.Type == "sing-box" || s.Type == "xray" ||
			m.EnableTransparent && (s.Type == "socks5" || s.Type == "http-connect")
		if engine {
			if p.TransparentPort < 1024 || p.TransparentPort > 65535 {
				return errors.New("invalid restored engine input")
			}
			for _, port := range []int{p.TransparentPort, p.DNSPort} {
				if port == 0 {
					continue
				}
				if port < 1024 || port > 65535 || ports[port] {
					return errors.New("invalid or duplicate restored port")
				}
				ports[port] = true
			}
		} else if p.TransparentPort != 0 || p.DNSPort != 0 {
			return errors.New("native source cannot restore engine inputs")
		}
		if s.Type == "interface" {
			var settings InterfaceSettings
			_ = StrictDecode(s.Settings, &settings)
			if settings.Name != p.Interface {
				return errors.New("restored interface does not match source")
			}
		} else if p.Interface != "" {
			return errors.New("unexpected restored interface")
		}
		if p.Mark != 0 && p.Mark != Mark(p.Slot) {
			return errors.New("invalid restored source mark")
		}
		if p.Queue != 0 && p.Queue != uint16(21000+p.Slot) {
			return errors.New("invalid restored source queue")
		}
		if p.IPv6 != m.EnableIPv6 {
			return errors.New("restored address-family capability does not match confirmed policy")
		}
		udp := s.Type != "http-connect"
		if s.Type == "sing-box" {
			var o SingOutbound
			_ = StrictDecode(s.Settings, &o)
			udp = o.Type != "http"
		}
		if p.UDP != udp {
			return errors.New("restored UDP capability does not match source")
		}
		p.Mark = Mark(p.Slot)
		p.Queue = uint16(21000 + p.Slot)
		p.ProxyURL = nil
		p.ProxyPort = 0
		restored[p.SourceID] = p
	}
	m.mu.Lock()
	if len(m.paths) != 0 {
		m.mu.Unlock()
		return errors.New("restore allocations before preparing sources")
	}
	m.restored = restored
	m.mu.Unlock()
	for _, p := range allocations {
		if e := m.prepare(ctx, byID[p.SourceID]); e != nil {
			m.mu.Lock()
			for id, prepared := range m.paths {
				releaseReservations(prepared)
				if prepared.config != "" {
					_ = os.Remove(prepared.config)
				}
				delete(m.paths, id)
			}
			m.mu.Unlock()
			return e
		}
	}
	return nil
}

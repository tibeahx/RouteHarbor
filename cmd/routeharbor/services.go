package main

import (
	"context"
	"path/filepath"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/api"
	"github.com/tibeahx/RouteHarbor/internal/control"
	"github.com/tibeahx/RouteHarbor/internal/helper"
	"github.com/tibeahx/RouteHarbor/internal/node"
	"github.com/tibeahx/RouteHarbor/internal/platform"
	"github.com/tibeahx/RouteHarbor/internal/probe"
)

// Services are wired here so UI and agent use identical runtime operations.
func wireServices(s *api.Server, state, socket string) error {
	var err error
	state, err = filepath.Abs(state)
	if err != nil {
		return err
	}
	var client *helper.Client
	discover := func(ctx context.Context) (platform.Report, error) {
		return platform.Detect(ctx), nil
	}
	if socket != "" {
		client = &helper.Client{SocketPath: socket, ExpectedUID: 0}
		discover = client.Platform
		s.Platform = discover
	}
	nodes, e := node.NewService(
		filepath.Join(state, "nodes"),
		func(ctx context.Context) node.Capabilities {
			report, err := discover(ctx)
			if err != nil {
				return node.Capabilities{Reason: "Privileged gateway discovery is unavailable"}
			}
			return node.CapabilitiesFrom(report)
		},
	)
	if e != nil {
		return e
	}
	if client != nil {
		if err := nodes.ConfigureGateway(client); err != nil {
			_ = nodes.Close()
			return err
		}
	}
	s.Coverage = nodes
	s.Runtime.Continuity, e = control.NewContinuityControl(
		client,
		filepath.Join(state, "continuity"),
	)
	if e != nil {
		_ = nodes.Close()
		return e
	}
	s.Runtime.Routing, e = control.NewRoutingControl(
		s.Runtime,
		client,
		filepath.Join(state, "routing"),
	)
	if e != nil {
		_ = nodes.Close()
		_ = s.Runtime.Continuity.Close(context.Background())
		return e
	}
	s.Routing = s.Runtime.Routing
	if client != nil {
		s.Maintenance = helper.MaintenanceClient{Client: client}
		s.Runtime.Adapters.EnableTransparent = true
		s.Runtime.Adapters.Packet = client
		s.Runtime.Adapters.NativeProbes = client
		s.Runtime.Adapters.ManagedEngines = client
		s.Runtime.Adapters.DNSResolver = s.Runtime.Store.Get().Network.DNSResolver
		s.Runtime.Adapters.EnableIPv6 = s.Runtime.Store.Get().Network.IPv6 == "proxy"
		if p, ok := s.Runtime.Prober.(*probe.Runner); ok {
			p.DialProbe = client
			p.ConfigureDNS(
				s.Runtime.Store.Get().Network.Enabled,
				s.Runtime.Store.Get().Network.DNSResolver,
			)
		}
		n := &control.NetworkCoordinator{Runtime: s.Runtime, Client: client, Platform: discover}
		s.Network = n
		s.Runtime.Network = n
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = n.Initialize(ctx)
	}
	return nil
}

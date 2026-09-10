package control

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/tibeahx/RouteHarbor/internal/adapter"
	"github.com/tibeahx/RouteHarbor/internal/dataplane"
	"github.com/tibeahx/RouteHarbor/internal/helper"
	"github.com/tibeahx/RouteHarbor/internal/model"
	"github.com/tibeahx/RouteHarbor/internal/platform"
)

type unavailableEngine struct{}

func (unavailableEngine) StartEngine(
	context.Context,
	model.Source,
	adapter.Path,
) (adapter.ManagedProcess, error) {
	return nil, errors.New("engine unavailable")
}

type unavailableClient struct {
	coordinatorClient
	prepared *dataplane.Desired
}

func (c *unavailableClient) Prepare(
	_ context.Context,
	d dataplane.Desired,
) (helper.Transaction, error) {
	c.prepared = &d
	return helper.Transaction{ID: strings.Repeat("a", 32), State: "prepared", Candidate: d}, nil
}

func unavailableFixture(t *testing.T) (*NetworkCoordinator, *unavailableClient, model.Config) {
	t.Helper()
	r := runtimeFixture(t)
	c := r.Store.Get()
	c.Network.Enabled = true
	c.Network.LANInterfaces = []string{"home0"}
	c.Network.WANInterface = "wan0"
	c.Network.LocalPrefixes = []string{"192.168.1.0/24"}
	c.Policy.Mode = "auto"
	c.Sources = append(
		c.Sources,
		model.Source{
			ID:       "missing",
			Name:     "Unavailable",
			Type:     "sing-box",
			Enabled:  true,
			Auto:     true,
			Settings: json.RawMessage(`{"type":"http","server":"1.1.1.1","server_port":8080}`),
		},
	)
	updated, e := r.Store.Replace(c.Revision, c)
	if e != nil {
		t.Fatal(e)
	}
	r.Reload()
	r.Adapters.ManagedEngines = unavailableEngine{}
	r.decision = model.Decision{Selected: "direct"}
	client := &unavailableClient{}
	n := &NetworkCoordinator{
		Runtime:  r,
		Client:   client,
		Platform: func(context.Context) (platform.Report, error) { return platform.Report{Supported: true}, nil },
	}
	return n, client, updated
}

func TestNewUnavailableCandidateDoesNotBlockHealthyRouting(t *testing.T) {
	n, client, c := unavailableFixture(t)
	if _, e := n.Prepare(context.Background(), c, 90); e != nil {
		t.Fatal(e)
	}
	d := client.prepared
	if d == nil || len(d.Paths) != 1 || d.Paths[0].SourceID != "direct" ||
		!reflect.DeepEqual(d.Unavailable, []string{"missing"}) {
		t.Fatal("unavailable source partition lost", d)
	}
	if !matchesDesired(c, *d) {
		t.Fatal("complete private checkpoint no longer binds routing partition")
	}
	if n.Runtime.Adapters.Status("missing").State == "running" {
		t.Fatal("unavailable engine reported running")
	}
	checkpoint, ok, e := n.Runtime.Store.Checkpoint(strings.Repeat("a", 32))
	if e != nil || !ok || len(checkpoint.Sources) != 2 {
		t.Fatal("unavailable source was removed from configuration checkpoint", e)
	}
}

func TestUnavailableCommittedOrSelectedSourceIsNeverSilentlyDropped(t *testing.T) {
	for _, retained := range []bool{false, true} {
		t.Run(map[bool]string{false: "selected", true: "retained"}[retained], func(t *testing.T) {
			n, client, c := unavailableFixture(t)
			if retained {
				n.initialized = true
				client.state.Committed = &dataplane.Desired{
					Network: c.Network,
					Paths: []dataplane.Path{
						{SourceID: "missing", Kind: "tproxy", Slot: 2, Port: 12000},
					},
					Selected: "direct",
					Fallback: c.Policy.Fallback,
				}
			} else {
				n.Runtime.decision = model.Decision{Selected: "missing"}
			}
			if _, e := n.Prepare(context.Background(), c, 90); e == nil {
				t.Fatal("unsafe missing source silently dropped")
			}
			if client.prepared != nil {
				t.Fatal("helper received unsafe routing change")
			}
		})
	}
}

func TestCheckpointRequiresCompleteDisjointSourcePartition(t *testing.T) {
	_, _, c := unavailableFixture(t)
	base := dataplane.Desired{
		Network:     c.Network,
		Fallback:    c.Policy.Fallback,
		Selected:    "direct",
		Paths:       []dataplane.Path{{SourceID: "direct", Kind: "direct", Slot: 1}},
		Unavailable: []string{"missing"},
	}
	if !matchesDesired(c, base) {
		t.Fatal("valid full source partition rejected")
	}
	for _, ids := range [][]string{nil, {"unknown"}, {"direct"}, {"missing", "missing"}} {
		d := base
		d.Unavailable = ids
		if matchesDesired(c, d) {
			t.Fatal("invalid source partition matched checkpoint", ids)
		}
	}
	d := base
	d.Selected = "missing"
	if matchesDesired(c, d) {
		t.Fatal("unavailable source could be selected")
	}
}

func TestRecoveredNewSourceRequiresPreparedRoutingAllocation(t *testing.T) {
	n, client, c := unavailableFixture(t)
	n.initialized = true
	n.confirmedRevision = c.Revision
	client.state.Committed = &dataplane.Desired{
		Network:     c.Network,
		Selected:    "direct",
		Unavailable: []string{"missing"},
	}
	n.Runtime.decision = model.Decision{Selected: "missing"}
	n.Sync(context.Background())
	if client.switched != 0 || n.lastError != "recovered_source_requires_routing_prepare" {
		t.Fatal("unallocated recovered source changed live routing")
	}
}

package control

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/adapter"
	"github.com/tibeahx/RouteHarbor/internal/config"
	"github.com/tibeahx/RouteHarbor/internal/model"
)

func runtimeFixture(t *testing.T) *Runtime {
	t.Helper()
	dir := t.TempDir()
	store, e := config.NewStore(filepath.Join(dir, "state"))
	if e != nil {
		t.Fatal(e)
	}
	c := store.Get()
	c.Routing = nil // This shared direct-source fixture represents legacy all-traffic routing.
	c.Sources = []model.Source{
		{
			ID:       "direct",
			Name:     "Direct",
			Type:     "direct",
			Enabled:  true,
			Auto:     true,
			Settings: json.RawMessage(`{}`),
		},
	}
	c.Targets = []model.Target{
		{
			ID:          "web",
			URL:         "https://example.com/",
			Required:    true,
			StatusCodes: []int{200},
			MaxBytes:    1024,
		},
	}
	if _, e = store.Replace(c.Revision, c); e != nil {
		t.Fatal(e)
	}
	journal, e := NewJournal(filepath.Join(dir, "ops"))
	if e != nil {
		t.Fatal(e)
	}
	r := New(store, adapter.NewManager(filepath.Join(dir, "engines")), journal)
	t.Cleanup(func() {
		r.Close()
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return r
}

func TestStagedRemovalRetainsEngineUntilNetworkConfirmation(t *testing.T) {
	r := runtimeFixture(t)
	s := r.Store.Get().Sources[0]
	if e := r.Adapters.Start(context.Background(), s); e != nil {
		t.Fatal(e)
	}
	r.retain(map[string]bool{s.ID: true})
	c := r.Store.Get()
	c.Sources = nil
	if _, e := r.Store.Replace(c.Revision, c); e != nil {
		t.Fatal(e)
	}
	r.Reload()
	if r.Adapters.Status(s.ID).State != "running" {
		t.Fatal("configuration save stopped a committed engine before a network transaction")
	}
	r.retain(map[string]bool{})
	if r.Adapters.Status(s.ID).State != "stopped" {
		t.Fatal("confirmed source removal leaked retired engine")
	}
}

func TestMetadataChangeKeepsPreparedConnection(t *testing.T) {
	r := runtimeFixture(t)
	s := r.Store.Get().Sources[0]
	if e := r.Adapters.Start(context.Background(), s); e != nil {
		t.Fatal(e)
	}
	before, _ := r.Adapters.ProbePath(context.Background(), s)
	c := r.Store.Get()
	c.Sources[0].Name = "Renamed"
	c.Sources[0].Auto = false
	if _, e := r.Store.Replace(c.Revision, c); e != nil {
		t.Fatal(e)
	}
	r.Reload()
	if e := r.Adapters.Start(context.Background(), c.Sources[0]); e != nil {
		t.Fatal("metadata edit invalidated the prepared endpoint", e)
	}
	if r.Adapters.Status(s.ID).State != "running" {
		t.Fatal("metadata edit restarted engine")
	}
	if r.Adapters.Status(s.ID).Path.Mark != before.Mark {
		t.Fatal("metadata edit reallocated connections")
	}
}

type cancelProber struct {
	started   chan struct{}
	cancelled chan struct{}
}

func (p cancelProber) Run(
	ctx context.Context,
	s model.Source,
	targets []model.Target,
	settings model.ProbeSettings,
	speed bool,
) (model.Measurement, error) {
	close(p.started)
	<-ctx.Done()
	close(p.cancelled)
	return model.Measurement{}, ctx.Err()
}

func TestReloadCancelsOldRevisionProbes(t *testing.T) {
	r := runtimeFixture(t)
	p := cancelProber{make(chan struct{}), make(chan struct{})}
	r.Prober = p
	done := make(chan error, 1)
	go func() { _, e := r.Probe(context.Background(), "direct", false); done <- e }()
	select {
	case <-p.started:
	case <-time.After(time.Second):
		t.Fatal("probe did not start")
	}
	c := r.Store.Get()
	c.Sources[0].Enabled = false
	if _, e := r.Store.Replace(c.Revision, c); e != nil {
		t.Fatal(e)
	}
	r.Reload()
	select {
	case <-p.cancelled:
	case <-time.After(time.Second):
		t.Fatal("revoked source probe continued")
	}
	if e := <-done; e == nil {
		t.Fatal("old measurement accepted after config change")
	}
	if len(r.History("direct")) != 0 {
		t.Fatal("stale measurement entered new selector")
	}
}

package helper

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/adapter"
	"github.com/tibeahx/RouteHarbor/internal/dataplane"
	"github.com/tibeahx/RouteHarbor/internal/dispatch"
	"github.com/tibeahx/RouteHarbor/internal/model"
	"github.com/tibeahx/RouteHarbor/internal/routing"
)

func securityDispatcherSpec() dispatch.Spec {
	p := adapter.AllocatePath(adapter.DispatcherSourceID, "dispatcher", 249)
	p.TransparentPort, p.ProxyPort, p.DNSPort, p.IPv6, p.UDP = 11249, 12249, 13249, true, true
	source := adapter.AllocatePath("tunnel", "interface", 4)
	source.Interface = "tunnel0"
	source.IPv6, source.UDP = true, true
	return dispatch.Spec{
		Allocation: adapter.DispatcherAllocation{
			Path:         p,
			DNSFrontPort: 14249,
			DirectPort:   15249,
			APIPort:      16249,
		},
		Network: model.Network{
			Enabled:       true,
			LANInterfaces: []string{"lan0"},
			WANInterface:  "wan0",
			LocalPrefixes: []string{"192.168.1.0/24"},
			IPv6:          "proxy",
			DNS:           "selected-path",
			DNSResolver:   "11.0.0.53",
		},
		Routing: model.RoutingConfig{
			Mode:          "selective",
			FailurePolicy: "direct",
			Registry:      model.RoutingRegistry{Enabled: true, Provider: "antifilter"},
		},
		Sources:  []adapter.Path{source},
		Selected: "tunnel",
	}
}

func securityDispatcherIntent(spec dispatch.Spec, ref routing.SnapshotRef) dataplane.Desired {
	d := selectiveDesired()
	d.Network = spec.Network
	d.Selective.Path = dispatcherPath(spec)
	d.Selective.DNSFrontPort = uint16(spec.Allocation.DNSFrontPort)
	d.Selective.PolicyHash = dispatch.PolicyHash(spec.Routing)
	d.Selective.FakePool = spec.Allocation.FakePool
	d.Selective.Snapshot = dataplane.SelectiveSnapshotRef{
		Generation: ref.Generation,
		SHA256:     ref.SHA256,
	}
	return d
}

func TestDispatcherSecurityCleansCrashOrphanUploads(t *testing.T) {
	s := &Server{Manager: testManager(t, &memoryBackend{}, nil)}
	if e := os.Mkdir(s.snapshotDir(), 0o700); e != nil {
		t.Fatal(e)
	}
	orphans := []string{
		filepath.Join(s.snapshotDir(), ".upload-crash-one"),
		filepath.Join(s.snapshotDir(), ".upload-crash-two"),
	}
	for _, name := range orphans {
		if e := os.WriteFile(name, []byte("incomplete upload"), 0o600); e != nil {
			t.Fatal(e)
		}
	}
	untouched := filepath.Join(s.snapshotDir(), "unrelated-state")
	if e := os.WriteFile(untouched, []byte("preserve"), 0o600); e != nil {
		t.Fatal(e)
	}
	ref := routing.SnapshotRef{Generation: 1, SHA256: strings.Repeat("a", 64), Size: 42}
	if _, e := s.dispatcherAction(
		context.Background(),
		DispatcherRequest{Action: "snapshot-begin", Snapshot: &ref},
	); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if s.dispatcherUpload != nil {
			_ = s.dispatcherUpload.file.Close()
			_ = os.Remove(s.dispatcherUpload.file.Name())
		}
	})
	for _, name := range orphans {
		if _, e := os.Lstat(name); !os.IsNotExist(e) {
			t.Fatal("crash orphan retained beyond single-upload bound", filepath.Base(name), e)
		}
	}
	if _, e := os.Stat(untouched); e != nil {
		t.Fatal("cleanup removed unrelated state", e)
	}
	entries, e := os.ReadDir(s.snapshotDir())
	if e != nil {
		t.Fatal(e)
	}
	uploads := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".upload-") {
			uploads++
		}
	}
	if uploads != 1 {
		t.Fatal("upload count", uploads)
	}
}

func TestDispatcherSecurityRejectsSameGenerationDifferentHash(t *testing.T) {
	ctx := context.Background()
	m := testManager(t, &memoryBackend{}, &testWatchdog{})
	s := &Server{Manager: m}
	desired := selectiveDesired()
	tx, e := m.Prepare(ctx, desired)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.Apply(ctx, tx.ID, 30*time.Second); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Confirm(tx.ID); e != nil {
		t.Fatal(e)
	}
	p := adapter.AllocatePath(
		adapter.DispatcherSourceID,
		"dispatcher",
		int(desired.Selective.Path.Slot),
	)
	p.TransparentPort = int(desired.Selective.Path.Port)
	p.IPv6, p.UDP = true, true
	record := &dispatcherRegistration{
		spec: dispatch.Spec{Allocation: adapter.DispatcherAllocation{Path: p}},
	}
	file := filepath.Join(t.TempDir(), "rules.json")
	before := []byte(`{"version":4,"rules":[]}`)
	if e = os.WriteFile(file, before, 0o600); e != nil {
		t.Fatal(e)
	}
	ref := routing.SnapshotRef{
		Generation: desired.Selective.Snapshot.Generation,
		SHA256:     strings.Repeat("b", 64),
		Size:       123,
	}
	if e = s.publishDispatcher(
		ctx,
		record,
		ref,
		file,
		[]byte(`{"version":4,"rules":[{"domain":["new.example"]}]}`),
	); e == nil {
		t.Fatal("same generation replaced its immutable snapshot")
	}
	got, e := os.ReadFile(file)
	if e != nil || !bytes.Equal(got, before) {
		t.Fatal("rejected publication changed rules", e)
	}
	state, e := m.Status()
	if e != nil || state.Committed.Selective.Snapshot != desired.Selective.Snapshot {
		t.Fatal("rejected publication changed journal", e)
	}
}

func TestDispatcherSecurityBindsContinuityPresenceAndPrivateIdentity(t *testing.T) {
	spec := securityDispatcherSpec()
	ref := routing.SnapshotRef{Generation: 1, SHA256: strings.Repeat("a", 64), Size: 100}
	record := &dispatcherRegistration{spec: spec, ref: ref, ready: true, done: make(chan struct{})}
	s := &Server{dispatchers: map[int]*dispatcherRegistration{spec.Allocation.Path.Slot: record}}
	d := securityDispatcherIntent(spec, ref)
	if e := s.validateDispatcherPlanLocked(d); e != nil {
		t.Fatal("valid nonrelay intent rejected", e)
	}
	worker := continuityFixture(t)
	worker.Bridge = &dispatch.Bridge{
		Port:     17500,
		Username: strings.Repeat("ab", 16),
		Password: strings.Repeat("cd", 32),
	}
	s.continuity = &continuityRegistration{request: worker, ready: true, done: make(chan struct{})}
	record.spec.Continuity = worker.Bridge
	if e := s.validateDispatcherPlanLocked(d); e == nil {
		t.Fatal("relay dispatcher accepted with continuity omitted from plan")
	}
	d.Continuity = &dataplane.ContinuityIntent{
		Config: worker.Config,
		Path:   continuityAllocation(worker),
	}
	if e := s.validateDispatcherPlanLocked(d); e != nil {
		t.Fatal("matching relay intent rejected", e)
	}
	record.spec.Continuity = nil
	if e := s.validateDispatcherPlanLocked(d); e == nil {
		t.Fatal("nonrelay dispatcher accepted for relay intent")
	}
	forged := *worker.Bridge
	forged.Password = strings.Repeat("ef", 32)
	record.spec.Continuity = &forged
	if e := s.validateDispatcherPlanLocked(d); e == nil {
		t.Fatal("private relay identity changed after preparation")
	}
}

func TestDispatcherSecurityStagedFakePoolsMustDifferAndIntentMustMatch(t *testing.T) {
	spec := securityDispatcherSpec()
	if e := dispatch.Validate(spec); e != nil {
		t.Fatal(e)
	}
	old := spec
	old.Allocation.Path.Slot = 250
	old.Allocation.Path.Mark = adapter.Mark(250)
	s := &Server{dispatchers: map[int]*dispatcherRegistration{250: {spec: old}}}
	if e := s.validateDispatcherLocked(spec); e == nil || e.Error() != "dispatcher_fake_pool_busy" {
		t.Fatal("staged worker reused active FakeIP namespace", e)
	}
	ref := routing.SnapshotRef{Generation: 1, SHA256: strings.Repeat("a", 64), Size: 100}
	s.dispatchers = map[int]*dispatcherRegistration{
		spec.Allocation.Path.Slot: {spec: spec, ref: ref, ready: true, done: make(chan struct{})},
	}
	d := securityDispatcherIntent(spec, ref)
	if e := s.validateDispatcherPlanLocked(d); e != nil {
		t.Fatal(e)
	}
	d.Selective.FakePool = 1
	if e := s.validateDispatcherPlanLocked(d); e == nil {
		t.Fatal("plan bound different FakeIP namespace than prepared engine")
	}
}

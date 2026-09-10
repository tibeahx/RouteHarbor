package maintenance

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tibeahx/RouteHarbor/internal/release"
)

type member struct {
	name   string
	data   []byte
	kind   byte
	target string
}

func archive(t testing.TB, members []member) []byte {
	t.Helper()
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	writer := tar.NewWriter(compressed)
	for _, entry := range members {
		kind := entry.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		header := tar.Header{
			Name:     entry.name,
			Mode:     0o755,
			Size:     int64(len(entry.data)),
			Typeflag: kind,
			Linkname: entry.target,
		}
		if kind != tar.TypeReg {
			header.Size = 0
		}
		if err := writer.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if kind == tar.TypeReg {
			if _, err := writer.Write(entry.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func packageBytes(t testing.TB, name, version string, files []member) []byte {
	t.Helper()
	control := []byte(
		"Package: " + name + "\nVersion: " + version + "\nArchitecture: x86_64\nDepends: routeharbor-guard\nDescription: offline test\n",
	)
	return archive(
		t,
		[]member{
			{"debian-binary", []byte("2.0\n"), 0, ""},
			{"data.tar.gz", archive(t, files), 0, ""},
			{"control.tar.gz", archive(t, []member{{"control", control, 0, ""}}), 0, ""},
		},
	)
}

type fixture struct {
	state string
	key   ed25519.PrivateKey
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	state := t.TempDir()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(
		filepath.Join(state, "trust.pub"),
		[]byte(base64.StdEncoding.EncodeToString(public)),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	return fixture{state, key}
}

func (f fixture) stage(t *testing.T, version string, payload []byte) (BundleSummary, error) {
	t.Helper()
	return Stage(f.state, f.source(t, version, payload), "x86_64")
}

func (f fixture) source(t *testing.T, version string, payload []byte) string {
	t.Helper()
	source := t.TempDir()
	name := "routeharbor_" + version + "_x86_64.ipk"
	hash := sha256.Sum256(payload)
	manifest := release.Manifest{
		SchemaVersion: 1,
		Project:       "RouteHarbor",
		Version:       version,
		Commit:        strings.Repeat("a", 40),
		Artifacts: []release.Artifact{
			{
				Name:         name,
				Architecture: "x86_64",
				SHA256:       hex.EncodeToString(hash[:]),
				Bytes:        int64(len(payload)),
			},
		},
	}
	raw, sig, err := release.Sign(manifest, f.key)
	if err != nil {
		t.Fatal(err)
	}
	for filename, data := range map[string][]byte{"manifest.json": raw, "manifest.sig": []byte(base64.StdEncoding.EncodeToString(sig)), name: payload} {
		if err = os.WriteFile(filepath.Join(source, filename), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return source
}

func TestStageAuthenticatesPackageIdentityAndPayload(t *testing.T) {
	f := newFixture(t)
	payload := packageBytes(
		t,
		"routeharbor",
		"0.1.0-r1",
		[]member{{"usr/bin/routeharbor", []byte("binary v1"), 0, ""}},
	)
	summary, err := f.stage(t, "0.1.0", payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Packages) != 1 || summary.Packages[0].Name != "routeharbor" {
		t.Fatal(summary)
	}
	stored, err := os.ReadFile(
		filepath.Join(f.state, "artifact-"+summary.Packages[0].SHA256+".ipk"),
	)
	if err != nil || !bytes.Equal(stored, payload) {
		t.Fatal("staged bytes changed", err)
	}
	info, err := os.Stat(filepath.Join(f.state, "artifact-"+summary.Packages[0].SHA256+".ipk"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("unsafe artifact mode")
	}
}

func TestAuthenticatedHostilePackagesRejected(t *testing.T) {
	for _, kind := range []string{"foreign-package", "traversal", "absolute-link", "device", "corrupt-gzip"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			name := "routeharbor"
			files := []member{{"usr/bin/routeharbor", []byte("canary executable"), 0, ""}}
			switch kind {
			case "foreign-package":
				name = "dropbear"
			case "traversal":
				files[0].name = "../../outside"
			case "absolute-link":
				files = []member{
					{name: "usr/bin/routeharbor", kind: tar.TypeSymlink, target: "/etc/passwd"},
				}
			case "device":
				files = []member{{name: "usr/bin/routeharbor", kind: tar.TypeChar}}
			}
			payload := packageBytes(t, name, "0.1.0-r1", files)
			if kind == "corrupt-gzip" {
				payload[len(payload)-8] ^= 1
			}
			if _, err := f.stage(t, "0.1.0", payload); err == nil {
				t.Fatal("authenticated unsafe package accepted")
			}
		})
	}
}

func TestInputContainedSymlinkAndInvalidTrustRejected(t *testing.T) {
	f := newFixture(t)
	root, err := os.OpenRoot(f.state)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err = os.WriteFile(filepath.Join(f.state, "real"), []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("real", filepath.Join(f.state, "link")); err != nil {
		t.Fatal(err)
	}
	if file, err := inputFile(root, "link", 1024); err == nil {
		_ = file.Close()
		t.Fatal("contained link accepted")
	}
	if err = os.WriteFile(
		filepath.Join(f.state, "trust.pub"),
		[]byte("not a key"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, _, err = trustedKey(root); err == nil {
		t.Fatal("invalid trust key accepted")
	}
}

type fakeBackend struct {
	packages                       map[string]string
	executions, acquires, releases int
	verifyErr                      error
	releaseFail                    bool
}

func (b *fakeBackend) Inventory(context.Context) (Inventory, error) {
	p := map[string]string{}
	maps.Copy(p, b.packages)
	return Inventory{Architecture: "x86_64", Packages: p, AvailableBytes: 1 << 30}, nil
}

func (b *fakeBackend) Compare(_ context.Context, a, op, c string) (bool, error) {
	switch op {
	case ">=":
		return a >= c, nil
	case "=":
		return a == c, nil
	default:
		return false, errors.New("unexpected operator")
	}
}
func (*fakeBackend) Check(context.Context, Plan, []string) error { return nil }
func (b *fakeBackend) Acquire(context.Context, string) error     { b.acquires++; return nil }
func (b *fakeBackend) Release(string) error {
	b.releases++
	if b.releaseFail {
		b.releaseFail = false
		return errors.New("lost release acknowledgement")
	}
	return nil
}
func (*fakeBackend) Decommission(context.Context, string, string) error { return nil }
func (b *fakeBackend) Execute(_ context.Context, plan Plan, _ []string) error {
	b.executions++
	for _, p := range plan.Packages {
		if plan.Request.Action == "remove" {
			delete(b.packages, p.Name)
		} else {
			b.packages[p.Name] = p.Version
		}
	}
	return nil
}
func (b *fakeBackend) Verify(context.Context, Plan, []PackagePayload) error { return b.verifyErr }

type fakeWorker struct {
	calls int
	fail  bool
}

func (w *fakeWorker) Arm(string) error {
	w.calls++
	if w.fail {
		w.fail = false
		return errors.New("worker start failed")
	}
	return nil
}

func managerFixture(t *testing.T) (*Manager, *fakeBackend, *fakeWorker, Request) {
	t.Helper()
	f := newFixture(t)
	old, err := f.stage(
		t,
		"0.1.0",
		packageBytes(
			t,
			"routeharbor",
			"0.1.0-r1",
			[]member{{"usr/bin/routeharbor", []byte("old"), 0, ""}},
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = old
	current, err := f.stage(
		t,
		"0.1.1",
		packageBytes(
			t,
			"routeharbor",
			"0.1.1-r1",
			[]member{{"usr/bin/routeharbor", []byte("new"), 0, ""}},
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	backend := &fakeBackend{
		packages: map[string]string{"routeharbor-guard": "0.1.0-r1", "routeharbor": "0.1.0-r1"},
	}
	worker := &fakeWorker{}
	manager, err := NewManager(f.state, backend, worker)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	inventory, _ := backend.Inventory(context.Background())
	digest, err := inventoryDigest(inventory)
	if err != nil {
		t.Fatal(err)
	}
	return manager, backend, worker, Request{
		Action:                  "upgrade",
		BundleID:                current.ID,
		Components:              []string{"routeharbor"},
		ExpectedInstalledDigest: digest,
	}
}

func TestWorkerArmFailureSameIdentityExecutesOnce(t *testing.T) {
	manager, backend, worker, request := managerFixture(t)
	id := strings.Repeat("1", 32)
	worker.fail = true
	first, err := manager.Start(context.Background(), id, request)
	if err == nil || first.State != "prepared" || !first.Retryable {
		t.Fatal(first, err)
	}
	if _, err = manager.Start(context.Background(), id, request); err != nil {
		t.Fatal(err)
	}
	if err = manager.Run(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err = manager.Start(context.Background(), id, request); err != nil {
		t.Fatal(err)
	}
	if err = manager.Run(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	status, err := manager.Status(context.Background(), id)
	if err != nil || status.State != "completed" || backend.executions != 1 || worker.calls != 2 {
		t.Fatal(status, backend.executions, worker.calls, err)
	}
}

func TestCrashDuringPackageManagerNeverCompletesFromVersionAlone(t *testing.T) {
	manager, backend, _, request := managerFixture(t)
	id := strings.Repeat("2", 32)
	if _, err := manager.Start(context.Background(), id, request); err != nil {
		t.Fatal(err)
	}
	if err := manager.update(id, "running", "package_manager", ""); err != nil {
		t.Fatal(err)
	}
	backend.packages["routeharbor"] = "0.1.1-r1"
	if err := manager.Run(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	status, err := manager.Status(context.Background(), id)
	if err != nil || status.State != "interrupted" || backend.releases != 0 ||
		backend.executions != 0 {
		t.Fatal(status, err)
	}
}

func TestVerificationFailureRetainsGateAndReleaseAckRetryDoesNotReapply(t *testing.T) {
	t.Run("payload", func(t *testing.T) {
		manager, backend, _, request := managerFixture(t)
		id := strings.Repeat("3", 32)
		backend.verifyErr = errors.New("partial installed binary")
		if _, err := manager.Start(context.Background(), id, request); err != nil {
			t.Fatal(err)
		}
		if err := manager.Run(context.Background(), id); err != nil {
			t.Fatal(err)
		}
		status, _ := manager.Status(context.Background(), id)
		if status.State != "interrupted" || backend.releases != 0 {
			t.Fatal(status)
		}
	})
	t.Run("release-ack", func(t *testing.T) {
		manager, backend, _, request := managerFixture(t)
		id := strings.Repeat("4", 32)
		backend.releaseFail = true
		if _, err := manager.Start(context.Background(), id, request); err != nil {
			t.Fatal(err)
		}
		if err := manager.Run(context.Background(), id); err == nil {
			t.Fatal("missing release failure")
		}
		acquires := backend.acquires
		if err := manager.Run(context.Background(), id); err != nil {
			t.Fatal(err)
		}
		status, _ := manager.Status(context.Background(), id)
		if status.State != "completed" || backend.executions != 1 || backend.acquires != acquires {
			t.Fatal(status, backend)
		}
	})
}

func TestPayloadVerificationChecksBytesModeAndCriticalConffile(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "usr/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	data := []byte("known signed executable")
	hash := sha256.Sum256(data)
	name := filepath.Join(dir, "usr/bin/routeharbor")
	if err := os.WriteFile(name, data, 0o755); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	payload := []PackagePayload{
		{
			Files: []PayloadFile{
				{
					Path:   "usr/bin/routeharbor",
					Type:   "file",
					Mode:   0o755,
					Bytes:  int64(len(data)),
					SHA256: hex.EncodeToString(hash[:]),
				},
			},
			Conffiles: []string{"usr/bin/routeharbor"},
		},
	}
	if err = verifyPayload(root, payload, false); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(name, []byte("partial"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err = verifyPayload(root, payload, false); err == nil {
		t.Fatal("same-version partial binary accepted")
	}
	if err = os.WriteFile(name, data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(name, 0o644); err != nil {
		t.Fatal(err)
	}
	if err = verifyPayload(root, payload, false); err == nil {
		t.Fatal("wrong executable mode accepted")
	}
}

func TestGuardReplacementAndUnstagedPreviousVersionRejected(t *testing.T) {
	manager, backend, _, request := managerFixture(t)
	guard := request
	guard.Components = []string{"routeharbor-guard"}
	if _, err := manager.Plan(context.Background(), guard); err == nil {
		t.Fatal("guard replacement accepted")
	}
	backend.packages["routeharbor"] = "0.0.9-r1"
	inventory, _ := backend.Inventory(context.Background())
	request.ExpectedInstalledDigest, _ = inventoryDigest(inventory)
	if _, err := manager.Plan(context.Background(), request); err == nil {
		t.Fatal("upgrade without offline previous package accepted")
	}
}

func TestPublicMetadataContainsNoLocalPathsOrSigningMaterial(t *testing.T) {
	manager, _, _, request := managerFixture(t)
	plan, err := manager.Plan(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{manager.dir, "manifest.sig", "trust.pub", "/root/"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatal("private maintenance detail escaped")
		}
	}
}

func TestReleaseRecoveryRevalidatesPayload(t *testing.T) {
	manager, backend, _, request := managerFixture(t)
	id := strings.Repeat("9", 32)
	backend.releaseFail = true
	if _, err := manager.Start(context.Background(), id, request); err != nil {
		t.Fatal(err)
	}
	if err := manager.Run(context.Background(), id); err == nil {
		t.Fatal("release fault not reached")
	}
	status, _ := manager.Status(context.Background(), id)
	if status.State != "verifying" || status.Phase != "releasing_gate" {
		t.Fatal(status)
	}
	backend.verifyErr = errors.New("installed executable lost after crash")
	if err := manager.Run(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	status, _ = manager.Status(context.Background(), id)
	if status.State == "completed" {
		t.Fatalf("release recovery completed despite failed payload verification: %+v", status)
	}
}

func TestStageRepairsInterruptedArtifactCopy(t *testing.T) {
	f := newFixture(t)
	payload := packageBytes(
		t,
		"routeharbor",
		"0.1.0-r1",
		[]member{{"usr/bin/routeharbor", []byte("binary v1"), 0, ""}},
	)
	hash := sha256.Sum256(payload)
	// This is the exact final pathname/mode left by SIGKILL during copyArtifact.
	if err := os.WriteFile(
		filepath.Join(f.state, "artifact-"+hex.EncodeToString(hash[:])+".ipk"),
		payload[:len(payload)/2],
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := f.stage(t, "0.1.0", payload); err != nil {
		t.Fatalf("valid signed retry cannot repair a torn artifact copy: %v", err)
	}
}

func TestPayloadMetadataBoundToSignedArchive(t *testing.T) {
	manager, _, _, request := managerFixture(t)
	record, err := readBundle(manager.root, request.BundleID)
	if err != nil {
		t.Fatal(err)
	}
	for i := range record.Metadata {
		record.Metadata[i].Files = nil
	}
	raw, _ := json.Marshal(record)
	if err := writePrivate(manager.root, "bundle-"+request.BundleID+".json", raw); err != nil {
		t.Fatal(err)
	}
	plan, err := manager.Plan(context.Background(), request)
	if err != nil {
		return
	}
	payloads, err := manager.payloads(plan)
	if err != nil {
		return
	}
	for _, payload := range payloads {
		if len(payload.Files) == 0 {
			t.Fatalf(
				"signature checked but unsigned cached file metadata accepted for %s",
				payload.Package.Name,
			)
		}
	}
}

func TestRestageRepairsCompletedBundleAndRejectsTampering(t *testing.T) {
	f := newFixture(t)
	payload := packageBytes(
		t,
		"routeharbor",
		"0.1.0-r1",
		[]member{{"usr/bin/routeharbor", []byte("binary"), 0, ""}},
	)
	summary, err := f.stage(t, "0.1.0", payload)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(f.state, "artifact-"+summary.Packages[0].SHA256+".ipk")
	for _, torn := range [][]byte{nil, payload[:len(payload)/2]} {
		if err = os.WriteFile(name, torn, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err = f.stage(t, "0.1.0", payload); err != nil {
			t.Fatal("authenticated restage", err)
		}
		actual, err := os.ReadFile(name)
		if err != nil || !bytes.Equal(actual, payload) {
			t.Fatal("restage did not restore bytes", err)
		}
	}
}

func (b *fakeBackend) Recover(
	ctx context.Context,
	plan Plan,
	remove []Package,
	paths []string,
) error {
	for _, p := range remove {
		delete(b.packages, p.Name)
	}
	b.verifyErr = nil
	return b.Execute(ctx, plan, paths)
}

func TestExplicitRecoveryAndRollbackStayDurable(t *testing.T) {
	for _, mode := range []string{"retry", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			manager, backend, _, request := managerFixture(t)
			id := strings.Repeat("6", 32)
			backend.verifyErr = errors.New("partial executable")
			if _, err := manager.Start(context.Background(), id, request); err != nil {
				t.Fatal(err)
			}
			if err := manager.Run(context.Background(), id); err != nil {
				t.Fatal(err)
			}
			status, _ := manager.Status(context.Background(), id)
			if status.State != "interrupted" {
				t.Fatal(status)
			}
			before := backend.executions
			if err := manager.Run(context.Background(), id); err != nil {
				t.Fatal(err)
			}
			if backend.executions != before {
				t.Fatal("uncertain execution automatically replayed")
			}
			if _, err := manager.Recover(context.Background(), id, mode); err != nil {
				t.Fatal(err)
			}
			if err := manager.Run(context.Background(), id); err != nil {
				t.Fatal(err)
			}
			status, _ = manager.Status(context.Background(), id)
			state, version := "completed", "0.1.1-r1"
			if mode == "rollback" {
				state, version = "failed", "0.1.0-r1"
			}
			if status.State != state || backend.packages["routeharbor"] != version ||
				backend.releases != 1 {
				t.Fatal(status, backend)
			}
		})
	}
}

func (b *fakeBackend) AcquireRecovery(ctx context.Context, id string) error {
	return b.Acquire(ctx, id)
}

func TestRestageRejectsTamperedIncomingBytesEvenWithValidCache(t *testing.T) {
	f := newFixture(t)
	payload := packageBytes(
		t,
		"routeharbor",
		"0.1.0-r1",
		[]member{{"usr/bin/routeharbor", []byte("binary"), 0, ""}},
	)
	summary, err := f.stage(t, "0.1.0", payload)
	if err != nil {
		t.Fatal(err)
	}
	source := f.source(t, "0.1.0", payload)
	payload[0] ^= 1
	if err = os.WriteFile(
		filepath.Join(source, "routeharbor_0.1.0_x86_64.ipk"),
		payload,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err = Stage(f.state, source, "x86_64"); err == nil {
		t.Fatal("tampered incoming bytes accepted")
	}
	root, err := os.OpenRoot(f.state)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if _, err = readBundle(root, summary.ID); err != nil {
		t.Fatal("valid cached artifact damaged", err)
	}
}

func FuzzInspectIPK(f *testing.F) {
	f.Add(
		packageBytes(
			f,
			"routeharbor",
			"0.1.0-r1",
			[]member{{"usr/bin/routeharbor", []byte("fixture"), 0, ""}},
		),
	)
	f.Add([]byte("not a package"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 2<<20 {
			t.Skip("bounded parser corpus")
		}
		metadata, err := InspectIPK(bytes.NewReader(raw))
		if err == nil && !allowedPackage(metadata.Name) {
			t.Fatal("foreign package accepted")
		}
	})
}

func TestConcurrentStartsAcceptOnlyOneJob(t *testing.T) {
	manager, _, _, request := managerFixture(t)
	begin := make(chan struct{})
	results := make(chan error, 2)
	for _, id := range []string{strings.Repeat("b", 32), strings.Repeat("c", 32)} {
		go func(id string) { <-begin; _, err := manager.Start(context.Background(), id, request); results <- err }(
			id,
		)
	}
	close(begin)
	successes := 0
	for range 2 {
		if <-results == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatal("concurrent jobs accepted", successes)
	}
}

func TestSignedNonGuardPackagesCannotClaimGuardPayloads(t *testing.T) {
	for _, filename := range []string{"usr/libexec/routeharbor-helper", "etc/init.d/routeharbor-guard", "etc/routeharbor-helper/transaction.json", "etc/routeharbor-maintenance/trust.pub", "usr/share/nftables.d/ruleset-pre/90-routeharbor-guard.nft", "etc/rc.d/S03routeharbor-guard"} {
		t.Run(filename, func(t *testing.T) {
			f := newFixture(t)
			payload := packageBytes(
				t,
				"routeharbor",
				"0.1.0-r1",
				[]member{{filename, []byte("wrongly packaged signed content"), 0, ""}},
			)
			if _, err := f.stage(t, "0.1.0", payload); err == nil {
				t.Fatal("signed controller package claimed guard-owned payload")
			}
		})
	}
	for _, file := range []member{
		{name: "usr/libexec", kind: tar.TypeSymlink, target: "bin"},
		{name: "usr/bin/alias", kind: tar.TypeSymlink, target: "../libexec/routeharbor-helper"},
		{name: "usr/bin/alias", kind: tar.TypeLink, target: "usr/libexec/routeharbor-helper"},
	} {
		if _, err := InspectIPK(
			bytes.NewReader(packageBytes(t, "routeharbor", "0.1.0-r1", []member{file})),
		); err == nil {
			t.Fatal("guard alias or ancestor replacement accepted", file.name)
		}
	}
	// The real guard IPK may be authenticated/staged but remains unselectable
	// through the public maintenance request contract.
	guard := packageBytes(
		t,
		"routeharbor-guard",
		"0.1.0-r1",
		[]member{{"usr/libexec/routeharbor-helper", []byte("guard fixture"), 0, ""}},
	)
	if _, err := InspectIPK(bytes.NewReader(guard)); err != nil {
		t.Fatal("guard staging rejected", err)
	}
	if err := ValidateRequest(
		Request{
			Action:     "upgrade",
			Components: []string{"routeharbor-guard"},
			BundleID:   strings.Repeat("a", 32),
		},
		false,
	); err == nil {
		t.Fatal("guard replacement enabled")
	}
}

func TestSignedPackageCannotReplaceOrConflictWithGuard(t *testing.T) {
	for _, field := range []string{"Replaces", "Conflicts"} {
		t.Run(field, func(t *testing.T) {
			control := []byte(
				"Package: routeharbor\nVersion: 0.1.0-r1\nArchitecture: x86_64\n" + field + ": routeharbor-guard (>= 0.1.0)\n",
			)
			payload := archive(
				t,
				[]member{
					{"debian-binary", []byte("2.0\n"), 0, ""},
					{"control.tar.gz", archive(t, []member{{"control", control, 0, ""}}), 0, ""},
					{
						"data.tar.gz",
						archive(t, []member{{"usr/bin/routeharbor", []byte("fixture"), 0, ""}}),
						0,
						"",
					},
				},
			)
			f := newFixture(t)
			if _, err := f.stage(t, "0.1.0", payload); err == nil {
				t.Fatal("signed package requested guard replacement")
			}
		})
	}
}

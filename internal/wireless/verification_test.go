package wireless

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Verifier, Receipt) {
	t.Helper()
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	binding := Binding{
		OpenWrtDigest:         strings.Repeat("c", 64),
		Kernel:                "test-kernel",
		Board:                 "fixture-only",
		PHY:                   "phy0",
		Driver:                "driver",
		RadioPath:             "test-radio",
		PHYCapabilitiesDigest: strings.Repeat("d", 64),
	}
	verifier := NewVerifier(t.TempDir(), "node", "")
	verifier.Now = func() time.Time { return now }
	verifier.Fingerprint = func() (string, error) { return strings.Repeat("a", 64), nil }
	verifier.Collect = func(context.Context, string) (Binding, error) { return binding, nil }
	receipt := Receipt{
		Radio:              "radio0",
		Mode:               "wds",
		LocalFingerprint:   strings.Repeat("a", 64),
		PeerFingerprint:    strings.Repeat("b", 64),
		ExpiresAt:          now.Add(time.Hour),
		Version:            1,
		Role:               "node",
		IssuedAt:           now,
		Binding:            binding,
		Checks:             Checks{true, true, true, true, true},
		Interface:          "wlan0",
		PeerMAC:            "02:00:00:00:00:01",
		LiveEvidenceDigest: strings.Repeat("e", 64),
	}
	return verifier, receipt
}

func TestReceiptRequiresAllChecksCurrentDeviceAndIdentity(t *testing.T) {
	v, r := fixture(t)
	if err := v.validate(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Receipt){
		"expired":                      func(r *Receipt) { r.ExpiresAt = v.Now() },
		"excessive lifetime":           func(r *Receipt) { r.ExpiresAt = r.IssuedAt.Add(8 * 24 * time.Hour) },
		"future":                       func(r *Receipt) { r.IssuedAt = r.IssuedAt.Add(2 * time.Minute) },
		"wrong role":                   func(r *Receipt) { r.Role = "gateway" },
		"identity changed":             func(r *Receipt) { r.LocalFingerprint = strings.Repeat("f", 64) },
		"board changed":                func(r *Receipt) { r.Binding.Board = "other-board" },
		"driver changed":               func(r *Receipt) { r.Binding.Driver = "other-driver" },
		"capabilities changed":         func(r *Receipt) { r.Binding.PHYCapabilitiesDigest = strings.Repeat("f", 64) },
		"missing encryption check":     func(r *Receipt) { r.Checks.EncryptedPeer = false },
		"missing client check":         func(r *Receipt) { r.Checks.ClientAddresses = false },
		"missing address-server check": func(r *Receipt) { r.Checks.SingleAddressServer = false },
		"missing management check":     func(r *Receipt) { r.Checks.ManagementRecovery = false },
		"missing concurrent AP check":  func(r *Receipt) { r.Checks.ConcurrentAP = false },
		"missing live evidence":        func(r *Receipt) { r.LiveEvidenceDigest = "" },
		"self peer":                    func(r *Receipt) { r.PeerFingerprint = r.LocalFingerprint },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := r
			change(&candidate)
			if v.validate(context.Background(), candidate) == nil {
				t.Fatal("invalid receipt accepted")
			}
		})
	}
	v.Collect = func(context.Context, string) (Binding, error) { return Binding{}, errors.New("unavailable") }
	if v.validate(context.Background(), r) == nil {
		t.Fatal("missing current radio evidence accepted")
	}
}

func TestIdentityFingerprintRejectsLinksAndExcessivePermissions(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-only"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(
		map[string]string{
			"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			"private_key": "CANARY-not-read-or-returned",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(dir, "identity.json")
	if err = os.WriteFile(identity, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, e := identityFingerprint(dir); e != nil || got != digest(der) {
		t.Fatalf("valid certificate rejected: %v", e)
	}
	if err = os.Chmod(identity, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err = identityFingerprint(dir); err == nil {
		t.Fatal("public identity file accepted")
	}
	if err = os.Chmod(identity, 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(dir, "linked.json")
	if err = os.Link(identity, linked); err != nil {
		t.Fatal(err)
	}
	if _, err = identityFingerprint(dir); err == nil {
		t.Fatal("hardlinked identity accepted")
	}
	if err = os.Remove(identity); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("linked.json", identity); err != nil {
		t.Fatal(err)
	}
	if _, err = identityFingerprint(dir); err == nil {
		t.Fatal("symlink identity accepted")
	}
}

func TestRootReceiptFilesystemAndScope(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires isolated root filesystem fixture; scripts/lab-wireless.sh")
	}
	v, r := fixture(t)
	if err := os.Chmod(v.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := v.write(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if err := v.Check(context.Background(), "radio0", "wds", r.PeerFingerprint); err != nil {
		t.Fatal(err)
	}
	for _, request := range [][3]string{{"radio1", "wds", r.PeerFingerprint}, {"radio0", "mesh", r.PeerFingerprint}, {"radio0", "wds", strings.Repeat("f", 64)}} {
		if v.Check(context.Background(), request[0], request[1], request[2]) == nil {
			t.Fatal("receipt scope mismatch accepted")
		}
	}
	path := filepath.Join(v.Dir, receiptName)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Authorized(context.Background()); err == nil {
		t.Fatal("readable receipt accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Authorized(context.Background()); err == nil {
		t.Fatal("service-owned receipt accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", path); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Authorized(context.Background()); err == nil {
		t.Fatal("symlink receipt accepted")
	}
}

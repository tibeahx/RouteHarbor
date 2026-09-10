package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestManifestTamperArchitectureDowngradeAndSymlink(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	data := []byte("test package")
	hash := sha256.Sum256(data)
	dir := t.TempDir()
	path := filepath.Join(dir, "routeharbor.ipk")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	m := Manifest{
		1,
		"RouteHarbor",
		"1.2.3",
		"0123456789012345678901234567890123456789",
		[]Artifact{
			{
				"routeharbor.ipk",
				"aarch64_cortex-a53",
				hex.EncodeToString(hash[:]),
				int64(len(data)),
			},
		},
	}
	raw, sig, e := Sign(m, key)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Verify(raw, sig, pub, "aarch64_cortex-a53", "1.2.2", path); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct{ arch, current string }{{"arm64", "1.2.2"}, {"aarch64_cortex-a53", "1.3.0"}} {
		if _, e = Verify(raw, sig, pub, tc.arch, tc.current, path); e == nil {
			t.Fatal("wrong arch or downgrade accepted")
		}
	}
	changed := append([]byte(nil), raw...)
	changed[0] ^= 1
	if _, e = Verify(changed, sig, pub, "aarch64_cortex-a53", "", path); e == nil {
		t.Fatal("tampered manifest accepted")
	}
	if err := os.WriteFile(path, []byte("evil package"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, e = Verify(raw, sig, pub, "aarch64_cortex-a53", "", path); e == nil {
		t.Fatal("tampered package accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "elsewhere"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), path); err != nil {
		t.Fatal(err)
	}
	if _, e = Verify(raw, sig, pub, "aarch64_cortex-a53", "", path); e == nil {
		t.Fatal("symlink accepted")
	}
}

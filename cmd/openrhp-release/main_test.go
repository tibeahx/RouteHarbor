package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tibeahx/OpenRHP/internal/release"
)

type releaseFixture struct {
	dir, manifest, signature, private, public, artifact string
	raw, sig, payload                                   []byte
}

func makeReleaseFixture(t *testing.T) releaseFixture {
	t.Helper()
	dir := t.TempDir()
	f := releaseFixture{
		dir:       dir,
		manifest:  filepath.Join(dir, "manifest.json"),
		signature: filepath.Join(dir, "manifest.sig"),
		private:   filepath.Join(dir, "private.key"),
		public:    filepath.Join(dir, "trusted.pub"),
		artifact:  filepath.Join(dir, "openrhp.ipk"),
	}
	if err := run([]string{"keygen", "--key", f.private, "--public-out", f.public}); err != nil {
		t.Fatal(err)
	}
	// An opaque executable-looking package must be hashed, never interpreted.
	f.payload = []byte("#!/bin/sh\ntouch " + filepath.Join(dir, "must-not-execute") + "\n")
	if err := os.WriteFile(f.artifact, f.payload, 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(f.payload)
	manifest := release.Manifest{
		SchemaVersion: 1,
		Project:       "OpenRHP",
		Version:       "1.2.3",
		Commit:        strings.Repeat("1", 40),
		Artifacts: []release.Artifact{
			{
				Name:         "openrhp.ipk",
				Architecture: "mips_24kc",
				SHA256:       hex.EncodeToString(sum[:]),
				Bytes:        int64(len(f.payload)),
			},
		},
	}
	var err error
	f.raw, err = json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.manifest, f.raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(
		[]string{"sign", "--manifest", f.manifest, "--key", f.private, "--signature", f.signature},
	); err != nil {
		t.Fatal(err)
	}
	f.sig, err = os.ReadFile(f.signature)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f releaseFixture) verify(current string) error {
	return run(
		[]string{
			"verify",
			"--manifest",
			f.manifest,
			"--signature",
			f.signature,
			"--key",
			f.public,
			"--arch",
			"mips_24kc",
			"--current-version",
			current,
			"--artifact",
			f.artifact,
		},
	)
}

func TestOfflineCLIEndToEndNeverExecutesPackage(t *testing.T) {
	f := makeReleaseFixture(t)
	if err := f.verify("1.2.2"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "must-not-execute")); !os.IsNotExist(err) {
		t.Fatal("verification executed package bytes")
	}
	before, err := os.ReadFile(f.private)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(f.private)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("private signing key permissions invalid")
	}
	if err := run([]string{"keygen", "--key", f.private, "--public-out", f.public}); err == nil {
		t.Fatal("repeated key generation replaced existing trust")
	}
	after, err := os.ReadFile(f.private)
	if err != nil || string(before) != string(after) {
		t.Fatal("failed repeat changed trust key")
	}
}

func TestOfflineCLITornStagingFailsClosedAndCanRetry(t *testing.T) {
	// These are deterministic torn-file states, not a claim of filesystem
	// power-loss atomicity or opkg upgrade recovery.
	for _, name := range []string{"manifest", "signature", "package"} {
		for _, position := range []string{"empty", "middle", "last-byte", "appended"} {
			t.Run(name+"/"+position, func(t *testing.T) {
				f := makeReleaseFixture(t)
				path, original := f.manifest, f.raw
				if name == "signature" {
					path, original = f.signature, f.sig
				}
				if name == "package" {
					path, original = f.artifact, f.payload
				}
				var damaged []byte
				switch position {
				case "empty":
					damaged = nil
				case "middle":
					damaged = original[:len(original)/2]
				case "last-byte":
					damaged = original[:len(original)-1]
				case "appended":
					damaged = append(append([]byte(nil), original...), byte('x'))
				}
				// A missing final newline on base64 is valid formatting, not torn data.
				if name == "signature" && position == "last-byte" {
					damaged = original[:len(original)-3]
				}
				if err := os.WriteFile(path, damaged, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := f.verify("1.2.2"); err == nil {
					t.Fatal("damaged staging accepted")
				}
				got, err := os.ReadFile(path)
				if err != nil || string(got) != string(damaged) {
					t.Fatal("verifier modified damaged staging")
				}
				if _, err := os.Stat(
					filepath.Join(f.dir, "must-not-execute"),
				); !os.IsNotExist(
					err,
				) {
					t.Fatal("damaged package executed")
				}
				if err := os.WriteFile(path, original, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := f.verify("1.2.2"); err != nil {
					t.Fatal("retry from complete trusted staging failed", err)
				}
			})
		}
	}
}

func TestOfflineCLIAuthenticatedMalformedManifestRejected(t *testing.T) {
	for _, kind := range []string{"unknown-key", "duplicate-key", "trailing-object", "wrong-project", "downgrade", "overflow-version", "duplicate-artifact", "traversal"} {
		t.Run(kind, func(t *testing.T) {
			f := makeReleaseFixture(t)
			var manifest release.Manifest
			if err := json.Unmarshal(f.raw, &manifest); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "wrong-project":
				manifest.Project = "Other"
			case "downgrade":
				manifest.Version = "1.2.1"
			case "overflow-version":
				manifest.Version = "4294967296.0.0"
			case "duplicate-artifact":
				manifest.Artifacts = append(manifest.Artifacts, manifest.Artifacts[0])
			case "traversal":
				manifest.Artifacts[0].Name = "../openrhp.ipk"
			}
			raw, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "unknown-key":
				raw = append(raw[:len(raw)-1], []byte(`,"execute":"evil"}`)...)
			case "duplicate-key":
				raw = append([]byte(`{"project":"OpenRHP",`), raw[1:]...)
			case "trailing-object":
				raw = append(raw, []byte(`{}`)...)
			}
			encoded, err := os.ReadFile(f.private)
			if err != nil {
				t.Fatal(err)
			}
			key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
			if err != nil {
				t.Fatal(err)
			}
			signature := ed25519.Sign(ed25519.PrivateKey(key), raw)
			if err := os.WriteFile(f.manifest, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(
				f.signature,
				[]byte(base64.StdEncoding.EncodeToString(signature)),
				0o600,
			); err != nil {
				t.Fatal(err)
			}
			if err := f.verify("1.2.2"); err == nil {
				t.Fatal("authenticated malformed release accepted")
			}
		})
	}
}

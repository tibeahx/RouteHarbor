// Package release verifies detached Ed25519 release manifests before installation.
// The trusted public key is supplied independently of the artifact download.
package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/tibeahx/OpenRHP/internal/adapter"
)

type Artifact struct {
	Name         string `json:"name"`
	Architecture string `json:"architecture"`
	SHA256       string `json:"sha256"`
	Bytes        int64  `json:"bytes"`
}
type Manifest struct {
	SchemaVersion int        `json:"schema_version"`
	Project       string     `json:"project"`
	Version       string     `json:"version"`
	Commit        string     `json:"commit"`
	Artifacts     []Artifact `json:"artifacts"`
}

var (
	semver   = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	hex40    = regexp.MustCompile(`^[a-f0-9]{40}$`)
	filename = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.+-]{0,180}$`)
)

func versionParts(v string) ([3]uint64, error) {
	var out [3]uint64
	if !semver.MatchString(v) {
		return out, errors.New("stable numeric version required")
	}
	for i, s := range strings.Split(v, ".") {
		n, e := strconv.ParseUint(s, 10, 32)
		if e != nil {
			return out, e
		}
		out[i] = n
	}
	return out, nil
}

func Validate(m Manifest) error {
	if m.SchemaVersion != 1 || m.Project != "OpenRHP" || !hex40.MatchString(m.Commit) ||
		len(m.Artifacts) == 0 ||
		len(m.Artifacts) > 256 {
		return errors.New("invalid manifest metadata")
	}
	if _, e := versionParts(m.Version); e != nil {
		return e
	}
	seen := map[string]bool{}
	for _, a := range m.Artifacts {
		hash, e := hex.DecodeString(a.SHA256)
		if !filename.MatchString(a.Name) || strings.Contains(a.Name, "..") ||
			a.Architecture == "" ||
			len(a.Architecture) > 64 ||
			len(hash) != 32 ||
			e != nil ||
			a.Bytes < 1 ||
			a.Bytes > 512<<20 ||
			seen[a.Name] {
			return errors.New("invalid or duplicate manifest artifact")
		}
		seen[a.Name] = true
	}
	return nil
}

func Sign(m Manifest, key ed25519.PrivateKey) ([]byte, []byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("invalid Ed25519 signing key")
	}
	if e := Validate(m); e != nil {
		return nil, nil, e
	}
	b, e := json.MarshalIndent(m, "", "  ")
	if e != nil {
		return nil, nil, e
	}
	return b, ed25519.Sign(key, b), nil
}

func Verify(
	raw, sig []byte,
	key ed25519.PublicKey,
	arch, current, artifactPath string,
) (Manifest, error) {
	var m Manifest
	if len(raw) > 256<<10 || len(key) != ed25519.PublicKeySize ||
		len(sig) != ed25519.SignatureSize ||
		!ed25519.Verify(key, raw, sig) {
		return m, errors.New("release signature rejected")
	}
	if adapter.StrictDecode(raw, &m) != nil || Validate(m) != nil {
		return m, errors.New("invalid release manifest")
	}
	if current != "" {
		a, e := versionParts(current)
		if e != nil {
			return m, e
		}
		b, _ := versionParts(m.Version)
		for i := range a {
			if b[i] < a[i] {
				return m, errors.New("release downgrade rejected")
			}
			if b[i] > a[i] {
				break
			}
		}
	}
	base := filepath.Base(artifactPath)
	var selected *Artifact
	for i := range m.Artifacts {
		a := m.Artifacts[i]
		if a.Name == base && a.Architecture == arch {
			selected = &a
			break
		}
	}
	if selected == nil {
		return m, errors.New("artifact or package architecture not in signed manifest")
	}
	f, e := os.Lstat(artifactPath)
	if e != nil || !f.Mode().IsRegular() || f.Size() != selected.Bytes {
		return m, errors.New("artifact type or length rejected")
	}
	file, e := os.Open(artifactPath)
	if e != nil {
		return m, errors.New("cannot open artifact")
	}
	defer func() { _ = file.Close() }()
	opened, e := file.Stat()
	if e != nil || !os.SameFile(f, opened) {
		return m, errors.New("artifact changed during verification")
	}
	h := sha256.New()
	count, e := io.Copy(h, io.LimitReader(file, selected.Bytes+1))
	if e != nil || count != selected.Bytes || hex.EncodeToString(h.Sum(nil)) != selected.SHA256 {
		return m, errors.New("artifact checksum rejected")
	}
	return m, nil
}

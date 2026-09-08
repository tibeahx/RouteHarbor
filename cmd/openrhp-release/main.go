// openrhp-release signs or verifies release manifests offline. It never installs
// an artifact or downloads trust keys, packages, scripts or firmware.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/tibeahx/OpenRHP/internal/release"
)

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}

func read(path string, max int64) ([]byte, error) {
	f, e := os.Lstat(path)
	if e != nil || !f.Mode().IsRegular() || f.Size() > max {
		return nil, errors.New("file missing, oversized or not regular")
	}
	return os.ReadFile(path)
}

func create(path string, b []byte, mode os.FileMode) (result error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if e != nil {
		return e
	}
	defer func() {
		if err := f.Close(); result == nil {
			result = err
		}
	}()
	if _, e = f.Write(b); e != nil {
		return e
	}
	return f.Sync()
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: openrhp-release keygen|sign|verify")
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	manifest := f.String("manifest", "", "manifest JSON")
	signature := f.String("signature", "", "detached base64 signature file")
	keyFile := f.String(
		"key",
		"",
		"independently trusted public key (verify) or private signing key (sign)",
	)
	public := f.String("public-out", "", "public key output (keygen)")
	arch := f.String("arch", "", "exact OpenWrt package architecture")
	current := f.String("current-version", "", "installed version to prevent downgrade")
	artifact := f.String("artifact", "", "downloaded artifact file")
	if e := f.Parse(args[1:]); e != nil {
		return e
	}
	if args[0] == "keygen" {
		pub, priv, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return e
		}
		if e = create(
			*keyFile,
			[]byte(base64.StdEncoding.EncodeToString(priv)+"\n"),
			0o600,
		); e != nil {
			return e
		}
		return create(*public, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644)
	}
	raw, e := read(*manifest, 256<<10)
	if e != nil {
		return e
	}
	kb, e := read(*keyFile, 1024)
	if e != nil {
		return e
	}
	key, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(kb)))
	if e != nil {
		return errors.New("invalid key encoding")
	}
	switch args[0] {
	case "sign":
		info, e := os.Stat(*keyFile)
		if e != nil || info.Mode().Perm()&0o077 != 0 {
			return errors.New("private signing key must have mode0600")
		}
		var m release.Manifest
		if e = json.Unmarshal(raw, &m); e != nil {
			return e
		}
		canonical, sig, e := release.Sign(m, ed25519.PrivateKey(key))
		if e != nil {
			return e
		}
		if string(canonical) != string(raw) {
			return errors.New(
				"manifest must be canonical JSON: marshal with two-space indentation and no final newline",
			)
		}
		return create(*signature, []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644)
	case "verify":
		sb, e := read(*signature, 1024)
		if e != nil {
			return e
		}
		sig, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sb)))
		if e != nil {
			return e
		}
		m, e := release.Verify(raw, sig, ed25519.PublicKey(key), *arch, *current, *artifact)
		if e != nil {
			return e
		}
		fmt.Printf("Verified OpenRHP %s, commit %s, architecture %s\n", m.Version, m.Commit, *arch)
		return nil
	default:
		return errors.New("unknown release command")
	}
}

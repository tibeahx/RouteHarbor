package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIssueRevokeAndReload(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	s, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	c, token, e := s.Issue("read")
	if e != nil {
		t.Fatal(e)
	}
	if x, ok := s.Verify(token); !ok || x.Role != "read" {
		t.Fatal("credential rejected")
	}
	if _, ok := s.Verify(token + "x"); ok {
		t.Fatal("invalid credential accepted")
	}
	s, e = Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := s.Verify(token); !ok {
		t.Fatal("not persisted")
	}
	if e = s.Revoke(c.ID); e != nil {
		t.Fatal(e)
	}
	if _, ok := s.Verify(token); ok {
		t.Fatal("revoked accepted")
	}
}

func TestRejectPublicOrSymlinkCredentialFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if e := os.Mkdir(dir, 0o700); e != nil {
		t.Fatal(e)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "credentials.json")); err != nil {
		t.Fatal(err)
	}
	if _, e := Open(dir); e == nil {
		t.Fatal("symlink accepted")
	}
}

func TestIndependentStoresSeeRevocationAndDoNotLoseUpdates(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	api, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	cli, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	admin, token, e := api.Issue("admin")
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := cli.Verify(token); !ok {
		t.Fatal("new credential invisible in another live process")
	}
	_, reader, e := cli.Issue("read")
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := api.Verify(reader); !ok {
		t.Fatal("CLI issue invisible to running API")
	}
	if len(api.List()) != 2 {
		t.Fatal("concurrent store overwrote existing credential")
	}
	if e = cli.Revoke(admin.ID); e != nil {
		t.Fatal(e)
	}
	if _, ok := api.Verify(token); ok {
		t.Fatal("live API accepted CLI-revoked credential")
	}
	if _, ok := api.Verify(reader); !ok {
		t.Fatal("revocation lost unrelated credential")
	}
}

func TestHardlinkedCredentialsRejected(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "auth")
	s, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	_, token, e := s.Issue("admin")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Link(
		filepath.Join(dir, "credentials.json"),
		filepath.Join(t.TempDir(), "linked"),
	); e != nil {
		t.Fatal(e)
	}
	if _, ok := s.Verify(token); ok {
		t.Fatal("hardlinked credential store accepted")
	}
}

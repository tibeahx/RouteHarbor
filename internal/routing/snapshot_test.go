package routing

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRegistryParsingRejectsBroadeningAndMalformedData(t *testing.T) {
	d, e := ParseDomains(
		strings.NewReader("# comment\nEXAMPLE.COM.\nexample.com\nlisted.example\n"),
	)
	if e != nil || len(d) != 2 || d[0] != "example.com" {
		t.Fatal(d, e)
	}
	for _, body := range []string{"", "*.example.com\n", "localhost\n", "https://example.com/\n", "x.example\n" + strings.Repeat("a", 4097)} {
		if _, e := ParseDomains(strings.NewReader(body)); e == nil {
			t.Errorf("accepted malformed list %q", body[:min(len(body), 80)])
		}
	}
	if _, e := ParseSubnets(strings.NewReader("8.8.8.0/24\n10.0.0.0/8\n")); e == nil {
		t.Fatal("accepted nonpublic prefix")
	}
	s, e := ParseSubnets(strings.NewReader("8.8.8.8\n8.8.8.8/32\n"))
	if e != nil || len(s) != 1 || s[0] != "8.8.8.8/32" {
		t.Fatal(s, e)
	}
}

func sampleSnapshot(n uint64) Snapshot {
	return Snapshot{
		Generation: n,
		CreatedAt:  time.Unix(1000, 0).UTC(),
		Domains:    []string{"blocked.example"},
		CIDRs:      []string{"8.8.8.0/24"},
	}
}

func TestAtomicSnapshotLastGoodIntegrityAndBoundedHistory(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0o700); e != nil {
		t.Fatal(e)
	}
	store, e := NewSnapshotStore(dir)
	if e != nil {
		t.Fatal(e)
	}
	for n := uint64(1); n <= 3; n++ {
		if _, e = store.Save(sampleSnapshot(n)); e != nil {
			t.Fatal(e)
		}
	}
	s, ref, e := store.Load()
	if e != nil || s.Generation != 3 {
		t.Fatal(s, ref, e)
	}
	bad := sampleSnapshot(4)
	bad.Domains = []string{"*.example.com"}
	if _, e = store.Save(bad); e == nil {
		t.Fatal("saved invalid candidate")
	}
	s, _, e = store.Load()
	if e != nil || s.Generation != 3 {
		t.Fatal("lost last good", e)
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 4 {
		t.Fatal("history unbounded", len(entries), e)
	}
	if _, e = store.Save(sampleSnapshot(2)); e == nil {
		t.Fatal("replayed snapshot")
	}
	if e = os.WriteFile(store.blob(ref), []byte("{}"), 0o600); e != nil {
		t.Fatal(e)
	}
	previous, previousRef, e := store.Load()
	if e != nil || previous.Generation != 2 {
		t.Fatal("did not recover verified previous snapshot", previous.Generation, e)
	}
	if _, e = store.Save(sampleSnapshot(4)); e != nil {
		t.Fatal("cannot refresh after corrupt head", e)
	}
	if e = os.WriteFile(store.blob(previousRef), []byte("{}"), 0o600); e != nil {
		t.Fatal(e)
	}
	_, currentRef, e := store.Load()
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(store.blob(currentRef), []byte("{}"), 0o600); e != nil {
		t.Fatal(e)
	}
	if _, _, e = store.Load(); e == nil {
		t.Fatal("loaded corrupt current and previous")
	}
	outside := t.TempDir()
	if e = os.Symlink(outside, filepath.Join(dir, "link")); e != nil {
		t.Fatal(e)
	}
	if _, e = NewSnapshotStore(filepath.Join(dir, "link")); e == nil {
		t.Fatal("accepted directory symlink")
	}
}

func TestSnapshotRejectsDuplicateKeysAndBoundsArraysDuringDecode(t *testing.T) {
	base := string(mustEncode(t, sampleSnapshot(1)))
	for _, bad := range []string{strings.Replace(base, `"generation":1`, `"generation":2,"generation":1`, 1), strings.Replace(base, `"domains":`, `"domains":[],"domains":`, 1), strings.Replace(base, `"created_at":`, `"unknown":1,"created_at":`, 1), `{"generation":1,"created_at":"1970-01-01T00:00:00Z","domains":[],"cidrs":[]}, {}`} {
		if _, e := DecodeSnapshot([]byte(bad)); e == nil {
			t.Fatal("ambiguous snapshot accepted")
		}
	}
	oversized := `{"generation":1,"created_at":"1970-01-01T00:00:00Z","domains":[],"cidrs":[` + strings.Repeat(
		`"8.8.8.8/32",`,
		MaxPrefixes,
	) + `"8.8.8.8/32"]}`
	if _, e := DecodeSnapshot([]byte(oversized)); e == nil {
		t.Fatal("oversized array accepted")
	}
}

func TestCompileUsesExactDomainsAndKeepsIPRulesSeparate(t *testing.T) {
	s := sampleSnapshot(1)
	data, e := CompileRuleSet(s, []string{"learned.example"})
	if e != nil {
		t.Fatal(e)
	}
	var decoded struct {
		Version int
		Rules   []map[string]json.RawMessage
	}
	if e = json.Unmarshal(data, &decoded); e != nil {
		t.Fatal(e)
	}
	if decoded.Version != 4 || len(decoded.Rules) != 2 ||
		decoded.Rules[0]["domain_suffix"] != nil ||
		decoded.Rules[0]["ip_cidr"] != nil ||
		decoded.Rules[1]["domain"] != nil {
		t.Fatal(string(data))
	}
	if _, e = DecodeSnapshot(append(mustEncode(t, s), []byte(" {}")...)); e == nil {
		t.Fatal("trailing snapshot accepted")
	}
}

func TestCompileBoundsNativeTriesWithoutLosingExactDomains(t *testing.T) {
	s := sampleSnapshot(1)
	s.Domains = make([]string, (32<<10)+1)
	for index := range s.Domains {
		s.Domains[index] = fmt.Sprintf("d%05d.example", index)
	}
	data, err := CompileRuleSet(s, []string{s.Domains[0], "learned.example"})
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Rules []struct {
			Domain       []string `json:"domain"`
			DomainSuffix []string `json:"domain_suffix"`
			IPCIDR       []string `json:"ip_cidr"`
		}
	}
	if err = json.Unmarshal(data, &set); err != nil {
		t.Fatal(err)
	}
	var flattened []string
	for _, rule := range set.Rules {
		if len(rule.Domain) > 16<<10 || len(rule.DomainSuffix) != 0 {
			t.Fatal("native trie exceeded bound or broadened exact domain")
		}
		flattened = append(flattened, rule.Domain...)
	}
	if len(flattened) != len(s.Domains)+1 ||
		strings.Join(flattened[:len(s.Domains)], "\n") != strings.Join(s.Domains, "\n") ||
		flattened[len(flattened)-1] != "learned.example" {
		t.Fatal("bounded OR rules lost, duplicated or reordered domains")
	}
}

func mustEncode(t *testing.T, s Snapshot) []byte {
	t.Helper()
	b, e := EncodeSnapshot(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

type registryResolver []netip.Addr

func (r registryResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r, nil
}

type registryTransport func(*http.Request) (*http.Response, error)

func (r registryTransport) RoundTrip(q *http.Request) (*http.Response, error) { return r(q) }
func TestRegistryFetcherOnlyExplicitListsNoRedirectsOrPrivateDNS(t *testing.T) {
	f := RegistryFetcher{Resolver: registryResolver{netip.MustParseAddr("127.0.0.1")}}
	if _, e := f.Fetch(context.Background(), 1, time.Now()); e == nil {
		t.Fatal("private registry DNS accepted")
	}
	paths := []string{}
	f.Transport = registryTransport(func(q *http.Request) (*http.Response, error) {
		paths = append(paths, q.URL.Path)
		body := "blocked.example\n"
		if strings.HasSuffix(q.URL.Path, "subnet.lst") {
			body = "8.8.8.0/24\n"
		}
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})
	if _, e := f.Fetch(context.Background(), 1, time.Now()); e != nil {
		t.Fatal(e)
	}
	if strings.Join(paths, ",") != "/list/domains.lst,/list/subnet.lst" {
		t.Fatal(paths)
	}
	f.Transport = registryTransport(func(q *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 302,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     http.Header{"Location": []string{"http://127.0.0.1/"}},
		}, nil
	})
	if _, e := f.Fetch(context.Background(), 1, time.Now()); e == nil {
		t.Fatal("registry redirect accepted")
	}
}

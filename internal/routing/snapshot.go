package routing

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	MaxListBytes     int64 = 64 << 20
	MaxSnapshotBytes int64 = 96 << 20
	MaxDomains             = 2000000
	MaxPrefixes            = 65536
	RegistryRefresh        = 30 * time.Minute
	RegistryStale          = 24 * time.Hour
)

type Snapshot struct {
	Generation      uint64    `json:"generation"`
	CreatedAt       time.Time `json:"created_at"`
	Domains         []string  `json:"domains"`
	CIDRs           []string  `json:"cidrs"`
	RejectedDomains int       `json:"rejected_domains,omitempty"`
}

// SnapshotRef contains no path and is small enough for the helper protocol.
type SnapshotRef struct {
	Generation uint64 `json:"generation"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
}

func ParseDomains(r io.Reader) ([]string, error) { return parseList(r, true) }
func ParseSubnets(r io.Reader) ([]string, error) { return parseList(r, false) }

const MaxRejectedDomains = 1024

// ParseRegistryDomains adapts the provider's real mixed ASCII/IDN feed. A small
// number of malformed entries is excluded rather than repaired or broadened;
// the rejected count is persisted and exposed. More than 1024 or 0.1 percent
// rejects fails the entire candidate and preserves the previous snapshot.
func ParseRegistryDomains(r io.Reader) ([]string, int, error) {
	lr := &io.LimitedReader{R: r, N: MaxListBytes + 1}
	scan := bufio.NewScanner(lr)
	scan.Buffer(make([]byte, 4096), 4096)
	values := []string{}
	rejected := 0
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(values) >= MaxDomains {
			return nil, rejected, errors.New("registry domain limit exceeded")
		}
		domain, e := registryDomain(line)
		if e != nil || LocalDomain(domain) {
			rejected++
			if rejected > MaxRejectedDomains {
				return nil, rejected, errors.New("registry malformed entry limit exceeded")
			}
			continue
		}
		values = append(values, domain)
	}
	if scan.Err() != nil || lr.N <= 0 {
		return nil, rejected, errors.New("registry list exceeds size or line limit")
	}
	if len(values) == 0 || rejected*1000 > len(values)+rejected {
		return nil, rejected, errors.New("registry malformed entry ratio exceeded")
	}
	return uniqueSorted(values), rejected, nil
}

func parseList(r io.Reader, domains bool) ([]string, error) {
	lr := &io.LimitedReader{R: r, N: MaxListBytes + 1}
	s := bufio.NewScanner(lr)
	s.Buffer(make([]byte, 4096), 4096)
	values := []string{}
	limit := MaxPrefixes
	if domains {
		limit = MaxDomains
	}
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(values) >= limit {
			return nil, errors.New("registry entry limit exceeded")
		}
		if domains {
			d, e := CanonicalDomain(line)
			if e != nil || LocalDomain(d) {
				return nil, errors.New("invalid registry domain")
			}
			values = append(values, d)
		} else {
			p, e := CanonicalPrefix(line)
			if e != nil {
				return nil, errors.New("invalid registry subnet")
			}
			values = append(values, p.String())
		}
	}
	if s.Err() != nil || lr.N <= 0 {
		return nil, errors.New("registry list exceeds size or line limit")
	}
	if len(values) == 0 {
		return nil, errors.New("empty registry list")
	}
	return uniqueSorted(values), nil
}

func ValidateSnapshot(s Snapshot) error {
	if s.Generation == 0 || s.CreatedAt.IsZero() || len(s.Domains) > MaxDomains ||
		len(s.CIDRs) > MaxPrefixes ||
		s.RejectedDomains < 0 ||
		s.RejectedDomains > MaxRejectedDomains {
		return errors.New("invalid registry snapshot metadata")
	}
	for i, d := range s.Domains {
		v, e := CanonicalDomain(d)
		if e != nil || v != d || LocalDomain(v) || i > 0 && s.Domains[i-1] >= d {
			return errors.New("registry domains must be canonical, sorted and unique")
		}
	}
	for i, cidr := range s.CIDRs {
		p, e := CanonicalPrefix(cidr)
		if e != nil || p.String() != cidr || i > 0 && s.CIDRs[i-1] >= cidr {
			return errors.New("registry subnets must be canonical, sorted and unique")
		}
	}
	return nil
}

func EncodeSnapshot(s Snapshot) ([]byte, error) {
	if err := ValidateSnapshot(s); err != nil {
		return nil, err
	}
	data, err := json.Marshal(s)
	if int64(len(data)) > MaxSnapshotBytes {
		return nil, errors.New("registry snapshot exceeds limit")
	}
	return data, err
}

func DecodeSnapshot(data []byte) (Snapshot, error) {
	var s Snapshot
	if int64(len(data)) > MaxSnapshotBytes {
		return s, errors.New("registry snapshot exceeds limit")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	var fields uint8
	// Stream the top-level object and bounded arrays. The ordinary struct
	// decoder silently accepts duplicate keys and allocates unbounded arrays
	// before validation, neither of which is appropriate at the helper boundary.
	err := decodeObject(d, func(key string) error {
		switch key {
		case "generation":
			fields |= 1
			return d.Decode(&s.Generation)
		case "created_at":
			fields |= 2
			return d.Decode(&s.CreatedAt)
		case "domains":
			fields |= 4
			var e error
			s.Domains, e = decodeStrings(d, MaxDomains)
			return e
		case "cidrs":
			fields |= 8
			var e error
			s.CIDRs, e = decodeStrings(d, MaxPrefixes)
			return e
		case "rejected_domains":
			return d.Decode(&s.RejectedDomains)
		default:
			return errors.New("unknown snapshot field")
		}
	}, -1)
	if err != nil || fields != 15 {
		return s, errors.New("invalid registry snapshot")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return s, errors.New("trailing registry snapshot content")
	}
	return s, ValidateSnapshot(s)
}

func decodeObject(d *json.Decoder, field func(string) error, count int) error {
	token, e := d.Token()
	if e != nil || token != json.Delim('{') {
		return errors.New("expected object")
	}
	seen := map[string]bool{}
	for d.More() {
		token, e = d.Token()
		if e != nil {
			return e
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return errors.New("duplicate or invalid object key")
		}
		seen[key] = true
		if e = field(key); e != nil {
			return e
		}
	}
	token, e = d.Token()
	if e != nil || token != json.Delim('}') || count >= 0 && len(seen) != count {
		return errors.New("invalid object fields")
	}
	return nil
}

func decodeStrings(d *json.Decoder, limit int) ([]string, error) {
	token, e := d.Token()
	if e != nil {
		return nil, e
	}
	if token == nil {
		return nil, nil
	}
	if token != json.Delim('[') {
		return nil, errors.New("expected string array")
	}
	values := []string{}
	for d.More() {
		if len(values) >= limit {
			return nil, errors.New("snapshot entry limit exceeded")
		}
		token, e = d.Token()
		if e != nil {
			return nil, e
		}
		s, ok := token.(string)
		if !ok || len(s) > 253 {
			return nil, errors.New("invalid snapshot entry")
		}
		values = append(values, s)
	}
	token, e = d.Token()
	if e != nil || token != json.Delim(']') {
		return nil, errors.New("invalid snapshot array")
	}
	return values, nil
}

func Reference(s Snapshot, data []byte) SnapshotRef {
	sum := sha256.Sum256(data)
	return SnapshotRef{s.Generation, hex.EncodeToString(sum[:]), int64(len(data))}
}

func ValidateReference(ref SnapshotRef) error {
	b, e := hex.DecodeString(ref.SHA256)
	if e != nil || len(b) != 32 || strings.ToLower(ref.SHA256) != ref.SHA256 ||
		ref.Generation == 0 ||
		ref.Size <= 0 ||
		ref.Size > MaxSnapshotBytes {
		return errors.New("invalid registry snapshot reference")
	}
	return nil
}

// CompileRuleSet is the single hot-reloadable sing-box source set. Manual direct
// and bypass exceptions belong in the dispatcher's earlier fixed route rules.
func CompileRuleSet(s Snapshot, learned []string) ([]byte, error) {
	if err := ValidateSnapshot(s); err != nil {
		return nil, err
	}
	domains := append([]string{}, s.Domains...)
	if len(learned) > MaxLearned {
		return nil, errors.New("learned domain limit exceeded")
	}
	for _, d := range learned {
		v, e := CanonicalDomain(d)
		if e != nil || LocalDomain(v) {
			return nil, errors.New("invalid learned domain")
		}
		domains = append(domains, v)
	}
	type rule struct {
		Domain []string `json:"domain,omitempty"`
		IPCIDR []string `json:"ip_cidr,omitempty"`
	}
	rules := []rule{}
	if len(domains) > 0 {
		domains = uniqueSorted(domains)
		// Headless rules are ORed. Keep each exact-domain trie bounded so a
		// full registry cannot cause one enormous native construction heap.
		const domainsPerRule = 16 << 10
		for offset := 0; offset < len(domains); offset += domainsPerRule {
			rules = append(
				rules,
				rule{Domain: domains[offset:min(offset+domainsPerRule, len(domains))]},
			)
		}
	}
	if len(s.CIDRs) > 0 {
		rules = append(rules, rule{IPCIDR: s.CIDRs})
	}
	return json.Marshal(struct {
		Version int    `json:"version"`
		Rules   []rule `json:"rules"`
	}{4, rules})
}

// SnapshotStore uses immutable content-addressed files and an atomic tiny head.
// The directory must be private and must not be a symlink. Interrupted writes
// cannot replace the previous head, and Load always verifies size and SHA256.
type SnapshotStore struct {
	dir string
	mu  sync.Mutex
}

func NewSnapshotStore(dir string) (*SnapshotStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("registry directory must be a private real directory")
	}
	return &SnapshotStore{dir: dir}, nil
}

func (s *SnapshotStore) blob(ref SnapshotRef) string {
	return filepath.Join(s.dir, fmt.Sprintf("%d-%s.json", ref.Generation, ref.SHA256))
}

func (s *SnapshotStore) Save(snapshot Snapshot) (SnapshotRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := EncodeSnapshot(snapshot)
	if err != nil {
		return SnapshotRef{}, err
	}
	ref := Reference(snapshot, data)
	_, old, oldErr := s.loadLastGood()
	if oldErr == nil && ref.Generation <= old.Generation {
		return SnapshotRef{}, errors.New("registry generation must increase")
	}
	if oldErr != nil && !errors.Is(oldErr, os.ErrNotExist) {
		return SnapshotRef{}, oldErr
	}
	if err = s.atomicWrite(s.blob(ref), data); err != nil {
		return SnapshotRef{}, err
	}
	if oldErr == nil {
		prev, _ := json.Marshal(old)
		if err = s.atomicWrite(filepath.Join(s.dir, "previous.json"), prev); err != nil {
			return SnapshotRef{}, err
		}
	}
	head, _ := json.Marshal(ref)
	if err = s.atomicWrite(filepath.Join(s.dir, "current.json"), head); err != nil {
		return SnapshotRef{}, err
	}
	// Keep the current and previous immutable snapshots; never grow flash forever.
	entries, _ := os.ReadDir(s.dir)
	for _, e := range entries {
		name := e.Name()
		if name == "current.json" || name == "previous.json" ||
			filepath.Join(s.dir, name) == s.blob(ref) ||
			oldErr == nil && filepath.Join(s.dir, name) == s.blob(old) {
			continue
		}
		if strings.HasSuffix(name, ".json") && !e.IsDir() {
			_ = os.Remove(filepath.Join(s.dir, name))
		}
	}
	return ref, nil
}

func (s *SnapshotStore) loadHead(name string) (SnapshotRef, error) {
	var ref SnapshotRef
	data, err := readPrivate(filepath.Join(s.dir, name), 2048)
	if err != nil {
		return ref, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if err = decodeObject(d, func(key string) error {
		switch key {
		case "generation":
			return d.Decode(&ref.Generation)
		case "sha256":
			return d.Decode(&ref.SHA256)
		case "size":
			return d.Decode(&ref.Size)
		default:
			return errors.New("unknown registry reference field")
		}
	}, 3); err != nil {
		return ref, errors.New("invalid registry head")
	}
	if d.Decode(new(any)) != io.EOF {
		return ref, errors.New("invalid registry head")
	}
	return ref, ValidateReference(ref)
}

func (s *SnapshotStore) Load() (Snapshot, SnapshotRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLastGood()
}

func (s *SnapshotStore) loadLastGood() (Snapshot, SnapshotRef, error) {
	snap, ref, err := s.loadNamed("current.json")
	if err == nil {
		return snap, ref, nil
	}
	previous, previousRef, previousErr := s.loadNamed("previous.json")
	if previousErr == nil {
		return previous, previousRef, nil
	}
	return Snapshot{}, SnapshotRef{}, err
}

func (s *SnapshotStore) loadNamed(name string) (Snapshot, SnapshotRef, error) {
	ref, err := s.loadHead(name)
	if err != nil {
		return Snapshot{}, ref, err
	}
	data, err := readPrivate(s.blob(ref), MaxSnapshotBytes)
	if err != nil {
		return Snapshot{}, ref, err
	}
	snap, err := DecodeSnapshot(data)
	if err != nil {
		return snap, ref, err
	}
	if Reference(snap, data) != ref {
		return Snapshot{}, ref, errors.New("registry snapshot integrity failed")
	}
	return snap, ref, nil
}

func readPrivate(path string, limit int64) ([]byte, error) {
	i, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !i.Mode().IsRegular() || i.Mode().Perm()&0o077 != 0 || i.Size() > limit {
		return nil, errors.New("unsafe registry file")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer func() { _ = f.Close() }()
	after, e := f.Stat()
	if e != nil || !os.SameFile(i, after) {
		return nil, errors.New("registry file changed during open")
	}
	return io.ReadAll(io.LimitReader(f, limit+1))
}

func (s *SnapshotStore) atomicWrite(path string, data []byte) error {
	f, e := os.CreateTemp(s.dir, ".registry-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }()
	if _, e = f.Write(data); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	d, e := os.Open(s.dir)
	if e != nil {
		return e
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

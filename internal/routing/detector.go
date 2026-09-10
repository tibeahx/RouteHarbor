package routing

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/platform"
)

const (
	MaxCandidates      = 2048
	MaxLearned         = 1024
	DetectionTTL       = time.Hour
	DetectionSpacing   = 10 * time.Second
	DetectionRecheck   = 10 * time.Minute
	CandidateRetention = 5 * time.Minute
	ControlFreshness   = 30 * time.Second
	DetectionPerMinute = 12
)

type AddressResult struct {
	IP               netip.Addr
	DirectSuccess    bool
	BypassSuccess    bool
	CertificateError bool
}

// Round is accepted only when every resolved public address was checked on both
// paths with the same IP and SNI. The caller must explicitly attest completeness.
type Round struct {
	Addresses []AddressResult
	Complete  bool
	ControlOK bool
	ControlAt time.Time
	DNSError  bool
}
type Candidate struct {
	Domain  string
	Epoch   string
	Token   uint64
	Recheck bool
}
type DetectorStatus struct {
	Enabled       bool   `json:"enabled"`
	Candidates    int    `json:"candidates"`
	Learned       int    `json:"learned"`
	InFlight      int    `json:"in_flight"`
	Dropped       uint64 `json:"dropped"`
	Indeterminate uint64 `json:"indeterminate"`
}
type candidateState struct {
	seen      time.Time
	checked   time.Time
	due       time.Time
	expires   time.Time
	inFlight  uint64
	started   time.Time
	failures  int
	successes int
}
type Detector struct {
	mu            sync.Mutex
	enabled       bool
	epoch         string
	nextToken     uint64
	entries       map[string]*candidateState
	window        time.Time
	budget        int
	dropped       uint64
	indeterminate uint64
}

func NewDetector(enabled bool) *Detector {
	return &Detector{enabled: enabled, entries: make(map[string]*candidateState)}
}

func (d *Detector) Observe(domain string, now time.Time) bool {
	domain, e := CanonicalDomain(domain)
	if e != nil || LocalDomain(domain) {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.enabled {
		return false
	}
	d.expire(now)
	if c := d.entries[domain]; c != nil {
		c.seen = now
		return true
	}
	if len(d.entries) >= MaxCandidates {
		d.dropped++
		return false
	}
	d.entries[domain] = &candidateState{seen: now}
	return true
}

func (d *Detector) expire(now time.Time) {
	for domain, c := range d.entries {
		if c.inFlight != 0 && now.Sub(c.started) > 2*time.Minute {
			c.inFlight = 0
			c.failures = 0
			c.successes = 0
			d.indeterminate++
		}
		if !c.expires.IsZero() && !now.Before(c.expires) {
			c.expires = time.Time{}
			c.failures = 0
			c.successes = 0
		}
		if c.expires.IsZero() && c.inFlight == 0 && now.Sub(c.seen) > CandidateRetention {
			delete(d.entries, domain)
		}
	}
}

func (d *Detector) Next(now time.Time, epoch string) (Candidate, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.enabled || epoch == "" {
		return Candidate{}, false
	}
	if epoch != d.epoch {
		d.epoch = epoch
		for _, c := range d.entries {
			c.failures = 0
			c.successes = 0
			c.inFlight = 0
			c.checked = time.Time{}
			c.due = time.Time{}
		}
	}
	d.expire(now)
	if d.window.IsZero() || now.Sub(d.window) >= time.Minute {
		d.window = now
		d.budget = 0
	}
	if d.budget >= DetectionPerMinute {
		return Candidate{}, false
	}
	// Pick by due time and then domain, independent of Go map iteration order.
	names := make([]string, 0, len(d.entries))
	for name := range d.entries {
		names = append(names, name)
	}
	sort.Strings(names)
	chosen := ""
	var first *candidateState
	for _, name := range names {
		c := d.entries[name]
		if c.inFlight != 0 || now.Before(c.due) {
			continue
		}
		if first == nil || c.checked.Before(first.checked) {
			chosen = name
			first = c
		}
	}
	if first == nil {
		return Candidate{}, false
	}
	d.nextToken++
	first.inFlight = d.nextToken
	first.started = now
	first.checked = now
	d.budget++
	return Candidate{chosen, epoch, d.nextToken, !first.expires.IsZero()}, true
}

func (d *Detector) Record(candidate Candidate, round Round, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	c := d.entries[candidate.Domain]
	if !d.enabled || c == nil || candidate.Epoch != d.epoch || candidate.Token == 0 ||
		c.inFlight != candidate.Token {
		return false
	}
	c.inFlight = 0
	valid := round.Complete && !round.DNSError && len(round.Addresses) > 0 &&
		len(round.Addresses) <= 64 &&
		!now.Before(c.started) &&
		now.Sub(c.started) <= 2*time.Minute
	anyDirect := false
	allBypass := true
	seen := map[netip.Addr]bool{}
	for _, a := range round.Addresses {
		ip := a.IP.Unmap()
		if !platform.PublicAddress(ip) || seen[ip] || a.CertificateError {
			valid = false
		}
		seen[ip] = true
		anyDirect = anyDirect || a.DirectSuccess
		allBypass = allBypass && a.BypassSuccess
	}
	if !valid {
		d.indeterminate++
		c.failures = 0
		c.successes = 0
		c.due = now.Add(time.Minute)
		return false
	}
	if anyDirect {
		c.failures = 0
		c.successes++
		if !c.expires.IsZero() && c.successes >= 3 {
			c.expires = time.Time{}
			c.successes = 0
			c.due = now.Add(time.Minute)
			return true
		}
		if !c.expires.IsZero() {
			c.due = now.Add(DetectionSpacing)
		} else {
			c.due = now.Add(time.Minute)
		}
		return false
	}
	controlFresh := round.ControlOK && !round.ControlAt.IsZero() && !now.Before(round.ControlAt) &&
		now.Sub(round.ControlAt) <= ControlFreshness
	if !allBypass || !controlFresh {
		d.indeterminate++
		c.failures = 0
		c.successes = 0
		c.due = now.Add(time.Minute)
		return false
	}
	c.successes = 0
	c.failures++
	if c.failures < 3 {
		c.due = now.Add(DetectionSpacing)
		return false
	}
	if c.expires.IsZero() {
		count := 0
		for _, entry := range d.entries {
			if now.Before(entry.expires) {
				count++
			}
		}
		if count >= MaxLearned {
			d.dropped++
			c.failures = 0
			c.due = now.Add(DetectionRecheck)
			return false
		}
	}
	c.expires = now.Add(DetectionTTL)
	c.failures = 0
	c.due = now.Add(DetectionRecheck)
	return true
}

func (d *Detector) Learned(now time.Time) map[string]time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.expire(now)
	out := map[string]time.Time{}
	for domain, c := range d.entries {
		if now.Before(c.expires) {
			out[domain] = c.expires
		}
	}
	return out
}

func (d *Detector) Status(now time.Time) DetectorStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.expire(now)
	s := DetectorStatus{
		Enabled:       d.enabled,
		Candidates:    len(d.entries),
		Dropped:       d.dropped,
		Indeterminate: d.indeterminate,
	}
	for _, c := range d.entries {
		if now.Before(c.expires) {
			s.Learned++
		}
		if c.inFlight != 0 {
			s.InFlight++
		}
	}
	return s
}

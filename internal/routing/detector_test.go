package routing

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func blockedRound(now time.Time) Round {
	return Round{
		Complete:  true,
		ControlOK: true,
		ControlAt: now,
		Addresses: []AddressResult{{IP: netip.MustParseAddr("93.184.216.34"), BypassSuccess: true}},
	}
}

func drive(t *testing.T, d *Detector, now time.Time, epoch string, round Round) bool {
	t.Helper()
	c, ok := d.Next(now, epoch)
	if !ok {
		t.Fatal("no due candidate")
	}
	return d.Record(c, round, now)
}

func TestDetectorNeedsThreeSpacedChecksAndExpiresExactDomain(t *testing.T) {
	now := time.Unix(1000, 0)
	d := NewDetector(true)
	if !d.Observe("blocked.example", now) {
		t.Fatal("not observed")
	}
	if drive(t, d, now, "wan-a:bypass-a", blockedRound(now)) {
		t.Fatal("one failure learned")
	}
	if _, ok := d.Next(now.Add(9*time.Second), "wan-a:bypass-a"); ok {
		t.Fatal("unspaced round allowed")
	}
	for i := 1; i < 3; i++ {
		at := now.Add(time.Duration(i) * 10 * time.Second)
		changed := drive(t, d, at, "wan-a:bypass-a", blockedRound(at))
		if changed != (i == 2) {
			t.Fatal("wrong threshold", i, changed)
		}
	}
	learned := d.Learned(now.Add(20 * time.Second))
	if len(learned) != 1 || !learned["blocked.example"].Equal(now.Add(20*time.Second+time.Hour)) {
		t.Fatal(learned)
	}
	if len(d.Learned(now.Add(20*time.Second+time.Hour))) != 0 {
		t.Fatal("expired rule retained")
	}
}

func TestDetectorRejectsIndeterminateRoundsAndResetsOnEpoch(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Round)
	}{
		{"partial", func(r *Round) { r.Complete = false }},
		{"dns", func(r *Round) { r.DNSError = true }},
		{"no control", func(r *Round) { r.ControlOK = false }},
		{"stale control", func(r *Round) { r.ControlAt = r.ControlAt.Add(-time.Minute) }},
		{"certificate", func(r *Round) { r.Addresses[0].CertificateError = true }},
		{"working address", func(r *Round) {
			r.Addresses = append(r.Addresses, AddressResult{IP: netip.MustParseAddr("1.1.1.1"), DirectSuccess: true})
		}},
		{"both fail", func(r *Round) { r.Addresses[0].BypassSuccess = false }},
		{"private", func(r *Round) { r.Addresses[0].IP = netip.MustParseAddr("10.0.0.1") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Unix(1000, 0)
			d := NewDetector(true)
			d.Observe("candidate.example", now)
			for i := 0; i < 3; i++ {
				at := now.Add(time.Duration(i) * time.Minute)
				r := blockedRound(at)
				tc.edit(&r)
				if drive(t, d, at, "epoch", r) {
					t.Fatal("indeterminate learned")
				}
			}
			if len(d.Learned(now.Add(2*time.Minute))) != 0 {
				t.Fatal("learned")
			}
		})
	}
	now := time.Unix(1000, 0)
	d := NewDetector(true)
	d.Observe("candidate.example", now)
	drive(t, d, now, "one", blockedRound(now))
	at := now.Add(10 * time.Second)
	old, ok := d.Next(at, "one")
	if !ok {
		t.Fatal("no candidate")
	}
	fresh, ok := d.Next(at, "two")
	if !ok {
		t.Fatal("no candidate after epoch")
	}
	if d.Record(old, blockedRound(at), at) {
		t.Fatal("stale result applied")
	}
	if d.Record(fresh, blockedRound(at), at) {
		t.Fatal("epoch retained confirmations")
	}
}

func TestDetectorRecoveryRenewalAndBoundedQueue(t *testing.T) {
	now := time.Unix(1000, 0)
	d := NewDetector(true)
	d.Observe("blocked.example", now)
	for i := 0; i < 3; i++ {
		at := now.Add(time.Duration(i) * 10 * time.Second)
		drive(t, d, at, "e", blockedRound(at))
	}
	at := now.Add(20*time.Second + DetectionRecheck)
	for i := 0; i < 3; i++ {
		roundAt := at.Add(time.Duration(i) * 10 * time.Second)
		r := blockedRound(roundAt)
		r.Addresses[0].DirectSuccess = true
		changed := drive(t, d, roundAt, "e", r)
		if changed != (i == 2) {
			t.Fatal("bad recovery threshold")
		}
	}
	if len(d.Learned(at.Add(20*time.Second))) != 0 {
		t.Fatal("recovered rule retained")
	}
	for i := 0; i < MaxCandidates; i++ {
		d.Observe(fmt.Sprintf("d%d.example", i), at)
	}
	if d.Observe("overflow.example", at) {
		t.Fatal("unbounded queue")
	}
	if d.Status(at).Candidates > MaxCandidates {
		t.Fatal("unbounded state")
	}
	for i := 0; i < DetectionPerMinute; i++ {
		if _, ok := d.Next(at.Add(time.Minute), "e"); !ok {
			t.Fatal("budget too small")
		}
	}
	if _, ok := d.Next(at.Add(time.Minute), "e"); ok {
		t.Fatal("rate budget not enforced")
	}
}

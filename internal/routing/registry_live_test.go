package routing

import (
	"context"
	"os"
	"testing"
	"time"
)

// Read-only provider evidence is separate from deterministic unit tests. It
// never creates routing rules, writes a router or touches a physical device.
func TestLiveRegistryProvider(t *testing.T) {
	if os.Getenv("OPENRHP_REGISTRY_LIVE") != "1" {
		t.Skip("requires explicit live registry download")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	s, e := (RegistryFetcher{}).Fetch(ctx, 1, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	b, e := EncodeSnapshot(s)
	if e != nil {
		t.Fatal(e)
	}
	t.Logf(
		"validated Antifilter domains=%d explicit_subnets=%d rejected_domains=%d snapshot_bytes=%d",
		len(s.Domains),
		len(s.CIDRs),
		s.RejectedDomains,
		len(b),
	)
}

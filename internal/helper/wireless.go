package helper

import (
	"context"

	"github.com/tibeahx/OpenRHP/internal/platform"
	"github.com/tibeahx/OpenRHP/internal/wireless"
)

// VerifiedPlatform projects only a current root-owned, device-bound authorization.
// It does not expose the receipt, private identity or arbitrary wireless config.
func VerifiedPlatform(ctx context.Context, verifier *wireless.Verifier) platform.Report {
	report := platform.Detect(ctx)
	reset := platform.Capability{
		Reason: "Install conntrack and kernel conntrack netlink support; privileged preflight verifies both families",
	}
	if err := (systemConntrack{}).check(ctx); err == nil {
		reset = platform.Capability{
			Available: true,
			Reason:    "Privileged IPv4/IPv6 connection mark filtering is available",
		}
	}
	report.Capabilities["break_existing"] = reset
	authorization, err := verifier.Authorized(ctx)
	if err != nil {
		return report
	}
	report.VerifiedPeerFingerprint = authorization.PeerFingerprint
	report.VerifiedRadio = authorization.Radio
	report.VerifiedMode = authorization.Mode
	reason := "Current root-recorded verification for this radio, encrypted mode and paired peer"
	for _, capability := range []string{authorization.Mode, "encrypted_backhaul", "concurrent_radio"} {
		report.Capabilities[capability] = platform.Capability{Available: true, Reason: reason}
	}
	return report
}

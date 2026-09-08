package platform

import (
	"net/netip"
	"testing"
)

func TestPublicAddressRejectsDocumentationAndDeprecatedSiteLocal(t *testing.T) {
	for _, s := range []string{"3fff::1", "3fff:fff::1", "fec0::1", "feff::1"} {
		if PublicAddress(netip.MustParseAddr(s)) {
			t.Fatal("special-use IPv6 accepted", s)
		}
	}
	if !PublicAddress(netip.MustParseAddr("2606:4700:4700::1111")) {
		t.Fatal("ordinary public IPv6 rejected")
	}
}

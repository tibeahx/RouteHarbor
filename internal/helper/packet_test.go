package helper

import (
	"strings"
	"testing"
)

func TestPacketManagerRejectsUnknownVersionAndInput(t *testing.T) {
	for _, s := range []string{"v72.10", "github version v72.9 (f0b0d89)", "github version v72.10 (attacker)", "self-built version unknown", "prefix github version v72.10 (f0b0d89)"} {
		if validPacketVersion(s) {
			t.Error("accepted unknown build", s)
		}
	}
	if !validPacketVersion("github version v72.10 (f0b0d89)\n\n") {
		t.Fatal("rejected pinned version")
	}
	for _, id := range []string{"../x", "a;b", "", "x\n"} {
		if validatePacketRequest(id, 1) == nil {
			t.Error("accepted source ID")
		}
	}
	for _, slot := range []int{-1, 0, 251} {
		if validatePacketRequest("safe", slot) == nil {
			t.Error("accepted queue slot")
		}
	}
}

func TestPacketQueueMarksDoNotCrossProfiles(t *testing.T) {
	a := strings.Join(packetArgs(1), " ")
	b := strings.Join(packetArgs(2), " ")
	if !strings.Contains(a, "--qnum=21001") ||
		!strings.Contains(a, "--dpi-desync-fwmark=0x4f018000") ||
		!strings.Contains(b, "--qnum=21002") ||
		!strings.Contains(b, "--dpi-desync-fwmark=0x4f028000") {
		t.Fatal("packet path namespace mismatch", a, b)
	}
	if strings.Contains(a, "lua") || !strings.Contains(a, "--user=nobody") {
		t.Fatal("packet execution boundary changed")
	}
}

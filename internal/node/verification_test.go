package node

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestEnrolledGatewayReadIsBoundedAndDoesNotFollowLinks(t *testing.T) {
	for _, kind := range []string{"valid", "wrong-version", "duplicate", "too-large", "world-readable", "symlink", "hardlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(dir, "enrollment.json")
			pin := strings.Repeat("a", 64)
			data, err := json.Marshal(enrollment{Version: 1, GatewayFingerprint: pin})
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "wrong-version":
				data = []byte(`{"version":2,"gateway_fingerprint":"` + pin + `"}`)
			case "duplicate":
				data = []byte(`{"version":1,"version":1,"gateway_fingerprint":"` + pin + `"}`)
			case "too-large":
				data = append(data, []byte(strings.Repeat(" ", 9<<10))...)
			}
			if kind == "fifo" {
				if err := syscall.Mkfifo(name, 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(name, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "world-readable":
				if err := os.Chmod(name, 0o644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(name, filepath.Join(dir, "target")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("target", name); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(name, filepath.Join(dir, "alias")); err != nil {
					t.Fatal(err)
				}
			}
			result, err := enrolledGateway(dir)
			if kind == "valid" {
				if err != nil || result != pin {
					t.Fatal("valid enrollment unavailable", err)
				}
			} else if err == nil {
				t.Fatal("unsafe enrollment accepted")
			}
		})
	}
}

func TestNodeReceiptRestrictsSelectedRadioAndMode(t *testing.T) {
	p := plan()
	p.Mode = "wds"
	p.Radio = "radio0"
	p.SSID = "Home"
	p.Passphrase = "verified-private-key"
	p.Channel = 6
	p.ShareRadio = true
	p.Uplink = "wlan0"
	p.EthernetUplink = p.LANPorts[0]
	caps := Capabilities{
		OpenWrt:              true,
		Ethernet:             true,
		AP:                   true,
		WDS:                  true,
		Mesh:                 true,
		EncryptedBackhaul:    true,
		ConcurrentRadio:      true,
		GatewayBackhaulReady: true,
		VerifiedRadio:        "radio1",
		VerifiedMode:         "wds",
	}
	if err := ValidatePlan(p, caps, caps); err == nil {
		t.Fatal("receipt from different radio accepted")
	}
	caps.VerifiedRadio = "radio0"
	caps.VerifiedMode = "mesh"
	if err := ValidatePlan(p, caps, caps); err == nil {
		t.Fatal("receipt from different mode accepted")
	}
}

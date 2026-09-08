//go:build linux

package helper

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/tibeahx/OpenRHP/internal/dataplane"
)

func TestLinuxConntrackResetPreservesCurrentAndForeignFlows(t *testing.T) {
	prepareLab(t)
	ctx := context.Background()
	binary, err := conntrackBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err = (systemConntrack{}).check(ctx); err != nil {
		t.Fatal(err)
	}
	for _, reset := range []bool{false, true} {
		t.Run(fmt.Sprint(reset), func(t *testing.T) {
			prepareLab(t)
			oldSlot, newSlot := uint16(21), uint16(22)
			if reset {
				oldSlot, newSlot = 23, 24
			}
			for fi, family := range []string{"ipv4", "ipv6"} {
				src, dst := "10.44.0.2", "198.51.100.2"
				if family == "ipv6" {
					src, dst = "fd44::2", "2001:db8::2"
				}
				marks := []uint32{
					dataplane.Mark(oldSlot) | 0xa5,
					dataplane.Mark(newSlot) | 0xb6,
					0x123400c7,
					0,
				}
				for mi, mark := range marks {
					for pi, protocol := range []string{"tcp", "udp"} {
						args := []string{
							"--create",
							"--proto",
							protocol,
							"--orig-src",
							src,
							"--orig-dst",
							dst,
							"--sport",
							fmt.Sprint(40000 + int(oldSlot)*100 + fi*40 + mi*4 + pi),
							"--dport",
							"443",
							"--timeout",
							"120",
							"--mark",
							fmt.Sprintf("0x%08x", mark),
						}
						if protocol == "tcp" {
							args = append(args, "--state", "ESTABLISHED")
						}
						labCommand(t, binary, args...)
					}
				}
			}
			m := testManager(t, labBackend(), &testWatchdog{})
			d := testDesired()
			d.Paths[0].Slot, d.Paths[1].Slot = oldSlot, newSlot
			d.BreakExisting = reset
			for _, selected := range []string{"a", "b"} {
				d.Selected = selected
				x, err := m.Prepare(ctx, d)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = m.Apply(ctx, x.ID, 30*time.Second); err != nil {
					t.Fatal(err)
				}
				x, err = m.Confirm(x.ID)
				if err != nil {
					t.Fatal(err)
				}
				if selected == "b" && reset && x.FlowTermination != "completed" {
					t.Fatal(x)
				}
			}
			for _, family := range []string{"ipv4", "ipv6"} {
				oldPresent, err := runConntrack(
					ctx,
					binary,
					"--dump",
					family,
					dataplane.Mark(oldSlot),
				)
				if err != nil || oldPresent == reset {
					t.Fatal("old source tracking", family, oldPresent, err)
				}
				currentPresent, err := runConntrack(
					ctx,
					binary,
					"--dump",
					family,
					dataplane.Mark(newSlot),
				)
				if err != nil || !currentPresent {
					t.Fatal("current source tracking removed", family, err)
				}
				for _, mark := range []string{"0x12340000/0xffff0000", "0/0xffffffff"} {
					out := labCommand(t, binary, "--dump", "--family", family, "--mark", mark)
					if !containsFlowTuple(out) {
						t.Fatal("foreign/unmarked flow removed", family, mark)
					}
				}
			}
			if reset {
				if err := (systemConntrack{}).reset(ctx, oldSlot); err != nil {
					t.Fatal("empty reset not idempotent", err)
				}
			}
		})
	}
}

func containsFlowTuple(data []byte) bool {
	for i := 0; i+4 <= len(data); i++ {
		if string(data[i:i+4]) == "src=" {
			return true
		}
	}
	return false
}

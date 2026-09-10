package helper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/dataplane"
)

// flowResetBackend is deliberately typed: clients cannot supply a mark, mask,
// family, command, or binary. Only a previous committed source slot is reset.
type flowResetBackend interface {
	CheckFlowReset(context.Context) error
	ResetFlowTracking(context.Context, uint16) error
}

func (b *NetworkBackend) CheckFlowReset(ctx context.Context) error {
	return (systemConntrack{}).check(ctx)
}

func (b *NetworkBackend) ResetFlowTracking(ctx context.Context, slot uint16) error {
	return (systemConntrack{}).reset(ctx, slot)
}

type systemConntrack struct{}

func conntrackBinary() (string, error) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return "", errors.New(
			"capability_unavailable: connection tracking reset requires the Linux root helper",
		)
	}
	for _, binary := range []string{"/usr/sbin/conntrack", "/sbin/conntrack"} {
		trusted := true
		for path := binary; ; path = filepath.Dir(path) {
			info, err := os.Lstat(path)
			if err != nil || !ownedByCurrentUID(info) || info.Mode().Perm()&0o022 != 0 ||
				info.Mode()&os.ModeSymlink != 0 {
				trusted = false
				break
			}
			if path == binary && (!info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0) {
				trusted = false
				break
			}
			if path == "/" {
				break
			}
		}
		if trusted {
			return binary, nil
		}
	}
	return "", errors.New(
		"capability_unavailable: install a trusted conntrack package and kernel conntrack netlink support",
	)
}

type presenceWriter struct{ present bool }

func (w *presenceWriter) Write(p []byte) (int, error) {
	w.present = w.present || len(p) != 0
	return len(p), nil
}

// Never retain connection tuples or expose command output. Execution, output
// memory and inherited environment are bounded independently of the API request.
func runConntrack(ctx context.Context, binary, action, family string, mark uint32) (bool, error) {
	if (action != "--dump" && action != "--delete") || (family != "ipv4" && family != "ipv6") ||
		mark&dataplane.NamespaceMask != dataplane.Namespace || mark&^dataplane.MarkMask != 0 {
		return false, errors.New("invalid_connection_tracking_operation")
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(
		ctx,
		binary,
		action,
		"--family",
		family,
		"--mark",
		fmt.Sprintf("0x%08x/0xffff0000", mark),
	)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.WaitDelay = 100 * time.Millisecond
	out := &presenceWriter{}
	cmd.Stdout, cmd.Stderr = out, io.Discard
	err := cmd.Run()
	return out.present, err
}

func (systemConntrack) check(ctx context.Context) error {
	binary, err := conntrackBinary()
	if err != nil {
		return err
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		// Slot zero is reserved and never assigned to a source. This is read-only
		// and proves both netlink families and the exact filter syntax work.
		if _, err := runConntrack(ctx, binary, "--dump", family, dataplane.Namespace); err != nil {
			return errors.New(
				"capability_unavailable: conntrack IPv4/IPv6 netlink mark filtering is unavailable",
			)
		}
	}
	return nil
}

func (systemConntrack) reset(ctx context.Context, slot uint16) error {
	if slot < 1 || slot > dataplane.MaxPaths {
		return errors.New("invalid_connection_tracking_slot")
	}
	binary, err := conntrackBinary()
	if err != nil {
		return err
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		// conntrack returns exit 1 when no entry matches. A subsequent successful
		// empty dump is the idempotent success criterion, including crash replay.
		_, _ = runConntrack(ctx, binary, "--delete", family, dataplane.Mark(slot))
		remaining, err := runConntrack(ctx, binary, "--dump", family, dataplane.Mark(slot))
		if err != nil || remaining {
			return errors.New("conntrack_delete_failed")
		}
	}
	return nil
}

func previousResetSlot(t *Transaction) uint16 {
	if !t.Candidate.BreakExisting || t.Previous == nil || t.Previous.Selected == "" ||
		t.Previous.Selected == t.Candidate.Selected {
		return 0
	}
	for _, path := range t.Previous.Paths {
		if path.SourceID == t.Previous.Selected {
			return path.Slot
		}
	}
	return 0
}

func (m *Manager) finishFlowReset(ctx context.Context, s *State) error {
	t := s.Transaction
	if t.State != "confirmed" || (t.FlowTermination != "pending" && t.FlowTermination != "failed") {
		return nil
	}
	slot := previousResetSlot(t)
	if slot == 0 {
		return errors.New(
			"journal_invalid: connection tracking reset lacks a previous selected path",
		)
	}
	// Persist intent before a retry too. The routing decision is already durable;
	// deletion cannot roll it back or turn a confirmed route into an API failure.
	t.FlowTermination = "pending"
	t.ErrorCode = ""
	if err := m.save(s); err != nil {
		return err
	}
	resetter, ok := m.backend.(flowResetBackend)
	ctx, cancel := context.WithTimeout(ctx, 18*time.Second)
	defer cancel()
	if !ok || resetter.ResetFlowTracking(ctx, slot) != nil {
		t.FlowTermination = "failed"
		t.ErrorCode = "conntrack_delete_failed"
	} else {
		t.FlowTermination = "completed"
	}
	return m.save(s)
}

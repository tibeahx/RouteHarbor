package helper

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"strings"

	"github.com/tibeahx/OpenRHP/internal/dataplane"
)

// Selection backends never install routes, guards or restart retained engines.
// They operate only on resources from a confirmed network transaction.
type selectionBackend interface {
	CheckSelection(context.Context, dataplane.Plan, dataplane.Plan) error
	ApplySelection(context.Context, dataplane.Plan, dataplane.Plan) error
}

var errSelectionFullApply = errors.New("selection_requires_full_apply")

func (b *NetworkBackend) CheckSelection(ctx context.Context, next, previous dataplane.Plan) error {
	if runtime.GOOS != "linux" {
		return errors.New("platform_unsupported")
	}
	batch, err := dataplane.SelectionNFT(previous.Desired, next.Desired)
	if err != nil {
		return err
	}
	if err = b.checkEnvironment(ctx, next, true); err != nil {
		return err
	}
	if err = b.checkTables(ctx); err != nil {
		return err
	}
	if err = b.selectionChainReady(ctx); err != nil {
		return err
	}
	if err = b.checkRoutes(ctx, next, &previous); err != nil {
		return err
	}
	// Missing retained routes are safe (their old flows remain blocked), but the
	// selected route and rule must already exist. Do not recreate either here.
	for _, p := range next.Desired.Paths {
		if p.SourceID != next.Desired.Selected {
			continue
		}
		for _, r := range next.Routes {
			if r.Mark != dataplane.Mark(p.Slot) {
				continue
			}
			exists, e := b.ruleExists(ctx, r)
			if e != nil {
				return e
			}
			if !exists {
				return errors.New("selection_target_unavailable: selected policy route is missing")
			}
			if r.Table == 254 {
				continue
			}
			entries, e := b.routeEntries(ctx, r.Family)
			if e != nil {
				return e
			}
			found := false
			for _, entry := range entries {
				if routeEntryMatches(entry, r) {
					found = true
				}
			}
			if !found {
				return errors.New("selection_target_unavailable: selected route table is missing")
			}
		}
	}
	if _, err = b.Runner.Run(
		ctx,
		b.NFTBinary,
		[]string{"--check", "--file", "-"},
		[]byte(batch),
	); err != nil {
		return errors.New("nft_check_failed")
	}
	return nil
}

func (b *NetworkBackend) selectionChainReady(ctx context.Context) error {
	raw, err := b.Runner.Run(ctx, b.NFTBinary, []string{"-j", "list", "ruleset"}, nil)
	if err != nil {
		return errors.New("firewall_unavailable")
	}
	var rules struct {
		NFT []struct {
			Table *struct{ Family, Name string }
			Chain *struct{ Family, Table, Name, Comment string }
		} `json:"nftables"`
	}
	if json.Unmarshal(raw, &rules) != nil {
		return errors.New("firewall_invalid")
	}
	ready := false
	for _, item := range rules.NFT {
		if item.Table != nil && item.Table.Family == "inet" &&
			item.Table.Name == dataplane.GuardTable {
			return errors.New("selection_guard_active: reconcile the guarded network first")
		}
		if c := item.Chain; c != nil && c.Family == "inet" && c.Table == dataplane.Table &&
			c.Name == "select_flow" {
			ready = c.Comment == "OpenRHP classifier v1"
			if c.Comment == "" {
				// nft 1.0.6 also omits chain comments from JSON.
				plain, e := b.Runner.Run(
					ctx,
					b.NFTBinary,
					[]string{"list", "chain", "inet", dataplane.Table, "select_flow"},
					nil,
				)
				ready = e == nil && selectionChainOwnedText(plain)
			}
		}
	}
	if !ready {
		// A pre-upgrade confirmed table has no classifier chain. Its first switch
		// uses the full transaction to migrate; never pretend a narrow switch ran.
		return errSelectionFullApply
	}
	return nil
}

func selectionChainOwnedText(raw []byte) bool {
	lines := []string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) < 3 || lines[0] != "table inet "+dataplane.Table+" {" {
		return false
	}
	lines = lines[1:]
	if lines[0] == "comment \""+dataplane.Owner+"\"" {
		lines = lines[1:]
	}
	return len(lines) >= 2 && lines[0] == "chain select_flow {" &&
		lines[1] == "comment \"OpenRHP classifier v1\""
}

func (b *NetworkBackend) ApplySelection(ctx context.Context, next, previous dataplane.Plan) error {
	// Ownership, target liveness and kernel validation are repeated immediately
	// before the one atomic mutation, while the caller holds the journal lock.
	if err := b.CheckSelection(ctx, next, previous); err != nil {
		return err
	}
	batch, err := dataplane.SelectionNFT(previous.Desired, next.Desired)
	if err != nil {
		return err
	}
	if _, err = b.Runner.Run(ctx, b.NFTBinary, []string{"--file", "-"}, []byte(batch)); err != nil {
		// A process timeout can occur after the kernel commits. The manager must
		// reconcile through its durable rollback, never report the old selection.
		return errors.New("selection_commit_ambiguous")
	}
	return nil
}

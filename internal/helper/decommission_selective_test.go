package helper

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/dataplane"
)

type decommissionSelectiveBackend struct {
	emergencyMemory
	dir           string
	requireHold   bool
	quarantineErr error
	removeErr     error
	quarantined   int
	removed       int
}

func (b *decommissionSelectiveBackend) Quarantine(context.Context, dataplane.Plan) error {
	b.quarantined++
	if b.requireHold {
		raw, err := os.ReadFile(filepath.Join(b.dir, "transaction.json"))
		if err != nil {
			return err
		}
		var state State
		if err = json.Unmarshal(raw, &state); err != nil {
			return err
		}
		if !state.MaintenanceHold {
			return errors.New("quarantine mutated before durable maintenance hold")
		}
	}
	return b.quarantineErr
}

func (b *decommissionSelectiveBackend) Remove(context.Context, dataplane.Plan) error {
	b.removed++
	return b.removeErr
}

func decommissionSelectiveFixture(
	t *testing.T,
	d dataplane.Desired,
) (*Manager, *decommissionSelectiveBackend, string) {
	t.Helper()
	b := &decommissionSelectiveBackend{}
	m := testManager(t, b, &testWatchdog{})
	b.dir = m.dir
	tx, err := m.Prepare(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Apply(context.Background(), tx.ID, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Confirm(tx.ID); err != nil {
		t.Fatal(err)
	}
	return m, b, tx.ID
}

func TestSelectiveDecommissionPreservesClosedAcrossWatchdogAndBoot(t *testing.T) {
	ctx := context.Background()
	d := selectiveDesired()
	m, b, confirmed := decommissionSelectiveFixture(t, d)
	b.requireHold = true
	if err := m.Decommission(ctx, "preserve-closed"); err != nil {
		t.Fatal(err)
	}
	state, err := m.Status()
	if err != nil || !state.MaintenanceHold || !state.Guarded || b.emergencies != 0 ||
		b.quarantined != 1 {
		t.Fatalf(
			"preserve-closed opened selective traffic: state=%+v emergency=%d guard=%d err=%v",
			state,
			b.emergencies,
			b.quarantined,
			err,
		)
	}
	if _, err = m.Confirm(confirmed); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewManager(m.dir, b, &testWatchdog{})
	if err != nil {
		t.Fatal(err)
	}
	if active, err := restarted.WatchSelectiveOnce(ctx); err != nil || active {
		t.Fatal("watchdog ignored explicit hold", active, err)
	}
	if err = restarted.SelectiveEmergencyFor(
		ctx,
		confirmed,
	); !errors.Is(
		err,
		ErrMaintenanceActive,
	) {
		t.Fatal("old watchdog reopened explicit hold", err)
	}
	if err = restarted.BootGuard(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.prepare(ctx, d, true); !errors.Is(err, ErrMaintenanceActive) {
		t.Fatal("automatic restore cleared explicit hold", err)
	}
	state, err = restarted.Status()
	if err != nil || !state.MaintenanceHold || !state.Guarded || b.emergencies != 0 {
		t.Fatal("boot or repeated confirmation cleared hold", state, err)
	}
	tx, err := restarted.Prepare(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.Apply(ctx, tx.ID, time.Minute); err != nil {
		t.Fatal(err)
	}
	state, err = restarted.Status()
	if err != nil || !state.MaintenanceHold {
		t.Fatal("apply cleared hold before confirmation", err)
	}
	if _, err = restarted.Rollback(ctx, tx.ID); err != nil {
		t.Fatal(err)
	}
	state, err = restarted.Status()
	if err != nil || !state.MaintenanceHold {
		t.Fatal("rollback cleared explicit hold", err)
	}
	tx, err = restarted.Prepare(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.Apply(ctx, tx.ID, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.Confirm(tx.ID); err != nil {
		t.Fatal(err)
	}
	state, err = restarted.Status()
	if err != nil || state.MaintenanceHold || state.Guarded {
		t.Fatal("new explicit confirmation did not restore routing", state, err)
	}
}

func TestSelectiveDecommissionFailedQuarantineKeepsDurableHold(t *testing.T) {
	ctx := context.Background()
	m, b, _ := decommissionSelectiveFixture(t, selectiveDesired())
	b.requireHold = true
	b.quarantineErr = errors.New("injected guard failure")
	if err := m.Decommission(ctx, "preserve-closed"); !errors.Is(err, b.quarantineErr) {
		t.Fatal("guard error lost", err)
	}
	restarted, err := NewManager(m.dir, b, &testWatchdog{})
	if err != nil {
		t.Fatal(err)
	}
	state, err := restarted.Status()
	if err != nil || !state.MaintenanceHold {
		t.Fatal("guard failure lost durable hold", state, err)
	}
	b.quarantineErr = nil
	if err = restarted.BootGuard(ctx); err != nil {
		t.Fatal(err)
	}
	if b.emergencies != 0 {
		t.Fatal("failed quarantine reopened direct during boot")
	}
}

func TestSelectiveDecommissionRejectsPendingTransactionsAndMaintenance(t *testing.T) {
	for _, candidateSelective := range []bool{false, true} {
		for _, applied := range []bool{false, true} {
			t.Run(
				map[bool]string{false: "legacy-candidate", true: "selective-candidate"}[candidateSelective]+map[bool]string{false: "-prepared", true: "-applied"}[applied],
				func(t *testing.T) {
					ctx := context.Background()
					committed, candidate := selectiveDesired(), testDesired()
					if candidateSelective {
						committed, candidate = testDesired(), selectiveDesired()
					}
					m, b, _ := decommissionSelectiveFixture(t, committed)
					tx, err := m.Prepare(ctx, candidate)
					if err != nil {
						t.Fatal(err)
					}
					if applied {
						if _, err = m.Apply(ctx, tx.ID, time.Minute); err != nil {
							t.Fatal(err)
						}
					}
					if err = m.Decommission(ctx, "preserve-closed"); !errors.Is(err, ErrBusy) {
						t.Fatal("decommission raced pending migration", err)
					}
					state, err := m.Status()
					if err != nil || state.MaintenanceHold || b.quarantined != 0 ||
						b.emergencies != 0 {
						t.Fatal("pending transaction was mutated", state, err)
					}
				},
			)
		}
	}
	ctx := context.Background()
	m, b, _ := decommissionSelectiveFixture(t, selectiveDesired())
	job := "11111111111111111111111111111111"
	if err := m.AcquireMaintenance(ctx, job, nil); err != nil {
		t.Fatal(err)
	}
	before := b.quarantined
	if err := m.Decommission(ctx, "preserve-closed"); !errors.Is(err, ErrMaintenanceActive) {
		t.Fatal("decommission bypassed package job", err)
	}
	state, err := m.Status()
	if err != nil || state.MaintenanceJob != job || !state.MaintenanceHold ||
		b.quarantined != before {
		t.Fatal("maintenance ownership changed", state, err)
	}
}

func TestSelectiveDecommissionExplicitDirectClearsOnlyOrdinaryHold(t *testing.T) {
	for _, maintenance := range []bool{false, true} {
		t.Run(
			map[bool]string{false: "ordinary", true: "package-job"}[maintenance],
			func(t *testing.T) {
				ctx := context.Background()
				m, b, _ := decommissionSelectiveFixture(t, selectiveDesired())
				var err error
				if maintenance {
					job := "22222222222222222222222222222222"
					if err = m.AcquireMaintenance(ctx, job, nil); err != nil {
						t.Fatal(err)
					}
					err = m.DecommissionMaintenance(ctx, job, "restore-direct")
				} else {
					if err = m.Decommission(ctx, "preserve-closed"); err != nil {
						t.Fatal(err)
					}
					err = m.Decommission(ctx, "restore-direct")
				}
				if err != nil {
					t.Fatal(err)
				}
				state, err := m.Status()
				if err != nil || state.Committed != nil || state.Guarded ||
					state.MaintenanceHold != maintenance ||
					b.removed != 1 {
					t.Fatal("explicit direct mishandled durable hold", state, err)
				}
			},
		)
	}
}

func TestLegacyDecommissionPreservesOriginalBootGuardSemantics(t *testing.T) {
	ctx := context.Background()
	m, b, _ := decommissionSelectiveFixture(t, testDesired())
	if _, err := m.Prepare(ctx, testDesired()); err != nil {
		t.Fatal(err)
	}
	if err := m.Decommission(ctx, "preserve-closed"); err != nil {
		t.Fatal(err)
	}
	state, err := m.Status()
	if err != nil || state.MaintenanceHold || !state.Guarded || b.quarantined != 1 ||
		b.emergencies != 0 {
		t.Fatal("legacy semantics changed", state, err)
	}
}

func TestSelectiveDecommissionDirectFailureRetainsHoldUntilRetry(t *testing.T) {
	for _, stage := range []string{"quarantine", "remove"} {
		t.Run(stage, func(t *testing.T) {
			ctx := context.Background()
			m, b, confirmed := decommissionSelectiveFixture(t, selectiveDesired())
			if err := m.SelectiveEmergency(ctx); err != nil {
				t.Fatal(err)
			}
			b.requireHold = true
			injected := errors.New("injected direct decommission failure")
			if stage == "quarantine" {
				b.quarantineErr = injected
			} else {
				b.removeErr = injected
			}
			// No preceding preserve-closed operation: explicit direct removal
			// itself must durably own its intermediate closed safety rules.
			if err := m.Decommission(ctx, "restore-direct"); !errors.Is(err, injected) {
				t.Fatal("direct removal did not preserve its failure", err)
			}
			restarted, err := NewManager(m.dir, b, &testWatchdog{})
			if err != nil {
				t.Fatal(err)
			}
			state, err := restarted.Status()
			if err != nil || !state.MaintenanceHold || !state.Guarded || state.Committed == nil {
				t.Fatal("failed direct removal lost durable closed ownership", state, err)
			}
			b.quarantineErr = nil
			b.removeErr = nil
			if err = restarted.BootGuard(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err = restarted.Confirm(confirmed); err != nil {
				t.Fatal(err)
			}
			if watch, err := restarted.WatchSelectiveOnce(ctx); err != nil || watch {
				t.Fatal("watchdog reopened failed direct removal", watch, err)
			}
			if err = restarted.SelectiveEmergencyFor(
				ctx,
				confirmed,
			); !errors.Is(
				err,
				ErrMaintenanceActive,
			) {
				t.Fatal("old watchdog reopened failed direct removal", err)
			}
			if _, err = restarted.prepare(
				ctx,
				selectiveDesired(),
				true,
			); !errors.Is(
				err,
				ErrMaintenanceActive,
			) {
				t.Fatal("automatic restore cleared failed removal hold", err)
			}
			if b.emergencies != 1 {
				t.Fatal("failed removal was replayed as emergency direct", b.emergencies)
			}
			if err = restarted.Decommission(ctx, "restore-direct"); err != nil {
				t.Fatal("explicit direct-only retry failed", err)
			}
			state, err = restarted.Status()
			if err != nil || state.MaintenanceHold || state.Guarded || state.Committed != nil ||
				state.SelectiveEmergency {
				t.Fatal("successful direct-only retry retained guard intent", state, err)
			}
		})
	}
}

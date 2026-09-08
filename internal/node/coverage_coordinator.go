package node

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
)

// These envelopes belong to the gateway service. Gateway configuration never
// crosses the remote node's narrower operation boundary.
type coveragePlan struct {
	Plan
	GatewayPlan *GatewayPlan `json:"gateway_plan,omitempty"`
}

type coverageOperation struct {
	Operation
	GatewayPlan *GatewayPlan `json:"gateway_plan,omitempty"`
}

type coverageParticipant struct {
	ID       string    `json:"id"`
	State    string    `json:"state"`
	Deadline time.Time `json:"deadline"`
}

type coverageTransaction struct {
	ID          string      `json:"id"`
	NodeID      string      `json:"node_id"`
	State       string      `json:"state"`
	CreatedAt   time.Time   `json:"created_at"`
	Deadline    time.Time   `json:"deadline"`
	Plan        Plan        `json:"plan"`
	GatewayPlan GatewayPlan `json:"gateway_plan"`
	ErrorCode   string      `json:"error_code,omitempty"`
}

type coverageEntry struct {
	Transaction coverageTransaction `json:"transaction"`
	Key         string              `json:"key"`
	Hash        string              `json:"hash"`
	Node        coverageParticipant `json:"node"`
	Gateway     coverageParticipant `json:"gateway"`
}

type coverageJournal struct {
	Version int                       `json:"version"`
	Entries map[string]*coverageEntry `json:"entries"`
}

// ConfigureGateway enables a typed, independent local gateway participant. The
// recovery loop only resumes durable confirmation/rollback intent, never a new
// apply. Both participants own their own apply deadlines and watchdogs.
func (s *Service) ConfigureGateway(operator GatewayOperator) error {
	if operator == nil {
		return errors.New("gateway_operator_required")
	}
	s.coverageMu.Lock()
	defer s.coverageMu.Unlock()
	if s.gatewayOperator != nil {
		return errors.New("gateway_operator_already_configured")
	}
	s.gatewayOperator = operator
	ctx, cancel := context.WithCancel(context.Background())
	s.recoveryCancel = cancel
	s.recoveryWG.Go(func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				attempt, stop := context.WithTimeout(ctx, 12*time.Second)
				_ = s.recoverCoverage(attempt)
				stop()
			}
		}
	})
	return nil
}

func (s *Service) addGatewaySetup(ctx context.Context, result map[string]any) {
	s.coverageMu.Lock()
	operator := s.gatewayOperator
	s.coverageMu.Unlock()
	addGatewaySetup(ctx, operator, result)
}

func addGatewaySetup(ctx context.Context, operator GatewayOperator, result map[string]any) {
	if operator == nil {
		result["gateway_setup_issue"] = "Gateway backhaul helper is unavailable"
		return
	}
	setup, e := operator.Do(ctx, GatewayOperation{Action: "inspect"})
	if e != nil {
		result["gateway_setup_issue"] = "Gateway backhaul inspection failed"
		return
	}
	// Never copy the helper's private node_wifi material into ordinary outputs.
	result["gateway_setup"] = setup["gateway_setup"]
}

func (s *Service) loadCoverage() (*coverageJournal, error) {
	j := &coverageJournal{Version: 1, Entries: map[string]*coverageEntry{}}
	data, e := readPrivate(s.root, "coverage.json")
	if errors.Is(e, os.ErrNotExist) {
		return j, nil
	}
	if e != nil || adapter.StrictDecode(data, j) != nil || j.Version != 1 || len(j.Entries) > 64 {
		return nil, errors.New("invalid_coverage_journal")
	}
	if j.Entries == nil {
		j.Entries = map[string]*coverageEntry{}
	}
	for nodeID, entry := range j.Entries {
		if entry == nil || !transactionID.MatchString(nodeID) ||
			entry.Transaction.NodeID != nodeID ||
			!transactionID.MatchString(entry.Transaction.ID) ||
			!requestKey.MatchString(entry.Key) ||
			len(entry.Hash) != 64 ||
			(entry.Node.ID != "" && !transactionID.MatchString(entry.Node.ID)) ||
			(entry.Gateway.ID != "" && !transactionID.MatchString(entry.Gateway.ID)) {
			return nil, errors.New("invalid_coverage_journal")
		}
		switch entry.Transaction.State {
		case "preparing",
			"prepared",
			"applying",
			"applied",
			"confirming",
			"confirmed",
			"rolling-back",
			"rolled-back":
		default:
			return nil, errors.New("invalid_coverage_journal")
		}
	}
	return j, nil
}

func (s *Service) saveCoverage(j *coverageJournal) error {
	data, e := json.Marshal(j)
	if e != nil {
		return errors.New("coverage_journal_encoding_failed")
	}
	return writePrivate(s.root, "coverage.json", data)
}

func coverageActive(entry *coverageEntry) bool {
	return entry.Transaction.State != "confirmed" && entry.Transaction.State != "rolled-back"
}

// Caller holds coverageMu, matching the coordinator's coverageMu -> mu order.
func (s *Service) checkCoverageUnpair(id string) error {
	j, e := s.loadCoverage()
	if e != nil {
		return e
	}
	if entry := j.Entries[id]; entry != nil && coverageActive(entry) {
		return errors.New("settle_coverage_transaction_before_unpairing")
	}
	return nil
}

func (s *Service) pairedRecord(id string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok {
		return Record{}, errors.New("node_not_found")
	}
	return record, nil
}

func coverageOutput(entry *coverageEntry) map[string]any {
	t := entry.Transaction
	t.Plan = RedactPlan(t.Plan)
	return map[string]any{
		"transaction":               t,
		"node_transaction":          entry.Node,
		"gateway_transaction":       entry.Gateway,
		"coordinated":               true,
		"distributed_atomic_commit": false,
	}
}

func decodeParticipant(result map[string]any) (coverageParticipant, error) {
	var participant coverageParticipant
	data, e := json.Marshal(result["transaction"])
	if e != nil || json.Unmarshal(data, &participant) != nil ||
		!transactionID.MatchString(participant.ID) {
		return coverageParticipant{}, errors.New("invalid_coverage_participant_response")
	}
	switch participant.State {
	case "prepared",
		"applying",
		"applied",
		"confirmed",
		"finalized",
		"rolling-back",
		"rolled-back",
		"failed":
		return participant, nil
	default:
		return coverageParticipant{}, errors.New("invalid_coverage_participant_state")
	}
}

func injectNodeWiFi(p Plan, result map[string]any) (Plan, error) {
	var wifi struct {
		SSID       string `json:"ssid"`
		Passphrase string `json:"passphrase"`
		Channel    int    `json:"channel"`
	}
	data, e := json.Marshal(result["node_wifi"])
	if e != nil || adapter.StrictDecode(data, &wifi) != nil || len(wifi.SSID) == 0 ||
		len(wifi.Passphrase) < 8 || wifi.Channel < 1 {
		return p, errors.New("gateway_wifi_material_unavailable")
	}
	p.SSID, p.Passphrase, p.Channel = wifi.SSID, wifi.Passphrase, wifi.Channel
	return p, nil
}

func (s *Service) validateCoverage(
	ctx context.Context,
	record Record,
	p Plan,
	gateway *GatewayPlan,
) (Plan, GatewayPlan, error) {
	if s.gatewayOperator == nil || gateway == nil || p.Mode == "ethernet" {
		return p, GatewayPlan{}, errors.New("managed_gateway_plan_required_for_wireless")
	}
	g := *gateway
	if g.PeerFingerprint != record.Fingerprint || g.Mode != p.Mode {
		return p, g, errors.New("gateway_node_plan_mismatch")
	}
	capabilities := s.gateway(ctx)
	if capabilities.VerifiedPeerFingerprint != record.Fingerprint ||
		record.Capabilities.VerifiedPeerFingerprint != s.identity.Fingerprint ||
		capabilities.VerifiedMode != p.Mode || record.Capabilities.VerifiedMode != p.Mode ||
		capabilities.VerifiedRadio == "" || record.Capabilities.VerifiedRadio != p.Radio {
		return p, g, errors.New("wireless_pair_receipt_mismatch")
	}
	result, e := s.gatewayOperator.Do(ctx, GatewayOperation{Action: "validate", Plan: &g})
	if e != nil {
		return p, g, errors.New("gateway_backhaul_preflight_failed")
	}
	p, e = injectNodeWiFi(p, result)
	if e != nil {
		return p, g, e
	}
	// The helper preflight proves this explicit counterpart can be provisioned;
	// it does not manufacture the peer's radio/driver compatibility evidence.
	capabilities.GatewayBackhaulReady = true
	if e = ValidatePlan(p, capabilities, record.Capabilities); e != nil {
		return p, g, e
	}
	return p, g, nil
}

func (s *Service) planCoverage(
	ctx context.Context,
	id string,
	proposed coveragePlan,
) (map[string]any, error) {
	s.coverageMu.Lock()
	defer s.coverageMu.Unlock()
	record, e := s.node(ctx, id)
	if e != nil {
		return nil, e
	}
	p, gateway, e := s.validateCoverage(ctx, record, proposed.Plan, proposed.GatewayPlan)
	if e != nil {
		return nil, e
	}
	return map[string]any{
		"plan":                                  RedactPlan(p),
		"gateway_plan":                          gateway,
		"requires_confirmation":                 true,
		"requires_independent_node_watchdog":    true,
		"requires_independent_gateway_watchdog": true,
		"distributed_atomic_commit":             false,
		"warning":                               "Gateway backhaul applies first; both independent rollback timers remain armed until you confirm tested client and management connectivity",
	}, nil
}

func (s *Service) operateCoverage(
	ctx context.Context,
	id string,
	op coverageOperation,
) (map[string]any, bool, error) {
	s.coverageMu.Lock()
	defer s.coverageMu.Unlock()
	lock, e := stateLock(s.root, "coverage.lock")
	if e != nil {
		return nil, true, e
	}
	defer stateUnlock(lock)
	j, e := s.loadCoverage()
	if e != nil {
		return nil, true, e
	}
	entry := j.Entries[id]
	wirelessPrepare := op.Action == "prepare" &&
		(op.GatewayPlan != nil || (op.Plan != nil && op.Plan.Mode != "ethernet"))
	if op.Action == "prepare" && !wirelessPrepare && entry != nil {
		if coverageActive(entry) {
			return nil, true, errors.New("settle_coverage_transaction_before_changing_uplink")
		}
		// The node's ordinary Ethernet journal becomes authoritative again. The
		// finalized gateway AP remains the administrator's existing access point.
		delete(j.Entries, id)
		if e = s.saveCoverage(j); e != nil {
			return nil, true, e
		}
		entry = nil
	}
	if !wirelessPrepare && entry == nil {
		return nil, false, nil
	}
	if !wirelessPrepare && op.Action != "status" && op.ID != entry.Transaction.ID {
		return nil, true, errors.New("coverage_pair_transaction_id_required")
	}
	if s.gatewayOperator == nil {
		return nil, true, errors.New("gateway_backhaul_helper_unavailable")
	}
	record, e := s.pairedRecord(id)
	if e != nil {
		return nil, true, e
	}
	if wirelessPrepare {
		result, e := s.prepareCoverage(ctx, j, record, op)
		return result, true, e
	}
	switch op.Action {
	case "status":
		result := coverageOutput(entry)
		result["gateway_fingerprint"] = s.identity.Fingerprint
		addGatewaySetup(ctx, s.gatewayOperator, result)
		if gatewayStatus, err := s.gatewayOperator.Do(
			ctx,
			GatewayOperation{Action: "status"},
		); err == nil {
			if current, err := decodeParticipant(
				gatewayStatus,
			); err == nil &&
				current.ID == entry.Gateway.ID {
				result["gateway_transaction"] = current
			}
		}
		nodeContext, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if nodeStatus, err := s.remoteCoverage(
			nodeContext,
			record,
			Operation{Action: "status"},
		); err == nil {
			if current, err := decodeParticipant(
				nodeStatus,
			); err == nil &&
				current.ID == entry.Node.ID {
				result["node_transaction"] = current
			}
			for _, key := range []string{"setup", "node_link", "capabilities"} {
				result[key] = nodeStatus[key]
			}
		} else {
			result["node_issue"] = "Node is unreachable; independent rollback remains local to the node"
		}
		return result, true, nil
	case "apply":
		e = s.applyCoverage(ctx, j, record, entry, op.TimeoutSeconds)
	case "confirm":
		e = s.confirmCoverage(ctx, j, record, entry)
	case "rollback":
		switch entry.Transaction.State {
		case "confirmed":
			e = errors.New("coverage_transaction_already_confirmed")
		case "confirming":
			// The node may already have committed even when its reply was lost.
			// Only reconciliation of participant state can safely compensate it.
			e = errors.New("coverage_confirmation_must_reconcile_before_rollback")
		default:
			e = s.rollbackCoverage(ctx, j, record, entry)
		}
	case "validate":
		_, e = s.gatewayOperator.Do(ctx, GatewayOperation{Action: "validate", ID: entry.Gateway.ID})
		if e == nil {
			_, e = s.remoteCoverage(ctx, record, Operation{Action: "validate", ID: entry.Node.ID})
		}
	default:
		e = errors.New("unsupported_coverage_operation")
	}
	return coverageOutput(entry), true, e
}

func (s *Service) remoteCoverage(
	ctx context.Context,
	record Record,
	op Operation,
) (map[string]any, error) {
	if op.Action == "status" {
		return s.request(ctx, record.Address, record.Fingerprint, "GET", "/node/v1/status", nil)
	}
	return s.request(ctx, record.Address, record.Fingerprint, "POST", "/node/v1/operations", op)
}

func (s *Service) prepareCoverage(
	ctx context.Context,
	journal *coverageJournal,
	record Record,
	op coverageOperation,
) (map[string]any, error) {
	if op.Plan == nil || !requestKey.MatchString(op.Key) {
		return nil, errors.New("coverage_plan_and_idempotency_key_required")
	}
	data, e := json.Marshal(struct {
		Node    *Plan        `json:"node"`
		Gateway *GatewayPlan `json:"gateway"`
	}{op.Plan, op.GatewayPlan})
	if e != nil {
		return nil, errors.New("invalid_coverage_plan")
	}
	digest := sha256.Sum256(data)
	hash := hex.EncodeToString(digest[:])
	entry := journal.Entries[record.ID]
	if entry != nil && entry.Key == op.Key {
		if entry.Hash != hash {
			return nil, errors.New("coverage_idempotency_conflict")
		}
		if entry.Transaction.State != "preparing" {
			return coverageOutput(entry), nil
		}
	} else {
		for _, active := range journal.Entries {
			if coverageActive(active) {
				return nil, errors.New("coverage_transaction_busy")
			}
		}
		if entry == nil && len(journal.Entries) >= 64 {
			return nil, errors.New("coverage_history_limit")
		}
		fresh, err := s.node(ctx, record.ID)
		if err != nil {
			return nil, err
		}
		p, gateway, err := s.validateCoverage(ctx, fresh, *op.Plan, op.GatewayPlan)
		if err != nil {
			return nil, err
		}
		var nonce [16]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return nil, err
		}
		entry = &coverageEntry{
			Key:  op.Key,
			Hash: hash,
			Transaction: coverageTransaction{
				ID: hex.EncodeToString(nonce[:]), NodeID: record.ID,
				State: "preparing", CreatedAt: time.Now().UTC(), Plan: p, GatewayPlan: gateway,
			},
		}
		journal.Entries[record.ID] = entry
		if e = s.saveCoverage(journal); e != nil {
			return nil, e
		}
	}
	if entry.Gateway.ID == "" {
		result, err := s.gatewayOperator.Do(
			ctx,
			GatewayOperation{
				Action: "prepare",
				Key:    entry.Transaction.ID + "-gateway",
				Plan:   &entry.Transaction.GatewayPlan,
			},
		)
		if err != nil {
			return coverageOutput(entry), errors.New("gateway_coverage_prepare_incomplete")
		}
		participant, err := decodeParticipant(result)
		if err != nil || participant.State != "prepared" {
			return coverageOutput(entry), errors.New("invalid_gateway_prepare_response")
		}
		p, err := injectNodeWiFi(entry.Transaction.Plan, result)
		if err != nil {
			return coverageOutput(entry), err
		}
		entry.Gateway = participant
		entry.Transaction.Plan = p
		if e = s.saveCoverage(journal); e != nil {
			return nil, e
		}
	}
	if entry.Node.ID == "" {
		result, err := s.remoteCoverage(
			ctx,
			record,
			Operation{
				Action: "prepare",
				Key:    entry.Transaction.ID + "-node",
				Plan:   &entry.Transaction.Plan,
			},
		)
		if err != nil {
			return coverageOutput(entry), errors.New("node_coverage_prepare_incomplete")
		}
		participant, err := decodeParticipant(result)
		if err != nil || participant.State != "prepared" {
			return coverageOutput(entry), errors.New("invalid_node_prepare_response")
		}
		entry.Node = participant
	}
	entry.Transaction.State = "prepared"
	entry.Transaction.ErrorCode = ""
	if e = s.saveCoverage(journal); e != nil {
		return nil, e
	}
	return coverageOutput(entry), nil
}

func (s *Service) applyCoverage(
	ctx context.Context,
	journal *coverageJournal,
	record Record,
	entry *coverageEntry,
	timeout int,
) error {
	if timeout < 30 || timeout > 180 {
		return errors.New("coverage_confirmation_window_must_be_30_to_180_seconds")
	}
	if entry.Transaction.State == "applied" || entry.Transaction.State == "confirmed" {
		return nil
	}
	if entry.Transaction.State != "prepared" {
		return errors.New("coverage_transaction_invalid_state")
	}
	fresh, e := s.node(ctx, record.ID)
	if e != nil {
		return e
	}
	prepared, _, e := s.validateCoverage(
		ctx,
		fresh,
		entry.Transaction.Plan,
		&entry.Transaction.GatewayPlan,
	)
	if e != nil {
		return e
	}
	if prepared.SSID != entry.Transaction.Plan.SSID ||
		prepared.Passphrase != entry.Transaction.Plan.Passphrase ||
		prepared.Channel != entry.Transaction.Plan.Channel {
		return errors.New("wireless_prepared_settings_changed")
	}
	entry.Transaction.State = "applying"
	entry.Transaction.Deadline = time.Now().Add(time.Duration(timeout) * time.Second).UTC()
	if e := s.saveCoverage(journal); e != nil {
		return e
	}
	result, e := s.gatewayOperator.Do(
		ctx,
		GatewayOperation{Action: "apply", ID: entry.Gateway.ID, TimeoutSeconds: timeout},
	)
	if e == nil {
		entry.Gateway, e = matchingParticipant(result, entry.Gateway.ID, "applied")
	}
	if e == nil {
		e = s.saveCoverage(journal)
	}
	if e == nil {
		// Never extend the overall confirmation window while the first participant
		// is starting. The node receives only time remaining from durable intent.
		remaining := int((time.Until(entry.Transaction.Deadline) + time.Second - 1) / time.Second)
		if remaining < 30 {
			e = errors.New("coverage_apply_window_exhausted")
		} else {
			result, e = s.remoteCoverage(
				ctx,
				record,
				Operation{Action: "apply", ID: entry.Node.ID, TimeoutSeconds: remaining},
			)
			if e == nil {
				entry.Node, e = matchingParticipant(result, entry.Node.ID, "applied")
			}
		}
	}
	if e != nil {
		entry.Transaction.ErrorCode = "coverage_apply_failed"
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 12*time.Second)
		defer cancel()
		if err := s.rollbackCoverage(cleanup, journal, record, entry); err != nil {
			return errors.New("coverage_apply_failed_rollback_pending")
		}
		return errors.New("coverage_apply_failed_and_rolled_back")
	}
	entry.Transaction.State = "applied"
	return s.saveCoverage(journal)
}

func matchingParticipant(
	result map[string]any,
	id string,
	states ...string,
) (coverageParticipant, error) {
	participant, e := decodeParticipant(result)
	if e != nil || participant.ID != id {
		return coverageParticipant{ID: id}, errors.New("coverage_participant_identity_mismatch")
	}
	if slices.Contains(states, participant.State) {
		return participant, nil
	}
	return coverageParticipant{ID: id}, errors.New("coverage_participant_state_mismatch")
}

func (s *Service) confirmCoverage(
	ctx context.Context,
	journal *coverageJournal,
	record Record,
	entry *coverageEntry,
) error {
	if entry.Transaction.State == "confirmed" {
		return nil
	}
	if entry.Transaction.State != "applied" && entry.Transaction.State != "confirming" {
		return errors.New("coverage_transaction_invalid_state")
	}
	if entry.Transaction.State == "applied" {
		if !time.Now().Before(entry.Transaction.Deadline) {
			_ = s.rollbackCoverage(ctx, journal, record, entry)
			return errors.New("coverage_confirmation_expired")
		}
		fresh, e := s.node(ctx, record.ID)
		if e != nil {
			return e
		}
		if _, _, e = s.validateCoverage(
			ctx,
			fresh,
			entry.Transaction.Plan,
			&entry.Transaction.GatewayPlan,
		); e != nil {
			return e
		}
		entry.Transaction.State = "confirming"
		if e := s.saveCoverage(journal); e != nil {
			return e
		}
	}
	// Gateway confirmation preserves a compensating snapshot. It cannot lose
	// its AP behind a committed node due to an independent timer expiring.
	result, e := s.gatewayOperator.Do(
		ctx,
		GatewayOperation{Action: "confirm", ID: entry.Gateway.ID},
	)
	if e != nil {
		if status, err := s.gatewayOperator.Do(
			ctx,
			GatewayOperation{Action: "status"},
		); err == nil {
			if gateway, err := matchingParticipant(
				status,
				entry.Gateway.ID,
				"rolled-back",
				"failed",
			); err == nil {
				entry.Gateway = gateway
				entry.Transaction.ErrorCode = "gateway_confirmation_failed"
				if e := s.rollbackCoverage(ctx, journal, record, entry); e != nil {
					return e
				}
				return errors.New("gateway_confirmation_failed_and_rolled_back")
			}
		}
		return errors.New("gateway_confirmation_pending")
	}
	entry.Gateway, e = matchingParticipant(result, entry.Gateway.ID, "confirmed", "finalized")
	if e != nil {
		return e
	}
	if e = s.saveCoverage(journal); e != nil {
		return e
	}
	result, e = s.remoteCoverage(ctx, record, Operation{Action: "confirm", ID: entry.Node.ID})
	if e != nil {
		// An uncertain confirmation may already be committed. Query its state;
		// do not blindly roll the gateway back behind that committed node.
		status, statusErr := s.remoteCoverage(ctx, record, Operation{Action: "status"})
		if statusErr != nil {
			return errors.New("node_confirmation_pending")
		}
		node, statusErr := matchingParticipant(
			status,
			entry.Node.ID,
			"confirmed",
			"rolled-back",
			"failed",
			"applied",
		)
		if statusErr != nil {
			return statusErr
		}
		entry.Node = node
		if node.State == "rolled-back" || node.State == "failed" {
			entry.Transaction.ErrorCode = "node_confirmation_failed"
			if e := s.rollbackCoverage(ctx, journal, record, entry); e != nil {
				return e
			}
			return errors.New("node_confirmation_failed_and_rolled_back")
		}
		if node.State != "confirmed" {
			return errors.New("node_confirmation_pending")
		}
	} else {
		entry.Node, e = matchingParticipant(result, entry.Node.ID, "confirmed")
		if e != nil {
			return e
		}
	}
	if e = s.saveCoverage(journal); e != nil {
		return e
	}
	result, e = s.gatewayOperator.Do(
		ctx,
		GatewayOperation{Action: "finalize", ID: entry.Gateway.ID},
	)
	if e != nil {
		return errors.New("gateway_finalization_pending")
	}
	entry.Gateway, e = matchingParticipant(result, entry.Gateway.ID, "confirmed", "finalized")
	if e != nil {
		return e
	}
	entry.Transaction.State = "confirmed"
	entry.Transaction.Deadline = time.Time{}
	entry.Transaction.Plan.Passphrase = ""
	entry.Transaction.ErrorCode = ""
	return s.saveCoverage(journal)
}

func (s *Service) rollbackCoverage(
	ctx context.Context,
	journal *coverageJournal,
	record Record,
	entry *coverageEntry,
) error {
	if entry.Transaction.State == "rolled-back" {
		return nil
	}
	entry.Transaction.State = "rolling-back"
	if e := s.saveCoverage(journal); e != nil {
		return e
	}
	var nodeErr, gatewayErr error
	// A lost prepare response can hide a participant's ID. Reuse the exact
	// durable subrequest key to recover it before cancelling; never guess an ID
	// from a different transaction or report an unknown participant cancelled.
	if entry.Node.ID == "" {
		nodeContext, cancel := context.WithTimeout(ctx, 5*time.Second)
		result, e := s.remoteCoverage(
			nodeContext,
			record,
			Operation{
				Action: "prepare",
				Key:    entry.Transaction.ID + "-node",
				Plan:   &entry.Transaction.Plan,
			},
		)
		cancel()
		if e == nil {
			entry.Node, e = decodeParticipant(result)
		}
		nodeErr = e
	}
	if entry.Gateway.ID == "" {
		result, e := s.gatewayOperator.Do(
			ctx,
			GatewayOperation{
				Action: "prepare",
				Key:    entry.Transaction.ID + "-gateway",
				Plan:   &entry.Transaction.GatewayPlan,
			},
		)
		if e == nil {
			entry.Gateway, e = decodeParticipant(result)
		}
		gatewayErr = e
	}
	if entry.Node.ID != "" && entry.Node.State != "rolled-back" && entry.Node.State != "failed" {
		nodeContext, cancel := context.WithTimeout(ctx, 5*time.Second)
		result, e := s.remoteCoverage(
			nodeContext,
			record,
			Operation{Action: "rollback", ID: entry.Node.ID},
		)
		cancel()
		if e == nil {
			entry.Node, e = matchingParticipant(result, entry.Node.ID, "rolled-back")
		}
		nodeErr = e
	}
	// Always attempt the gateway rollback even when the peer cannot respond.
	if entry.Gateway.ID != "" && entry.Gateway.State != "rolled-back" &&
		entry.Gateway.State != "failed" {
		result, e := s.gatewayOperator.Do(
			ctx,
			GatewayOperation{Action: "rollback", ID: entry.Gateway.ID},
		)
		if e == nil {
			entry.Gateway, e = matchingParticipant(result, entry.Gateway.ID, "rolled-back")
		}
		gatewayErr = e
	}
	if nodeErr != nil || gatewayErr != nil {
		entry.Transaction.ErrorCode = "coverage_rollback_pending"
		if e := s.saveCoverage(journal); e != nil {
			return e
		}
		return errors.New("coverage_rollback_pending")
	}
	entry.Transaction.State = "rolled-back"
	entry.Transaction.Deadline = time.Time{}
	entry.Transaction.Plan.Passphrase = ""
	return s.saveCoverage(journal)
}

func (s *Service) recoverCoverage(ctx context.Context) error {
	s.coverageMu.Lock()
	defer s.coverageMu.Unlock()
	lock, e := stateLock(s.root, "coverage.lock")
	if e != nil {
		return e
	}
	defer stateUnlock(lock)
	j, e := s.loadCoverage()
	if e != nil {
		return e
	}
	for id, entry := range j.Entries {
		if !coverageActive(entry) {
			continue
		}
		record, e := s.pairedRecord(id)
		if e != nil {
			return e
		}
		switch entry.Transaction.State {
		case "confirming":
			return s.confirmCoverage(ctx, j, record, entry)
		case "rolling-back":
			return s.rollbackCoverage(ctx, j, record, entry)
		case "applying", "applied":
			if !time.Now().Before(entry.Transaction.Deadline) {
				return s.rollbackCoverage(ctx, j, record, entry)
			}
		}
	}
	return nil
}

package wireless

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"
)

// RecordCommand is only exposed by trusted local root CLI entry points. It is
// never an HTTP, node protocol, or privileged-helper socket operation.
func (v *Verifier) RecordCommand(ctx context.Context, args []string, output io.Writer) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("verification_requires_trusted_root_access_on_the_tested_openwrt_device")
	}
	flags := flag.NewFlagSet("verify-wireless", flag.ContinueOnError)
	flags.SetOutput(output)
	stateDir := flags.String("state-dir", v.Dir, "private root-owned helper state directory")
	identityDir := flags.String(
		"identity-dir",
		v.IdentityDir,
		"existing service identity directory",
	)
	radio := flags.String("radio", "", "tested UCI radio name")
	iface := flags.String("interface", "", "active tested wireless peer interface")
	mode := flags.String("mode", "", "tested mode: wds or mesh")
	peer := flags.String(
		"peer-fingerprint",
		"",
		"verified SHA-256 TLS fingerprint of the paired router",
	)
	peerMAC := flags.String("peer-mac", "", "observed wireless MAC of that same paired router")
	duration := flags.Duration("valid-for", 24*time.Hour, "receipt lifetime, at most 168h")
	checks := Checks{}
	flags.BoolVar(
		&checks.EncryptedPeer,
		"checked-encryption",
		false,
		"I verified encrypted traffic to this exact paired router",
	)
	flags.BoolVar(
		&checks.ClientAddresses,
		"checked-client-addresses",
		false,
		"I verified client addresses remain visible on the gateway",
	)
	flags.BoolVar(
		&checks.SingleAddressServer,
		"checked-single-dhcp",
		false,
		"I verified the gateway is the only DHCP/RA source",
	)
	flags.BoolVar(
		&checks.ManagementRecovery,
		"checked-management-recovery",
		false,
		"I verified the independent management and recovery path",
	)
	flags.BoolVar(
		&checks.ConcurrentAP,
		"checked-concurrent-ap",
		false,
		"I verified client AP traffic while this backhaul is active",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !validChecks(checks) || *duration <= 0 || *duration > 7*24*time.Hour {
		return errors.New("record_only_completed_client_checks_and_a_lifetime_of_at_most_168h")
	}
	if *mode != "wds" && *mode != "mesh" {
		return errors.New("tested_mode_must_be_wds_or_mesh")
	}
	if !fingerprintPattern.MatchString(*peer) {
		return errors.New("verified_paired_tls_fingerprint_required")
	}
	verifier := NewVerifier(*stateDir, v.Role, *identityDir)
	local, err := verifier.Fingerprint()
	if err != nil {
		return err
	}
	binding, err := verifier.Collect(ctx, *radio)
	if err != nil {
		return err
	}
	proof, err := collectLiveProof(ctx, v.Role, *radio, *iface, *mode, *peerMAC)
	if err != nil {
		return err
	}
	now := verifier.Now().UTC()
	receipt := Receipt{
		Radio:              *radio,
		Mode:               *mode,
		LocalFingerprint:   local,
		PeerFingerprint:    *peer,
		ExpiresAt:          now.Add(*duration),
		Version:            1,
		Role:               v.Role,
		IssuedAt:           now,
		Binding:            binding,
		Checks:             checks,
		Interface:          *iface,
		PeerMAC:            *peerMAC,
		LiveEvidenceDigest: proof,
	}
	if err = verifier.write(ctx, receipt); err != nil {
		return err
	}
	_, err = fmt.Fprintln(
		output,
		"Recorded local pair verification. This is operator evidence, not device certification; firmware, radio, identity, peer or expiry changes invalidate it.",
	)
	return err
}

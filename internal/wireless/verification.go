// Package wireless records operator-observed pair verification. A receipt is
// local evidence for an exact device and peer, never a hardware certification.
package wireless

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"regexp"
	"syscall"
	"time"

	"github.com/tibeahx/OpenRHP/internal/platform"
)

const receiptName = "wireless-verification.json"

type Authorization struct {
	Radio            string    `json:"radio"`
	Mode             string    `json:"mode"`
	LocalFingerprint string    `json:"local_fingerprint"`
	PeerFingerprint  string    `json:"peer_fingerprint"`
	ExpiresAt        time.Time `json:"expires_at"`
}

type Binding struct {
	OpenWrtDigest         string `json:"openwrt_digest"`
	Kernel                string `json:"kernel"`
	Board                 string `json:"board"`
	PHY                   string `json:"phy"`
	Driver                string `json:"driver"`
	RadioPath             string `json:"radio_path"`
	PHYCapabilitiesDigest string `json:"phy_capabilities_digest"`
}

type Checks struct {
	EncryptedPeer       bool `json:"encrypted_peer"`
	ClientAddresses     bool `json:"client_addresses"`
	SingleAddressServer bool `json:"single_address_server"`
	ManagementRecovery  bool `json:"management_recovery"`
	ConcurrentAP        bool `json:"concurrent_ap"`
}

type Receipt struct {
	Authorization
	Version            int       `json:"version"`
	Role               string    `json:"role"`
	IssuedAt           time.Time `json:"issued_at"`
	Binding            Binding   `json:"binding"`
	Checks             Checks    `json:"checks"`
	Interface          string    `json:"interface"`
	PeerMAC            string    `json:"peer_mac"`
	LiveEvidenceDigest string    `json:"live_evidence_digest"`
}

type Verifier struct {
	Dir         string
	Role        string
	IdentityDir string
	Collect     func(context.Context, string) (Binding, error)
	Fingerprint func() (string, error)
	Now         func() time.Time
}

var fingerprintPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func NewVerifier(dir, role, identityDir string) *Verifier {
	return &Verifier{
		Dir: dir, Role: role, IdentityDir: identityDir,
		Collect:     CollectBinding,
		Fingerprint: func() (string, error) { return identityFingerprint(identityDir) },
		Now:         time.Now,
	}
}

func validChecks(c Checks) bool {
	return c.EncryptedPeer && c.ClientAddresses && c.SingleAddressServer && c.ManagementRecovery &&
		c.ConcurrentAP
}

func (v *Verifier) validate(ctx context.Context, r Receipt) error {
	now := v.Now()
	if (v.Role != "gateway" && v.Role != "node") || r.Version != 1 || r.Role != v.Role ||
		!platform.ValidInterfaceName(r.Radio) || !platform.ValidInterfaceName(r.Interface) ||
		(r.Mode != "wds" && r.Mode != "mesh") || !fingerprintPattern.MatchString(r.LocalFingerprint) ||
		!fingerprintPattern.MatchString(
			r.PeerFingerprint,
		) || r.LocalFingerprint == r.PeerFingerprint ||
		!validChecks(r.Checks) || !fingerprintPattern.MatchString(r.LiveEvidenceDigest) ||
		r.IssuedAt.After(
			now.Add(time.Minute),
		) || !r.ExpiresAt.After(now) || !r.ExpiresAt.After(r.IssuedAt) ||
		r.ExpiresAt.Sub(r.IssuedAt) > 7*24*time.Hour {
		return errors.New("wireless_verification_missing_expired_or_invalid")
	}
	local, err := v.Fingerprint()
	if err != nil || local != r.LocalFingerprint {
		return errors.New("wireless_verification_identity_changed")
	}
	current, err := v.Collect(ctx, r.Radio)
	if err != nil || current != r.Binding {
		return errors.New("wireless_verification_platform_or_radio_changed")
	}
	return nil
}

func privateRoot(dir string) (*os.Root, error) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("wireless_verification_requires_private_root_directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return nil, errors.New("wireless_verification_requires_root_ownership")
	}
	return os.OpenRoot(dir)
}

func (v *Verifier) Authorized(ctx context.Context) (Authorization, error) {
	root, err := privateRoot(v.Dir)
	if err != nil {
		return Authorization{}, err
	}
	defer func() { _ = root.Close() }()
	info, err := root.Lstat(receiptName)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		info.Size() > 16<<10 {
		return Authorization{}, errors.New("wireless_verification_receipt_unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 {
		return Authorization{}, errors.New("wireless_verification_receipt_ownership_invalid")
	}
	file, err := root.Open(receiptName)
	if err != nil {
		return Authorization{}, errors.New("wireless_verification_receipt_unavailable")
	}
	defer func() { _ = file.Close() }()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		return Authorization{}, errors.New("wireless_verification_receipt_changed")
	}
	var receipt Receipt
	decoder := json.NewDecoder(io.LimitReader(file, 16<<10+1))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || decoder.Decode(new(any)) != io.EOF {
		return Authorization{}, errors.New("wireless_verification_receipt_invalid")
	}
	if err = v.validate(ctx, receipt); err != nil {
		return Authorization{}, err
	}
	return receipt.Authorization, nil
}

func (v *Verifier) Check(ctx context.Context, radio, mode, peer string) error {
	authorization, err := v.Authorized(ctx)
	if err != nil {
		return err
	}
	if authorization.Radio != radio || authorization.Mode != mode ||
		authorization.PeerFingerprint != peer {
		return errors.New("wireless_verification_pair_or_mode_mismatch")
	}
	return nil
}

func (v *Verifier) write(ctx context.Context, receipt Receipt) error {
	if os.Geteuid() != 0 {
		return errors.New("wireless_verification_requires_trusted_root_administration")
	}
	if err := v.validate(ctx, receipt); err != nil {
		return err
	}
	root, err := privateRoot(v.Dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	name := ".wireless-verification-" + hex.EncodeToString(nonce[:])
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(name) }()
	if _, err = file.Write(append(data, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = root.Rename(name, receiptName); err != nil {
		return err
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

func identityFingerprint(dir string) (string, error) {
	// Root reads only the certificate field. The service's private key is never
	// printed, copied into receipts, or exposed by a helper response.
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("local_coverage_identity_directory_invalid")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", errors.New("local_coverage_identity_unavailable")
	}
	defer func() { _ = root.Close() }()
	linkInfo, err := root.Lstat("identity.json")
	if err != nil || !linkInfo.Mode().IsRegular() {
		return "", errors.New("local_coverage_identity_file_invalid")
	}
	file, err := root.OpenFile(
		"identity.json",
		os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,
		0,
	)
	if err != nil {
		return "", errors.New("local_coverage_identity_unavailable")
	}
	defer func() { _ = file.Close() }()
	fileInfo, err := file.Stat()
	if err != nil || !os.SameFile(linkInfo, fileInfo) || !fileInfo.Mode().IsRegular() ||
		fileInfo.Mode().Perm() != 0o600 ||
		fileInfo.Size() > 32<<10 {
		return "", errors.New("local_coverage_identity_file_invalid")
	}
	dirStat, dirOK := info.Sys().(*syscall.Stat_t)
	fileStat, fileOK := fileInfo.Sys().(*syscall.Stat_t)
	if !dirOK || !fileOK || dirStat.Uid != fileStat.Uid || fileStat.Nlink != 1 {
		return "", errors.New("local_coverage_identity_file_ownership_invalid")
	}
	var identity struct {
		Certificate string `json:"certificate"`
	}
	if json.NewDecoder(io.LimitReader(file, 32<<10)).Decode(&identity) != nil {
		return "", errors.New("local_coverage_identity_invalid")
	}
	block, rest := pem.Decode([]byte(identity.Certificate))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return "", errors.New("local_coverage_certificate_invalid")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || time.Now().Before(certificate.NotBefore) ||
		!time.Now().Before(certificate.NotAfter) {
		return "", errors.New("local_coverage_certificate_invalid")
	}
	hash := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(hash[:]), nil
}

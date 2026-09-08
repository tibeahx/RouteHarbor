package node

import (
	"context"
	"errors"
	"io"
	"os"
	"syscall"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/platform"
	"github.com/tibeahx/OpenRHP/internal/wireless"
)

// VerifiedCapabilities is evaluated inside the root helper. A receipt adds
// wireless eligibility only for the enrolled gateway and the unchanged device.
func VerifiedCapabilities(
	ctx context.Context,
	verifier *wireless.Verifier,
	identityDir string,
) Capabilities {
	caps := CapabilitiesFrom(platform.Detect(ctx))
	// Generic driver discovery cannot substitute for pair-specific evidence.
	caps.WDS, caps.Mesh, caps.EncryptedBackhaul, caps.ConcurrentRadio = false, false, false, false
	a, err := verifier.Authorized(ctx)
	if err != nil || !caps.OpenWrt || !caps.AP {
		return caps
	}
	peer, err := enrolledGateway(identityDir)
	if err != nil || peer != a.PeerFingerprint {
		caps.Reason = "The wireless verification does not match the enrolled gateway."
		return caps
	}
	caps.WDS, caps.Mesh = a.Mode == "wds", a.Mode == "mesh"
	caps.EncryptedBackhaul, caps.ConcurrentRadio = true, true
	caps.VerifiedPeerFingerprint, caps.VerifiedRadio, caps.VerifiedMode = a.PeerFingerprint, a.Radio, a.Mode
	caps.Reason = "A current local verification matches this radio, platform and enrolled gateway."
	return caps
}

func enrolledGateway(dir string) (string, error) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("node_enrollment_unavailable")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", errors.New("node_enrollment_unavailable")
	}
	defer func() { _ = root.Close() }()
	before, err := root.Lstat("enrollment.json")
	if err != nil || !before.Mode().IsRegular() {
		return "", errors.New("node_enrollment_invalid")
	}
	file, err := root.OpenFile(
		"enrollment.json",
		os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,
		0,
	)
	if err != nil {
		return "", errors.New("node_enrollment_unavailable")
	}
	defer func() { _ = file.Close() }()
	stat, err := file.Stat()
	if err != nil || !os.SameFile(before, stat) || !stat.Mode().IsRegular() ||
		stat.Mode().Perm() != 0o600 ||
		stat.Size() > 8<<10 {
		return "", errors.New("node_enrollment_invalid")
	}
	owner, ok := stat.Sys().(*syscall.Stat_t)
	dirOwner, validOwner := info.Sys().(*syscall.Stat_t)
	if !ok || !validOwner || owner.Nlink != 1 || owner.Uid != dirOwner.Uid {
		return "", errors.New("node_enrollment_invalid")
	}
	data, err := io.ReadAll(io.LimitReader(file, 8<<10+1))
	var state enrollment
	if err != nil || len(data) > 8<<10 || adapter.StrictDecode(data, &state) != nil ||
		state.Version != 1 ||
		!validFingerprint(state.GatewayFingerprint) {
		return "", errors.New("node_enrollment_invalid")
	}
	return state.GatewayFingerprint, nil
}

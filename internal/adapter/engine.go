package adapter

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/tibeahx/OpenRHP/internal/model"
)

const (
	SingBoxVersion = "1.14.0"
	XrayVersion    = "26.3.27"
)

type boundedVersionOutput struct{ bytes.Buffer }

func (b *boundedVersionOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 8192 {
		return 0, errors.New("version output too large")
	}
	return b.Buffer.Write(p)
}

func trustedEngine(binary string) error {
	for _, path := range []string{"/usr", "/usr/bin", binary} {
		i, e := os.Lstat(path)
		if e != nil {
			return errors.New("supported engine package is not installed")
		}
		st, ok := i.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || i.Mode().Perm()&0o022 != 0 || i.Mode()&os.ModeSymlink != 0 {
			return errors.New(
				"installed engine and parent directories must be root owned and not writable by other users",
			)
		}
		if path == binary && (!i.Mode().IsRegular() || i.Mode().Perm()&0o111 == 0) {
			return errors.New("installed engine must be a regular executable")
		}
	}
	return nil
}

func supportedEngineVersion(engine, output string) bool {
	for _, line := range strings.Split(output, "\n") {
		if engine == "sing-box" && line == "sing-box version "+SingBoxVersion {
			return true
		}
		if engine == "xray" && strings.HasPrefix(line, "Xray "+XrayVersion+" ") {
			return true
		}
	}
	return false
}

func verifyEngine(ctx context.Context, engine, binary string) error {
	if e := trustedEngine(binary); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "version")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	var output boundedVersionOutput
	cmd.Stdout = &output
	cmd.Stderr = &output
	if e := cmd.Run(); e != nil {
		return errors.New("could not verify installed engine version")
	}
	if !supportedEngineVersion(engine, output.String()) {
		return errors.New(
			"installed engine version is unsupported; install the pinned adapter package",
		)
	}
	return nil
}

// VerifyEngineInstallation is used by the typed helper worker. It accepts only
// the two fixed supported engine packages, never a caller-supplied binary path.
func VerifyEngineInstallation(ctx context.Context, engine string) error {
	if engine != "sing-box" && engine != "xray" {
		return errors.New("unsupported engine")
	}
	return verifyEngine(ctx, engine, "/usr/bin/"+engine)
}

// RequireNumericEngineEndpoint prevents an engine worker from introducing an
// implicit system-DNS lookup after the controller has pinned its bootstrap IP.
func RequireNumericEngineEndpoint(s model.Source) error {
	var host string
	switch s.Type {
	case "sing-box":
		var o SingOutbound
		if e := StrictDecode(s.Settings, &o); e != nil {
			return e
		}
		host = o.Server
	case "socks5", "http-connect":
		var p ProxySettings
		if e := StrictDecode(s.Settings, &p); e != nil {
			return e
		}
		host = p.Server
	case "xray":
		var x XraySettings
		if e := StrictDecode(s.Settings, &x); e != nil {
			return e
		}
		o, e := normalizeXray(x)
		if e != nil {
			return e
		}
		host = o.Settings.VNext[0].Address
	default:
		return errors.New("source has no managed engine")
	}
	ip, e := netip.ParseAddr(host)
	if e != nil || ip.Zone() != "" {
		return errors.New("managed engine endpoint must be a numeric IP")
	}
	return nil
}

package node

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/platform"
)

// nodeRunner adds only the service reload operations required after a typed UCI
// transaction. It does not extend the general platform command surface.
type nodeRunner struct{}

func (nodeRunner) Available(binary string) error {
	switch binary {
	case "/etc/init.d/dnsmasq", "/etc/init.d/odhcpd", "/sbin/wifi":
	default:
		return errors.New("node service path is outside the fixed allowlist")
	}
	info, err := os.Stat(binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("required node service tool is unavailable")
	}
	return nil
}

func (nodeRunner) Run(
	ctx context.Context,
	binary string,
	args []string,
	input []byte,
) ([]byte, error) {
	want := ""
	switch binary {
	case "/etc/init.d/dnsmasq", "/etc/init.d/odhcpd":
		want = "restart"
	case "/sbin/wifi":
		want = "reload"
	default:
		return (platform.ProductionRunner{}).Run(ctx, binary, args, input)
	}
	if len(args) != 1 || args[0] != want || len(input) != 0 {
		return nil, errors.New("node service command is outside the fixed allowlist")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Run(); err != nil {
		return nil, errors.New("node service reload failed")
	}
	return nil, nil
}

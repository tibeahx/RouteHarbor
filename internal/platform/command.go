package platform

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"time"
)

// Runner is injectable for tests. ProductionRunner never invokes a shell or PATH.
type Runner interface {
	Run(context.Context, string, []string, []byte) ([]byte, error)
}
type ProductionRunner struct{}

var binaries = map[string]bool{
	"/bin/ubus":     true,
	"/sbin/ubus":    true,
	"/sbin/uci":     true,
	"/sbin/nft":     true,
	"/usr/sbin/nft": true,
	"/sbin/ip":      true,
	"/usr/sbin/ip":  true,
	"/usr/sbin/iw":  true,
	"/sbin/fw4":     true,
}

// UBusBinary checks only fixed OpenWrt installation locations, never PATH.
func UBusBinary() string {
	return ubusBinary(func(path string) bool {
		info, err := os.Stat(path)
		return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
	})
}

func ubusBinary(exists func(string) bool) string {
	if exists("/bin/ubus") {
		return "/bin/ubus"
	}
	return "/sbin/ubus"
}

const MaxCommandOutput = 2 << 20

type boundedBuffer struct {
	data     []byte
	max      int
	exceeded bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if len(b.data)+len(p) > b.max {
		remaining := b.max - len(b.data)
		b.data = append(b.data, p[:remaining]...)
		b.exceeded = true
		return n, nil
	}
	b.data = append(b.data, p...)
	return n, nil
}

func (ProductionRunner) Run(
	ctx context.Context,
	binary string,
	args []string,
	stdin []byte,
) ([]byte, error) {
	if !binaries[binary] {
		return nil, errors.New("binary is outside the fixed platform allowlist")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	if stdin != nil {
		cmd.Stdin = &byteReader{data: stdin}
	}
	output := &boundedBuffer{max: MaxCommandOutput}
	cmd.Stdout = output
	cmd.Stderr = output
	err := cmd.Run()
	if output.exceeded {
		return nil, errors.New("platform command exceeded output limit")
	}
	if err != nil {
		return nil, errors.New("platform command failed")
	}
	return output.data, nil
}

type byteReader struct{ data []byte }

func (b *byteReader) Read(p []byte) (int, error) {
	if len(b.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b.data)
	b.data = b.data[n:]
	return n, nil
}

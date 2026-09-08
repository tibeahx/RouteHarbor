//go:build !linux

package helper

import (
	"errors"
	"io"
	"os/exec"
)

func startPacketWorker(int) (*exec.Cmd, io.Closer, error) {
	return nil, nil, errors.New("capability_unavailable: packet supervisor requires Linux")
}

func RunPacketWorker(int) error {
	return errors.New("capability_unavailable: packet supervisor requires Linux")
}

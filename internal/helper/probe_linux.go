//go:build linux

package helper

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"syscall"

	"github.com/tibeahx/RouteHarbor/internal/dataplane"
)

func dialMarked(ctx context.Context, p dataplane.Path, address string) (*net.TCPConn, error) {
	d := net.Dialer{Control: func(network, address string, raw syscall.RawConn) error {
		var inner error
		err := raw.Control(func(fd uintptr) {
			inner = syscall.SetsockoptInt(
				int(fd),
				syscall.SOL_SOCKET,
				syscall.SO_MARK,
				int(dataplane.Mark(p.Slot)),
			)
			if inner == nil && p.Interface != "" {
				inner = syscall.SetsockoptString(
					int(fd),
					syscall.SOL_SOCKET,
					syscall.SO_BINDTODEVICE,
					p.Interface,
				)
			}
		})
		if err != nil {
			return err
		}
		return inner
	}}
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}

func sendConn(c *net.UnixConn, tcp *net.TCPConn) error {
	f, err := tcp.File()
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	data, _ := json.Marshal(Response{OK: true})
	_, _, err = c.WriteMsgUnix(append(data, '\n'), syscall.UnixRights(int(f.Fd())), nil)
	return err
}

func (c *Client) DialProbe(ctx context.Context, sourceID, address string) (net.Conn, error) {
	if _, err := validateProbeAddress(address); err != nil {
		return nil, err
	}
	conn, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	req := Request{Operation: "dial_probe", SourceID: sourceID, Address: address}
	if err = validateRequest(req); err != nil {
		return nil, err
	}
	data, _ := json.Marshal(req)
	if _, err = conn.Write(append(data, '\n')); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	control := make([]byte, syscall.CmsgSpace(4))
	n, oob, flags, _, err := conn.ReadMsgUnix(buf, control)
	if err != nil {
		return nil, err
	}
	var r Response
	if err = DecodeStrict(buf[:n], &r); err != nil {
		return nil, err
	}
	if !r.OK {
		return nil, errors.New(r.Error)
	}
	if flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 {
		return nil, errors.New("invalid_helper_response")
	}
	msgs, err := syscall.ParseSocketControlMessage(control[:oob])
	if err != nil {
		return nil, err
	}
	fds := []int{}
	for _, msg := range msgs {
		rights, e := syscall.ParseUnixRights(&msg)
		if e != nil {
			for _, fd := range fds {
				_ = syscall.Close(fd)
			}
			return nil, e
		}
		fds = append(fds, rights...)
	}
	if len(fds) != 1 {
		for _, fd := range fds {
			_ = syscall.Close(fd)
		}
		return nil, errors.New("invalid_helper_response")
	}
	syscall.CloseOnExec(fds[0])
	f := os.NewFile(uintptr(fds[0]), "routeharbor-probe")
	defer func() { _ = f.Close() }()
	return net.FileConn(f)
}

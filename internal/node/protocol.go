package node

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/helper"
)

type Operation struct {
	Action         string `json:"action"`
	ID             string `json:"id,omitempty"`
	Key            string `json:"key,omitempty"`
	Plan           *Plan  `json:"plan,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}
type Operator interface {
	Do(context.Context, Operation) (map[string]any, error)
}
type LocalOperator struct{ Manager *Manager }

func (l LocalOperator) Do(ctx context.Context, o Operation) (map[string]any, error) {
	var t Transaction
	var e error
	switch o.Action {
	case "inspect":
		return l.Manager.Inspect(ctx)
	case "link":
		return l.Manager.Link(ctx)
	case "status":
		return l.Manager.Status()
	case "prepare":
		if o.Plan == nil {
			return nil, errors.New("node_plan_required")
		}
		t, e = l.Manager.Prepare(ctx, o.Key, *o.Plan)
	case "validate":
		t, e = l.Manager.Validate(ctx, o.ID)
	case "apply":
		t, e = l.Manager.Apply(ctx, o.ID, time.Duration(o.TimeoutSeconds)*time.Second)
	case "confirm":
		t, e = l.Manager.Confirm(ctx, o.ID)
	case "rollback":
		t, e = l.Manager.Rollback(ctx, o.ID)
	default:
		return nil, errors.New("unsupported_node_operation")
	}
	if e != nil {
		return nil, e
	}
	return map[string]any{"transaction": t}, nil
}

type (
	HelperClient  struct{ Socket string }
	protocolReply struct {
		Result map[string]any `json:"result,omitempty"`
		Error  string         `json:"error,omitempty"`
	}
)

func (c HelperClient) Do(ctx context.Context, o Operation) (map[string]any, error) {
	if e := helper.SupportedPeerCredentials(); e != nil {
		return nil, e
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	connection, e := d.DialContext(ctx, "unix", c.Socket)
	if e != nil {
		return nil, errors.New("node_helper_unavailable")
	}
	defer func() { _ = connection.Close() }()
	conn, ok := connection.(*net.UnixConn)
	if !ok {
		return nil, errors.New("invalid_node_helper_connection")
	}
	uid, e := helper.PeerUID(conn)
	if e != nil || uid != 0 {
		return nil, errors.New("node_helper_identity_mismatch")
	}
	deadline := time.Now().Add(45 * time.Second)
	if bound, ok := ctx.Deadline(); ok && bound.Before(deadline) {
		deadline = bound
	}
	if e = conn.SetDeadline(deadline); e != nil {
		return nil, errors.New("node_helper_deadline_failed")
	}
	if e = json.NewEncoder(conn).Encode(o); e != nil {
		return nil, errors.New("node_helper_request_failed")
	}
	data, e := bufio.NewReader(io.LimitReader(conn, 256<<10+1)).ReadBytes('\n')
	if e != nil || len(data) > 256<<10 {
		return nil, errors.New("invalid_node_helper_response")
	}
	var reply protocolReply
	if adapter.StrictDecode(data, &reply) != nil {
		return nil, errors.New("invalid_node_helper_response")
	}
	if reply.Error != "" {
		return nil, errors.New("node_helper_rejected: " + reply.Error)
	}
	return reply.Result, nil
}

// ServeHelper is a typed, root-owned local privilege boundary. Filesystem
// permissions and Linux peer credentials both identify the intended agent UID.
func ServeHelper(ctx context.Context, socket string, uid uint32, operator Operator) error {
	if os.Geteuid() != 0 {
		return errors.New("node helper requires root")
	}
	if uid == 0 {
		return errors.New("node API agent must have a separate unprivileged UID")
	}
	if e := helper.SupportedPeerCredentials(); e != nil {
		return e
	}
	if !filepath.IsAbs(socket) {
		return errors.New("node helper socket must be absolute")
	}
	if info, e := os.Lstat(socket); e == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("node helper socket path is occupied")
		}
		if e = os.Remove(socket); e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if e != nil {
		return e
	}
	defer func() { _ = l.Close() }()
	defer func() { _ = os.Remove(socket) }()
	if e = os.Chmod(socket, 0o600); e != nil {
		return e
	}
	if e = os.Chown(socket, int(uid), -1); e != nil {
		return e
	}
	go func() { <-ctx.Done(); _ = l.Close() }()
	semaphore := make(chan struct{}, 8)
	for {
		conn, e := l.AcceptUnix()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		select {
		case semaphore <- struct{}{}:
			go func() {
				defer func() { <-semaphore }()
				defer func() { _ = conn.Close() }()
				peer, e := helper.PeerUID(conn)
				if e != nil || peer != uid {
					return
				}
				if conn.SetDeadline(time.Now().Add(45*time.Second)) != nil {
					return
				}
				data, e := bufio.NewReader(io.LimitReader(conn, 64<<10+1)).ReadBytes('\n')
				reply := protocolReply{}
				var operation Operation
				if e != nil || len(data) > 64<<10 || adapter.StrictDecode(data, &operation) != nil {
					reply.Error = "invalid_operation"
				} else {
					opctx, cancel := context.WithTimeout(ctx, 40*time.Second)
					result, e := operator.Do(opctx, operation)
					cancel()
					if e != nil {
						reply.Error = "operation_rejected"
					} else {
						reply.Result = result
					}
				}
				if json.NewEncoder(conn).Encode(reply) != nil {
					return
				}
			}()
		default:
			_ = conn.Close()
		}
	}
}

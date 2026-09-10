package helper

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/tibeahx/OpenRHP/internal/routing"
)

// Recovery reads immutable, content-addressed snapshots through fixed bounded
// chunks. Neither callers nor engine configuration can name filesystem paths.
func (s *Server) dispatcherSnapshotRead(r DispatcherRequest) (DispatcherStatus, error) {
	ref := *r.Snapshot
	f, e := openPrivate(s.snapshotName(ref), os.O_RDONLY, 0o600)
	if e != nil {
		return DispatcherStatus{}, errors.New("dispatcher_snapshot_unavailable")
	}
	defer func() { _ = f.Close() }()
	info, e := f.Stat()
	if e != nil || info.Size() < 1 || info.Size() > routing.MaxSnapshotBytes {
		return DispatcherStatus{}, errors.New("dispatcher_snapshot_invalid")
	}
	if r.Action == "snapshot-info" {
		ref.Size = info.Size()
		if _, e = s.readDispatcherSnapshot(ref); e != nil {
			return DispatcherStatus{}, e
		}
		return DispatcherStatus{Snapshot: &ref}, nil
	}
	if info.Size() != ref.Size || r.Offset < 0 || r.Offset >= ref.Size {
		return DispatcherStatus{}, errors.New("dispatcher_snapshot_offset_invalid")
	}
	if _, e = f.Seek(r.Offset, io.SeekStart); e != nil {
		return DispatcherStatus{}, errors.New("dispatcher_snapshot_read_failed")
	}
	data, e := io.ReadAll(io.LimitReader(f, min(48<<10, ref.Size-r.Offset)))
	if e != nil {
		return DispatcherStatus{}, errors.New("dispatcher_snapshot_read_failed")
	}
	return DispatcherStatus{Snapshot: &ref, Data: data}, nil
}

func (c *Client) LoadRoutingSnapshot(
	ctx context.Context,
	generation uint64,
	hash string,
) (routing.Snapshot, routing.SnapshotRef, error) {
	ref := routing.SnapshotRef{Generation: generation, SHA256: hash}
	result, e := c.Dispatcher(ctx, DispatcherRequest{Action: "snapshot-info", Snapshot: &ref})
	if e != nil {
		return routing.Snapshot{}, ref, e
	}
	if result.Snapshot == nil || routing.ValidateReference(*result.Snapshot) != nil ||
		result.Snapshot.Generation != generation ||
		result.Snapshot.SHA256 != hash {
		return routing.Snapshot{}, ref, errors.New("invalid_helper_response")
	}
	ref = *result.Snapshot
	data := make([]byte, 0, int(ref.Size))
	for int64(len(data)) < ref.Size {
		chunk, e := c.Dispatcher(
			ctx,
			DispatcherRequest{Action: "snapshot-read", Snapshot: &ref, Offset: int64(len(data))},
		)
		if e != nil {
			return routing.Snapshot{}, ref, e
		}
		if chunk.Snapshot == nil || *chunk.Snapshot != ref || len(chunk.Data) == 0 ||
			len(chunk.Data) > 48<<10 ||
			int64(len(data)+len(chunk.Data)) > ref.Size {
			return routing.Snapshot{}, ref, errors.New("invalid_helper_response")
		}
		data = append(data, chunk.Data...)
	}
	snapshot, e := routing.DecodeSnapshot(data)
	if e != nil || routing.Reference(snapshot, data) != ref {
		return routing.Snapshot{}, ref, errors.New("dispatcher_snapshot_invalid")
	}
	return snapshot, ref, nil
}

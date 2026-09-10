package continuity

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

const (
	frameOpen byte = iota + 1
	frameOpened
	frameData
	frameACK
	frameFIN
	frameFINACK
	frameClose
	frameUDP
	frameUDPACK
	framePing
	framePong
	frameSelect
	frameClosed
)

const (
	chunkSize               = 16 << 10
	maxPayload              = 65507
	segmentOverhead   int64 = 192
	flowOverhead      int64 = 2048
	controlOverhead   int64 = 96
	carrierQueueBytes int64 = 4096
	headerSize              = 25
)

type frame struct {
	kind                byte
	flow, offset, value uint64
	data                []byte
}

func writeFrame(w io.Writer, f frame) error {
	if len(f.data) > maxPayload {
		return errors.New("oversized continuity frame")
	}
	var b [4 + headerSize]byte
	binary.BigEndian.PutUint32(b[:4], uint32(headerSize+len(f.data)))
	b[4] = f.kind
	binary.BigEndian.PutUint64(b[5:13], f.flow)
	binary.BigEndian.PutUint64(b[13:21], f.offset)
	binary.BigEndian.PutUint64(b[21:29], f.value)
	if err := writeAll(w, b[:]); err != nil {
		return err
	}
	return writeAll(w, f.data)
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n > 0 {
			b = b[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func readFrame(r io.Reader) (frame, error) {
	var b [4 + headerSize]byte
	var f frame
	if _, err := io.ReadFull(r, b[:4]); err != nil {
		return f, err
	}
	n := binary.BigEndian.Uint32(b[:4])
	if n < headerSize || n > headerSize+maxPayload {
		return f, errors.New("invalid continuity frame size")
	}
	if _, err := io.ReadFull(r, b[4:]); err != nil {
		return f, err
	}
	f.kind = b[4]
	f.flow = binary.BigEndian.Uint64(b[5:13])
	f.offset = binary.BigEndian.Uint64(b[13:21])
	f.value = binary.BigEndian.Uint64(b[21:29])
	if f.kind < frameOpen || f.kind > frameClosed {
		return f, errors.New("invalid continuity frame type")
	}
	f.data = make([]byte, int(n)-headerSize)
	_, err := io.ReadFull(r, f.data)
	return f, err
}

type hello struct {
	Version    int    `json:"version"`
	Session    string `json:"session"`
	Generation string `json:"generation"`
	Path       string `json:"path"`
	Lane       int    `json:"lane"`
	Limits     Limits `json:"limits"`
}
type welcome struct {
	Generation string `json:"generation"`
	FlowBytes  int64  `json:"flow_bytes,omitempty"`
	Error      string `json:"error,omitempty"`
}

func writeJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > 4096 {
		return errors.New("handshake too large")
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b)))
	if err = writeAll(w, h[:]); err != nil {
		return err
	}
	return writeAll(w, b)
}

func readJSON(r io.Reader, v any) error {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > 4096 {
		return errors.New("invalid handshake size")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

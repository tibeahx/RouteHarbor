package continuity

import (
	"context"
	"errors"
	"io"
	"net"
	"sort"
	"sync"
	"time"
)

type segment struct {
	f                   frame
	cost                int64
	sending, udp, owned bool
	refs                int
	sentPath            string
	sentAt              time.Time
}
type queued struct {
	f       frame
	segment *segment
	cost    int64
}
type carrier struct {
	p                                              *peer
	path                                           string
	lane                                           int
	conn                                           net.Conn
	control                                        chan queued
	data                                           chan queued
	done                                           chan struct{}
	closed                                         bool
	lastPong, lastPing, pendingSince, lastProgress time.Time
	srtt, variance                                 time.Duration
	pingID                                         uint64
}

func (c *carrier) rto() time.Duration {
	d := c.srtt + 4*c.variance + 2*time.Millisecond
	if d < 60*time.Millisecond {
		return 60 * time.Millisecond
	}
	return d
}

type logicalFlow struct {
	id                                   uint64
	destination                          string
	udp                                  bool
	conn                                 net.Conn
	deliver                              func([]byte) error
	opened, opening, closed              bool
	ackDirty                             bool
	lastActive                           time.Time
	next, acked, window                  uint64
	pending                              []*segment
	sendBytes                            int64
	recv                                 map[uint64]*segment
	ready                                []*segment
	recvNext, consumed                   uint64
	recvBytes                            int64
	readEOF, finACK, recvFIN, finApplied bool
	finOffset                            uint64
	seen                                 datagramWindow
	done                                 chan struct{}
	err                                  error
}

// A bounded sliding bitmap deduplicates unordered datagrams. An authenticated
// peer cannot grow a map indefinitely by sending distinct sequence numbers.
type datagramWindow struct {
	high uint64
	bits [64]uint64
}

func (w *datagramWindow) contains(n uint64) bool {
	if n == 0 {
		return true
	}
	if w.high >= n && w.high-n >= 4096 {
		return true
	}
	return n <= w.high && w.bits[(n%4096)/64]&(uint64(1)<<(n%64)) != 0
}

func (w *datagramWindow) add(n uint64) {
	if n > w.high {
		if n-w.high >= 4096 {
			w.bits = [64]uint64{}
		} else {
			for k := w.high + 1; ; k++ {
				w.bits[(k%4096)/64] &^= uint64(1) << (k % 64)
				if k == n {
					break
				}
			}
		}
		w.high = n
	}
	w.bits[(n%4096)/64] |= uint64(1) << (n % 64)
}

type peer struct {
	mu                                   sync.Mutex
	ctx                                  context.Context
	cancel                               context.CancelFunc
	limits                               Limits
	session, generation                  string
	server                               bool
	dial                                 TargetDialFunc
	paths                                map[string][CarriersPerPath]*carrier
	preferred, active                    string
	flows                                map[uint64]*logicalFlow
	seen                                 datagramWindow
	keys                                 map[string]uint64
	closing                              map[uint64]time.Time
	lastCloseRetry                       time.Time
	lastWindowRefresh                    time.Time
	nextID                               uint64
	used                                 [2][2]int64 // direction (receive/send), class (TCP/UDP)
	controlBytes                         int64
	closed                               bool
	terminalErr                          error
	lastReady, switchedAt                time.Time
	replayed, expired, dropped, switches uint64
	pause                                time.Duration
	wg                                   sync.WaitGroup
}

func newPeer(l Limits, session, generation string, server bool, dial TargetDialFunc) *peer {
	ctx, cancel := context.WithCancel(context.Background())
	p := &peer{
		ctx:        ctx,
		cancel:     cancel,
		limits:     l,
		session:    session,
		generation: generation,
		server:     server,
		dial:       dial,
		paths:      make(map[string][CarriersPerPath]*carrier),
		flows:      make(map[uint64]*logicalFlow),
		keys:       make(map[string]uint64),
		closing:    make(map[uint64]time.Time),
		lastReady:  time.Now(),
	}
	p.wg.Add(1)
	go p.run()
	return p
}

func (p *peer) reserve(send, udp bool, n int64) bool {
	d, k := 0, 0
	if send {
		d = 1
	}
	if udp {
		k = 1
	}
	limit := (p.limits.BufferBytes - p.limits.UDPReserveBytes) / 2
	if udp {
		limit = p.limits.UDPReserveBytes / 2
	}
	if n < 0 || p.used[d][k]+n > limit {
		return false
	}
	p.used[d][k] += n
	return true
}

func (p *peer) release(s *segment) {
	if s.owned || s.refs > 0 {
		return
	}
	d, k := 0, 0
	if s.sending {
		d = 1
	}
	if s.udp {
		k = 1
	}
	p.used[d][k] -= s.cost
	s.cost = 0
	s.f.data = nil
}
func (p *peer) discard(s *segment) { s.owned = false; p.release(s) }
func (p *peer) ready(path string) bool {
	cs, ok := p.paths[path]
	if !ok {
		return false
	}
	for _, c := range cs {
		if c == nil || c.closed {
			return false
		}
	}
	return true
}

func (p *peer) selectPath(now time.Time) {
	chosen := p.active
	if !p.ready(chosen) && p.ready(p.preferred) {
		chosen = p.preferred
	} else if !p.ready(chosen) {
		chosen = ""
		names := make([]string, 0, len(p.paths))
		for n := range p.paths {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if p.ready(n) {
				chosen = n
				break
			}
		}
	}
	if chosen != "" {
		p.lastReady = now
	}
	if chosen != p.active {
		if p.active != "" && chosen != "" {
			p.switches++
			p.switchedAt = now
		}
		p.active = chosen
	}
}

func (p *peer) addCarrier(path string, lane int, conn net.Conn, rtt time.Duration) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrClosed
	}
	if p.terminalErr != nil {
		return p.terminalErr
	}
	if _, ok := p.paths[path]; !ok && len(p.paths) >= 2 {
		return ErrCapacity
	}
	if p.controlBytes+carrierQueueBytes > p.limits.ControlBytes {
		return ErrCapacity
	}
	cs := p.paths[path]
	if old := cs[lane]; old != nil && !old.closed {
		p.closeCarrier(old)
	}
	if rtt < time.Millisecond {
		rtt = time.Millisecond
	}
	c := &carrier{
		p:        p,
		path:     path,
		lane:     lane,
		conn:     conn,
		control:  make(chan queued, 16),
		data:     make(chan queued, 32),
		done:     make(chan struct{}),
		lastPong: time.Now(),
		srtt:     rtt,
		variance: rtt / 2,
	}
	p.controlBytes += carrierQueueBytes
	cs[lane] = c
	p.paths[path] = cs
	if p.preferred == "" {
		p.preferred = path
	}
	p.selectPath(time.Now())
	p.wg.Add(2)
	go c.readLoop()
	go c.writeLoop()
	return nil
}

func (p *peer) closeCarrier(c *carrier) {
	if c.closed {
		return
	}
	c.closed = true
	close(c.done)
	_ = c.conn.Close()
}

func (p *peer) enqueue(c *carrier, f frame, s *segment) bool {
	if c == nil || c.closed {
		return false
	}
	cost := controlOverhead
	if s == nil {
		cost += int64(len(f.data))
	}
	if p.controlBytes+cost > p.limits.ControlBytes {
		return false
	}
	q := queued{f: f, segment: s, cost: cost}
	ch := c.control
	if s != nil {
		ch = c.data
	}
	select {
	case ch <- q:
		p.controlBytes += cost
		if s != nil {
			s.refs++
		}
		return true
	default:
		return false
	}
}

func (p *peer) releaseQueued(q queued) {
	p.controlBytes -= q.cost
	if q.segment != nil {
		q.segment.refs--
		p.release(q.segment)
	}
}

func (c *carrier) writeLoop() {
	defer c.p.wg.Done()
	defer func() {
		c.p.mu.Lock()
		for {
			select {
			case q := <-c.control:
				c.p.releaseQueued(q)
			case q := <-c.data:
				c.p.releaseQueued(q)
			default:
				c.control = nil
				c.data = nil
				c.p.controlBytes -= carrierQueueBytes
				c.p.mu.Unlock()
				return
			}
		}
	}()
	for {
		var q queued
		select {
		case <-c.done:
			return
		case q = <-c.control:
		default:
			select {
			case <-c.done:
				return
			case q = <-c.control:
			case q = <-c.data:
			}
		}
		c.p.mu.Lock()
		deadline := c.rto()
		closed := c.closed
		c.p.mu.Unlock()
		var err error
		if !closed {
			_ = c.conn.SetWriteDeadline(time.Now().Add(deadline))
			err = writeFrame(c.conn, q.f)
		}
		c.p.mu.Lock()
		c.p.releaseQueued(q)
		if err != nil {
			c.p.closeCarrier(c)
			c.p.selectPath(time.Now())
		}
		c.p.mu.Unlock()
		if err != nil {
			return
		}
	}
}

func (c *carrier) readLoop() {
	defer c.p.wg.Done()
	for {
		f, err := readFrame(c.conn)
		if err != nil {
			c.p.mu.Lock()
			c.p.closeCarrier(c)
			c.p.selectPath(time.Now())
			c.p.mu.Unlock()
			return
		}
		c.p.handle(c, f)
	}
}

func (p *peer) run() {
	defer p.wg.Done()
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case now := <-ticker.C:
			p.mu.Lock()
			p.tick(now)
			p.mu.Unlock()
		}
	}
}

func (p *peer) tick(now time.Time) {
	if p.closed {
		return
	}
	for _, cs := range p.paths {
		for _, c := range cs {
			if c == nil || c.closed {
				continue
			}
			if !c.pendingSince.IsZero() && !p.outstanding(c) {
				c.pendingSince = time.Time{}
			}
			if now.Sub(c.lastPong) > c.rto() ||
				(!c.pendingSince.IsZero() && now.Sub(c.lastProgress) > c.rto()) {
				p.closeCarrier(c)
				continue
			}
			if now.Sub(c.lastPing) >= 20*time.Millisecond {
				c.pingID++
				if p.enqueue(
					c,
					frame{kind: framePing, offset: c.pingID, value: uint64(now.UnixNano())},
					nil,
				) {
					c.lastPing = now
				}
				if !p.server && c.lane == 5 && p.active != "" {
					p.enqueue(c, frame{kind: frameSelect, data: []byte(p.active)}, nil)
				}
			}
		}
	}
	p.selectPath(now)
	refreshWindows := now.Sub(p.lastWindowRefresh) >= 20*time.Millisecond
	if refreshWindows {
		p.lastWindowRefresh = now
	}
	if now.Sub(p.lastCloseRetry) >= 20*time.Millisecond {
		p.lastCloseRetry = now
		for id, deadline := range p.closing {
			if now.After(deadline) {
				delete(p.closing, id)
				p.controlBytes -= 128
				continue
			}
			if p.active != "" {
				p.enqueue(p.paths[p.active][5], frame{kind: frameClose, flow: id}, nil)
			}
		}
	}
	if p.active == "" && now.Sub(p.lastReady) >= p.limits.DisconnectedGrace {
		for _, f := range p.flows {
			p.closeFlow(f, ErrNoPath, false)
		}
		return
	}
	for _, f := range p.flows {
		if f.udp && now.Sub(f.lastActive) > p.limits.UDPIdle {
			p.closeFlow(f, nil, true)
			continue
		}
		if refreshWindows && f.opened && !f.udp {
			f.ackDirty = true
		}
		if f.udp {
			keep := f.pending[:0]
			for _, s := range f.pending {
				if now.Sub(time.Unix(0, int64(s.f.value))) > p.limits.UDPReplay {
					f.sendBytes -= s.cost
					p.discard(s)
					p.expired++
				} else {
					keep = append(keep, s)
				}
			}
			f.pending = keep
			for _, cs := range p.paths {
				c := cs[4]
				if c != nil && !c.closed && !p.outstanding(c) {
					c.pendingSince = time.Time{}
				}
			}
		}
		if p.active == "" {
			continue
		}
		lane := int(f.id % 4)
		if f.udp {
			lane = 4
		}
		c := p.paths[p.active][lane]
		if f.ackDirty && !f.udp {
			p.acknowledge(c, f)
		}
		if !f.opened {
			if !p.server && !f.opening {
				p.enqueue(
					c,
					frame{
						kind:  frameOpen,
						flow:  f.id,
						value: boolUint(f.udp),
						data:  []byte(f.destination),
					},
					nil,
				)
			}
			continue
		}
		for _, s := range f.pending {
			if s.refs > 0 {
				continue
			}
			if !f.udp && s.f.offset+uint64(len(s.f.data)) > f.window {
				continue
			}
			if s.sentPath == p.active && now.Sub(s.sentAt) < c.rto() {
				continue
			}
			if p.enqueue(c, s.f, s) {
				if !s.sentAt.IsZero() {
					p.replayed++
				}
				s.sentPath = p.active
				s.sentAt = now
				if c.pendingSince.IsZero() {
					c.pendingSince = now
					c.lastProgress = now
				}
			} else {
				break
			}
		}
		if f.readEOF && !f.finACK {
			p.enqueue(p.controlCarrier(c), frame{kind: frameFIN, flow: f.id, offset: f.next}, nil)
		}
	}
}

func boolUint(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

func (p *peer) newFlow(id uint64, dest string, udp bool) (*logicalFlow, error) {
	n := 0
	for _, f := range p.flows {
		if f.udp == udp {
			n++
		}
	}
	limit := p.limits.MaxTCP
	if udp {
		limit = p.limits.MaxUDP
	}
	if n >= limit || len(p.flows)+len(p.closing) >= p.limits.MaxTCP+p.limits.MaxUDP ||
		p.controlBytes+128 > p.limits.ControlBytes ||
		!p.reserve(false, udp, flowOverhead) {
		return nil, ErrCapacity
	}
	p.controlBytes += 128
	f := &logicalFlow{
		id:          id,
		destination: dest,
		udp:         udp,
		lastActive:  time.Now(),
		next:        0,
		recv:        make(map[uint64]*segment),
		done:        make(chan struct{}),
	}
	p.flows[id] = f
	return f, nil
}

func (p *peer) closeFlow(f *logicalFlow, err error, notify bool) {
	if f.closed {
		return
	}
	f.closed = true
	f.err = err
	close(f.done)
	if f.conn != nil {
		_ = f.conn.Close()
	}
	for _, s := range f.pending {
		p.discard(s)
	}
	for _, s := range f.recv {
		p.discard(s)
	}
	for _, s := range f.ready {
		p.discard(s)
	}
	k := 0
	if f.udp {
		k = 1
	}
	p.used[0][k] -= flowOverhead
	delete(p.flows, f.id)
	for key, id := range p.keys {
		if id == f.id {
			delete(p.keys, key)
		}
	}
	if notify {
		p.closing[f.id] = time.Now().Add(p.limits.DisconnectedGrace)
	} else {
		p.controlBytes -= 128
	}
}

func (p *peer) acknowledge(c *carrier, f *logicalFlow) {
	f.ackDirty = !p.enqueue(
		p.controlCarrier(c),
		frame{
			kind:   frameACK,
			flow:   f.id,
			offset: f.recvNext,
			value:  p.receiveWindow(f),
		},
		nil,
	)
}

// Credits include queued segment metadata and the shared receive budget. A
// zero window is explicit backpressure, not missing carrier progress. Credits
// are refreshed independently when another stream releases shared capacity.
func (p *peer) receiveWindow(f *logicalFlow) uint64 {
	available := min(
		p.limits.FlowBytes-f.recvBytes,
		(p.limits.BufferBytes-p.limits.UDPReserveBytes)/2-p.used[0][0],
	) - segmentOverhead
	if available < 0 {
		available = 0
	}
	return f.recvNext + uint64(available)
}

// ACK/window and FIN records use the separate control transport, so a blocked
// DATA writer cannot consume the service queue or stop receive-window progress.
func (p *peer) controlCarrier(c *carrier) *carrier {
	if c == nil {
		return nil
	}
	if cs, ok := p.paths[c.path]; ok {
		if control := cs[5]; control != nil && !control.closed {
			return control
		}
		if control := p.paths[p.active][5]; control != nil && !control.closed {
			return control
		}
		return nil
	}
	return c // synthetic carrier used by the protocol's isolated receiver tests
}

func (p *peer) dataProgress(c *carrier, f *logicalFlow, now time.Time) {
	if cs, ok := p.paths[c.path]; ok {
		if data := cs[laneFor(f)]; data != nil && !data.closed {
			p.progress(data, now)
		}
		return
	}
	p.progress(c, now)
}

func laneFor(f *logicalFlow) int {
	if f.udp {
		return 4
	}
	return int(f.id % 4)
}

func (p *peer) outstanding(c *carrier) bool {
	for _, f := range p.flows {
		if laneFor(f) != c.lane {
			continue
		}
		for _, s := range f.pending {
			if s.sentPath == c.path && !s.sentAt.IsZero() &&
				(f.udp || s.f.offset+uint64(len(s.f.data)) <= f.window) {
				return true
			}
		}
	}
	return false
}

func (p *peer) progress(c *carrier, now time.Time) {
	c.lastProgress = now
	c.pendingSince = time.Time{}
	if p.outstanding(c) {
		c.pendingSince = now
	}
	if !p.switchedAt.IsZero() {
		p.pause = now.Sub(p.switchedAt)
		p.switchedAt = time.Time{}
	}
}

func (p *peer) handle(c *carrier, m frame) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || c.closed {
		return
	}
	now := time.Now()
	if m.kind == frameSelect {
		if !p.server || c.lane != 5 || !pathName.Match(m.data) {
			p.closeCarrier(c)
			return
		}
		name := string(m.data)
		if p.ready(name) && p.active != name {
			p.preferred = name
			p.active = name
			p.switches++
			p.switchedAt = now
		}
		return
	}
	if m.kind == frameClosed {
		if _, ok := p.closing[m.flow]; ok {
			delete(p.closing, m.flow)
			p.controlBytes -= 128
		}
		return
	}
	if m.kind == framePing {
		p.enqueue(c, frame{kind: framePong, offset: m.offset, value: m.value}, nil)
		return
	}
	if m.kind == framePong {
		if m.offset <= c.pingID && int64(m.value) > 0 {
			sample := now.Sub(time.Unix(0, int64(m.value)))
			if sample > 0 && sample < time.Minute {
				delta := c.srtt - sample
				if delta < 0 {
					delta = -delta
				}
				c.variance = (3*c.variance + delta) / 4
				c.srtt = (7*c.srtt + sample) / 8
				c.lastPong = now
			}
		}
		return
	}
	f := p.flows[m.flow]
	if m.kind == frameOpen {
		if !p.server || m.flow == 0 || len(m.data) == 0 || len(m.data) > 300 || m.value > 1 {
			p.closeCarrier(c)
			return
		}
		if f != nil {
			if f.destination != string(m.data) || f.udp != (m.value == 1) {
				p.closeCarrier(c)
				return
			}
			if f.opened {
				p.enqueue(
					c,
					frame{kind: frameOpened, flow: f.id, value: uint64(p.limits.FlowBytes)},
					nil,
				)
			}
			return
		}
		if p.seen.contains(m.flow) {
			p.enqueue(c, frame{kind: frameClose, flow: m.flow}, nil)
			return
		}
		var err error
		f, err = p.newFlow(m.flow, string(m.data), m.value == 1)
		if err != nil {
			p.enqueue(c, frame{kind: frameClose, flow: m.flow}, nil)
			return
		}
		p.seen.add(m.flow)
		f.opening = true
		p.wg.Add(1)
		go p.openTarget(f)
		return
	}
	if f == nil {
		if m.kind == frameClose {
			p.enqueue(c, frame{kind: frameClosed, flow: m.flow}, nil)
		} else {
			p.enqueue(c, frame{kind: frameClose, flow: m.flow}, nil)
		}
		return
	}
	f.lastActive = now
	switch m.kind {
	case frameOpened:
		if !p.server && !f.opened {
			f.opened = true
			f.window = m.value
		}
	case frameData:
		if f.udp || !f.opened || len(m.data) == 0 || len(m.data) > chunkSize ||
			m.offset > ^uint64(0)-uint64(len(m.data)) {
			p.closeFlow(f, errors.New("invalid stream frame"), true)
			return
		}
		end := m.offset + uint64(len(m.data))
		if f.recvFIN && end > f.finOffset {
			p.closeFlow(f, errors.New("data beyond stream finish"), true)
			return
		}
		if end <= f.recvNext {
			p.acknowledge(c, f)
			return
		}
		if m.offset < f.recvNext {
			m.data = m.data[f.recvNext-m.offset:]
			m.offset = f.recvNext
		}
		if m.offset+uint64(len(m.data)) > f.consumed+uint64(p.limits.FlowBytes) {
			p.acknowledge(c, f)
			return
		}
		for offset, old := range f.recv {
			if m.offset == offset && len(m.data) == len(old.f.data) {
				p.acknowledge(c, f)
				return
			}
			if m.offset < offset+uint64(len(old.f.data)) && offset < m.offset+uint64(len(m.data)) {
				p.closeFlow(f, errors.New("overlapping stream frame"), true)
				return
			}
		}
		cost := int64(len(m.data)) + segmentOverhead
		if f.recvBytes+cost > p.limits.FlowBytes || !p.reserve(false, false, cost) {
			p.acknowledge(c, f)
			return
		}
		s := &segment{f: m, cost: cost, owned: true}
		f.recv[m.offset] = s
		f.recvBytes += cost
		for {
			s = f.recv[f.recvNext]
			if s == nil {
				break
			}
			delete(f.recv, f.recvNext)
			f.recvNext += uint64(len(s.f.data))
			f.ready = append(f.ready, s)
		}
		p.acknowledge(c, f)
	case frameACK:
		if f.udp || m.offset > f.next || m.value < m.offset ||
			m.value-m.offset > uint64(p.limits.FlowBytes) {
			p.closeFlow(f, errors.New("invalid stream acknowledgement"), true)
			return
		}
		f.window = m.value
		if m.offset > f.acked {
			f.acked = m.offset
			keep := f.pending[:0]
			for _, s := range f.pending {
				if s.f.offset+uint64(len(s.f.data)) <= m.offset {
					f.sendBytes -= s.cost
					p.discard(s)
				} else {
					keep = append(keep, s)
				}
			}
			f.pending = keep
			p.dataProgress(c, f, now)
		}
	case frameFIN:
		if f.udp || m.offset < f.recvNext || f.recvFIN && f.finOffset != m.offset {
			p.closeFlow(f, errors.New("invalid stream finish"), true)
			return
		}
		f.recvFIN = true
		f.finOffset = m.offset
		p.enqueue(p.controlCarrier(c), frame{kind: frameFINACK, flow: f.id, offset: m.offset}, nil)
	case frameFINACK:
		if f.readEOF && m.offset == f.next {
			f.finACK = true
		}
	case frameClose:
		p.closeFlow(f, nil, false)
		p.enqueue(c, frame{kind: frameClosed, flow: m.flow}, nil)
	case frameUDP:
		if !f.udp || !f.opened || len(m.data) > maxPayload {
			p.closeFlow(f, errors.New("invalid datagram"), true)
			return
		}
		if f.seen.contains(m.offset) {
			p.enqueue(
				p.controlCarrier(c),
				frame{kind: frameUDPACK, flow: f.id, offset: m.offset},
				nil,
			)
			return
		}
		cost := int64(len(m.data)) + segmentOverhead
		if !p.reserve(false, true, cost) {
			p.dropped++
			return
		}
		f.seen.add(m.offset)
		s := &segment{f: m, cost: cost, owned: true, udp: true}
		f.ready = append(f.ready, s)
		f.recvBytes += cost
		p.enqueue(p.controlCarrier(c), frame{kind: frameUDPACK, flow: f.id, offset: m.offset}, nil)
	case frameUDPACK:
		if !f.udp {
			return
		}
		keep := f.pending[:0]
		advanced := false
		for _, s := range f.pending {
			if s.f.offset == m.offset {
				f.sendBytes -= s.cost
				p.discard(s)
				advanced = true
			} else {
				keep = append(keep, s)
			}
		}
		f.pending = keep
		if advanced {
			p.dataProgress(c, f, now)
		}
	}
}

func (p *peer) openTarget(f *logicalFlow) {
	defer p.wg.Done()
	network := "tcp"
	if f.udp {
		network = "udp"
	}
	ctx, cancel := context.WithTimeout(p.ctx, 10*time.Second)
	defer cancel()
	conn, err := p.dial(ctx, network, f.destination)
	p.mu.Lock()
	defer p.mu.Unlock()
	if f.closed || p.closed {
		if conn != nil {
			_ = conn.Close()
		}
		return
	}
	if err != nil {
		p.closeFlow(f, ErrDestination, true)
		return
	}
	f.conn = conn
	f.opening = false
	f.opened = true
	f.window = uint64(p.limits.FlowBytes)
	if p.active != "" {
		lane := int(f.id % 4)
		if f.udp {
			lane = 4
		}
		p.enqueue(
			p.paths[p.active][lane],
			frame{kind: frameOpened, flow: f.id, value: uint64(p.limits.FlowBytes)},
			nil,
		)
	}
	p.startFlow(f)
}

func (p *peer) startFlow(f *logicalFlow) {
	p.wg.Add(1)
	go p.writeEndpoint(f)
	if f.conn != nil {
		p.wg.Add(1)
		go p.readEndpoint(f)
	}
}

func (p *peer) readEndpoint(f *logicalFlow) {
	defer p.wg.Done()
	for {
		p.mu.Lock()
		if f.closed || p.closed {
			p.mu.Unlock()
			return
		}
		size := chunkSize
		if f.udp {
			size = maxPayload
		} else if int64(size)+segmentOverhead > p.limits.FlowBytes {
			size = int(p.limits.FlowBytes - segmentOverhead)
		}
		if !f.opened ||
			!f.udp &&
				(f.next >= f.window || f.sendBytes+int64(size)+segmentOverhead > p.limits.FlowBytes) {
			p.mu.Unlock()
			if !waitFlow(p.ctx, f.done) {
				return
			}
			continue
		}
		if !f.udp && uint64(size) > f.window-f.next {
			size = int(f.window - f.next)
		}
		cost := int64(size) + segmentOverhead
		if !p.reserve(true, f.udp, cost) {
			p.mu.Unlock()
			if !waitFlow(p.ctx, f.done) {
				return
			}
			continue
		}
		p.mu.Unlock()
		b := make([]byte, size)
		if f.udp {
			_ = f.conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		}
		n, err := f.conn.Read(b)
		if n > 0 && n < len(b) {
			trimmed := make([]byte, n)
			copy(trimmed, b[:n])
			b = trimmed
		}
		p.mu.Lock()
		s := &segment{cost: cost, sending: true, udp: f.udp}
		if f.closed || p.closed {
			p.release(s)
			p.mu.Unlock()
			return
		}
		if n > 0 {
			actual := int64(n) + segmentOverhead
			d := 0
			if f.udp {
				d = 1
			}
			p.used[1][d] -= cost - actual
			s.cost = actual
			s.owned = true
			s.f = frame{kind: frameData, flow: f.id, offset: f.next, data: b[:n]}
			if f.udp {
				f.next++
				s.f.kind = frameUDP
				s.f.offset = f.next
				s.f.value = uint64(time.Now().UnixNano())
			} else {
				f.next += uint64(n)
			}
			f.pending = append(f.pending, s)
			f.sendBytes += actual
			f.lastActive = time.Now()
		} else {
			p.release(s)
		}
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() && f.udp {
				p.mu.Unlock()
				if !waitFlow(p.ctx, f.done) {
					return
				}
				continue
			}
			if errors.Is(err, io.EOF) && !f.udp {
				f.readEOF = true
			} else {
				p.closeFlow(f, err, true)
			}
			p.mu.Unlock()
			return
		}
		p.mu.Unlock()
	}
}

func waitFlow(ctx context.Context, done <-chan struct{}) bool {
	timer := time.NewTimer(2 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-done:
		return false
	case <-timer.C:
		return true
	}
}

func (p *peer) writeEndpoint(f *logicalFlow) {
	defer p.wg.Done()
	for {
		p.mu.Lock()
		if f.closed || p.closed {
			p.mu.Unlock()
			return
		}
		if len(f.ready) == 0 {
			if f.recvFIN && f.recvNext == f.finOffset && !f.finApplied {
				f.finApplied = true
				if cw, ok := f.conn.(interface{ CloseWrite() error }); ok {
					_ = cw.CloseWrite()
				}
			}
			if f.finApplied && f.readEOF && f.finACK && len(f.pending) == 0 {
				p.closeFlow(f, nil, false)
				p.mu.Unlock()
				return
			}
			p.mu.Unlock()
			if !waitFlow(p.ctx, f.done) {
				return
			}
			continue
		}
		s := f.ready[0]
		s.refs++
		p.mu.Unlock()
		var err error
		if f.deliver != nil {
			err = f.deliver(s.f.data)
		} else if f.udp {
			var n int
			n, err = f.conn.Write(s.f.data)
			if err == nil && n != len(s.f.data) {
				err = io.ErrShortWrite
			}
		} else {
			err = writeAll(f.conn, s.f.data)
		}
		p.mu.Lock()
		s.refs--
		if f.closed {
			p.release(s)
			p.mu.Unlock()
			return
		}
		f.ready = f.ready[1:]
		f.recvBytes -= s.cost
		f.consumed += uint64(len(s.f.data))
		p.discard(s)
		if err != nil {
			p.closeFlow(f, err, true)
			p.mu.Unlock()
			return
		}
		if !f.udp && p.active != "" {
			p.acknowledge(p.paths[p.active][int(f.id%4)], f)
		}
		p.mu.Unlock()
	}
}

func (p *peer) close() error {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		p.cancel()
		for _, cs := range p.paths {
			for _, c := range cs {
				if c != nil {
					p.closeCarrier(c)
				}
			}
		}
		for _, f := range p.flows {
			p.closeFlow(f, ErrClosed, false)
		}
		p.controlBytes -= int64(len(p.closing)) * 128
		clear(p.closing)
	}
	p.mu.Unlock()
	p.wg.Wait()
	return nil
}

func (p *peer) snapshot() Snapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := Snapshot{
		SessionID:         p.session,
		Generation:        p.generation,
		PreferredPath:     p.preferred,
		ActivePath:        p.active,
		Paths:             []PathSnapshot{},
		ControlQueueBytes: p.controlBytes,
		ReplayedFrames:    p.replayed,
		ExpiredUDP:        p.expired,
		DroppedUDP:        p.dropped,
		Switches:          p.switches,
		LastSwitchPauseMS: float64(p.pause) / float64(time.Millisecond),
		Status:            "Degraded",
		DegradedReason:    "Path pair has not passed the 100 ms / 100 Mbit/s qualification profile",
	}
	for _, f := range p.flows {
		if f.udp {
			s.UDPFlows++
		} else {
			s.TCPFlows++
		}
	}
	for d := range p.used {
		for k, n := range p.used[d] {
			s.QueueBytes += n
			if k == 1 {
				s.UDPQueueBytes += n
			}
		}
	}
	names := make([]string, 0, len(p.paths))
	for name := range p.paths {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ps := PathSnapshot{Name: name, Ready: p.ready(name), Carriers: []CarrierSnapshot{}}
		for i, c := range p.paths[name] {
			cs := CarrierSnapshot{Index: i, Kind: "tcp"}
			if i == 4 {
				cs.Kind = "udp"
			}
			if i == 5 {
				cs.Kind = "control"
			}
			if c != nil {
				cs.Ready = !c.closed
				cs.SRTTMS = float64(c.srtt) / float64(time.Millisecond)
				cs.RTOMS = float64(c.rto()) / float64(time.Millisecond)
			}
			ps.Carriers = append(ps.Carriers, cs)
		}
		s.Paths = append(s.Paths, ps)
		if name != p.active && ps.Ready {
			s.StandbyPath = name
		}
	}
	if p.active == "" {
		s.Status = "Disconnected"
		s.DegradedReason = "No fully connected relay path"
	} else if s.StandbyPath == "" {
		s.DegradedReason = "Hot standby is not ready"
	}
	if p.terminalErr != nil {
		s.Status = "Disconnected"
		s.DegradedReason = "relay_generation_lost"
	}
	return s
}

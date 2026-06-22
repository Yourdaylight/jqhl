package mux

import (
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type window struct {
	maxSizeDone uint64
	// 64bit alignment
	// maxSizeDone contains 4 parts
	//   1       31       1      31
	// wait   maxSize  useless  done
	// wait zero means false, one means true
	off       uint32
	closeOp   uint32
	closeOpCh chan struct{}
	mux       *Mux
}

const windowBits = 31

const waitBits = dequeueBits + windowBits

const mask1 = 1

const mask31 = 1<<windowBits - 1

func (Self *window) unpack(ptrs uint64) (maxSize, done uint32, wait bool) {
	maxSize = uint32((ptrs >> dequeueBits) & mask31)
	done = uint32(ptrs & mask31)
	if ((ptrs >> waitBits) & mask1) == 1 {
		wait = true
		return
	}
	return
}

func (Self *window) pack(maxSize, done uint32, wait bool) uint64 {
	if wait {
		return (uint64(1)<<waitBits |
			uint64(maxSize&mask31)<<dequeueBits) |
			uint64(done&mask31)
	}
	return (uint64(0)<<waitBits |
		uint64(maxSize&mask31)<<dequeueBits) |
		uint64(done&mask31)
}

func (Self *window) New() {
	Self.closeOpCh = make(chan struct{})
}

func (Self *window) IsClosed() bool {
	return atomic.LoadUint32(&Self.closeOp) == 1
}

func (Self *window) CloseWindow() {
	if atomic.CompareAndSwapUint32(&Self.closeOp, 0, 1) {
		if Self.closeOpCh != nil {
			close(Self.closeOpCh)
		}
	}
}

type writeBandwidth struct {
	writeBW   uint64 // store in bits, but it's float64
	readEnd   time.Time
	duration  float64
	bufLength uint32
	ratio     uint32
}

const writeCalcThreshold uint32 = 5 * 1024 * 1024

func newWriteBandwidth() *writeBandwidth {
	return &writeBandwidth{ratio: 1}
}

func (Self *writeBandwidth) StartRead() {
	if Self.readEnd.IsZero() {
		Self.readEnd = time.Now()
	}
	Self.duration += time.Since(Self.readEnd).Seconds()
	if Self.bufLength >= writeCalcThreshold*atomic.LoadUint32(&Self.ratio) {
		Self.calcBandWidth()
	}
}

func (Self *writeBandwidth) SetCopySize(n uint16) {
	Self.bufLength += uint32(n)
	Self.endRead()
}

func (Self *writeBandwidth) endRead() {
	Self.readEnd = time.Now()
}

func (Self *writeBandwidth) calcBandWidth() {
	atomic.StoreUint64(&Self.writeBW, math.Float64bits(float64(Self.bufLength)/Self.duration))
	Self.bufLength = 0
	Self.duration = 0
}

func (Self *writeBandwidth) Get() (bw float64) {
	bw = math.Float64frombits(atomic.LoadUint64(&Self.writeBW))
	if bw <= 0 {
		bw = 0
	}
	return
}

func (Self *writeBandwidth) GrowRatio() {
	atomic.AddUint32(&Self.ratio, 1)
}

type timeoutError struct {
	msg string
}

func (e timeoutError) Error() string { return e.msg }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

var (
	errReceiveWindowTimeout net.Error = timeoutError{msg: "mux.queue: read time out"}
	errSendWindowTimeout    net.Error = timeoutError{msg: "conn.writeWindow: write to time out"}
)

func notifySignal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func stopTimer(t *time.Timer) {
	if t == nil {
		return
	}
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}

// Conn is a logical stream carried by a Mux.
type Conn struct {
	net.Conn
	connStatusOkCh    chan struct{}
	connStatusFailCh  chan struct{}
	connId            int32
	priority          bool
	isClose           uint32
	closingFlag       uint32 // closing Conn flag
	writeClosed       uint32
	remoteWriteClosed uint32
	receiveWindow     *receiveWindow
	sendWindow        *sendWindow
	readMu            sync.Mutex
	writeMu           sync.Mutex
	once              sync.Once
}

// NewConn constructs a logical stream bound to mux.
//
// Deprecated: this is a low-level constructor kept for compatibility. External
// callers should prefer Mux.NewConn.
func NewConn(connId int32, mux *Mux) *Conn {
	c := &Conn{
		connStatusOkCh:   make(chan struct{}, 1),
		connStatusFailCh: make(chan struct{}, 1),
		connId:           connId,
		priority:         false,
		receiveWindow:    new(receiveWindow),
		sendWindow:       new(sendWindow),
		once:             sync.Once{},
	}
	c.receiveWindow.New(mux)
	c.sendWindow.New(mux)
	return c
}

func (s *Conn) SetPriority() {
	if s == nil {
		return
	}
	s.priority = true
	s.sendWindow.priority = true
	s.receiveWindow.priority = true
}

func (s *Conn) Read(buf []byte) (n int, err error) {
	if s == nil || s.receiveWindow == nil {
		return 0, net.ErrClosed
	}
	if len(buf) == 0 {
		return 0, nil
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if s.IsClosed() {
		return 0, errors.New("the conn has closed")
	}
	n, err = s.receiveWindow.Read(buf, s.connId)
	if err == io.EOF && atomic.LoadUint32(&s.writeClosed) == 1 && atomic.LoadUint32(&s.remoteWriteClosed) == 1 {
		s.closeLocal()
	}
	return
}

func (s *Conn) Write(buf []byte) (n int, err error) {
	if s == nil || s.sendWindow == nil {
		return 0, net.ErrClosed
	}
	if len(buf) == 0 {
		return 0, nil
	}
	if s.IsClosed() {
		return 0, errors.New("the conn has closed")
	}
	if atomic.LoadUint32(&s.closingFlag) == 1 || atomic.LoadUint32(&s.writeClosed) == 1 {
		return 0, errors.New("io: write on closed conn")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	n, err = s.sendWindow.WriteFull(buf, s.connId)
	return
}

func (s *Conn) IsClosed() bool {
	if s == nil {
		return true
	}
	return atomic.LoadUint32(&s.isClose) == 1
}

func (s *Conn) SetClosingFlag() {
	if s == nil {
		return
	}
	atomic.StoreUint32(&s.closingFlag, 1)
}

func (s *Conn) markRemoteWriteClosed() {
	atomic.StoreUint32(&s.remoteWriteClosed, 1)
}

func (s *Conn) CloseWrite() error {
	if s == nil || s.receiveWindow == nil || s.sendWindow == nil {
		return net.ErrClosed
	}
	if s.IsClosed() {
		return errors.New("the conn has closed")
	}
	if !s.receiveWindow.mux.supportsRemoteCapability(capabilityCloseWrite) {
		return s.Close()
	}
	if !atomic.CompareAndSwapUint32(&s.writeClosed, 0, 1) {
		return nil
	}
	s.sendWindow.CloseWindow()
	if !s.receiveWindow.mux.IsClosed() {
		s.receiveWindow.mux.sendInfo(muxConnCloseWrite, s.connId, s.priority, nil)
	}
	return nil
}

func (s *Conn) Close() (err error) {
	if s == nil {
		return nil
	}
	s.once.Do(func() {
		s.closeProcess(true)
	})
	return
}

func (s *Conn) closeLocal() {
	if s == nil {
		return
	}
	s.once.Do(func() {
		s.closeProcess(false)
	})
}

func (s *Conn) closeProcess(notifyRemote bool) {
	if s == nil || s.receiveWindow == nil || s.sendWindow == nil || s.receiveWindow.mux == nil {
		return
	}
	atomic.StoreUint32(&s.isClose, 1)
	atomic.StoreUint32(&s.closingFlag, 1)
	atomic.StoreUint32(&s.writeClosed, 1)
	s.receiveWindow.mux.connMap.Delete(s.connId)
	if notifyRemote && !s.receiveWindow.mux.IsClosed() {
		s.receiveWindow.mux.sendInfo(muxConnClose, s.connId, s.priority, nil)
	}
	s.sendWindow.CloseWindow()
	s.readMu.Lock()
	s.receiveWindow.CloseWindow()
	s.readMu.Unlock()
}

func (s *Conn) LocalAddr() net.Addr {
	if s == nil || s.receiveWindow == nil || s.receiveWindow.mux == nil || s.receiveWindow.mux.conn == nil {
		return nil
	}
	return s.receiveWindow.mux.conn.LocalAddr()
}

func (s *Conn) RemoteAddr() net.Addr {
	if s == nil || s.receiveWindow == nil || s.receiveWindow.mux == nil || s.receiveWindow.mux.conn == nil {
		return nil
	}
	return s.receiveWindow.mux.conn.RemoteAddr()
}

func (s *Conn) SetDeadline(t time.Time) error {
	if err := s.SetReadDeadline(t); err != nil {
		return err
	}
	return s.SetWriteDeadline(t)
}

func (s *Conn) SetReadDeadline(t time.Time) error {
	if s == nil || s.receiveWindow == nil {
		return net.ErrClosed
	}
	s.receiveWindow.SetTimeOut(t)
	return nil
}

func (s *Conn) SetWriteDeadline(t time.Time) error {
	if s == nil || s.sendWindow == nil {
		return net.ErrClosed
	}
	s.sendWindow.SetTimeOut(t)
	return nil
}

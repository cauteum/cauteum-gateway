package sshrelay

import (
	"io"
	"net"
	"sync"
	"time"
)

// halfPipeConn is an in-memory duplex connection whose write side can be
// closed independently. It is used to represent OpenShell gRPC relay streams,
// where client CloseSend maps to TCP FIN while response bytes remain readable.
type halfPipeConn struct {
	reader   *io.PipeReader
	writer   *io.PipeWriter
	once     sync.Once
	mu       sync.Mutex
	timer    *time.Timer
	closed   bool
	timedOut bool
}

func newHalfPipePair() (*halfPipeConn, *halfPipeConn) {
	aToBReader, aToBWriter := io.Pipe()
	bToAReader, bToAWriter := io.Pipe()
	return &halfPipeConn{reader: bToAReader, writer: aToBWriter}, &halfPipeConn{reader: aToBReader, writer: bToAWriter}
}

func (c *halfPipeConn) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	if c.hasTimedOut() {
		return n, relayPipeTimeout{}
	}
	return n, err
}

func (c *halfPipeConn) Write(p []byte) (int, error) {
	n, err := c.writer.Write(p)
	if c.hasTimedOut() {
		return n, relayPipeTimeout{}
	}
	return n, err
}

// CloseWrite sends EOF to the peer's Read while preserving this side's Read.
func (c *halfPipeConn) CloseWrite() error { return c.writer.Close() }

func (c *halfPipeConn) Close() error {
	var readErr, writeErr error
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		if c.timer != nil {
			c.timer.Stop()
		}
		c.mu.Unlock()
		readErr = c.reader.Close()
		writeErr = c.writer.Close()
	})
	if readErr != nil {
		return readErr
	}
	return writeErr
}

func (*halfPipeConn) LocalAddr() net.Addr  { return relayPipeAddr("local") }
func (*halfPipeConn) RemoteAddr() net.Addr { return relayPipeAddr("remote") }

func (c *halfPipeConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.timedOut = false
	if !deadline.IsZero() {
		delay := time.Until(deadline)
		if delay <= 0 {
			c.timedOut = true
			c.closed = true
			go c.closeUnderlying()
		} else {
			c.timer = time.AfterFunc(delay, func() {
				c.mu.Lock()
				c.timedOut = true
				c.closed = true
				c.mu.Unlock()
				c.closeUnderlying()
			})
		}
	}
	return nil
}

func (c *halfPipeConn) SetReadDeadline(deadline time.Time) error  { return c.SetDeadline(deadline) }
func (c *halfPipeConn) SetWriteDeadline(deadline time.Time) error { return c.SetDeadline(deadline) }

func (c *halfPipeConn) closeUnderlying() {
	_ = c.reader.Close()
	_ = c.writer.Close()
}

func (c *halfPipeConn) hasTimedOut() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.timedOut
}

type relayPipeTimeout struct{}

func (relayPipeTimeout) Error() string   { return "relay pipe deadline exceeded" }
func (relayPipeTimeout) Timeout() bool   { return true }
func (relayPipeTimeout) Temporary() bool { return true }

var _ net.Conn = (*halfPipeConn)(nil)

type relayPipeAddr string

func (a relayPipeAddr) Network() string { return "relaypipe" }
func (a relayPipeAddr) String() string  { return string(a) }

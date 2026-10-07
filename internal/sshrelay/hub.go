// Package sshrelay tracks live supervisor sessions and opens per-request byte
// relays into sandboxes (OpenShell supervisor relay). The gateway never dials a
// sandbox: supervisors connect out, and each channel is a fresh outbound data
// stream paired with a waiting client.
package sshrelay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/whaleshell/whaleshell-core/relayproto"
)

// ErrNotConnected means the sandbox supervisor has no live control stream.
var ErrNotConnected = errors.New("sandbox is not ready: supervisor relay not connected")

// ErrOpenTimeout means the supervisor did not dial back the data stream in time.
var ErrOpenTimeout = errors.New("supervisor relay did not open the channel in time")

const defaultOpenTimeout = 10 * time.Second

// Hub is safe for concurrent use.
type Hub struct {
	OpenTimeout       time.Duration
	KeepaliveInterval time.Duration
	KeepaliveTimeout  time.Duration
	Log               *slog.Logger

	mu       sync.Mutex
	sessions map[string]*session
	pending  map[string]*pending
}

type session struct {
	sandbox    string
	instanceID string
	conn       net.Conn
	w          *relayproto.MessageWriter
	open       func(channel, target string) error
	closeFn    func()
	done       chan struct{}
	once       sync.Once
}

func (s *session) close() {
	s.once.Do(func() {
		close(s.done)
		if s.conn != nil {
			_ = s.conn.Close()
		}
		if s.closeFn != nil {
			s.closeFn()
		}
	})
}

// RegisterOpenShellSupervisor registers a control stream backed by OpenShell
// ConnectSupervisor. The callback must enqueue a RelayOpen on that stream.
// The returned function unregisters this exact session (safe after replacement).
func (h *Hub) RegisterOpenShellSupervisor(sandbox, instanceID string, open func(channel, target string) error, done <-chan struct{}, closeFn func()) func() {
	s := &session{sandbox: sandbox, instanceID: instanceID, open: open, closeFn: closeFn, done: make(chan struct{})}
	h.mu.Lock()
	prev := h.sessions[sandbox]
	h.sessions[sandbox] = s
	h.mu.Unlock()
	if prev != nil {
		prev.close()
	}
	go func() {
		select {
		case <-done:
			s.close()
		case <-s.done:
		}
	}()
	return func() {
		h.mu.Lock()
		if h.sessions[sandbox] == s {
			delete(h.sessions, sandbox)
		}
		h.mu.Unlock()
		s.close()
	}
}

// OpenShellSupervisorInstance returns the instance ID for the currently
// connected pinned OpenShell control stream.
func (h *Hub) OpenShellSupervisorInstance(sandbox string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.sessions[sandbox]
	if !ok || s.instanceID == "" {
		return "", false
	}
	return s.instanceID, true
}

// AcceptOpenShellRelay claims a pending channel and returns the stream side of
// a byte pipe. OpenChannel receives the other side after the claim succeeds.
func (h *Hub) AcceptOpenShellRelay(sandbox, channel string) (net.Conn, error) {
	h.mu.Lock()
	p := h.pending[channel]
	if p == nil || p.sandbox != sandbox {
		h.mu.Unlock()
		return nil, ErrOpenTimeout
	}
	delete(h.pending, channel)
	h.mu.Unlock()
	client, stream := newHalfPipePair()
	select {
	case p.ready <- client:
		return stream, nil
	default:
		_ = client.Close()
		_ = stream.Close()
		return nil, ErrOpenTimeout
	}
}

type pending struct {
	sandbox string
	ready   chan net.Conn
	failed  chan error
}

// RejectOpenShellRelay completes a pending OpenChannel request when the
// supervisor rejects the requested target.
func (h *Hub) RejectOpenShellRelay(sandbox, channel string, cause error) {
	h.mu.Lock()
	p := h.pending[channel]
	if p != nil && p.sandbox == sandbox {
		delete(h.pending, channel)
	} else {
		p = nil
	}
	h.mu.Unlock()
	if p != nil {
		if cause == nil {
			cause = ErrNotConnected
		}
		select {
		case p.failed <- cause:
		default:
		}
	}
}

// NewHub returns a hub with OpenShell-aligned keepalive defaults.
func NewHub() *Hub {
	return &Hub{
		OpenTimeout:       defaultOpenTimeout,
		KeepaliveInterval: relayproto.KeepaliveInterval,
		KeepaliveTimeout:  relayproto.KeepaliveTimeout,
		sessions:          map[string]*session{},
		pending:           map[string]*pending{},
	}
}

func (h *Hub) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

// Connected reports whether sandbox has a live supervisor control stream.
func (h *Hub) Connected(sandbox string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.sessions[sandbox]
	return ok
}

// WaitConnected blocks until the sandbox supervisor has registered its control
// stream. A running container alone is not sufficient readiness for relay RPCs.
func (h *Hub) WaitConnected(ctx context.Context, sandbox string, timeout time.Duration) error {
	if h == nil {
		return ErrNotConnected
	}
	if timeout <= 0 {
		timeout = defaultOpenTimeout
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if h.Connected(sandbox) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return ErrNotConnected
		case <-ticker.C:
		}
	}
}

// Disconnect drops the supervisor session for sandbox (e.g. on delete).
func (h *Hub) Disconnect(sandbox string) {
	h.mu.Lock()
	s := h.sessions[sandbox]
	delete(h.sessions, sandbox)
	h.mu.Unlock()
	if s != nil {
		s.close()
	}
}

// ServeSupervisor upgrades r into the control stream for an already
// authenticated sandbox and blocks until the stream ends.
func (h *Hub) ServeSupervisor(w http.ResponseWriter, r *http.Request, sandbox string) {
	conn, err := relayproto.Accept(w, r)
	if err != nil {
		return
	}
	s := &session{sandbox: sandbox, conn: conn, w: relayproto.NewMessageWriter(conn), done: make(chan struct{})}
	h.mu.Lock()
	prev := h.sessions[sandbox]
	h.sessions[sandbox] = s
	h.mu.Unlock()
	if prev != nil {
		prev.close()
	}
	log := h.log().With(slog.String("op", "gateway.relay.supervisor"), slog.String("sandbox", sandbox))
	log.Info("supervisor connected")
	defer func() {
		h.mu.Lock()
		if h.sessions[sandbox] == s {
			delete(h.sessions, sandbox)
		}
		h.mu.Unlock()
		s.close()
		log.Info("supervisor disconnected")
	}()

	seen := make(chan struct{}, 1)
	go func() {
		rd := relayproto.NewMessageReader(conn)
		for {
			m, err := rd.Read()
			if err != nil {
				s.close()
				return
			}
			if m.Type == relayproto.MsgPong || m.Type == relayproto.MsgHello {
				select {
				case seen <- struct{}{}:
				default:
				}
			}
		}
	}()

	tick := time.NewTicker(h.KeepaliveInterval)
	defer tick.Stop()
	last := time.Now()
	for {
		select {
		case <-s.done:
			return
		case <-r.Context().Done():
			return
		case <-seen:
			last = time.Now()
		case <-tick.C:
			if time.Since(last) > h.KeepaliveTimeout {
				log.Warn("supervisor keepalive timeout")
				return
			}
			if err := s.w.Write(relayproto.Message{Type: relayproto.MsgPing}); err != nil {
				return
			}
		}
	}
}

// OpenChannel asks the sandbox supervisor for a new data stream to target and
// returns it once the supervisor dials back.
func (h *Hub) OpenChannel(ctx context.Context, sandbox, target string) (net.Conn, error) {
	id, err := newChannelID()
	if err != nil {
		return nil, err
	}
	p := &pending{sandbox: sandbox, ready: make(chan net.Conn, 1), failed: make(chan error, 1)}
	h.mu.Lock()
	s := h.sessions[sandbox]
	if s == nil {
		h.mu.Unlock()
		return nil, ErrNotConnected
	}
	h.pending[id] = p
	h.mu.Unlock()
	delivered := false
	defer func() {
		h.mu.Lock()
		delete(h.pending, id)
		h.mu.Unlock()
		if !delivered {
			select {
			case c := <-p.ready:
				_ = c.Close()
			default:
			}
		}
	}()
	var openErr error
	if s.open != nil {
		openErr = s.open(id, target)
	} else {
		openErr = s.w.Write(relayproto.Message{Type: relayproto.MsgOpen, Channel: id, Target: target})
	}
	if openErr != nil {
		s.close()
		return nil, ErrNotConnected
	}
	timeout := h.OpenTimeout
	if timeout <= 0 {
		timeout = defaultOpenTimeout
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case c := <-p.ready:
		delivered = true
		return c, nil
	case err := <-p.failed:
		return nil, err
	case <-s.done:
		return nil, ErrNotConnected
	case <-t.C:
		return nil, ErrOpenTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ServeRelay upgrades the supervisor data stream for channel and hands it to
// the waiting OpenChannel caller. The channel must belong to sandbox.
func (h *Hub) ServeRelay(w http.ResponseWriter, r *http.Request, sandbox, channel string) {
	h.mu.Lock()
	p := h.pending[channel]
	if p != nil && p.sandbox == sandbox {
		delete(h.pending, channel)
	} else {
		p = nil
	}
	h.mu.Unlock()
	if p == nil {
		http.Error(w, "unknown relay channel", http.StatusNotFound)
		return
	}
	conn, err := relayproto.Accept(w, r)
	if err != nil {
		return
	}
	select {
	case p.ready <- conn:
	default:
		_ = conn.Close()
	}
}

func newChannelID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Bridge pipes client <-> supervisor until both sides finish.
func Bridge(client, supervisor io.ReadWriteCloser) {
	relayproto.Pipe(client, supervisor)
}

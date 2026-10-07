// Package logbuf is an in-memory ring buffer of sandbox observation log lines
// (OpenShell-style gateway-buffered WatchSandbox / SSE).
package logbuf

import (
	"sync"
	"time"
)

// Line is one observation log entry.
type Line struct {
	Sequence uint64            `json:"-"`
	TS       time.Time         `json:"ts"`
	Source   string            `json:"source"` // proxy | sandbox | proc | gateway
	Level    string            `json:"level"`  // INFO | MED | HIGH | OCSF | …
	Target   string            `json:"target,omitempty"`
	Text     string            `json:"text"`
	Fields   map[string]string `json:"fields,omitempty"`
}

// Buffer is a bounded per-sandbox ring (drop oldest under load).
type Buffer struct {
	mu       sync.Mutex
	max      int
	lines    []Line
	waiters  []chan struct{}
	watchers map[chan struct{}]struct{}
	sequence uint64
}

// Hub maps sandbox name → Buffer.
type Hub struct {
	mu      sync.Mutex
	max     int
	buffers map[string]*Buffer
}

// NewHub creates a hub with per-sandbox capacity max (default 4096).
func NewHub(max int) *Hub {
	if max <= 0 {
		max = 4096
	}
	return &Hub{max: max, buffers: map[string]*Buffer{}}
}

func (h *Hub) buf(name string) *Buffer {
	h.mu.Lock()
	defer h.mu.Unlock()
	b, ok := h.buffers[name]
	if !ok {
		b = &Buffer{max: h.max, watchers: map[chan struct{}]struct{}{}}
		h.buffers[name] = b
	}
	return b
}

// Append adds lines for a sandbox.
func (h *Hub) Append(sandbox string, lines []Line) {
	if sandbox == "" || len(lines) == 0 {
		return
	}
	h.buf(sandbox).append(lines)
}

// Snapshot returns a copy of recent lines (optionally filtered).
func (h *Hub) Snapshot(sandbox string, since time.Time, source, level string, limit int) []Line {
	return h.buf(sandbox).snapshot(since, source, level, limit)
}

// Subscribe returns a channel closed when new lines arrive; call again after drain.
func (h *Hub) Subscribe(sandbox string) <-chan struct{} {
	return h.buf(sandbox).subscribe()
}

// Watch subscribes to persistent edge notifications. The returned cancel
// function must be called when the consumer exits.
func (h *Hub) Watch(sandbox string) (<-chan struct{}, func()) {
	b := h.buf(sandbox)
	ch := make(chan struct{}, 1)
	b.mu.Lock()
	b.watchers[ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.watchers, ch)
		b.mu.Unlock()
	}
}

// Tail returns the newest lines and the current sequence cursor atomically.
func (h *Hub) Tail(sandbox string, limit int) ([]Line, uint64) {
	return h.buf(sandbox).tail(limit)
}

// After returns buffered lines appended after sequence.
func (h *Hub) After(sandbox string, sequence uint64) []Line {
	return h.buf(sandbox).after(sequence)
}

// Names returns sandboxes that have any buffered lines.
func (h *Hub) Names() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, 0, len(h.buffers))
	for k := range h.buffers {
		out = append(out, k)
	}
	return out
}

// Remove drops the ring buffer for a sandbox (call on sandbox delete).
// OpenShell TracingLogBus.remove cleans the same way; without this, deleted
// names keep up to max lines in gateway RSS until process restart.
func (h *Hub) Remove(sandbox string) {
	if h == nil || sandbox == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.buffers, sandbox)
}

func (b *Buffer) append(lines []Line) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ln := range lines {
		b.sequence++
		ln.Sequence = b.sequence
		if ln.TS.IsZero() {
			ln.TS = time.Now().UTC()
		}
		b.lines = append(b.lines, ln)
	}
	if len(b.lines) > b.max {
		b.lines = append([]Line{}, b.lines[len(b.lines)-b.max:]...)
	}
	for _, ch := range b.waiters {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	b.waiters = nil
	for ch := range b.watchers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (b *Buffer) tail(limit int) ([]Line, uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	start := 0
	if limit > 0 && len(b.lines) > limit {
		start = len(b.lines) - limit
	}
	return append([]Line(nil), b.lines[start:]...), b.sequence
}

func (b *Buffer) after(sequence uint64) []Line {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []Line
	for _, line := range b.lines {
		if line.Sequence > sequence {
			out = append(out, line)
		}
	}
	return out
}

func (b *Buffer) subscribe() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan struct{}, 1)
	b.waiters = append(b.waiters, ch)
	return ch
}

func (b *Buffer) snapshot(since time.Time, source, level string, limit int) []Line {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []Line
	for _, ln := range b.lines {
		if !since.IsZero() && ln.TS.Before(since) {
			continue
		}
		if source != "" && ln.Source != source {
			continue
		}
		if level != "" && !levelMatch(ln.Level, level) {
			continue
		}
		out = append(out, ln)
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return append([]Line{}, out...)
}

func levelMatch(got, want string) bool {
	if got == want {
		return true
	}
	// warn matches MED/HIGH style shorthand
	switch want {
	case "warn", "warning":
		return got == "MED" || got == "WARN" || got == "HIGH"
	case "error":
		return got == "HIGH" || got == "CRIT" || got == "FATAL" || got == "ERROR"
	case "debug", "info":
		return got == "INFO" || got == "LOW" || got == "OCSF" || got == ""
	}
	return false
}

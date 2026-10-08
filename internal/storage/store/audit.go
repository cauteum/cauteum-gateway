package store

import (
	"fmt"
	"slices"
	"time"
)

const MaxAuditEvents = 2048

// AuditEvent records a security decision without request bodies, tokens or
// backend error text. IDs remain monotonic across gateway restarts.
type AuditEvent struct {
	ID        uint64    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Workspace string    `json:"workspace,omitempty"`
	Sandbox   string    `json:"sandbox,omitempty"`
	Outcome   string    `json:"outcome"`
	Code      string    `json:"code,omitempty"`
}

// AppendAuditEvent writes one bounded, durable audit entry. The caller must
// provide only safe categorical fields; arbitrary detail is intentionally
// excluded from the schema.
func (s *Store) AppendAuditEvent(event AuditEvent) (AuditEvent, error) {
	if len(event.Actor) > 256 || len(event.Action) > 64 || len(event.Workspace) > 128 || len(event.Sandbox) > 128 || len(event.Outcome) > 32 || len(event.Code) > 64 || event.Actor == "" || event.Action == "" || event.Outcome == "" {
		return AuditEvent{}, fmt.Errorf("invalid audit event")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := slices.Clone(s.state.AuditEvents)
	previousID := s.state.AuditNextID
	if previousID == ^uint64(0) {
		return AuditEvent{}, fmt.Errorf("audit event id overflow")
	}
	s.state.AuditNextID++
	event.ID = s.state.AuditNextID
	event.Timestamp = time.Now().UTC()
	s.state.AuditEvents = append(s.state.AuditEvents, event)
	if len(s.state.AuditEvents) > MaxAuditEvents {
		s.state.AuditEvents = slices.Clone(s.state.AuditEvents[len(s.state.AuditEvents)-MaxAuditEvents:])
	}
	if err := s.flushLocked(); err != nil {
		s.state.AuditEvents = previous
		s.state.AuditNextID = previousID
		return AuditEvent{}, err
	}
	return event, nil
}

// ListAuditEvents returns a bounded ascending page; after is an exclusive ID.
func (s *Store) ListAuditEvents(after uint64, limit int) []AuditEvent {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AuditEvent, 0, limit)
	for _, event := range s.state.AuditEvents {
		if event.ID <= after {
			continue
		}
		out = append(out, event)
		if len(out) == limit {
			break
		}
	}
	return out
}

// ListAuditEventsWorkspace filters before pagination to avoid gaps caused by
// audit entries from other workspaces.
func (s *Store) ListAuditEventsWorkspace(workspace string, after uint64, limit int) []AuditEvent {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AuditEvent, 0, limit)
	for _, event := range s.state.AuditEvents {
		if event.Workspace != workspace || event.ID <= after {
			continue
		}
		out = append(out, event)
		if len(out) == limit {
			break
		}
	}
	return out
}

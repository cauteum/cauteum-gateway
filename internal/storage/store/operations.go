package store

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
)

const MaxOperations = 2048

const (
	OperationRunning   = "running"
	OperationSucceeded = "succeeded"
	OperationFailed    = "failed"
	OperationUncertain = "uncertain"
)

var (
	ErrOperationConflict = errors.New("operation request id reused with different input")
	ErrOperationFull     = errors.New("operation history is full")
	ErrOperationNotFound = errors.New("operation not found")
	ErrOperationInvalid  = errors.New("invalid operation input")
)

// Operation is a durable record of one client action. Fingerprint is a hash
// of the normalized request; request bodies and backend errors are not stored.
type Operation struct {
	ID                    string    `json:"id"`
	Number                uint64    `json:"number"`
	RequestID             string    `json:"request_id"`
	Actor                 string    `json:"actor"`
	Workspace             string    `json:"workspace"`
	Sandbox               string    `json:"sandbox"`
	Action                string    `json:"action"`
	Fingerprint           string    `json:"fingerprint"`
	State                 string    `json:"state"`
	ErrorCode             string    `json:"error_code,omitempty"`
	ResultRegistryStatus  string    `json:"result_registry_status,omitempty"`
	ResultResourceVersion uint64    `json:"result_resource_version,omitempty"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

func validOperationRequestID(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

// BeginOperation reserves a request ID for an actor/workspace before runtime
// side effects. Replaying identical input returns the existing operation.
func (s *Store) BeginOperation(input Operation) (Operation, bool, error) {
	if !validOperationRequestID(input.RequestID) || input.Actor == "" || len(input.Actor) > 256 || input.Workspace == "" || len(input.Workspace) > 128 || input.Sandbox == "" || len(input.Sandbox) > 128 || input.Action == "" || len(input.Action) > 64 || len(input.Fingerprint) != 64 {
		return Operation{}, false, ErrOperationInvalid
	}
	for _, r := range input.Fingerprint {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return Operation{}, false, ErrOperationInvalid
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.state.Operations {
		if existing.Actor != input.Actor || existing.Workspace != input.Workspace || existing.RequestID != input.RequestID {
			continue
		}
		if existing.Action != input.Action || existing.Sandbox != input.Sandbox || existing.Fingerprint != input.Fingerprint {
			return Operation{}, false, ErrOperationConflict
		}
		return existing, false, nil
	}
	previous := maps.Clone(s.state.Operations)
	previousID := s.state.OperationNextID
	if len(s.state.Operations) >= MaxOperations {
		oldestID := ""
		oldestNumber := ^uint64(0)
		for id, operation := range s.state.Operations {
			if operation.State != OperationRunning && operation.Number < oldestNumber {
				oldestID, oldestNumber = id, operation.Number
			}
		}
		if oldestID == "" {
			return Operation{}, false, ErrOperationFull
		}
		delete(s.state.Operations, oldestID)
	}
	if s.state.OperationNextID == ^uint64(0) {
		return Operation{}, false, fmt.Errorf("operation id overflow")
	}
	s.state.OperationNextID++
	input.ID = fmt.Sprintf("op-%016x", s.state.OperationNextID)
	input.Number = s.state.OperationNextID
	input.State = OperationRunning
	input.ErrorCode = ""
	input.ResultRegistryStatus = ""
	input.ResultResourceVersion = 0
	input.CreatedAt = time.Now().UTC()
	input.UpdatedAt = input.CreatedAt
	s.state.Operations[input.ID] = input
	if err := s.flushLocked(); err != nil {
		s.state.Operations = previous
		s.state.OperationNextID = previousID
		return Operation{}, false, err
	}
	return input, true, nil
}

// FinishOperation records a known result. uncertain means the caller must
// reconcile the sandbox's current state before a new attempt.
func (s *Store) FinishOperation(id, state, code, registryStatus string, version uint64) (Operation, error) {
	if state != OperationSucceeded && state != OperationFailed && state != OperationUncertain || len(code) > 64 || len(registryStatus) > 64 {
		return Operation{}, ErrOperationInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, ok := s.state.Operations[id]
	if !ok {
		return Operation{}, ErrOperationNotFound
	}
	if previous.State != OperationRunning {
		if previous.State == state && previous.ErrorCode == code && previous.ResultRegistryStatus == registryStatus && previous.ResultResourceVersion == version {
			return previous, nil
		}
		return Operation{}, ErrOperationConflict
	}
	updated := previous
	updated.State = state
	updated.ErrorCode = code
	updated.ResultRegistryStatus = registryStatus
	updated.ResultResourceVersion = version
	updated.UpdatedAt = time.Now().UTC()
	s.state.Operations[id] = updated
	if err := s.flushLocked(); err != nil {
		s.state.Operations[id] = previous
		return Operation{}, err
	}
	return updated, nil
}

func (s *Store) GetOperation(id string) (Operation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation, ok := s.state.Operations[id]
	return operation, ok
}

func (s *Store) GetOperationByRequest(actor, workspace, requestID string) (Operation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, operation := range s.state.Operations {
		if operation.Actor == actor && operation.Workspace == workspace && operation.RequestID == requestID {
			return operation, true
		}
	}
	return Operation{}, false
}

// ListOperations returns a bounded ascending page after a numeric sequence.
func (s *Store) ListOperations(workspace string, after uint64, limit int) []Operation {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Operation, 0, len(s.state.Operations))
	for _, operation := range s.state.Operations {
		if operation.Workspace == workspace && operation.Number > after {
			out = append(out, operation)
		}
	}
	slices.SortFunc(out, func(a, b Operation) int {
		switch {
		case a.Number < b.Number:
			return -1
		case a.Number > b.Number:
			return 1
		default:
			return 0
		}
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

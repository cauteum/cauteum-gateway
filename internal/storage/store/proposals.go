// SPDX-FileCopyrightText: Copyright (c) 2026 cautem
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"fmt"
	"time"
)

// Proposal is one agent policy chunk awaiting human review (policy.local).
type Proposal struct {
	ID               string    `json:"id"`
	Sandbox          string    `json:"sandbox"`
	Status           string    `json:"status"` // pending|approved|rejected
	IntentSummary    string    `json:"intent_summary,omitempty"`
	RuleName         string    `json:"rule_name,omitempty"`
	RuleYAML         string    `json:"rule_yaml,omitempty"`
	RuleProtoJSON    string    `json:"rule_proto_json,omitempty"`
	Rationale        string    `json:"rationale,omitempty"`
	SecurityNotes    string    `json:"security_notes,omitempty"`
	Confidence       float32   `json:"confidence,omitempty"`
	ReviewToken      string    `json:"review_token,omitempty"`
	Hosts            []string  `json:"hosts,omitempty"`
	RejectionReason  string    `json:"rejection_reason,omitempty"`
	ValidationResult string    `json:"validation_result,omitempty"`
	SecurityFlagged  bool      `json:"security_flagged,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	DecidedAt        time.Time `json:"decided_at"`
}

// DeleteProposal removes one draft chunk.
func (s *Store) DeleteProposal(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.state.Proposals, id)
	s.state.UpdatedAt = time.Now().UTC()
	return s.flushLocked()
}

// PutProposal inserts or replaces a proposal for a sandbox.
func (s *Store) PutProposal(p Proposal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Proposals == nil {
		s.state.Proposals = map[string]Proposal{}
	}
	if p.ID == "" {
		return fmt.Errorf("proposal id required")
	}
	if p.Sandbox == "" {
		return fmt.Errorf("proposal sandbox required")
	}
	if p.Status == "" {
		p.Status = "pending"
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	s.state.Proposals[p.ID] = cloneProposal(p)
	s.state.UpdatedAt = time.Now().UTC()
	return s.flushLocked()
}

// GetProposal returns one proposal by id.
func (s *Store) GetProposal(id string) (Proposal, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.state.Proposals[id]
	return cloneProposal(p), ok
}

// ListProposals returns proposals, optionally filtered by sandbox/status.
func (s *Store) ListProposals(sandbox, status string) []Proposal {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Proposal, 0)
	for _, p := range s.state.Proposals {
		if sandbox != "" && p.Sandbox != sandbox {
			continue
		}
		if status != "" && p.Status != status {
			continue
		}
		// Older persisted proposals predate trusted risk classification. Treat
		// pending entries conservatively, even when their stored flag is false.
		if p.Status == "pending" {
			p.SecurityFlagged = true
		}
		out = append(out, cloneProposal(p))
	}
	return out
}

// DecideProposal sets approved/rejected.
func (s *Store) DecideProposal(id, status, reason string) (Proposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.state.Proposals[id]
	if !ok {
		return Proposal{}, fmt.Errorf("proposal not found")
	}
	if status != "approved" && status != "rejected" {
		return Proposal{}, fmt.Errorf("status must be approved|rejected")
	}
	p.Status = status
	p.RejectionReason = reason
	p.DecidedAt = time.Now().UTC()
	s.state.Proposals[id] = p
	s.state.UpdatedAt = time.Now().UTC()
	if err := s.flushLocked(); err != nil {
		return Proposal{}, err
	}
	return cloneProposal(p), nil
}

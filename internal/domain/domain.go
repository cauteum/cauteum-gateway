// Package domain holds control-plane entities (no I/O).
package domain

import "time"

// Sandbox is a registered sandbox record.
type Sandbox struct {
	Name      string
	ID        string
	Image     string
	Status    string
	UpdatedAt time.Time
}

// Provider is a provider profile attachment record.
type Provider struct {
	Name string
	Kind string
}

// Proposal is a policy change proposal awaiting approval.
type Proposal struct {
	ID     string
	Status string
}

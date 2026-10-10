package store

import (
	"fmt"
	"slices"
	"time"
)

// GlobalSandboxPolicy is the effective policy snapshot prepared for one
// sandbox before a global policy mutation is committed.
type GlobalSandboxPolicy struct {
	ResourceVersion uint64
	PolicyRevision  int
	YAML            string
}

// SetGlobalPolicyWithSandboxRevisionsIfRevision atomically stores a global
// policy and creates a pending, reportable policy revision for every sandbox.
// The complete sandbox snapshot must still match the caller's observed state.
func (s *Store) SetGlobalPolicyWithSandboxRevisionsIfRevision(yaml string, expected uint64, policies map[string]GlobalSandboxPolicy) (uint64, map[string]int, bool, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.GlobalPolicyRevision != expected {
		return s.state.GlobalPolicyRevision, nil, false, false, nil
	}
	if len(policies) != len(s.state.Sandboxes) {
		return s.state.GlobalPolicyRevision, nil, false, false, nil
	}
	for name, sandbox := range s.state.Sandboxes {
		candidate, ok := policies[name]
		if !ok || sandbox.ResourceVersion != candidate.ResourceVersion || sandbox.PolicyRev != candidate.PolicyRevision {
			return s.state.GlobalPolicyRevision, nil, false, false, nil
		}
	}
	if yaml == s.state.GlobalPolicyYAML {
		revisions := make(map[string]int, len(s.state.Sandboxes))
		for name, sandbox := range s.state.Sandboxes {
			revisions[name] = sandbox.PolicyRev
		}
		return s.state.GlobalPolicyRevision, revisions, true, false, nil
	}
	if s.state.GlobalPolicyRevision == ^uint64(0) || s.state.GlobalPolicyRevision >= uint64(int(^uint(0)>>1)) {
		return 0, nil, false, false, fmt.Errorf("global policy revision overflow")
	}
	for name, sandbox := range s.state.Sandboxes {
		if sandbox.ResourceVersion == ^uint64(0) || sandbox.PolicyRev == int(^uint(0)>>1) {
			return 0, nil, false, false, fmt.Errorf("sandbox %q policy revision overflow", name)
		}
		if policies[name].YAML == "" {
			return 0, nil, false, false, fmt.Errorf("sandbox %q effective policy is empty", name)
		}
	}

	previousGlobalYAML := s.state.GlobalPolicyYAML
	previousGlobalRevision := s.state.GlobalPolicyRevision
	previousGlobalHistory := clonePolicyRevisions(s.state.GlobalPolicyRevisions)
	previousSandboxes := make(map[string]Sandbox, len(s.state.Sandboxes))
	for name, sandbox := range s.state.Sandboxes {
		previousSandboxes[name] = cloneSandbox(sandbox)
	}

	now := time.Now().UTC()
	s.state.GlobalPolicyYAML = yaml
	s.state.GlobalPolicyRevision++
	globalRevision := s.state.GlobalPolicyRevision
	names := make([]string, 0, len(s.state.Sandboxes))
	for name := range s.state.Sandboxes {
		names = append(names, name)
	}
	slices.Sort(names)
	globalStatus := PolicyStatusPending
	if len(names) == 0 {
		globalStatus = PolicyStatusLoaded
	}
	for i := range s.state.GlobalPolicyRevisions {
		if s.state.GlobalPolicyRevisions[i].Status == PolicyStatusPending {
			s.state.GlobalPolicyRevisions[i].Status = PolicyStatusSuperseded
		}
	}
	s.state.GlobalPolicyRevisions = append(s.state.GlobalPolicyRevisions, PolicyRevision{
		Rev: int(globalRevision), UpdatedAt: now, Bytes: len(yaml), Status: globalStatus, YAML: yaml,
		ExpectedSandboxes: names, Cleared: yaml == "",
	})
	if globalStatus == PolicyStatusLoaded {
		s.state.GlobalPolicyRevisions[len(s.state.GlobalPolicyRevisions)-1].LoadedAt = now
	}
	if len(s.state.GlobalPolicyRevisions) > MaxPolicyRevisions {
		s.state.GlobalPolicyRevisions = s.state.GlobalPolicyRevisions[len(s.state.GlobalPolicyRevisions)-MaxPolicyRevisions:]
	}
	revisions := make(map[string]int, len(names))
	for _, name := range names {
		sandbox := s.state.Sandboxes[name]
		for i := range sandbox.PolicyRevisions {
			if sandbox.PolicyRevisions[i].GlobalRevision != 0 && sandbox.PolicyRevisions[i].Status == PolicyStatusPending {
				sandbox.PolicyRevisions[i].Status = PolicyStatusSuperseded
			}
		}
		sandbox.ResourceVersion++
		sandbox.PolicyRev++
		sandbox.UpdatedAt = now
		sandbox.PolicyRevisions = append(sandbox.PolicyRevisions, PolicyRevision{
			Rev: sandbox.PolicyRev, GlobalRevision: globalRevision, UpdatedAt: now,
			Bytes: len(policies[name].YAML), Status: PolicyStatusPending, YAML: policies[name].YAML,
		})
		if len(sandbox.PolicyRevisions) > MaxPolicyRevisions {
			sandbox.PolicyRevisions = sandbox.PolicyRevisions[len(sandbox.PolicyRevisions)-MaxPolicyRevisions:]
		}
		s.state.Sandboxes[name] = sandbox
		revisions[name] = sandbox.PolicyRev
	}
	if err := s.flushLocked(); err != nil {
		s.state.GlobalPolicyYAML = previousGlobalYAML
		s.state.GlobalPolicyRevision = previousGlobalRevision
		s.state.GlobalPolicyRevisions = previousGlobalHistory
		for name, sandbox := range previousSandboxes {
			s.state.Sandboxes[name] = sandbox
		}
		return 0, nil, false, false, err
	}
	return globalRevision, revisions, true, true, nil
}

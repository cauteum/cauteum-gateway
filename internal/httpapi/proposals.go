// SPDX-FileCopyrightText: Copyright (c) 2026 cauteum
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/cauteum/cauteum-core/policy"
	"github.com/cauteum/cauteum-gateway/internal/logger"
	"github.com/cauteum/cauteum-gateway/internal/storage/store"
	"github.com/cauteum/slogx"
	"gopkg.in/yaml.v3"
)

func handleSandboxProposals(w http.ResponseWriter, r *http.Request, st *store.Store, builtinDir, name, rest string) {
	rest = strings.Trim(rest, "/")
	switch {
	case rest == "" && r.Method == http.MethodGet:
		const op = "gateway.proposals.list"
		log := logger.FromContext(r.Context()).With(slog.String("op", op), slog.String("sandbox", name))
		status := r.URL.Query().Get("status")
		list := st.ListProposals(name, status)
		log.Info("listed proposals", slog.Int("count", len(list)), slog.String("status_filter", status))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"proposals": list})
	case rest == "" && r.Method == http.MethodPost:
		const op = "gateway.proposals.create"
		log := logger.FromContext(r.Context()).With(slog.String("op", op), slog.String("sandbox", name))
		log.Info("creating proposal")
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			log.Error("failed to read proposal body", slogx.Err(err))
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var p store.Proposal
		if err := json.Unmarshal(body, &p); err != nil {
			log.Error("failed to decode proposal", slogx.Err(err))
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		p.Sandbox = name
		// Every proposal can expand egress policy. The submitter's risk flag is
		// untrusted, so require an explicit operator override for bulk approval.
		p.SecurityFlagged = true
		if p.CreatedAt.IsZero() {
			p.CreatedAt = time.Now().UTC()
		}
		if p.Status == "" {
			p.Status = "pending"
		}
		if err := st.PutProposal(p); err != nil {
			log.Error("failed to store proposal", slogx.Err(err))
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Info("proposal created", slog.String("proposal_id", p.ID), slog.String("status", p.Status))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(p)
	case rest != "" && !strings.Contains(rest, "/") && r.Method == http.MethodGet:
		const op = "gateway.proposals.get"
		log := logger.FromContext(r.Context()).With(slog.String("op", op), slog.String("sandbox", name), slog.String("proposal_id", rest))
		p, ok := st.GetProposal(rest)
		if !ok || p.Sandbox != name {
			log.Info("proposal not found")
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		log.Info("proposal fetched", slog.String("status", p.Status))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(p)
	case strings.HasSuffix(rest, "/approve") && r.Method == http.MethodPost:
		id := strings.TrimSuffix(rest, "/approve")
		id = strings.Trim(id, "/")
		const op = "gateway.proposals.approve"
		log := logger.FromContext(r.Context()).With(slog.String("op", op), slog.String("sandbox", name), slog.String("proposal_id", id))
		log.Info("approving proposal")
		if err := approveProposal(st, builtinDir, name, id); err != nil {
			log.Error("failed to approve proposal", slogx.Err(err))
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		p, _ := st.GetProposal(id)
		log.Info("proposal approved")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(p)
	case strings.HasSuffix(rest, "/reject") && r.Method == http.MethodPost:
		id := strings.TrimSuffix(rest, "/reject")
		id = strings.Trim(id, "/")
		const op = "gateway.proposals.reject"
		log := logger.FromContext(r.Context()).With(slog.String("op", op), slog.String("sandbox", name), slog.String("proposal_id", id))
		log.Info("rejecting proposal")
		reason := ""
		var body struct {
			Reason string `json:"reason"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		reason = body.Reason
		p, err := st.DecideProposal(id, "rejected", reason)
		if err != nil {
			log.Error("failed to reject proposal", slogx.Err(err))
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if p.Sandbox != name {
			log.Info("proposal not found for sandbox")
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		log.Info("proposal rejected")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(p)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func approveProposal(st *store.Store, builtinDir, sandbox, id string) error {
	p, ok := st.GetProposal(id)
	if !ok || p.Sandbox != sandbox {
		return fmt.Errorf("proposal not found")
	}
	if p.Status == "approved" {
		return nil
	}
	sb, ok := st.GetSandbox(sandbox)
	if !ok {
		return fmt.Errorf("sandbox not found")
	}
	base := sb.BasePolicyYAML
	if strings.TrimSpace(base) == "" {
		base = "version: 1\nnetwork_policies: {}\n"
	}
	merged, err := mergeProposalYAML(base, p.RuleName, p.RuleYAML)
	if err != nil {
		return err
	}
	if _, _, err := setSandboxBasePolicy(st, builtinDir, sandbox, []byte(merged)); err != nil {
		return err
	}
	_, err = st.DecideProposal(id, "approved", "")
	return err
}

func mergeProposalYAML(baseYAML, ruleName, ruleYAML string) (string, error) {
	baseDoc, err := policy.Parse([]byte(baseYAML))
	if err != nil {
		return "", fmt.Errorf("base policy: %w", err)
	}
	var frag struct {
		NetworkPolicies map[string]policy.NetworkPolicy `yaml:"network_policies"`
	}
	if err := yaml.Unmarshal([]byte(ruleYAML), &frag); err != nil {
		return "", fmt.Errorf("proposal rule: %w", err)
	}
	if baseDoc.NetworkPolicies == nil {
		baseDoc.NetworkPolicies = map[string]policy.NetworkPolicy{}
	}
	for k, v := range frag.NetworkPolicies {
		name := k
		if ruleName != "" {
			name = ruleName
			v.Name = ruleName
		}
		baseDoc.NetworkPolicies[name] = v
	}
	if err := baseDoc.Validate(); err != nil {
		return "", err
	}
	b, err := yaml.Marshal(baseDoc)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

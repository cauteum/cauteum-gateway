// SPDX-FileCopyrightText: Copyright (c) 2026 whaleshell
// SPDX-License-Identifier: MIT

package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whaleshell/whaleshell-gateway/internal/storage/store"
)

func TestProposalRiskFlagCannotBeClearedBySubmitter(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "gateway"), "gw-test")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"id":"p1","security_flagged":false}`))
	w := httptest.NewRecorder()
	handleSandboxProposals(w, req, st, "", "sandbox", "")
	if w.Code != http.StatusAccepted {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var proposal store.Proposal
	if err := json.Unmarshal(w.Body.Bytes(), &proposal); err != nil {
		t.Fatal(err)
	}
	if !proposal.SecurityFlagged {
		t.Fatal("untrusted security_flagged=false bypassed server classification")
	}
	// Legacy state can still hold false; listing pending must be fail-closed.
	proposal.SecurityFlagged = false
	if err := st.PutProposal(proposal); err != nil {
		t.Fatal(err)
	}
	listed := st.ListProposals("sandbox", "pending")
	if len(listed) != 1 || !listed[0].SecurityFlagged {
		t.Fatalf("legacy proposal was not conservatively flagged: %+v", listed)
	}
}

func TestMergeProposalYAML(t *testing.T) {
	base := "version: 1\nnetwork_policies:\n  keep:\n    name: keep\n    endpoints:\n    - host: keep.example\n      port: 443\n"
	frag := "network_policies:\n  api:\n    name: api\n    endpoints:\n    - host: api.example.com\n      port: 443\n"
	out, err := mergeProposalYAML(base, "api", frag)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "keep.example") || !strings.Contains(out, "api.example.com") {
		t.Fatalf("%s", out)
	}
}

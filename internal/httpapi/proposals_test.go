// SPDX-FileCopyrightText: Copyright (c) 2026 cauteum
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"strings"
	"testing"
)

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

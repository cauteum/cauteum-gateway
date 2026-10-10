// SPDX-FileCopyrightText: Copyright (c) 2026 cauteum
// SPDX-License-Identifier: Apache-2.0

package logbuf

import (
	"testing"
	"time"
)

func TestHubRemoveDropsBuffer(t *testing.T) {
	h := NewHub(8)
	h.Append("demo", []Line{{TS: time.Now().UTC(), Source: "proxy", Level: "INFO", Text: "hi"}})
	if len(h.Names()) != 1 {
		t.Fatalf("Names=%v want [demo]", h.Names())
	}
	h.Remove("demo")
	if len(h.Names()) != 0 {
		t.Fatalf("after Remove Names=%v want empty", h.Names())
	}
	if got := h.Snapshot("demo", time.Time{}, "", "", 0); len(got) != 0 {
		t.Fatalf("Snapshot after Remove len=%d want 0", len(got))
	}
}

func TestHubRemoveIdempotent(t *testing.T) {
	h := NewHub(4)
	h.Remove("")
	h.Remove("missing")
	var nilHub *Hub
	nilHub.Remove("x")
}

func TestHubRingCaps(t *testing.T) {
	h := NewHub(3)
	for range 10 {
		h.Append("s", []Line{{Text: "x"}})
	}
	got := h.Snapshot("s", time.Time{}, "", "", 0)
	if len(got) != 3 {
		t.Fatalf("len=%d want 3", len(got))
	}
}

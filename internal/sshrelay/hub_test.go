package sshrelay

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWaitConnected(t *testing.T) {
	t.Run("already connected", func(t *testing.T) {
		h := NewHub()
		h.sessions["demo"] = &session{}
		if err := h.WaitConnected(context.Background(), "demo", time.Second); err != nil {
			t.Fatalf("WaitConnected: %v", err)
		}
	})

	t.Run("connects while waiting", func(t *testing.T) {
		h := NewHub()
		go func() {
			time.Sleep(30 * time.Millisecond)
			h.mu.Lock()
			h.sessions["demo"] = &session{}
			h.mu.Unlock()
		}()
		if err := h.WaitConnected(context.Background(), "demo", time.Second); err != nil {
			t.Fatalf("WaitConnected: %v", err)
		}
	})

	t.Run("deadline", func(t *testing.T) {
		h := NewHub()
		err := h.WaitConnected(context.Background(), "demo", time.Millisecond)
		if !errors.Is(err, ErrNotConnected) {
			t.Fatalf("WaitConnected error = %v, want %v", err, ErrNotConnected)
		}
	})

	t.Run("caller cancellation", func(t *testing.T) {
		h := NewHub()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := h.WaitConnected(ctx, "demo", time.Second); !errors.Is(err, context.Canceled) {
			t.Fatalf("WaitConnected error = %v, want context.Canceled", err)
		}
	})
}

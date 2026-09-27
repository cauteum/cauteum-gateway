package httpapi

import (
	"context"
	"strings"
	"testing"
)

func TestAllowUnauthenticatedRequiresLoopbackListen(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:7443", ":7443", "[::]:7443", "192.168.1.10:7443"} {
		t.Run(listen, func(t *testing.T) {
			if err := validateUnauthenticatedListen(listen, true); err == nil || !strings.Contains(err.Error(), "non-loopback") {
				t.Fatalf("expected non-loopback rejection, got %v", err)
			}
		})
	}
	for _, listen := range []string{"127.0.0.1:7443", "[::1]:7443", "localhost:7443"} {
		t.Run(listen, func(t *testing.T) {
			if err := validateUnauthenticatedListen(listen, true); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := Serve(context.Background(), Options{
		Listen: "0.0.0.0:7443", DataDir: t.TempDir(), AllowUnauthenticated: true,
	}); err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("Serve must reject before opening state or socket, got %v", err)
	}
}

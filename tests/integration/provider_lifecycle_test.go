//go:build linux

package integration

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/whaleshell/whaleshell-gateway/internal/httpapi"
)

func TestProviderCredentialLifecycleThroughHTTP(t *testing.T) {
	var rotations atomic.Int32
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse refresh request: %v", err)
		}
		if got := r.Form.Get("refresh_token"); got != "initial-refresh" {
			t.Errorf("refresh_token=%q", got)
		}
		rotations.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"rotated-access","refresh_token":"rotated-refresh","expires_in":300}`)
	}))
	defer tokenEndpoint.Close()

	g := newTestGateway(t, httpapi.Options{})
	body := map[string]any{
		"type":        "openai",
		"env_vars":    []string{"API_KEY", "REFRESH_TOKEN"},
		"credentials": map[string]string{"API_KEY": "initial-access", "REFRESH_TOKEN": "initial-refresh"},
		"refresh": map[string]any{
			"API_KEY": map[string]any{
				"strategy": "oauth2-refresh-token",
				"material": map[string]string{"token_url": tokenEndpoint.URL, "refresh_token": "initial-refresh"},
				"outputs":  map[string]string{"access_token": "API_KEY", "refresh_token": "REFRESH_TOKEN"},
			},
		},
	}
	if code, out := g.do(http.MethodPut, "/v1/providers/acme", g.token, body); code != http.StatusNoContent {
		t.Fatalf("configure provider=%d body=%s", code, out)
	}

	if code, out := g.do(http.MethodPost, "/v1/providers/acme/refresh/API_KEY/rotate", g.token, nil); code != http.StatusNoContent {
		t.Fatalf("rotate provider=%d body=%s", code, out)
	}
	if rotations.Load() != 1 {
		t.Fatalf("token endpoint rotations=%d, want 1", rotations.Load())
	}
	code, out := g.do(http.MethodGet, "/v1/providers/acme", g.token, nil)
	if code != http.StatusOK {
		t.Fatalf("read provider=%d body=%s", code, out)
	}
	text := string(out)
	for _, secret := range []string{"initial-access", "initial-refresh", "rotated-access", "rotated-refresh", tokenEndpoint.URL} {
		if strings.Contains(text, secret) {
			t.Fatalf("provider response leaked %q: %s", secret, text)
		}
	}
	if !strings.Contains(text, "[configured]") {
		t.Fatalf("provider response did not expose redacted refresh metadata: %s", text)
	}

	if code, out := g.do(http.MethodDelete, "/v1/providers/acme", g.token, nil); code != http.StatusNoContent {
		t.Fatalf("delete provider=%d body=%s", code, out)
	}
	if code, _ := g.do(http.MethodGet, "/v1/providers/acme", g.token, nil); code != http.StatusNotFound {
		t.Fatalf("deleted provider status=%d, want 404", code)
	}
}

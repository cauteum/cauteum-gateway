package integration

import (
	"net/http"
	"strings"
	"testing"

	"github.com/whaleshell/whaleshell-gateway/internal/httpapi"
)

func TestAuthRequiredOnAPI(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{})
	g.createSandbox("demo")
	for _, path := range []string{"/v1/sandboxes", "/v1/info", "/v1/whoami", "/v1/ssh-sessions", "/debug/loglevel", "/v1/sandboxes/demo/secrets", "/v1/providers"} {
		for _, token := range []string{"", "wrong-token"} {
			if code, _ := g.do(http.MethodGet, path, token, nil); code != http.StatusUnauthorized {
				t.Errorf("GET %s with token %q = %d, want 401", path, token, code)
			}
		}
	}
	for _, path := range []string{"/v1/sandboxes/demo/ssh-session", "/v1/sandboxes/demo/exec", "/v1/sandboxes/demo/supervisor-token"} {
		if code, _ := g.do(http.MethodPost, path, "", nil); code != http.StatusUnauthorized {
			t.Errorf("POST %s without token = %d, want 401", path, code)
		}
	}
	if code, _ := g.do(http.MethodGet, "/healthz", "", nil); code != http.StatusOK {
		t.Errorf("/healthz = %d, want 200", code)
	}
	if code, _ := g.do(http.MethodGet, "/v1/sandboxes", g.token, nil); code != http.StatusOK {
		t.Errorf("/v1/sandboxes with token = %d, want 200", code)
	}
}

func TestSandboxPrincipalScope(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{})
	g.createSandbox("demo")
	g.createSandbox("other")
	token := g.sandboxToken("demo")
	for _, path := range []string{"/v1/whoami", "/v1/sandboxes/demo/secrets"} {
		if code, body := g.do(http.MethodGet, path, token, nil); code == http.StatusUnauthorized || code == http.StatusForbidden {
			t.Errorf("GET %s = %d %s, want allowed", path, code, body)
		}
	}
	denied := []struct{ method, path string }{
		{http.MethodGet, "/v1/sandboxes"},
		{http.MethodGet, "/v1/sandboxes/demo"},
		{http.MethodDelete, "/v1/sandboxes/demo"},
		{http.MethodGet, "/v1/sandboxes/other/secrets"},
		{http.MethodPost, "/v1/sandboxes/demo/ssh-session"},
		{http.MethodPost, "/v1/sandboxes/demo/exec"},
		{http.MethodPost, "/v1/sandboxes/demo/supervisor-token"},
		{http.MethodPost, "/v1/sandboxes/other/proposals"},
		{http.MethodGet, "/v1/ssh-sessions"},
		{http.MethodGet, "/v1/info"},
		{http.MethodGet, "/v1/supervisor/connect?sandbox=other"},
		{http.MethodPut, "/v1/policy/global"},
	}
	for _, c := range denied {
		if code, _ := g.do(c.method, c.path, token, nil); code != http.StatusForbidden {
			t.Errorf("%s %s with sandbox token = %d, want 403", c.method, c.path, code)
		}
	}
	var who map[string]any
	g.mustJSON(http.MethodGet, "/v1/whoami", token, nil, http.StatusOK, &who)
	if who["sandbox"] != "demo" {
		t.Errorf("whoami = %v", who)
	}
}

func TestAllowUnauthenticated(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{AllowUnauthenticated: true})
	if code, _ := g.do(http.MethodGet, "/v1/sandboxes", "", nil); code != http.StatusOK {
		t.Fatalf("unsafe mode without token = %d, want 200", code)
	}
	if code, _ := g.do(http.MethodGet, "/v1/sandboxes", "wrong", nil); code != http.StatusUnauthorized {
		t.Fatalf("unsafe mode with bad token = %d, want 401", code)
	}
}

func TestLocalLoginLoopbackOnly(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{})
	get := func(path string, headers map[string]string) *http.Response {
		req, err := http.NewRequest(http.MethodGet, g.srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		for key, value := range headers {
			if key == "Host" {
				req.Host = value
				continue
			}
			req.Header.Set(key, value)
		}
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		return res
	}
	for _, tc := range []struct {
		path    string
		headers map[string]string
		want    int
	}{
		{"/v1/auth/login", nil, http.StatusOK},
		{"/v1/auth/login", map[string]string{"X-Forwarded-For": "203.0.113.9"}, http.StatusForbidden},
		{"/v1/auth/login", map[string]string{"Host": "evil.example:7443"}, http.StatusForbidden},
		{"/v1/auth/login?redirect_uri=https://evil.example/cb", nil, http.StatusBadRequest},
	} {
		if res := get(tc.path, tc.headers); res.StatusCode != tc.want {
			t.Errorf("%s headers=%v: status=%d, want %d", tc.path, tc.headers, res.StatusCode, tc.want)
		}
	}
	res := get("/v1/auth/login?redirect_uri=http://127.0.0.1:5555/cb", nil)
	if res.StatusCode != http.StatusFound || !strings.HasPrefix(res.Header.Get("Location"), "http://127.0.0.1:5555/cb?token=") {
		t.Fatalf("loopback redirect = %d %s", res.StatusCode, res.Header.Get("Location"))
	}
}

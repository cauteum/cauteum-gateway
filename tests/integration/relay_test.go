//go:build linux

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whaleshell/whaleshell-core/relayproto"
	"github.com/whaleshell/whaleshell-gateway/internal/httpapi"
	"github.com/whaleshell/whaleshell-gateway/internal/storage/store"
	"github.com/whaleshell/whaleshell-runtime/relayclient"
	"github.com/whaleshell/whaleshell-runtime/sshserver"
	"golang.org/x/crypto/ssh"
)

type testGateway struct {
	t     *testing.T
	srv   *httptest.Server
	token string
	dir   string
}

func newTestGateway(t *testing.T, opt httpapi.Options) *testGateway {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	opt.DataDir = filepath.Join(t.TempDir(), "gw")
	h, err := httpapi.NewHandler(ctx, opt)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	b, err := os.ReadFile(filepath.Join(opt.DataDir, store.AuthTokenFile))
	if err != nil {
		t.Fatal(err)
	}
	return &testGateway{t: t, srv: srv, token: strings.TrimSpace(string(b)), dir: opt.DataDir}
}

func (g *testGateway) do(method, path, token string, body any) (int, []byte) {
	g.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, g.srv.URL+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		g.t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, out
}

func (g *testGateway) mustJSON(method, path, token string, body any, want int, into any) {
	g.t.Helper()
	code, out := g.do(method, path, token, body)
	if code != want {
		g.t.Fatalf("%s %s = %d (%s), want %d", method, path, code, out, want)
	}
	if into != nil {
		if err := json.Unmarshal(out, into); err != nil {
			g.t.Fatalf("%s %s: decode %q: %v", method, path, out, err)
		}
	}
}

func (g *testGateway) createSandbox(name string) {
	g.t.Helper()
	g.mustJSON(http.MethodPut, "/v1/sandboxes/"+name, g.token, map[string]any{}, http.StatusNoContent, nil)
}

func (g *testGateway) sandboxToken(name string) string {
	g.t.Helper()
	var out struct {
		Token string `json:"sandbox_token"`
	}
	g.mustJSON(http.MethodPost, "/v1/sandboxes/"+name+"/supervisor-token", g.token, nil, http.StatusOK, &out)
	return out.Token
}

// startSupervisor runs a real sshserver on a Unix socket and a relayclient
// dialing out to the gateway, like the proxy sidecar does.
func (g *testGateway) startSupervisor(name, token string) {
	g.t.Helper()
	initPath := filepath.Join(g.t.TempDir(), "whaleshell-init")
	if err := os.WriteFile(initPath, []byte("#!/bin/sh\n[ \"$1\" = \"--\" ] || exit 99\nshift\nexec \"$@\"\n"), 0o700); err != nil {
		g.t.Fatal(err)
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := sshserver.New(sshserver.Config{
		Shell:    "/bin/sh",
		InitPath: initPath,
		Env:      []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + g.t.TempDir()},
		Log:      quiet,
	})
	if err != nil {
		g.t.Fatal(err)
	}
	sock := filepath.Join(g.t.TempDir(), "ssh", "sshd.sock")
	ln, err := sshserver.ListenUnix(sock)
	if err != nil {
		g.t.Fatal(err)
	}
	g.t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = srv.Serve(ln) }()

	ctx, cancel := context.WithCancel(context.Background())
	g.t.Cleanup(cancel)
	connected := make(chan struct{}, 1)
	go func() {
		_ = relayclient.Run(ctx, relayclient.Config{
			GatewayURL: g.srv.URL,
			Sandbox:    name,
			Token:      token,
			SSHSocket:  sock,
			Log:        quiet,
			MinBackoff: 20 * time.Millisecond,
			MaxBackoff: 100 * time.Millisecond,
			OnConnected: func() {
				select {
				case connected <- struct{}{}:
				default:
				}
			},
		})
	}()
	select {
	case <-connected:
	case <-time.After(5 * time.Second):
		g.t.Fatal("supervisor did not connect")
	}
	// The hub registers the session right after the handshake; wait for it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if code, _ := g.do(http.MethodPost, "/v1/sandboxes/"+name+"/ssh-session", g.token, nil); code == http.StatusOK {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	g.t.Fatal("relay not ready")
}

type sshSessionResp struct {
	SessionID string `json:"session_id"`
	SandboxID string `json:"sandbox_id"`
	Token     string `json:"token"`
	Scheme    string `json:"gateway_scheme"`
	Host      string `json:"gateway_host"`
	Port      int    `json:"gateway_port"`
	ExpiresAt int64  `json:"expires_at_ms"`
}

func (g *testGateway) sshSession(name string) sshSessionResp {
	g.t.Helper()
	var s sshSessionResp
	g.mustJSON(http.MethodPost, "/v1/sandboxes/"+name+"/ssh-session", g.token, nil, http.StatusOK, &s)
	return s
}

func (g *testGateway) dialSSH(sandbox, sessionToken string) (*ssh.Client, error) {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+sessionToken)
	h.Set(relayproto.HeaderSandboxID, sandbox)
	conn, err := relayproto.Dial(context.Background(), g.srv.URL, relayproto.PathSSHConnect, relayproto.DialOptions{Header: h})
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, "sandbox", &ssh.ClientConfig{
		User:            "sandbox",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

func statusOf(err error) int {
	var se *relayproto.StatusError
	if errors.As(err, &se) {
		return se.Code
	}
	return 0
}

func TestRelaySSHSessionEndToEnd(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{})
	g.createSandbox("demo")
	g.startSupervisor("demo", g.sandboxToken("demo"))

	s := g.sshSession("demo")
	if s.Token == "" || s.SandboxID != "demo" || s.Scheme != "http" || s.Port == 0 || s.ExpiresAt == 0 {
		t.Fatalf("session response = %+v", s)
	}
	client, err := g.dialSSH("demo", s.Token)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sess.Output("echo relay-ok")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(out)) != "relay-ok" {
		t.Fatalf("out = %q", out)
	}
	_ = client.Close()

	var list struct {
		Sessions []struct {
			ID      string `json:"id"`
			Sandbox string `json:"sandbox"`
			Subject string `json:"subject"`
		} `json:"sessions"`
	}
	g.mustJSON(http.MethodGet, "/v1/ssh-sessions?sandbox=demo", g.token, nil, http.StatusOK, &list)
	found := false
	for _, row := range list.Sessions {
		if row.ID == s.SessionID {
			found = row.Sandbox == "demo" && row.Subject == "local-dev"
		}
	}
	if !found {
		t.Fatalf("session %s missing from list: %+v", s.SessionID, list)
	}

	g.mustJSON(http.MethodDelete, "/v1/ssh-sessions/"+s.SessionID, g.token, nil, http.StatusNoContent, nil)
	if _, err := g.dialSSH("demo", s.Token); statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("revoked session dial = %v, want 401", err)
	}
}

func TestRelaySSHConnectRejections(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{})
	g.createSandbox("demo")
	g.createSandbox("other")
	g.startSupervisor("demo", g.sandboxToken("demo"))
	s := g.sshSession("demo")

	cases := map[string]struct{ sandbox, token string }{
		"no token":        {"demo", ""},
		"user token":      {"demo", g.token},
		"wrong sandbox":   {"other", s.Token},
		"unknown sandbox": {"ghost", s.Token},
		"garbage token":   {"demo", "deadbeef"},
	}
	for name, c := range cases {
		if _, err := g.dialSSH(c.sandbox, c.token); statusOf(err) != http.StatusUnauthorized {
			t.Errorf("%s: err = %v, want 401", name, err)
		}
	}
}

func TestRelaySessionExpires(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{SSHSessionTTL: 300 * time.Millisecond})
	g.createSandbox("demo")
	g.startSupervisor("demo", g.sandboxToken("demo"))
	s := g.sshSession("demo")
	time.Sleep(400 * time.Millisecond)
	if _, err := g.dialSSH("demo", s.Token); statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("expired session dial = %v, want 401", err)
	}
}

func TestRelayNotReady(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{})
	g.createSandbox("cold")
	if code, body := g.do(http.MethodPost, "/v1/sandboxes/cold/ssh-session", g.token, nil); code != http.StatusPreconditionFailed {
		t.Fatalf("ssh-session without supervisor = %d %s, want 412", code, body)
	}
	if code, _ := g.do(http.MethodPost, "/v1/sandboxes/cold/exec", g.token, map[string]any{"argv": []string{"true"}}); code != http.StatusPreconditionFailed {
		t.Fatalf("exec without supervisor = %d, want 412", code)
	}
	if code, _ := g.do(http.MethodPost, "/v1/sandboxes/ghost/ssh-session", g.token, nil); code != http.StatusNotFound {
		t.Fatalf("ssh-session unknown sandbox = %d, want 404", code)
	}
}

func TestRelayExec(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{})
	g.createSandbox("demo")
	g.startSupervisor("demo", g.sandboxToken("demo"))

	var res struct {
		ExitCode int    `json:"exit_code"`
		Output   string `json:"output"`
	}
	g.mustJSON(http.MethodPost, "/v1/sandboxes/demo/exec", g.token,
		map[string]any{"argv": []string{"sh", "-c", `echo "it's fine"; exit 4`}}, http.StatusOK, &res)
	if res.ExitCode != 4 || strings.TrimSpace(res.Output) != "it's fine" {
		t.Fatalf("exec = %+v", res)
	}
	g.mustJSON(http.MethodPost, "/v1/relay/demo/exec", g.token,
		map[string]any{"argv": []string{"echo", "legacy"}}, http.StatusOK, &res)
	if res.ExitCode != 0 || strings.TrimSpace(res.Output) != "legacy" {
		t.Fatalf("legacy exec = %+v", res)
	}
	for _, p := range []string{"/v1/relay/demo/poll", "/v1/relay/demo/result"} {
		if code, _ := g.do(http.MethodGet, p, g.token, nil); code != http.StatusGone {
			t.Errorf("%s = %d, want 410", p, code)
		}
	}
}

func TestSupervisorTokenRotationKicksOldSupervisor(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{})
	g.createSandbox("demo")
	old := g.sandboxToken("demo")
	g.sandboxToken("demo")
	if code, _ := g.do(http.MethodGet, "/v1/whoami", old, nil); code != http.StatusUnauthorized {
		t.Fatalf("rotated supervisor token = %d, want 401", code)
	}
	h := http.Header{}
	h.Set("Authorization", "Bearer "+old)
	_, err := relayproto.Dial(context.Background(), g.srv.URL, relayproto.PathSupervisorConnect+"?sandbox=demo", relayproto.DialOptions{Header: h})
	if statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("old supervisor connect = %v, want 401", err)
	}
}

func TestSandboxDeleteRevokesRelay(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{})
	g.createSandbox("demo")
	sbTok := g.sandboxToken("demo")
	g.startSupervisor("demo", sbTok)
	s := g.sshSession("demo")
	g.mustJSON(http.MethodDelete, "/v1/sandboxes/demo", g.token, nil, http.StatusNoContent, nil)
	if _, err := g.dialSSH("demo", s.Token); statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("session after delete = %v, want 401", err)
	}
	if code, _ := g.do(http.MethodGet, "/v1/whoami", sbTok, nil); code != http.StatusUnauthorized {
		t.Fatalf("sandbox token after delete = %d, want 401", code)
	}
}

func TestAuthRequiredOnAPI(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{})
	g.createSandbox("demo")
	for _, p := range []string{"/v1/sandboxes", "/v1/info", "/v1/whoami", "/v1/ssh-sessions", "/debug/loglevel", "/v1/sandboxes/demo/secrets", "/v1/providers"} {
		if code, _ := g.do(http.MethodGet, p, "", nil); code != http.StatusUnauthorized {
			t.Errorf("GET %s without token = %d, want 401", p, code)
		}
		if code, _ := g.do(http.MethodGet, p, "wrong-token", nil); code != http.StatusUnauthorized {
			t.Errorf("GET %s with bad token = %d, want 401", p, code)
		}
	}
	for _, p := range []string{"/v1/sandboxes/demo/ssh-session", "/v1/sandboxes/demo/exec", "/v1/sandboxes/demo/supervisor-token"} {
		if code, _ := g.do(http.MethodPost, p, "", nil); code != http.StatusUnauthorized {
			t.Errorf("POST %s without token = %d, want 401", p, code)
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
	tok := g.sandboxToken("demo")

	allowed := []struct{ method, path string }{
		{http.MethodGet, "/v1/whoami"},
		{http.MethodGet, "/v1/sandboxes/demo/secrets"},
	}
	for _, c := range allowed {
		if code, body := g.do(c.method, c.path, tok, nil); code == http.StatusUnauthorized || code == http.StatusForbidden {
			t.Errorf("%s %s = %d %s, want allowed", c.method, c.path, code, body)
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
		if code, _ := g.do(c.method, c.path, tok, nil); code != http.StatusForbidden {
			t.Errorf("%s %s with sandbox token = %d, want 403", c.method, c.path, code)
		}
	}
	var who map[string]any
	g.mustJSON(http.MethodGet, "/v1/whoami", tok, nil, http.StatusOK, &who)
	if who["sandbox"] != "demo" {
		t.Errorf("whoami = %v", who)
	}
}

func TestUserTokenCannotActAsSupervisor(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{})
	g.createSandbox("demo")
	h := http.Header{}
	h.Set("Authorization", "Bearer "+g.token)
	_, err := relayproto.Dial(context.Background(), g.srv.URL, relayproto.PathSupervisorConnect+"?sandbox=demo", relayproto.DialOptions{Header: h})
	if statusOf(err) != http.StatusForbidden {
		t.Fatalf("user token supervisor connect = %v, want 403", err)
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
	get := func(path string, hdr map[string]string) *http.Response {
		req, _ := http.NewRequest(http.MethodGet, g.srv.URL+path, nil)
		for k, v := range hdr {
			if k == "Host" {
				req.Host = v
				continue
			}
			req.Header.Set(k, v)
		}
		c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		return res
	}
	if res := get("/v1/auth/login", nil); res.StatusCode != http.StatusOK {
		t.Fatalf("loopback login = %d", res.StatusCode)
	}
	if res := get("/v1/auth/login", map[string]string{"X-Forwarded-For": "203.0.113.9"}); res.StatusCode != http.StatusForbidden {
		t.Fatalf("proxied login = %d, want 403", res.StatusCode)
	}
	if res := get("/v1/auth/login", map[string]string{"Host": "evil.example:7443"}); res.StatusCode != http.StatusForbidden {
		t.Fatalf("rebinding host login = %d, want 403", res.StatusCode)
	}
	if res := get("/v1/auth/login?redirect_uri=https://evil.example/cb", nil); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("external redirect = %d, want 400", res.StatusCode)
	}
	res := get("/v1/auth/login?redirect_uri="+"http://127.0.0.1:5555/cb", nil)
	if res.StatusCode != http.StatusFound || !strings.HasPrefix(res.Header.Get("Location"), "http://127.0.0.1:5555/cb?token=") {
		t.Fatalf("loopback redirect = %d %s", res.StatusCode, res.Header.Get("Location"))
	}
}

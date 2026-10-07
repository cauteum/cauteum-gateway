package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/whaleshell/slogx"
	"github.com/whaleshell/whaleshell-core/relayproto"
	"github.com/whaleshell/whaleshell-gateway/internal/sshrelay"
	"github.com/whaleshell/whaleshell-gateway/internal/storage/store"
	"golang.org/x/crypto/ssh"
)

// DefaultSSHSessionTTL matches OpenShell ssh_session_ttl_secs (24h).
const DefaultSSHSessionTTL = 24 * time.Hour

// maxExecOutputBytes caps relayed exec output held in gateway memory.
const maxExecOutputBytes = 4 << 20

type sshAPI struct {
	st         *store.Store
	hub        *sshrelay.Hub
	sessionTTL time.Duration
	log        *slog.Logger
}

func (a *sshAPI) mount(mux *http.ServeMux) {
	mux.HandleFunc(relayproto.PathSSHConnect, a.handleSSHConnect)
	mux.HandleFunc(relayproto.PathSupervisorConnect, a.handleSupervisorConnect)
	mux.HandleFunc(relayproto.PathSupervisorRelay, a.handleSupervisorRelay)
	mux.HandleFunc("/v1/ssh-sessions", a.handleSessions)
	mux.HandleFunc("/v1/ssh-sessions/", a.handleSession)
	mux.HandleFunc("/v1/relay/", a.handleLegacyRelay)
}

// sandboxSubpath serves /v1/sandboxes/{name}/{sub} routes owned by this API.
// It returns false when sub is not an SSH/relay route.
func (a *sshAPI) sandboxSubpath(w http.ResponseWriter, r *http.Request, name, sub string) bool {
	switch sub {
	case "ssh-session":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return true
		}
		a.createSession(w, r, name)
	case "supervisor-token":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return true
		}
		a.issueSandboxToken(w, r, name)
	case "exec":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return true
		}
		a.exec(w, r, name)
	default:
		return false
	}
	return true
}

// resolveSandbox accepts a sandbox name or registry id.
func (a *sshAPI) resolveSandbox(nameOrID string) (store.Sandbox, bool) {
	if sb, ok := a.st.GetSandbox(nameOrID); ok {
		return sb, true
	}
	for _, sb := range a.st.Snapshot().Sandboxes {
		if sb.ID != "" && sb.ID == nameOrID {
			return sb, true
		}
	}
	return store.Sandbox{}, false
}

func (a *sshAPI) issueSandboxToken(w http.ResponseWriter, r *http.Request, name string) {
	tok, err := a.st.IssueSandboxToken(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	a.hub.Disconnect(name)
	a.log.Info("sandbox supervisor token issued", slog.String("op", "gateway.sandbox.token"), slog.String("sandbox", name))
	writeJSON(w, http.StatusOK, map[string]any{"sandbox": name, "sandbox_token": tok})
}

// createSession is CreateSshSession: authorize, require a live relay, mint a token.
func (a *sshAPI) createSession(w http.ResponseWriter, r *http.Request, name string) {
	sb, ok := a.resolveSandbox(name)
	if !ok {
		http.Error(w, "sandbox not found", http.StatusNotFound)
		return
	}
	if !a.hub.Connected(sb.Name) {
		http.Error(w, "sandbox is not ready", http.StatusPreconditionFailed)
		return
	}
	p := PrincipalFrom(r.Context())
	sess, tok, err := a.st.CreateSSHSession(sb.Name, p.Subject, a.sessionTTL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host, portStr, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
		portStr = "80"
		if scheme == "https" {
			portStr = "443"
		}
	}
	port, _ := strconv.Atoi(portStr)
	a.log.Info("ssh session created",
		slog.String("op", "gateway.ssh.session"),
		slog.String("sandbox", sb.Name),
		slog.String("session_id", sess.ID),
		slog.String("subject", p.Subject))
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id":     sess.ID,
		"sandbox_id":     sb.Name,
		"token":          tok,
		"gateway_scheme": scheme,
		"gateway_host":   host,
		"gateway_port":   port,
		"expires_at_ms":  sess.ExpiresAtMS,
	})
}

func (a *sshAPI) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	type row struct {
		ID          string `json:"id"`
		Sandbox     string `json:"sandbox"`
		Subject     string `json:"subject,omitempty"`
		CreatedAtMS int64  `json:"created_at_ms"`
		ExpiresAtMS int64  `json:"expires_at_ms,omitempty"`
		Revoked     bool   `json:"revoked,omitempty"`
	}
	list := a.st.ListSSHSessions(r.URL.Query().Get("sandbox"))
	out := make([]row, 0, len(list))
	for _, s := range list {
		out = append(out, row{ID: s.ID, Sandbox: s.Sandbox, Subject: s.Subject, CreatedAtMS: s.CreatedAtMS, ExpiresAtMS: s.ExpiresAtMS, Revoked: s.Revoked})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

// handleSession is RevokeSshSession: DELETE /v1/ssh-sessions/{id}.
func (a *sshAPI) handleSession(w http.ResponseWriter, r *http.Request) {
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/ssh-sessions/"), "/")
	if id == "" || r.Method != http.MethodDelete {
		http.Error(w, "usage: DELETE /v1/ssh-sessions/{id}", http.StatusMethodNotAllowed)
		return
	}
	if err := a.st.RevokeSSHSession(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	a.log.Info("ssh session revoked", slog.String("op", "gateway.ssh.revoke"), slog.String("session_id", id))
	w.WriteHeader(http.StatusNoContent)
}

// handleSSHConnect is ForwardTcp(SshRelayTarget): session token -> relay bytes.
func (a *sshAPI) handleSSHConnect(w http.ResponseWriter, r *http.Request) {
	log := a.log.With(slog.String("op", "gateway.ssh.connect"))
	sandbox := strings.TrimSpace(r.Header.Get(relayproto.HeaderSandboxID))
	if sandbox == "" {
		http.Error(w, relayproto.HeaderSandboxID+" required", http.StatusBadRequest)
		return
	}
	// Unknown sandboxes fail like bad tokens so names cannot be probed.
	sb, ok := a.resolveSandbox(sandbox)
	if !ok {
		sb = store.Sandbox{Name: sandbox}
	}
	sess, err := a.st.ValidateSSHSession(bearerToken(r), sb.Name, time.Now())
	if err != nil {
		log.Warn("ssh session rejected", slog.String("sandbox", sb.Name), slog.String("reason", err.Error()))
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "invalid ssh session", http.StatusUnauthorized)
		return
	}
	if !relayproto.IsUpgrade(r) {
		w.Header().Set("Upgrade", relayproto.UpgradeProtocol)
		http.Error(w, "upgrade required", http.StatusUpgradeRequired)
		return
	}
	upstream, err := a.hub.OpenChannel(r.Context(), sb.Name, relayproto.TargetSSH)
	if err != nil {
		log.Warn("ssh relay channel open failed", slog.String("sandbox", sb.Name), slog.String("session_id", sess.ID), slogx.Err(err))
		code := http.StatusBadGateway
		if errors.Is(err, sshrelay.ErrNotConnected) {
			code = http.StatusPreconditionFailed
		} else if errors.Is(err, sshrelay.ErrOpenTimeout) {
			code = http.StatusGatewayTimeout
		}
		http.Error(w, err.Error(), code)
		return
	}
	client, err := relayproto.Accept(w, r)
	if err != nil {
		if closeErr := upstream.Close(); closeErr != nil {
			log.Debug("ssh relay upstream close failed", slog.String("sandbox", sb.Name), slogx.Err(closeErr))
		}
		log.Debug("ssh client relay upgrade rejected", slog.String("sandbox", sb.Name), slogx.Err(err))
		return
	}
	log.Info("ssh relay open", slog.String("sandbox", sb.Name), slog.String("session_id", sess.ID))
	if err := sshrelay.Bridge(client, upstream); err != nil {
		log.Warn("ssh relay ended with error", slog.String("sandbox", sb.Name), slog.String("session_id", sess.ID), slogx.Err(err))
	}
	log.Info("ssh relay closed", slog.String("sandbox", sb.Name), slog.String("session_id", sess.ID))
}

func (a *sshAPI) handleSupervisorConnect(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	if p.Kind != PrincipalSandbox || p.Sandbox != r.URL.Query().Get("sandbox") {
		http.Error(w, "supervisor token required", http.StatusForbidden)
		return
	}
	a.hub.ServeSupervisor(w, r, p.Sandbox)
}

func (a *sshAPI) handleSupervisorRelay(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	if p.Kind != PrincipalSandbox {
		http.Error(w, "supervisor token required", http.StatusForbidden)
		return
	}
	channel := strings.Trim(strings.TrimPrefix(r.URL.Path, relayproto.PathSupervisorRelay), "/")
	if channel == "" {
		http.Error(w, "channel required", http.StatusBadRequest)
		return
	}
	a.hub.ServeRelay(w, r, p.Sandbox, channel)
}

// handleLegacyRelay keeps POST /v1/relay/{name}/exec for SDK callers and
// retires the unauthenticated long-poll agent endpoints.
func (a *sshAPI) handleLegacyRelay(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/relay/"), "/")
	name, action, ok := strings.Cut(rest, "/")
	if !ok || name == "" {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	switch action {
	case "exec":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.exec(w, r, name)
	case "poll", "result":
		http.Error(w, "whaleshell-agent long-poll relay was removed; exec now runs over the supervisor SSH relay", http.StatusGone)
	default:
		http.Error(w, "unknown action", http.StatusNotFound)
	}
}

// exec is ExecSandbox: the gateway acts as SSH client over a relay channel.
func (a *sshAPI) exec(w http.ResponseWriter, r *http.Request, name string) {
	var req struct {
		Argv       []string `json:"argv"`
		TimeoutSec int      `json:"timeout_sec,omitempty"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || len(req.Argv) == 0 {
		http.Error(w, "argv required", http.StatusBadRequest)
		return
	}
	sb, ok := a.resolveSandbox(name)
	if !ok {
		http.Error(w, "sandbox not found", http.StatusNotFound)
		return
	}
	timeout := relayExecTimeout
	if req.TimeoutSec > 0 {
		timeout = time.Duration(req.TimeoutSec) * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	out, code, err := execOverRelay(ctx, a.hub, sb.Name, req.Argv)
	if err != nil {
		status := http.StatusBadGateway
		switch {
		case errors.Is(err, sshrelay.ErrNotConnected):
			status = http.StatusPreconditionFailed
		case errors.Is(err, sshrelay.ErrOpenTimeout), errors.Is(err, context.DeadlineExceeded):
			status = http.StatusGatewayTimeout
		}
		http.Error(w, err.Error(), status)
		return
	}
	a.log.Info("relay exec completed",
		slog.String("op", "gateway.sandbox.exec"),
		slog.String("sandbox", sb.Name),
		slog.Int("argv_len", len(req.Argv)),
		slog.Int("exit_code", code))
	writeJSON(w, http.StatusOK, map[string]any{"id": "", "exit_code": code, "output": out})
}

func execOverRelay(ctx context.Context, hub *sshrelay.Hub, sandbox string, argv []string) (string, int, error) {
	conn, err := hub.OpenChannel(ctx, sandbox, relayproto.TargetSSH)
	if err != nil {
		return "", 0, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	cfg := &ssh.ClientConfig{
		User: "sandbox",
		// The relay channel is already authenticated end to end (gateway
		// principal + sandbox supervisor token); host keys are ephemeral.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
		Timeout:         relayRequestTimeout,
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, "sandbox", cfg)
	if err != nil {
		return "", 0, fmt.Errorf("relay ssh handshake: %w", err)
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return "", 0, fmt.Errorf("relay ssh session: %w", err)
	}
	defer sess.Close()
	buf := &cappedBuffer{max: maxExecOutputBytes}
	sess.Stdout = buf
	sess.Stderr = buf
	done := make(chan error, 1)
	go func() { done <- sess.Run(shellJoin(argv)) }()
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		_ = client.Close()
		return buf.String(), 0, ctx.Err()
	}
	if err == nil {
		return buf.String(), 0, nil
	}
	if exitErr, ok := errors.AsType[*ssh.ExitError](err); ok {
		return buf.String(), exitErr.ExitStatus(), nil
	}
	return buf.String(), 0, fmt.Errorf("relay exec: %w", err)
}

// shellJoin quotes argv for the remote login shell.
func shellJoin(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = shellQuote(a)
	}
	return strings.Join(parts, " ")
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, c := range s {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("@%+=:,./-_", c)
		if !ok {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

type cappedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
	cut bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cut {
		return len(p), nil
	}
	if remain := c.max - c.buf.Len(); len(p) > remain {
		c.buf.Write(p[:remain])
		c.buf.WriteString("\n…[truncated]\n")
		c.cut = true
		return len(p), nil
	}
	return c.buf.Write(p)
}

func (c *cappedBuffer) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

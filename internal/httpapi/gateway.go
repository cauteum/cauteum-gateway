// Package gateway is the control-plane daemon (P8).
package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/whaleshell/slogx"
	"github.com/whaleshell/whaleshell-core/defaults"
	"github.com/whaleshell/whaleshell-core/policy"
	"github.com/whaleshell/whaleshell-core/relayproto"
	"github.com/whaleshell/whaleshell-gateway/internal/logbuf"
	"github.com/whaleshell/whaleshell-gateway/internal/logger"
	"github.com/whaleshell/whaleshell-gateway/internal/sshrelay"
	"github.com/whaleshell/whaleshell-gateway/internal/storage/store"
	"github.com/whaleshell/whaleshell-runtime/secrets"
)

// Options configure the HTTP(S) control plane.
type Options struct {
	Listen  string // default defaults.GatewayListen
	DataDir string // durable state
	TLSCert string // optional
	TLSKey  string // optional
	OIDC    OIDCOptions
	// SSHSessionTTL bounds SSH session tokens (OpenShell ssh_session_ttl_secs).
	// Zero selects DefaultSSHSessionTTL; negative disables expiry.
	SSHSessionTTL time.Duration
	// AllowUnauthenticated is the unsafe OpenShell allow_unauthenticated_users switch.
	AllowUnauthenticated bool
}

// EnvAllowUnauthenticated enables Options.AllowUnauthenticated (unsafe, dev only).
const EnvAllowUnauthenticated = "WHALESHELL_GATEWAY_ALLOW_UNAUTHENTICATED"

// EnvSSHSessionTTL overrides the SSH session TTL in seconds (0 = no expiry).
const EnvSSHSessionTTL = "WHALESHELL_SSH_SESSION_TTL_SECS"

// Run starts the gateway until context cancel / signal via ListenAndServe.
func Run(args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := logger.Setup(ctx, logger.Options{Service: "whaleshell-gateway"})
	ctx = logger.ToContext(ctx, log)

	opt := Options{
		Listen:  defaults.GatewayListen,
		DataDir: defaultDataDir(),
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--listen":
			i++
			if i >= len(args) {
				return fmt.Errorf("--listen needs a value")
			}
			opt.Listen = args[i]
		case "--data-dir":
			i++
			if i >= len(args) {
				return fmt.Errorf("--data-dir needs a value")
			}
			opt.DataDir = args[i]
		case "--tls-cert":
			i++
			if i >= len(args) {
				return fmt.Errorf("--tls-cert needs a value")
			}
			opt.TLSCert = args[i]
		case "--tls-key":
			i++
			if i >= len(args) {
				return fmt.Errorf("--tls-key needs a value")
			}
			opt.TLSKey = args[i]
		case "--oidc-issuer":
			i++
			if i >= len(args) {
				return fmt.Errorf("--oidc-issuer needs a value")
			}
			opt.OIDC.Issuer = args[i]
		case "--oidc-audience":
			i++
			if i >= len(args) {
				return fmt.Errorf("--oidc-audience needs a value")
			}
			opt.OIDC.Audience = args[i]
		case "--oidc-client-id":
			i++
			if i >= len(args) {
				return fmt.Errorf("--oidc-client-id needs a value")
			}
			opt.OIDC.ClientID = args[i]
		case "--oidc-allow-insecure-http":
			opt.OIDC.AllowInsecureHTTP = true
		case "--ssh-session-ttl-secs":
			i++
			if i >= len(args) {
				return fmt.Errorf("--ssh-session-ttl-secs needs a value")
			}
			ttl, err := parseTTLSecs(args[i])
			if err != nil {
				return fmt.Errorf("--ssh-session-ttl-secs: %w", err)
			}
			opt.SSHSessionTTL = ttl
		case "--allow-unauthenticated-users":
			opt.AllowUnauthenticated = true
		case "-h", "--help":
			fmt.Fprintf(os.Stderr, "usage: whaleshell-gateway [--listen ADDR] [--data-dir DIR] [--tls-cert F] [--tls-key F]\n")
			fmt.Fprintf(os.Stderr, "                 [--oidc-issuer URL] [--oidc-client-id ID] [--oidc-audience AUD]\n")
			fmt.Fprintf(os.Stderr, "                 [--oidc-allow-insecure-http] [--ssh-session-ttl-secs N]\n")
			fmt.Fprintf(os.Stderr, "                 [--allow-unauthenticated-users]  (unsafe: local development only)\n")
			return nil
		default:
			return fmt.Errorf("unknown flag %q", args[i])
		}
	}
	oidcFromEnvAndFlags(&opt)
	if err := authFromEnv(&opt); err != nil {
		return err
	}
	return Serve(ctx, opt)
}

func parseTTLSecs(s string) (time.Duration, error) {
	var n int64
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n); err != nil || n < 0 {
		return 0, fmt.Errorf("want seconds >= 0, got %q", s)
	}
	if n == 0 {
		return -1, nil
	}
	return time.Duration(n) * time.Second, nil
}

func authFromEnv(opt *Options) error {
	if v := strings.ToLower(strings.TrimSpace(os.Getenv(EnvAllowUnauthenticated))); v == "1" || v == "true" || v == "yes" {
		opt.AllowUnauthenticated = true
	}
	if opt.SSHSessionTTL == 0 {
		if v := strings.TrimSpace(os.Getenv(EnvSSHSessionTTL)); v != "" {
			ttl, err := parseTTLSecs(v)
			if err != nil {
				return fmt.Errorf("%s: %w", EnvSSHSessionTTL, err)
			}
			opt.SSHSessionTTL = ttl
		}
	}
	return nil
}

func defaultDataDir() string {
	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
		return filepath.Join(xdg, "whaleshell", "gateway")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "whaleshell-gateway")
	}
	return filepath.Join(home, ".local", "state", "whaleshell", "gateway")
}

func newGatewayID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "gw-" + hex.EncodeToString(b[:])
}

// Serve runs the HTTP API.
func Serve(ctx context.Context, opt Options) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if opt.Listen == "" {
		opt.Listen = defaults.GatewayListen
	}
	if err := validateUnauthenticatedListen(opt.Listen, opt.AllowUnauthenticated); err != nil {
		return err
	}
	handler, err := NewHandler(ctx, opt)
	if err != nil {
		return err
	}
	return listenAndServe(ctx, opt, handler)
}

func validateUnauthenticatedListen(listen string, allowed bool) error {
	if !allowed {
		return nil
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("gateway listen %q: %w", listen, err)
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("refusing allow_unauthenticated on non-loopback %q (use whaleshell gateway login)", listen)
}

// NewHandler builds the authenticated gateway HTTP handler and starts the SSH
// session reaper (stopped when ctx ends).
func NewHandler(ctx context.Context, opt Options) (http.Handler, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	log := logger.FromContext(ctx)
	if opt.DataDir == "" {
		opt.DataDir = defaultDataDir()
	}
	st, err := store.Open(opt.DataDir, newGatewayID())
	if err != nil {
		return nil, err
	}
	tokenPath, err := st.WriteAuthTokenFile()
	if err != nil {
		return nil, fmt.Errorf("gateway auth token: %w", err)
	}
	sec, err := secrets.OpenLocal(opt.DataDir)
	if err != nil {
		return nil, fmt.Errorf("gateway secrets: %w", err)
	}
	oidcFromEnvAndFlags(&opt)
	oidcValidator, err := newOIDCValidator(opt.OIDC)
	if err != nil {
		return nil, fmt.Errorf("gateway oidc: %w", err)
	}
	ttl := opt.SSHSessionTTL
	if ttl == 0 {
		ttl = DefaultSSHSessionTTL
	}
	if ttl < 0 {
		ttl = 0
	}
	logs := logbuf.NewHub(4096)
	relayHub := sshrelay.NewHub()
	relayHub.Log = log.Logger
	ssh := &sshAPI{st: st, hub: relayHub, sessionTTL: ttl, log: log.Logger}
	go reapSSHSessions(ctx, st, log.Logger)
	log.Info("auth enabled",
		slog.String("op", "gateway.auth"),
		slog.String("token_file", tokenPath),
		slog.Bool("oidc", oidcValidator != nil),
		slog.Bool("allow_unauthenticated", opt.AllowUnauthenticated))
	if opt.AllowUnauthenticated {
		log.Warn("UNSAFE: --allow-unauthenticated-users: requests without a bearer act as an operator",
			slog.String("op", "gateway.auth"))
	}
	mux := http.NewServeMux()
	ssh.mount(mux)
	mux.Handle("/debug/loglevel", log.LevelHTTPHandler())
	mux.Handle("/debug/loglevel/", log.LevelHTTPHandler())

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		s := st.Snapshot()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":         true,
			"gateway_id": s.GatewayID,
			"time":       time.Now().UTC(),
		})
	})
	mux.HandleFunc("/v1/info", func(w http.ResponseWriter, _ *http.Request) {
		s := st.Snapshot()
		kek := secrets.Inspect(opt.DataDir, os.Getenv)
		authMode := "local-dev"
		if oidcValidator != nil {
			authMode = "oidc"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"gateway_id":            s.GatewayID,
			"sandbox_count":         len(s.Sandboxes),
			"updated_at":            s.UpdatedAt,
			"data_dir":              opt.DataDir,
			"auth_mode":             authMode,
			"allow_unauthenticated": opt.AllowUnauthenticated,
			"oidc_issuer":           opt.OIDC.Issuer,
			"host_osg_internal":     "host.whaleshell.internal → host-gateway (Docker)",
			"relay":                 "supervisor relay: " + relayproto.PathSupervisorConnect + " + " + relayproto.PathSSHConnect,
			"ssh_session_ttl_s":     int64(ttl / time.Second),
			"secrets_kek": map[string]any{
				"source":           string(kek.Source),
				"pinned":           kek.Pinned,
				"env":              secrets.EnvKEK,
				"warning":          kek.Warning(),
				"format":           kek.Format,
				"migration_needed": kek.MigrationNeeded,
			},
		})
	})
	mux.HandleFunc("/v1/sandboxes", func(w http.ResponseWriter, r *http.Request) {
		const op = "gateway.sandboxes.list"
		log := logger.FromContext(r.Context()).With(slog.String("op", op))
		switch r.Method {
		case http.MethodGet:
			s := st.Snapshot()
			list := make([]store.Sandbox, 0, len(s.Sandboxes))
			for _, sb := range s.Sandboxes {
				list = append(list, sb)
			}
			log.Info("listed sandboxes", slog.Int("count", len(list)))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"sandboxes": list})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/v1/sandboxes/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/v1/sandboxes/")
		rest = strings.Trim(rest, "/")
		if rest == "" {
			http.Error(w, "bad name", http.StatusBadRequest)
			return
		}
		name, sub, hasSub := strings.Cut(rest, "/")
		if name == "" {
			http.Error(w, "bad name", http.StatusBadRequest)
			return
		}
		if hasSub {
			if ssh.sandboxSubpath(w, r, name, strings.Trim(sub, "/")) {
				return
			}
			handleSandboxSubpath(w, r, st, sec, logs, BuiltinProvidersDir(), name, sub)
			return
		}
		switch r.Method {
		case http.MethodGet:
			const op = "gateway.sandboxes.get"
			log := logger.FromContext(r.Context()).With(slog.String("op", op), slog.String("sandbox", name))
			sb, ok := st.GetSandbox(name)
			if !ok {
				log.Info("sandbox not found")
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			log.Info("sandbox fetched")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(sb)
		case http.MethodPut:
			const op = "gateway.sandboxes.upsert"
			log := logger.FromContext(r.Context()).With(slog.String("op", op), slog.String("sandbox", name))
			log.Info("upserting sandbox")
			var sb store.Sandbox
			if err := json.NewDecoder(r.Body).Decode(&sb); err != nil {
				log.Error("failed to decode sandbox body", slogx.Err(err))
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			sb.Name = name
			if err := st.UpsertSandbox(sb); err != nil {
				log.Error("failed to upsert sandbox", slogx.Err(err))
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			log.Info("sandbox upserted")
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			const op = "gateway.sandboxes.delete"
			log := logger.FromContext(r.Context()).With(slog.String("op", op), slog.String("sandbox", name))
			log.Info("deleting sandbox")
			if err := st.DeleteSandbox(name); err != nil {
				log.Error("failed to delete sandbox", slogx.Err(err))
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			relayHub.Disconnect(name)
			logs.Remove(name)
			log.Info("sandbox deleted")
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mountProviderAPI(mux, st, sec, BuiltinProvidersDir())
	mountParityAPI(mux, st, oidcValidator)
	mountOIDCAuthAPI(mux, opt.OIDC, oidcValidator, st.AuthToken)
	if oidcValidator != nil {
		log.Info("oidc auth enabled", slog.String("op", "gateway.oidc"), slog.String("issuer", opt.OIDC.Issuer))
	}
	// Fleet logs: GET /v1/logs?follow=1 lists all sandboxes' ring buffers via query names=
	mux.HandleFunc("/v1/logs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		names := r.URL.Query()["name"]
		if all := r.URL.Query().Get("all"); all == "1" || all == "true" {
			snap := st.Snapshot()
			names = names[:0]
			for n := range snap.Sandboxes {
				names = append(names, n)
			}
		}
		if len(names) == 0 {
			http.Error(w, "usage: /v1/logs?name=a&name=b or ?all=1", http.StatusBadRequest)
			return
		}
		// Snapshot merge (non-follow) for simplicity; follow uses per-sandbox SSE.
		follow := r.URL.Query().Get("follow") == "1" || r.URL.Query().Get("follow") == "true"
		if follow && len(names) == 1 {
			handleSandboxLogs(w, r, logs, names[0])
			return
		}
		if follow {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "streaming unsupported", http.StatusInternalServerError)
				return
			}
			last := map[string]time.Time{}
			for {
				for _, n := range names {
					for _, ln := range logs.Snapshot(n, last[n], "", "", 0) {
						if !last[n].IsZero() && !ln.TS.After(last[n]) {
							continue
						}
						fmt.Fprintf(w, "data: [%s] %s\n\n", n, formatLogLine(ln))
						last[n] = ln.TS
					}
				}
				flusher.Flush()
				select {
				case <-r.Context().Done():
					return
				case <-time.After(500 * time.Millisecond):
				}
			}
		}
		var all []map[string]any
		for _, n := range names {
			for _, ln := range logs.Snapshot(n, time.Time{}, "", "", 200) {
				all = append(all, map[string]any{"sandbox": n, "line": ln})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"lines": all})
	})
	mux.HandleFunc("/v1/policy/global", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			const op = "gateway.policy.global.get"
			log := logger.FromContext(r.Context()).With(slog.String("op", op))
			yaml := st.GetGlobalPolicy()
			log.Info("global policy fetched", slog.Int("bytes", len(yaml)))
			w.Header().Set("Content-Type", "application/yaml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(yaml))
		case http.MethodPut:
			const op = "gateway.policy.global.set"
			log := logger.FromContext(r.Context()).With(slog.String("op", op))
			log.Info("setting global policy")
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				log.Error("failed to read global policy body", slogx.Err(err))
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			doc, err := policy.Parse(body)
			if err != nil {
				log.Error("failed to parse global policy", slogx.Err(err))
				http.Error(w, "invalid policy: "+err.Error(), http.StatusBadRequest)
				return
			}
			if err := doc.Validate(); err != nil {
				log.Error("global policy validation failed", slogx.Err(err))
				http.Error(w, "invalid policy: "+err.Error(), http.StatusBadRequest)
				return
			}
			if err := st.SetGlobalPolicy(string(body)); err != nil {
				log.Error("failed to store global policy", slogx.Err(err))
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			log.Info("global policy set", slog.Int("bytes", len(body)))
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	auth := withAuth(mux, st, AuthOptions{
		OIDC:                 oidcValidator,
		AllowUnauthenticated: opt.AllowUnauthenticated,
		Log:                  log.Logger,
	})
	log.Info("gateway ready",
		slog.String("op", "gateway.serve"),
		slog.String("data_dir", opt.DataDir),
		slog.String("gateway_id", st.Snapshot().GatewayID),
	)
	return withEdgeRouter(auth, st), nil
}

func reapSSHSessions(ctx context.Context, st *store.Store, log *slog.Logger) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if n, err := st.ReapSSHSessions(now); err != nil {
				log.Warn("ssh session reap failed", slog.String("op", "gateway.ssh.reap"), slogx.Err(err))
			} else if n > 0 {
				log.Info("reaped ssh sessions", slog.String("op", "gateway.ssh.reap"), slog.Int("count", n))
			}
		}
	}
}

func listenAndServe(ctx context.Context, opt Options, handler http.Handler) error {
	log := logger.FromContext(ctx)
	srv := &http.Server{
		Addr:              opt.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	ln, err := net.Listen("tcp", opt.Listen)
	if err != nil {
		return fmt.Errorf("gateway listen %s: %w", opt.Listen, err)
	}
	if opt.AllowUnauthenticated && !ln.Addr().(*net.TCPAddr).IP.IsLoopback() {
		_ = ln.Close()
		return fmt.Errorf("refusing allow_unauthenticated on non-loopback %q (use whaleshell gateway login)", ln.Addr())
	}
	log.Info("listening", slog.String("op", "gateway.serve"), slog.String("addr", opt.Listen))
	if opt.TLSCert != "" && opt.TLSKey != "" {
		log.Info("tls enabled", slog.String("op", "gateway.serve"))
		errCh := make(chan error, 1)
		go func() { errCh <- srv.ServeTLS(ln, opt.TLSCert, opt.TLSKey) }()
		select {
		case <-ctx.Done():
			_ = srv.Shutdown(context.Background())
			return ctx.Err()
		case err := <-errCh:
			if err == http.ErrServerClosed {
				return nil
			}
			return err
		}
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shCtx)
		return nil
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

// Package gateway is the control-plane daemon (P8).
package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/whaleshell/whaleshell-gateway/internal/gatewayconfig"
	"google.golang.org/grpc"

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

// DriverConfigs maps a driver name to its decoded configuration table.
// Keep this an alias so existing Options literals remain source-compatible.
type DriverConfigs = map[string]map[string]any

// Options configure the HTTP(S) control plane.
type Options struct {
	Name                         string // operator-facing gateway installation identity
	LogLevel                     string // explicit startup filter
	RequireTLS                   bool   // selected OpenShell TLS posture
	DisableTLS                   bool   // explicit disable_tls ignores TLS files
	Listen                       string // default defaults.GatewayListen
	HealthListen                 string // optional unauthenticated liveness/readiness listener
	MetricsListen                string // optional Prometheus exposition listener
	DataDir                      string // durable state
	TLSCert                      string // optional
	TLSKey                       string // optional
	TLSClientCA                  string
	TLSRequireClientAuth         bool
	TLSExternalCert              string
	TLSExternalKey               string
	TLSExternalServerNames       []string
	EnableMTLSAuth               bool
	ProviderProfileSources       []string
	RegisterGRPC                 func(*grpc.Server)
	grpcRuntime                  *grpcRuntime
	ComputeDriverNames           []string
	ComputeDriverConfigs         DriverConfigs
	CredentialDriverNames        []string
	DefaultCredentialDriver      string
	PolicyValidationFailureMode  string
	SupervisorMiddlewareServices []*sandboxv1.SupervisorMiddlewareService
	CredentialDriverConfigs      DriverConfigs
	CredentialStorage            map[string]any
	GatewayInterceptors          []gatewayconfig.Interceptor
	tlsConfig                    *tls.Config
	OIDC                         OIDCOptions
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
	opt, err := resolveGatewayOptions(args)
	if errors.Is(err, errGatewayHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	var level slog.Level
	if opt.LogLevel != "" {
		var err error
		level, err = slogx.ParseLevel(opt.LogLevel)
		if err != nil {
			return fmt.Errorf("gateway log_level filter is not supported")
		}
	}
	log := logger.Setup(ctx, logger.Options{Service: "whaleshell-gateway", Level: level, LevelSet: opt.LogLevel != ""})
	if opt.Name != "" {
		log = log.With("openshell.gateway.name", opt.Name)
	}
	ctx = logger.ToContext(ctx, log)
	return Serve(ctx, opt)
}

var errGatewayHelp = errors.New("gateway help requested")

func resolveGatewayOptions(args []string) (Options, error) {
	args = normalizedGatewayArgs(args)
	opt, configFile, err := configStartup(args)
	if err != nil {
		return Options{}, err
	}
	var healthPortFlag, metricsPortFlag string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--config":
			i++
			if i >= len(args) {
				return Options{}, fmt.Errorf("--config needs a value")
			}
		case "--name", "--log-level", "--bind-address", "--port", "--health-port", "--metrics-port", "--oidc-jwks-ttl", "--oidc-roles-claim", "--oidc-admin-role", "--oidc-user-role", "--oidc-scopes-claim", "--tls-client-ca":
			flag := args[i]
			i++
			if i >= len(args) {
				return Options{}, fmt.Errorf("%s needs a value", flag)
			}
			switch flag {
			case "--name":
				opt.Name = args[i]
			case "--log-level":
				opt.LogLevel = args[i]
			case "--bind-address":
				if net.ParseIP(args[i]) == nil {
					return Options{}, fmt.Errorf("--bind-address must be an IP address")
				}
				_, port, _ := net.SplitHostPort(opt.Listen)
				opt.Listen = net.JoinHostPort(args[i], port)
			case "--port":
				if _, err := strconv.ParseUint(args[i], 10, 16); err != nil {
					return Options{}, fmt.Errorf("--port must be a uint16")
				}
				host, _, _ := net.SplitHostPort(opt.Listen)
				opt.Listen = net.JoinHostPort(host, args[i])
			case "--health-port", "--metrics-port":
				if flag == "--health-port" {
					healthPortFlag = args[i]
				} else {
					metricsPortFlag = args[i]
				}
			case "--tls-client-ca":
				opt.TLSClientCA = args[i]
			case "--oidc-jwks-ttl":
				seconds, err := strconv.ParseUint(args[i], 10, 64)
				if err != nil {
					return Options{}, fmt.Errorf("--oidc-jwks-ttl must be positive seconds")
				}
				opt.OIDC.JWKSTTLSecs, opt.OIDC.JWKSTTLSecsSet = seconds, true
			case "--oidc-roles-claim":
				opt.OIDC.RolesClaim = args[i]
				opt.OIDC.RolesClaimSet = true
			case "--oidc-admin-role":
				opt.OIDC.AdminRole = args[i]
				opt.OIDC.AdminRoleSet = true
			case "--oidc-user-role":
				opt.OIDC.UserRole = args[i]
				opt.OIDC.UserRoleSet = true
			case "--oidc-scopes-claim":
				opt.OIDC.ScopesClaim = args[i]
			}
		case "--disable-tls", "--disable-tls=true":
			opt.RequireTLS = false
			opt.DisableTLS = true
		case "--disable-tls=false":
			opt.RequireTLS = true
			opt.DisableTLS = false
		case "--listen":
			i++
			if i >= len(args) {
				return Options{}, fmt.Errorf("--listen needs a value")
			}
			opt.Listen = args[i]
		case "--data-dir":
			i++
			if i >= len(args) {
				return Options{}, fmt.Errorf("--data-dir needs a value")
			}
			opt.DataDir = args[i]
		case "--tls-cert":
			i++
			if i >= len(args) {
				return Options{}, fmt.Errorf("--tls-cert needs a value")
			}
			opt.TLSCert = args[i]
		case "--tls-key":
			i++
			if i >= len(args) {
				return Options{}, fmt.Errorf("--tls-key needs a value")
			}
			opt.TLSKey = args[i]
		case "--enable-mtls-auth", "--enable-mtls-auth=true":
			opt.EnableMTLSAuth = true
		case "--enable-mtls-auth=false":
			opt.EnableMTLSAuth = false
		case "--oidc-issuer":
			i++
			if i >= len(args) {
				return Options{}, fmt.Errorf("--oidc-issuer needs a value")
			}
			opt.OIDC.Issuer = args[i]
		case "--oidc-audience":
			i++
			if i >= len(args) {
				return Options{}, fmt.Errorf("--oidc-audience needs a value")
			}
			opt.OIDC.Audience = args[i]
		case "--oidc-client-id":
			i++
			if i >= len(args) {
				return Options{}, fmt.Errorf("--oidc-client-id needs a value")
			}
			opt.OIDC.ClientID = args[i]
		case "--oidc-allow-insecure-http", "--oidc-allow-insecure-http=true":
			opt.OIDC.AllowInsecureHTTP = true
		case "--oidc-allow-insecure-http=false":
			opt.OIDC.AllowInsecureHTTP = false
		case "--ssh-session-ttl-secs":
			i++
			if i >= len(args) {
				return Options{}, fmt.Errorf("--ssh-session-ttl-secs needs a value")
			}
			ttl, err := parseTTLSecs(args[i])
			if err != nil {
				return Options{}, fmt.Errorf("--ssh-session-ttl-secs: %w", err)
			}
			opt.SSHSessionTTL = ttl
		case "--allow-unauthenticated-users", "--allow-unauthenticated-users=true":
			opt.AllowUnauthenticated = true
		case "--allow-unauthenticated-users=false":
			opt.AllowUnauthenticated = false
		case "-h", "--help":
			fmt.Fprintf(os.Stderr, "usage: whaleshell-gateway [--config TOML] [--name NAME] [--listen ADDR] [--data-dir DIR]\n")
			fmt.Fprintf(os.Stderr, "                 [--bind-address IP] [--port N] [--log-level LEVEL] [--disable-tls]\n")
			fmt.Fprintf(os.Stderr, "                 [--health-port N] [--metrics-port N]\n")
			fmt.Fprintf(os.Stderr, "                 [--tls-cert FILE] [--tls-key FILE] [--tls-client-ca FILE]\n")
			fmt.Fprintf(os.Stderr, "                 [--enable-mtls-auth]\n")
			fmt.Fprintf(os.Stderr, "                 [--oidc-issuer URL] [--oidc-client-id ID] [--oidc-audience AUD]\n")
			fmt.Fprintf(os.Stderr, "                 [--oidc-jwks-ttl N] [--oidc-roles-claim PATH] [--oidc-admin-role NAME] [--oidc-user-role NAME] [--oidc-scopes-claim PATH]\n")
			fmt.Fprintf(os.Stderr, "                 [--oidc-allow-insecure-http] [--ssh-session-ttl-secs N]\n")
			fmt.Fprintf(os.Stderr, "                 [--allow-unauthenticated-users]  (unsafe: local development only)\n")
			return Options{}, errGatewayHelp
		default:
			return Options{}, fmt.Errorf("unknown flag %q", args[i])
		}
	}
	for _, listener := range []struct {
		flagPort, env, name string
		target              *string
	}{{healthPortFlag, "OPENSHELL_HEALTH_PORT", "--health-port", &opt.HealthListen}, {metricsPortFlag, "OPENSHELL_METRICS_PORT", "--metrics-port", &opt.MetricsListen}} {
		port := listener.flagPort
		if port == "" && !gatewayExplicitFlags(args)[listener.name] {
			if value, present := os.LookupEnv(listener.env); present {
				port = value
			}
		}
		if port != "" {
			address, err := optionalListenerAddress(opt.Listen, *listener.target, port)
			if err != nil {
				return Options{}, fmt.Errorf("%s: %w", listener.name, err)
			}
			*listener.target = address
		}
	}
	if err := configRuntimeGaps(configFile, opt); err != nil {
		return Options{}, err
	}
	if _, err := newOIDCValidator(opt.OIDC); err != nil {
		return Options{}, fmt.Errorf("gateway OIDC config: %w", err)
	}
	if opt.DisableTLS {
		if opt.TLSClientCA != "" || opt.EnableMTLSAuth {
			return Options{}, fmt.Errorf("--disable-tls cannot be combined with client certificate verification or mTLS authentication")
		}
		opt.TLSCert, opt.TLSKey = "", ""
	}
	return opt, nil
}

func parseTTLSecs(s string) (time.Duration, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("want seconds >= 0, got %q", s)
	}
	return checkedSeconds(n)
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

func configuredDriverStatus(names []string, configs DriverConfigs) []map[string]string {
	if len(names) == 0 {
		names = []string{"docker"}
	}
	out := make([]map[string]string, 0, len(names))
	for _, name := range names {
		state := "compatibility_stub"
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "docker", "podman":
			state = "engine_registered_lazy"
		case "vm", "kubernetes":
			state = "compatibility_stub"
		default:
			if stringConfig(driverConfig(configs, name), "grpc_endpoint") != "" {
				state = "remote_registered"
			}
		}
		out = append(out, map[string]string{"name": name, "state": state})
	}
	return out
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
	opt.grpcRuntime = &grpcRuntime{}
	if opt.Listen == "" {
		opt.Listen = defaults.GatewayListen
	}
	if err := validateUnauthenticatedListen(opt.Listen, opt.AllowUnauthenticated); err != nil {
		return err
	}
	if (opt.TLSCert == "") != (opt.TLSKey == "") || opt.RequireTLS && opt.TLSCert == "" {
		return fmt.Errorf("gateway TLS requires both certificate and key")
	}
	if opt.EnableMTLSAuth && opt.TLSClientCA == "" {
		return fmt.Errorf("mTLS authentication requires a TLS client CA")
	}
	if opt.TLSClientCA != "" && opt.TLSCert == "" {
		return fmt.Errorf("client certificate verification requires gateway TLS")
	}
	if opt.RequireTLS || opt.TLSCert != "" {
		tlsConfig, err := buildGatewayTLSConfig(opt)
		if err != nil {
			return err
		}
		opt.tlsConfig = tlsConfig
	}
	handler, err := NewHandler(ctx, opt)
	if err != nil {
		return err
	}
	if opt.RegisterGRPC == nil {
		opt.RegisterGRPC = func(server *grpc.Server) { registerOpenShellRPCWithOptions(server, opt) }
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
	if opt.grpcRuntime != nil {
		opt.grpcRuntime.st = st
		opt.grpcRuntime.sec = sec
		opt.grpcRuntime.opt = opt
		opt.grpcRuntime.compute = newComputeRegistry(opt)
		var registryErr error
		opt.grpcRuntime.drivers, registryErr = newDriverRegistry(opt)
		if registryErr != nil {
			return nil, fmt.Errorf("driver registry: %w", registryErr)
		}
		for name, registration := range opt.grpcRuntime.drivers.compute {
			if registration.client != nil {
				opt.grpcRuntime.compute.bindRemote(name, newRemoteComputeEngine(name, registration.client))
			}
		}
		if registryErr = opt.grpcRuntime.drivers.probe(ctx); registryErr != nil {
			_ = opt.grpcRuntime.drivers.close()
			return nil, fmt.Errorf("driver capability probe: %w", registryErr)
		}
	}
	oidcFromEnvAndFlags(&opt)
	oidcValidator, err := newOIDCValidator(opt.OIDC)
	if err != nil {
		return nil, fmt.Errorf("gateway oidc: %w", err)
	}
	if opt.grpcRuntime != nil {
		opt.grpcRuntime.oidc = oidcValidator
		opt.grpcRuntime.opt.OIDC = opt.OIDC
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
	if opt.grpcRuntime != nil {
		opt.grpcRuntime.logs = logs
		opt.grpcRuntime.relay = relayHub
		opt.grpcRuntime.sshSessionTTL = ttl
	}
	relayHub.Log = log.Logger
	ssh := &sshAPI{st: st, hub: relayHub, sessionTTL: ttl, log: log.Logger}
	go reapSSHSessions(ctx, st, log.Logger)
	if opt.grpcRuntime != nil {
		go reconcileRuntimeState(ctx, st, opt.grpcRuntime.compute, log.Logger)
	}
	log.Info("auth enabled",
		slog.String("op", "gateway.auth"),
		slog.String("token_file", tokenPath),
		slog.Bool("oidc", oidcValidator != nil),
		slog.Bool("allow_unauthenticated", opt.AllowUnauthenticated))
	if opt.AllowUnauthenticated {
		log.Warn("UNSAFE: --allow-unauthenticated-users: requests without a bearer act as an operator",
			slog.String("op", "gateway.auth"))
	}
	if opt.EnableMTLSAuth && opt.TLSClientCA == "" {
		return nil, fmt.Errorf("mTLS authentication requires a TLS client CA")
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
			"gateway_id":                s.GatewayID,
			"sandbox_count":             len(s.Sandboxes),
			"updated_at":                s.UpdatedAt,
			"data_dir":                  opt.DataDir,
			"auth_mode":                 authMode,
			"compute_drivers":           configuredDriverStatus(opt.ComputeDriverNames, opt.ComputeDriverConfigs),
			"credential_drivers":        opt.CredentialDriverNames,
			"default_credential_driver": opt.DefaultCredentialDriver,
			"allow_unauthenticated":     opt.AllowUnauthenticated,
			"oidc_issuer":               opt.OIDC.Issuer,
			"host_osg_internal":         "host.whaleshell.internal → host-gateway (Docker)",
			"relay":                     "supervisor relay: " + relayproto.PathSupervisorConnect + " + " + relayproto.PathSSHConnect,
			"ssh_session_ttl_s":         int64(ttl / time.Second),
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
			handleSandboxSubpath(w, r, st, sec, logs, BuiltinProvidersDir(), opt.ProviderProfileSources, name, sub)
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
	mountProviderAPIWithSources(mux, st, sec, BuiltinProvidersDir(), opt.ProviderProfileSources)
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
				case <-time.After(relayRetryInterval):
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
		OIDCSettings:         opt.OIDC,
		AllowUnauthenticated: opt.AllowUnauthenticated,
		EnableMTLSAuth:       opt.EnableMTLSAuth,
		Log:                  log.Logger,
	})
	log.Info("gateway ready",
		slog.String("op", "gateway.serve"),
		slog.String("data_dir", opt.DataDir),
		slog.String("gateway_id", st.Snapshot().GatewayID),
	)
	return withEdgeRouter(auth, st, relayHub), nil
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
	grpcServer := grpc.NewServer(grpcAuthServerOptions(opt)...)
	if opt.RegisterGRPC != nil {
		opt.RegisterGRPC(grpcServer)
	}
	combinedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
			return
		}
		handler.ServeHTTP(w, r)
	})
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	if opt.tlsConfig == nil {
		protocols.SetUnencryptedHTTP2(true)
	} else {
		protocols.SetHTTP2(true)
	}
	srv := &http.Server{
		Addr:              opt.Listen,
		Handler:           combinedHandler,
		ReadHeaderTimeout: headerReadTimeout,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		TLSConfig:         opt.tlsConfig,
		Protocols:         protocols,
	}
	ln, err := net.Listen("tcp", opt.Listen)
	if err != nil {
		return fmt.Errorf("gateway listen %s: %w", opt.Listen, err)
	}
	if opt.AllowUnauthenticated && !ln.Addr().(*net.TCPAddr).IP.IsLoopback() {
		_ = ln.Close()
		return fmt.Errorf("refusing allow_unauthenticated on non-loopback %q (use whaleshell gateway login)", ln.Addr())
	}
	auxiliary := make([]*http.Server, 0, 2)
	for _, endpoint := range []struct {
		name    string
		addr    string
		handler http.Handler
	}{{"health", opt.HealthListen, healthHandler()}, {"metrics", opt.MetricsListen, gatewayMetricsHandler()}} {
		if endpoint.addr == "" {
			continue
		}
		auxListener, listenErr := net.Listen("tcp", endpoint.addr)
		if listenErr != nil {
			_ = ln.Close()
			for _, server := range auxiliary {
				_ = server.Close()
			}
			return fmt.Errorf("gateway %s listen %s: %w", endpoint.name, endpoint.addr, listenErr)
		}
		server := &http.Server{Addr: endpoint.addr, Handler: endpoint.handler, ReadHeaderTimeout: headerReadTimeout, BaseContext: func(net.Listener) context.Context { return ctx }}
		auxiliary = append(auxiliary, server)
		go func(server *http.Server, listener net.Listener) {
			if serveErr := server.Serve(listener); serveErr != nil && serveErr != http.ErrServerClosed {
				log.Error("auxiliary listener failed", slog.String("listener", endpoint.name), slogx.Err(serveErr))
			}
		}(server, auxListener)
		log.Info("auxiliary listener started", slog.String("listener", endpoint.name), slog.String("addr", endpoint.addr))
	}
	defer func() {
		grpcServer.Stop()
		for _, server := range auxiliary {
			_ = server.Close()
		}
	}()
	log.Info("listening", slog.String("op", "gateway.serve"), slog.String("addr", opt.Listen))
	if opt.TLSCert != "" && opt.TLSKey != "" {
		log.Info("tls enabled", slog.String("op", "gateway.serve"))
		errCh := make(chan error, 1)
		go func() { errCh <- srv.ServeTLS(ln, "", "") }()
		select {
		case <-ctx.Done():
			shCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			_ = srv.Shutdown(shCtx)
			cancel()
			stopGRPCGracefully(grpcServer)
			shutdownAuxiliary(auxiliary)
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
		shCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shCtx)
		stopGRPCGracefully(grpcServer)
		shutdownAuxiliary(auxiliary)
		return nil
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func stopGRPCGracefully(server *grpc.Server) {
	done := make(chan struct{})
	go func() {
		server.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(shutdownTimeout):
		server.Stop()
		<-done
	}
}

func shutdownAuxiliary(servers []*http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, server := range servers {
		_ = server.Shutdown(ctx)
	}
}

func healthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	ready := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"healthy"}`)
	}
	mux.HandleFunc("/readyz", ready)
	mux.HandleFunc("/health", ready)
	return mux
}

func gatewayMetricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = io.WriteString(w, "# HELP whaleshell_gateway_up Whether the gateway process is serving.\n# TYPE whaleshell_gateway_up gauge\nwhaleshell_gateway_up 1\n")
	})
	return mux
}

package httpapi

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/whaleshell/whaleshell-core/relayproto"
	"github.com/whaleshell/whaleshell-gateway/internal/storage/store"
	"github.com/whaleshell/whaleshell-runtime/idp"
)

// PrincipalKind distinguishes operators from sandbox supervisors.
type PrincipalKind int

const (
	PrincipalNone PrincipalKind = iota
	// PrincipalUser is an operator (OIDC JWT or local-dev token): full API.
	PrincipalUser
	// PrincipalSandbox is one sandbox supervisor (proxy sidecar): only its own
	// secrets/logs/proposals/relay routes.
	PrincipalSandbox
)

// Principal is the authenticated caller of one request.
type Principal struct {
	Kind    PrincipalKind
	Subject string
	IDP     string
	Sandbox string // PrincipalSandbox only
	Roles   []string
}

type principalKey struct{}

// PrincipalFrom returns the request principal set by the auth middleware.
func PrincipalFrom(ctx context.Context) Principal {
	p, _ := ctx.Value(principalKey{}).(Principal)
	return p
}

func withPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// AuthOptions configure the gateway auth middleware.
type AuthOptions struct {
	OIDC *idp.OIDC
	// AllowUnauthenticated is the OpenShell allow_unauthenticated_users escape
	// hatch: requests without a bearer act as a local operator. Unsafe.
	AllowUnauthenticated bool
	Log                  *slog.Logger
}

// publicRoutes never require a bearer. /v1/ssh/connect authenticates with the
// SSH session token inside its handler; /v1/auth/login is loopback-only.
func isPublicRoute(path string) bool {
	switch path {
	case "/healthz", "/v1/healthz", "/v1/auth/oidc", "/v1/auth/login", relayproto.PathSSHConnect:
		return true
	}
	return false
}

// resolvePrincipal maps a bearer token to a principal. ok=false means a token
// was presented but is not valid.
func resolvePrincipal(r *http.Request, st *store.Store, validator *idp.OIDC) (Principal, bool) {
	tok := bearerToken(r)
	if tok == "" {
		return Principal{}, true
	}
	if validator != nil {
		if claims, err := validator.Validate(r.Context(), tok); err == nil {
			sub := claims.Subject
			if sub == "" {
				sub = claims.Email
			}
			if sub == "" {
				sub = "oidc-user"
			}
			return Principal{Kind: PrincipalUser, Subject: sub, IDP: "oidc", Roles: claimRoles(claims.Raw)}, true
		}
	}
	if local := st.AuthToken(); local != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(local)) == 1 {
		return Principal{Kind: PrincipalUser, Subject: "local-dev", IDP: "local"}, true
	}
	if name, ok := st.SandboxForToken(tok); ok {
		return Principal{Kind: PrincipalSandbox, Subject: "sandbox:" + name, IDP: "sandbox", Sandbox: name}, true
	}
	return Principal{}, false
}

func claimRoles(raw map[string]any) []string {
	var out []string
	for _, key := range []string{"roles", "groups"} {
		switch values := raw[key].(type) {
		case []string:
			out = append(out, values...)
		case []any:
			for _, value := range values {
				if role, ok := value.(string); ok {
					out = append(out, role)
				}
			}
		case string:
			out = append(out, values)
		}
	}
	return out
}

// withAuth enforces authentication on every route except isPublicRoute and
// scopes sandbox principals to sandboxRouteAllowed.
func withAuth(next http.Handler, st *store.Store, opt AuthOptions) http.Handler {
	log := opt.Log
	if log == nil {
		log = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicRoute(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		p, valid := resolvePrincipal(r, st, opt.OIDC)
		if !valid {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			http.Error(w, "invalid bearer token", http.StatusUnauthorized)
			return
		}
		if p.Kind == PrincipalNone {
			if !opt.AllowUnauthenticated {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "authentication required (whaleshell gateway login)", http.StatusUnauthorized)
				return
			}
			p = Principal{Kind: PrincipalUser, Subject: "anonymous", IDP: "none"}
		}
		if p.Kind == PrincipalSandbox && !sandboxRouteAllowed(r.Method, r.URL, p.Sandbox) {
			log.Warn("sandbox principal denied",
				slog.String("op", "gateway.auth"),
				slog.String("sandbox", p.Sandbox),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path))
			http.Error(w, "forbidden for sandbox principal", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(withPrincipal(r.Context(), p)))
	})
}

// sandboxRouteAllowed is the complete allowlist for a sandbox supervisor
// token. Handlers for supervisor streams re-check channel ownership.
func sandboxRouteAllowed(method string, u *url.URL, sandbox string) bool {
	path := u.Path
	switch {
	case path == relayproto.PathSupervisorConnect:
		return method == http.MethodGet && u.Query().Get("sandbox") == sandbox
	case strings.HasPrefix(path, relayproto.PathSupervisorRelay):
		return method == http.MethodGet
	case path == "/v1/whoami":
		return method == http.MethodGet
	}
	prefix := "/v1/sandboxes/" + sandbox + "/"
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(path, prefix), "/"), "/")
	switch {
	case len(parts) == 1 && parts[0] == "secrets":
		return method == http.MethodGet
	case len(parts) == 1 && parts[0] == "logs":
		return method == http.MethodPost
	case len(parts) == 1 && (parts[0] == "policy" || parts[0] == "effective-policy"):
		return method == http.MethodGet
	case len(parts) == 1 && parts[0] == "proposals":
		return method == http.MethodPost
	case len(parts) == 2 && parts[0] == "proposals":
		return method == http.MethodGet
	}
	return false
}

// isLoopbackRequest is true only for direct loopback peers (no proxy hops)
// addressed by a loopback Host, which defeats DNS-rebinding pages.
func isLoopbackRequest(r *http.Request) bool {
	if r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("Forwarded") != "" {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return false
	}
	return isLoopbackHostHeader(r.Host)
}

func isLoopbackHostHeader(h string) bool {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// isLoopbackRedirect accepts only http://127.0.0.1:PORT/… or localhost
// callbacks, so a web page cannot bounce the local token to another origin.
func isLoopbackRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Port() == "" {
		return false
	}
	switch u.Hostname() {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	return false
}

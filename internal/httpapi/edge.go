package httpapi

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/whaleshell/whaleshell-gateway/internal/sshrelay"
	"github.com/whaleshell/whaleshell-gateway/internal/storage/store"
)

const (
	edgeSuffixOpenShell = ".openshell.localhost"
	edgeSuffixOSG       = ".whaleshell.localhost"
)

// withEdgeRouter proxies Host *.openshell.localhost / *.whaleshell.localhost to registered services.
// Other requests fall through to the control-plane mux (.localhost resolves to 127.0.0.1).
func withEdgeRouter(next http.Handler, st *store.Store, relays ...*sshrelay.Hub) http.Handler {
	var relay *sshrelay.Hub
	if len(relays) > 0 {
		relay = relays[0]
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		name, ok := edgeServiceName(host)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		svc, found := st.GetService(name)
		if !found {
			http.Error(w, fmt.Sprintf("service %q not exposed", name), http.StatusNotFound)
			return
		}
		backendHost := strings.TrimSpace(svc.BackendHost)
		backendPort := svc.BackendPort
		if backendHost == "" && relay == nil {
			backendHost = "127.0.0.1"
		}
		if backendPort <= 0 {
			backendPort = svc.Port
		}
		if backendPort <= 0 {
			http.Error(w, "service has no backend port", http.StatusBadGateway)
			return
		}
		targetHost := backendHost
		if targetHost == "" {
			targetHost = "127.0.0.1"
		}
		target, err := url.Parse(fmt.Sprintf("http://%s", net.JoinHostPort(targetHost, fmt.Sprintf("%d", backendPort))))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		proxy := &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(target)
				pr.Out.Host = target.Host
			},
			ErrorHandler: func(rw http.ResponseWriter, _ *http.Request, err error) {
				http.Error(rw, "edge proxy: "+err.Error(), http.StatusBadGateway)
			},
		}
		if backendHost == "" && relay != nil {
			proxy.Transport = &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return relay.OpenChannel(ctx, svc.Sandbox, fmt.Sprintf("tcp://127.0.0.1:%d", backendPort))
				},
				ForceAttemptHTTP2: false,
			}
		}
		proxy.ServeHTTP(w, r)
	})
}

func edgeServiceName(host string) (string, bool) {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, suf := range []string{edgeSuffixOpenShell, edgeSuffixOSG} {
		if before, ok := strings.CutSuffix(host, suf); ok {
			name := before
			if name == "" || strings.Contains(name, ".") {
				return "", false
			}
			return name, true
		}
	}
	return "", false
}

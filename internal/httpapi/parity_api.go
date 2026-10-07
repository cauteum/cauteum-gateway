package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/whaleshell/whaleshell-gateway/internal/storage/store"
	"github.com/whaleshell/whaleshell-runtime/idp"
	"github.com/whaleshell/whaleshell-runtime/secrets"
)

// mountParityAPI registers inference, settings, templates, whoami, and local auth.
func mountParityAPI(mux *http.ServeMux, st *store.Store, oidcValidator *idp.OIDC) {
	mux.HandleFunc("/v1/inference", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			route, ok := st.GetInferenceRoute()
			if !ok {
				http.Error(w, "inference route not set", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(route)
		case http.MethodPut:
			var body struct {
				Provider   string `json:"provider"`
				Model      string `json:"model"`
				TimeoutSec int    `json:"timeout_sec"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if strings.TrimSpace(body.Provider) == "" || strings.TrimSpace(body.Model) == "" {
				http.Error(w, "provider and model required", http.StatusBadRequest)
				return
			}
			if _, ok := st.GetProvider(body.Provider); !ok {
				http.Error(w, fmt.Sprintf("provider %q not found", body.Provider), http.StatusBadRequest)
				return
			}
			route := store.InferenceRoute{Provider: body.Provider, Model: body.Model, TimeoutSec: body.TimeoutSec}
			if err := st.SetInferenceRoute(route); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			out, _ := st.GetInferenceRoute()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
		case http.MethodDelete:
			if err := st.ClearInferenceRoute(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/v1/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"settings": st.AllSettings()})
	})
	mux.HandleFunc("/v1/settings/", func(w http.ResponseWriter, r *http.Request) {
		key := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/settings/"), "/")
		if key == "" || strings.Contains(key, "/") {
			http.Error(w, "bad key", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodGet:
			v, ok := st.GetSetting(key)
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"key": key, "value": v})
		case http.MethodPut:
			var body struct {
				Value string `json:"value"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := st.SetSetting(key, body.Value); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			if err := st.DeleteSetting(key); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/v1/templates", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"templates": st.ListTemplates()})
	})
	mux.HandleFunc("/v1/templates/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/templates/"), "/")
		if name == "" || strings.Contains(name, "/") {
			http.Error(w, "bad name", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodGet:
			t, ok := st.GetTemplate(name)
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(t)
		case http.MethodPut:
			var t store.TemplateRecord
			if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			t.Name = name
			if err := st.UpsertTemplate(t); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			if err := st.DeleteTemplate(name); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/v1/whoami", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := PrincipalFrom(r.Context())
		auth := "authenticated"
		roles := []string{"platform_admin"}
		switch p.Kind {
		case PrincipalSandbox:
			roles = []string{"sandbox_supervisor"}
		case PrincipalUser:
			if p.IDP == "oidc" || p.IDP == "local_dev" {
				roles = p.Roles
			}
		case PrincipalNone:
			auth, roles = "anonymous", []string{"user"}
		}
		if p.IDP == "local_dev" {
			auth = "unauthenticated_allowed"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"subject":    p.Subject,
			"auth":       auth,
			"roles":      roles,
			"scopes":     p.Scopes,
			"idp":        p.IDP,
			"sandbox":    p.Sandbox,
			"gateway_id": st.Snapshot().GatewayID,
		})
	})

	// Local-dev token hand-off: loopback peers only, loopback callbacks only.
	// Remote operators use OIDC or the owner-only <data-dir>/auth_token file.
	mux.HandleFunc("/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackRequest(r) {
			http.Error(w, "local login is only available from loopback; use OIDC or `whaleshell gateway login --token $(cat <data-dir>/auth_token)`", http.StatusForbidden)
			return
		}
		redirect := r.URL.Query().Get("redirect_uri")
		if redirect != "" && !isLoopbackRedirect(redirect) {
			http.Error(w, "redirect_uri must be an http://127.0.0.1:PORT/ callback", http.StatusBadRequest)
			return
		}
		token, err := st.EnsureAuthToken()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if redirect != "" {
			sep := "?"
			if strings.Contains(redirect, "?") {
				sep = "&"
			}
			http.Redirect(w, r, redirect+sep+"token="+token, http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      token,
			"expires_at": time.Now().Add(defaultServiceSessionTTL).UTC(),
			"mode":       "local-dev",
		})
	})

	mountServicesAPI(mux, st)
	mountWorkspacesAPI(mux, st)
}

func mountServicesAPI(mux *http.ServeMux, st *store.Store) {
	mux.HandleFunc("/v1/services", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"services": st.ListServices()})
	})
	mux.HandleFunc("/v1/services/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/services/"), "/")
		if name == "" || strings.Contains(name, "/") {
			http.Error(w, "bad name", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodGet:
			rec, ok := st.GetService(name)
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(rec)
		case http.MethodPut:
			var rec store.ServiceRecord
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&rec); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			rec.Name = name
			if err := st.UpsertService(rec); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(rec)
		case http.MethodDelete:
			if err := st.DeleteService(name); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

func mountWorkspacesAPI(mux *http.ServeMux, st *store.Store) {
	mux.HandleFunc("/v1/workspaces", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"workspaces": st.ListWorkspaces()})
		case http.MethodPost:
			var body struct {
				Name string `json:"name"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			body.Name = strings.TrimSpace(body.Name)
			if body.Name == "" {
				http.Error(w, "name required", http.StatusBadRequest)
				return
			}
			ws := store.WorkspaceRecord{Name: body.Name}
			if err := st.UpsertWorkspace(ws); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			out, _ := st.GetWorkspace(body.Name)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(out)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/v1/workspaces/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/workspaces/"), "/")
		parts := strings.Split(path, "/")
		if len(parts) == 0 || parts[0] == "" {
			http.Error(w, "bad path", http.StatusBadRequest)
			return
		}
		name := parts[0]
		if len(parts) == 1 {
			switch r.Method {
			case http.MethodGet:
				ws, ok := st.GetWorkspace(name)
				if !ok {
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(ws)
			case http.MethodDelete:
				if err := st.DeleteWorkspace(name); err != nil {
					code := http.StatusInternalServerError
					if errors.Is(err, store.ErrWorkspaceNotEmpty) {
						code = http.StatusConflict
					}
					http.Error(w, err.Error(), code)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			}
			return
		}
		if len(parts) >= 2 && parts[1] == "members" {
			switch {
			case len(parts) == 2 && r.Method == http.MethodGet:
				ws, ok := st.GetWorkspace(name)
				if !ok {
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"members": ws.Members})
			case len(parts) == 2 && r.Method == http.MethodPut:
				var body struct {
					Subject string `json:"subject"`
					Role    string `json:"role"`
				}
				if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				if strings.TrimSpace(body.Subject) == "" {
					http.Error(w, "subject required", http.StatusBadRequest)
					return
				}
				if err := st.WorkspaceMemberUpsert(name, body.Subject, body.Role); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			case len(parts) == 3 && r.Method == http.MethodDelete:
				if err := st.WorkspaceMemberRemove(name, parts[2]); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			}
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	})
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func handleProviderRefreshPath(w http.ResponseWriter, r *http.Request, st *store.Store, sec *secrets.LocalEncrypted, name, sub string) bool {
	if !strings.HasPrefix(sub, "refresh") {
		return false
	}
	rec, ok := st.GetProvider(name)
	if !ok {
		http.Error(w, "provider not found", http.StatusNotFound)
		return true
	}
	parts := strings.Split(sub, "/")
	switch {
	case len(parts) == 1 && parts[0] == "refresh" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"refresh": redactProviderRefresh(rec.Refresh)})
	case len(parts) == 2 && parts[0] == "refresh" && r.Method == http.MethodPut:
		var body store.ProviderRefreshConfig
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return true
		}
		body.CredentialKey = parts[1]
		if body.Strategy == "" {
			body.Strategy = "env"
		}
		protected, err := protectProviderRefreshMaterial(r.Context(), sec, name, body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return true
		}
		body = protected
		if previous, exists := rec.Refresh[body.CredentialKey]; exists && sec != nil {
			keep := make(map[string]struct{}, len(body.MaterialSecretKeys))
			for _, key := range body.MaterialSecretKeys {
				keep[key] = struct{}{}
			}
			for _, key := range previous.MaterialSecretKeys {
				if _, ok := keep[key]; !ok {
					_ = sec.Delete(r.Context(), refreshMaterialKey(name, body.CredentialKey, key))
				}
			}
		}
		if rec.Refresh == nil {
			rec.Refresh = map[string]store.ProviderRefreshConfig{}
		}
		rec.Refresh[body.CredentialKey] = body
		if body.ExpiresAtMS > 0 {
			if rec.CredentialExpiresAtMS == nil {
				rec.CredentialExpiresAtMS = map[string]int64{}
			}
			rec.CredentialExpiresAtMS[body.CredentialKey] = body.ExpiresAtMS
		}
		if err := st.UpsertProvider(rec); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		w.WriteHeader(http.StatusNoContent)
	case len(parts) == 2 && parts[0] == "refresh" && r.Method == http.MethodDelete:
		if rec.Refresh != nil {
			if previous, exists := rec.Refresh[parts[1]]; exists && sec != nil {
				for _, key := range previous.MaterialSecretKeys {
					_ = sec.Delete(r.Context(), refreshMaterialKey(name, parts[1], key))
				}
			}
			delete(rec.Refresh, parts[1])
		}
		if err := st.UpsertProvider(rec); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		w.WriteHeader(http.StatusNoContent)
	case len(parts) == 3 && parts[0] == "refresh" && parts[2] == "rotate" && r.Method == http.MethodPost:
		key := parts[1]
		if err := refreshStoredProviderCredential(r.Context(), st, sec, name, key); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return true
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
	return true
}

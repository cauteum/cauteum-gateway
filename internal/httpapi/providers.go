package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cauteum/cauteum-core/policy"
	"github.com/cauteum/cauteum-gateway/internal/logbuf"
	"github.com/cauteum/cauteum-gateway/internal/storage/store"
	"github.com/cauteum/cauteum-providers/provider"
	"github.com/cauteum/cauteum-runtime/secrets"
	"gopkg.in/yaml.v3"
)

// providerWriteBody is the PUT payload: metadata + optional write-only credential values.
type providerWriteBody struct {
	Name                  string                                 `json:"name"`
	Type                  string                                 `json:"type"`
	Workspace             string                                 `json:"workspace,omitempty"`
	EnvVars               []string                               `json:"env_vars,omitempty"`
	Credentials           map[string]string                      `json:"credentials,omitempty"` // write-only; never returned
	CredentialExpiresAtMS map[string]int64                       `json:"credential_expires_at_ms,omitempty"`
	RuntimeCredentials    bool                                   `json:"runtime_credentials,omitempty"`
	Config                map[string]string                      `json:"config,omitempty"`
	Refresh               map[string]store.ProviderRefreshConfig `json:"refresh,omitempty"`
}

func mountProviderAPI(mux *http.ServeMux, st *store.Store, sec *secrets.LocalEncrypted, builtinDir string) {
	mountProviderAPIWithSources(mux, st, sec, builtinDir, nil)
}

func mountProviderAPIWithSources(mux *http.ServeMux, st *store.Store, sec *secrets.LocalEncrypted, builtinDir string, profileSources []string) {
	profileSources = effectiveProviderProfileSources(profileSources)

	mux.HandleFunc("/v1/providers", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s := st.Snapshot()
			list := make([]store.ProviderRecord, 0, len(s.Providers))
			for _, p := range s.Providers {
				list = append(list, p) // EnvVars only — no secret values
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"providers": list})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/v1/providers/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/providers/"), "/")
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
			if handleProviderRefreshPath(w, r, st, sec, name, sub) {
				return
			}
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodGet:
			p, ok := st.GetProvider(name)
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			// Material values may contain OAuth secrets. The refresh service owns
			// them; provider metadata reads expose only whether a value is set.
			p.Refresh = redactProviderRefresh(p.Refresh)
			_ = json.NewEncoder(w).Encode(p) // never includes credential values
		case http.MethodPut:
			var body providerWriteBody
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			body.Name = name
			if strings.TrimSpace(body.Type) == "" {
				http.Error(w, "type (profile id) required", http.StatusBadRequest)
				return
			}
			profileScope, profileWorkspace := "global", ""
			if strings.TrimSpace(body.Workspace) != "" {
				profileScope, profileWorkspace = "workspace", strings.TrimSpace(body.Workspace)
			}
			if !authorizeProfileScope(w, r, st, profileScope, profileWorkspace, true) {
				return
			}
			if _, _, err := resolveProfileForWorkspaceWithSources(st, builtinDir, body.Type, profileWorkspace, profileSources); err != nil {
				http.Error(w, "unknown profile type: "+err.Error(), http.StatusBadRequest)
				return
			}
			envVars := body.EnvVars
			if len(envVars) == 0 && len(body.Credentials) > 0 {
				for k := range body.Credentials {
					envVars = append(envVars, k)
				}
			}
			for key, cfg := range body.Refresh {
				cfg.CredentialKey = key
				protected, protectErr := protectProviderRefreshMaterial(r.Context(), sec, name, cfg)
				if protectErr != nil {
					http.Error(w, protectErr.Error(), http.StatusServiceUnavailable)
					return
				}
				body.Refresh[key] = protected
			}
			rec := store.ProviderRecord{
				Name:                  name,
				Type:                  body.Type,
				Workspace:             body.Workspace,
				EnvVars:               envVars,
				CredentialExpiresAtMS: body.CredentialExpiresAtMS,
				RuntimeCredentials:    body.RuntimeCredentials,
				Config:                body.Config,
				Refresh:               body.Refresh,
			}
			if err := st.UpsertProvider(rec); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if sec != nil && len(body.Credentials) > 0 {
				if err := sec.PutProviderCredentials(r.Context(), name, body.Credentials); err != nil {
					http.Error(w, "store credentials: "+err.Error(), http.StatusInternalServerError)
					return
				}
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			if err := st.DeleteProvider(name); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if sec != nil {
				_ = sec.DeletePrefix(r.Context(), "provider/"+name+"/")
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

func handleSandboxSubpath(w http.ResponseWriter, r *http.Request, st *store.Store, sec *secrets.LocalEncrypted, logs *logbuf.Hub, builtinDir string, profileSources []string, name, rest string) {
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	switch {
	case len(parts) == 1 && parts[0] == "providers" && r.Method == http.MethodGet:
		sb, ok := st.GetSandbox(name)
		if !ok {
			http.Error(w, "sandbox not found", http.StatusNotFound)
			return
		}
		type att struct {
			Name    string   `json:"name"`
			Type    string   `json:"type,omitempty"`
			EnvVars []string `json:"env_vars,omitempty"`
		}
		list := make([]att, 0, len(sb.AttachedProviders))
		for _, pn := range sb.AttachedProviders {
			a := att{Name: pn}
			if rec, ok := st.GetProvider(pn); ok {
				a.Type = rec.Type
				a.EnvVars = append([]string{}, rec.EnvVars...)
			}
			list = append(list, a)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"providers": list})
	case len(parts) == 1 && parts[0] == "secrets" && r.Method == http.MethodGet:
		// Sidecar resolve: return KEY=VAL map for all attached providers (never logged).
		out, err := resolveSandboxSecretsWithSources(r.Context(), st, sec, builtinDir, name, profileSources)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"secrets": out})
	case len(parts) == 1 && parts[0] == "logs":
		handleSandboxLogs(w, r, logs, name)
	case parts[0] == "proposals":
		sub := ""
		if len(parts) > 1 {
			sub = strings.Join(parts[1:], "/")
		}
		handleSandboxProposals(w, r, st, builtinDir, name, sub)
	case len(parts) == 2 && parts[0] == "providers":
		prov := parts[1]
		switch r.Method {
		case http.MethodPut, http.MethodPost:
			inst, ok := st.GetProvider(prov)
			if !ok {
				http.Error(w, "provider not found", http.StatusNotFound)
				return
			}
			sb, ok := st.GetSandbox(name)
			if !ok {
				http.Error(w, "sandbox not found", http.StatusNotFound)
				return
			}
			if inst.Workspace != "" && inst.Workspace != sb.Workspace {
				http.Error(w, "provider belongs to a different workspace", http.StatusForbidden)
				return
			}
			if err := st.AttachProvider(name, prov); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			if err := st.DetachProvider(name, prov); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// setSandboxBasePolicy validates and stores base YAML, then returns effective YAML.
func setSandboxBasePolicy(st *store.Store, builtinDir, name string, body []byte) (effective []byte, stripped int, err error) {
	return setSandboxBasePolicyWithSources(st, builtinDir, name, body, nil)
}

func setSandboxBasePolicyWithSources(st *store.Store, builtinDir, name string, body []byte, profileSources []string) (effective []byte, stripped int, err error) {
	if _, ok := st.GetSandbox(name); !ok {
		return nil, 0, fmt.Errorf("sandbox %q not found", name)
	}
	doc, err := policy.Parse(body)
	if err != nil {
		return nil, 0, fmt.Errorf("base policy: %w", err)
	}
	doc, stripped = provider.OmitProviderComposed(doc)
	if err := doc.Validate(); err != nil {
		return nil, 0, fmt.Errorf("base policy: %w", err)
	}
	storeYAML := body
	if stripped > 0 {
		storeYAML, err = yaml.Marshal(doc)
		if err != nil {
			return nil, 0, err
		}
	}
	prev, _ := st.GetSandbox(name)
	prevBase := prev.BasePolicyYAML
	if err := st.SetBasePolicy(name, string(storeYAML)); err != nil {
		return nil, 0, err
	}
	effDoc, err := effectivePolicyWithSources(st, builtinDir, name, profileSources)
	if err != nil {
		_ = st.SetBasePolicy(name, prevBase) // roll back
		return nil, 0, fmt.Errorf("effective policy: %w", err)
	}
	b, err := yaml.Marshal(effDoc)
	if err != nil {
		_ = st.SetBasePolicy(name, prevBase)
		return nil, 0, err
	}
	return b, stripped, nil
}

func setSandboxBasePolicyWithSourcesExpected(st *store.Store, builtinDir, name string, body []byte, profileSources []string, expected int) (effective []byte, stripped int, revision int, err error) {
	if _, ok := st.GetSandbox(name); !ok {
		return nil, 0, 0, fmt.Errorf("sandbox %q not found", name)
	}
	doc, err := policy.Parse(body)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("base policy: %w", err)
	}
	doc, stripped = provider.OmitProviderComposed(doc)
	if err := doc.Validate(); err != nil {
		return nil, 0, 0, fmt.Errorf("base policy: %w", err)
	}
	storeYAML := body
	if stripped > 0 {
		storeYAML, err = yaml.Marshal(doc)
		if err != nil {
			return nil, 0, 0, err
		}
	}
	previous, _ := st.GetSandbox(name)
	newRevision, updated, err := st.SetBasePolicyIfRevision(name, string(storeYAML), expected)
	if err != nil {
		return nil, 0, 0, err
	}
	if !updated {
		return nil, 0, newRevision, fmt.Errorf("sandbox policy revision changed")
	}
	effectiveDoc, err := effectivePolicyWithSources(st, builtinDir, name, profileSources)
	if err != nil {
		_ = st.SetBasePolicy(name, previous.BasePolicyYAML)
		return nil, 0, 0, fmt.Errorf("effective policy: %w", err)
	}
	effective, err = yaml.Marshal(effectiveDoc)
	if err != nil {
		_ = st.SetBasePolicy(name, previous.BasePolicyYAML)
		return nil, 0, 0, err
	}
	return effective, stripped, newRevision, nil
}

func resolveSandboxSecrets(ctx context.Context, st *store.Store, sec *secrets.LocalEncrypted, builtinDir, sandbox string) (map[string]string, error) {
	return resolveSandboxSecretsWithSources(ctx, st, sec, builtinDir, sandbox, nil)
}

func resolveSandboxSecretsWithSources(ctx context.Context, st *store.Store, sec *secrets.LocalEncrypted, builtinDir, sandbox string, profileSources []string) (map[string]string, error) {
	return resolveSandboxSecretsWithSourcesAndDrivers(ctx, st, sec, nil, Options{}, builtinDir, sandbox, profileSources)
}

func resolveProviderCredentialsForRecord(ctx context.Context, sec *secrets.LocalEncrypted, drivers *driverRegistry, record store.ProviderRecord, keys []string) (map[string]string, error) {
	if drivers != nil && record.CredentialDriver != "" {
		values, _, err := drivers.resolveProviderCredentialsWithExpiry(ctx, record, keys, sec)
		return values, err
	}
	if sec == nil {
		return nil, fmt.Errorf("local credential storage is not initialized")
	}
	return sec.GetProviderCredentials(ctx, record.Name, keys)
}

func resolveSandboxSecretsWithSourcesAndDrivers(ctx context.Context, st *store.Store, sec *secrets.LocalEncrypted, drivers *driverRegistry, opt Options, builtinDir, sandbox string, profileSources []string) (map[string]string, error) {
	sb, ok := st.GetSandbox(sandbox)
	if !ok {
		return nil, fmt.Errorf("sandbox %q not found", sandbox)
	}
	out := map[string]string{}
	if sec == nil && drivers == nil {
		return out, nil
	}
	for _, pname := range sb.AttachedProviders {
		inst, ok := st.GetProvider(pname)
		if !ok {
			continue
		}
		for key, cfg := range inst.Refresh {
			expiresAt := cfg.ExpiresAtMS
			if expiresAt == 0 {
				expiresAt = inst.CredentialExpiresAtMS[key]
			}
			if expiresAt == 0 {
				continue // no known expiry; first rotation remains an explicit operation
			}
			refreshAt := time.Now().Add(time.Duration(cfg.RefreshBeforeSeconds) * time.Second).UnixMilli()
			if refreshAt >= expiresAt {
				if err := refreshStoredProviderCredentialWithDrivers(ctx, st, sec, drivers, opt, pname, key); err != nil {
					return nil, fmt.Errorf("provider %s credential %s refresh: %w", pname, key, err)
				}
				// Refresh updates the durable expiry and may rotate the set of
				// output keys; use the fresh record for the fail-closed check below.
				inst, _ = st.GetProvider(pname)
			}
		}
		now := time.Now().UnixMilli()
		for key, expiresAt := range inst.CredentialExpiresAtMS {
			if expiresAt > 0 && expiresAt <= now {
				return nil, fmt.Errorf("provider %s credential %s is expired", pname, key)
			}
		}
		keys := inst.EnvVars
		if len(keys) == 0 {
			if prof, _, err := resolveProfileForWorkspaceWithSources(st, builtinDir, inst.Type, sb.Workspace, profileSources); err == nil {
				keys = prof.EnvKeys()
			}
		}
		var creds map[string]string
		var resolvedExpiry map[string]int64
		var err error
		if drivers != nil {
			creds, resolvedExpiry, err = drivers.resolveProviderCredentialsWithExpiry(ctx, inst, keys, sec)
		} else {
			creds, err = sec.GetProviderCredentials(ctx, pname, keys)
		}
		if err != nil {
			return nil, err
		}
		if len(resolvedExpiry) > 0 {
			if inst.CredentialExpiresAtMS == nil {
				inst.CredentialExpiresAtMS = map[string]int64{}
			}
			changed := false
			for key, expiresAt := range resolvedExpiry {
				if inst.CredentialExpiresAtMS[key] != expiresAt {
					inst.CredentialExpiresAtMS[key] = expiresAt
					changed = true
				}
			}
			if changed {
				if err := st.UpsertProvider(inst); err != nil {
					return nil, fmt.Errorf("persist credential expiry: %w", err)
				}
			}
		}
		maps.Copy(out, creds)
	}
	aliasGitHubTokenKeys(out)
	return out, nil
}

// aliasGitHubTokenKeys mirrors GITHUB_TOKEN ↔ GH_TOKEN so guest/policy can use either
// name while the provider instance only stores one key.
func aliasGitHubTokenKeys(out map[string]string) {
	if out == nil {
		return
	}
	gh, hasGH := out["GITHUB_TOKEN"]
	tok, hasTok := out["GH_TOKEN"]
	if hasGH && strings.TrimSpace(gh) != "" && !hasTok {
		out["GH_TOKEN"] = gh
	}
	if hasTok && strings.TrimSpace(tok) != "" && !hasGH {
		out["GITHUB_TOKEN"] = tok
	}
}

func handleSandboxLogs(w http.ResponseWriter, r *http.Request, logs *logbuf.Hub, name string) {
	if logs == nil {
		http.Error(w, "logs unavailable", http.StatusServiceUnavailable)
		return
	}
	q := r.URL.Query()
	switch r.Method {
	case http.MethodPost:
		var body struct {
			Lines []logbuf.Line `json:"lines"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		logs.Append(name, body.Lines)
		w.WriteHeader(http.StatusNoContent)
	case http.MethodGet:
		follow := q.Get("follow") == "1" || q.Get("follow") == "true"
		source := q.Get("source")
		level := q.Get("level")
		var since time.Time
		if s := q.Get("since"); s != "" {
			if dur, err := time.ParseDuration(s); err == nil {
				since = time.Now().UTC().Add(-dur)
			} else if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
				since = t
			}
		}
		limit := 500
		if follow {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "streaming unsupported", http.StatusInternalServerError)
				return
			}
			sent := since
			for {
				lines := logs.Snapshot(name, sent, source, level, 0)
				for _, ln := range lines {
					if !sent.IsZero() && !ln.TS.After(sent) {
						continue
					}
					fmt.Fprintf(w, "data: %s\n\n", formatLogLine(ln))
					sent = ln.TS
				}
				flusher.Flush()
				select {
				case <-r.Context().Done():
					return
				case <-logs.Subscribe(name):
				case <-time.After(providerRotationInterval):
					fmt.Fprintf(w, ": keepalive\n\n")
					flusher.Flush()
				}
			}
		}
		lines := logs.Snapshot(name, since, source, level, limit)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"lines": lines})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func formatLogLine(ln logbuf.Line) string {
	src := ln.Source
	if src == "" {
		src = "proxy"
	}
	return fmt.Sprintf("[%s] %s", src, ln.Text)
}

func authorizeProfileScope(w http.ResponseWriter, r *http.Request, st *store.Store, scope, workspace string, write bool) bool {
	principal := PrincipalFrom(r.Context())
	if principal.Kind == PrincipalNone || principal.IDP == "local" || principal.IDP == "local_dev" {
		return true // direct handler tests and the local operator token
	}
	if scope == "global" {
		for _, role := range principal.Roles {
			if role == "platform-admin" || role == "platform_admin" || role == "cauteum:platform-admin" {
				return true
			}
		}
		http.Error(w, "platform-admin role required for global provider profiles", http.StatusForbidden)
		return false
	}
	ws, ok := st.GetWorkspace(workspace)
	if !ok {
		http.Error(w, "workspace not found", http.StatusNotFound)
		return false
	}
	for _, member := range ws.Members {
		if member.Subject != principal.Subject {
			continue
		}
		role := strings.ToLower(strings.TrimSpace(member.Role))
		if role == "owner" || role == "admin" || !write && (role == "user" || role == "member" || role == "reader" || role == "viewer") {
			return true
		}
	}
	http.Error(w, "workspace membership with profile access required", http.StatusForbidden)
	return false
}

func listProfilesWithSources(st *store.Store, builtinDir, workspace string, profileSources []string) []map[string]string {
	profileSources = effectiveProviderProfileSources(profileSources)
	catalog := map[string]map[string]string{}
	workspaceOverrides := map[string]bool{}
	if providerProfileSourceEnabled(profileSources, "builtin") && builtinDir != "" {
		if m, err := provider.LoadDir(builtinDir); err == nil {
			for id, prof := range m {
				catalog[id] = map[string]string{"id": id, "category": prof.Category, "source": "builtin", "scope": "builtin"}
			}
		}
	}
	if providerProfileSourceEnabled(profileSources, "user") {
		for key, rec := range st.Snapshot().Profiles {
			isWorkspace := rec.Scope == "workspace" || strings.HasPrefix(key, "workspace/")
			if isWorkspace && (workspace == "" || rec.Workspace != workspace) {
				continue
			}
			if !isWorkspace && workspace == "" && rec.Workspace != "" {
				continue
			}
			id := rec.ID
			if !isWorkspace && workspaceOverrides[id] {
				continue
			}
			category := ""
			if prof, err := provider.ParseYAML([]byte(rec.YAML)); err == nil {
				category = prof.Category
			}
			scope := "global"
			if isWorkspace {
				scope = "workspace"
			}
			catalog[id] = map[string]string{"id": id, "category": category, "source": "custom", "scope": scope}
			if isWorkspace {
				workspaceOverrides[id] = true
			}
		}
	}
	ids := make([]string, 0, len(catalog))
	for id := range catalog {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]map[string]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, catalog[id])
	}
	return out
}

func resolveProfileForWorkspaceWithSources(st *store.Store, builtinDir, id, workspace string, profileSources []string) (provider.Profile, string, error) {
	profileSources = effectiveProviderProfileSources(profileSources)
	if providerProfileSourceEnabled(profileSources, "user") {
		if rec, ok := st.GetProfileScoped(id, workspace); ok {
			p, err := provider.ParseYAML([]byte(rec.YAML))
			p.Source = "user"
			p.Scope = "platform"
			if rec.Scope == "workspace" || rec.Workspace != "" {
				p.Scope = "workspace"
			}
			return p, "custom", err
		}
	}
	if providerProfileSourceEnabled(profileSources, "builtin") && builtinDir != "" {
		path := filepath.Join(builtinDir, id+".yaml")
		if _, err := os.Stat(path); err == nil {
			p, err := provider.LoadFile(path)
			p.Source, p.Scope = "builtin", ""
			return p, "builtin", err
		}
		path = filepath.Join(builtinDir, id+".yml")
		if _, err := os.Stat(path); err == nil {
			p, err := provider.LoadFile(path)
			p.Source, p.Scope = "builtin", ""
			return p, "builtin", err
		}
	}
	return provider.Profile{}, "", fmt.Errorf("profile %q not found", id)
}

func effectiveProviderProfileSources(configured []string) []string {
	if configured == nil {
		return []string{"builtin", "user"}
	}
	return append([]string(nil), configured...)
}

func providerProfileSourceEnabled(sources []string, source string) bool {
	for _, configured := range sources {
		if configured == source {
			return true
		}
	}
	return false
}

func effectivePolicyWithSources(st *store.Store, builtinDir, sandbox string, profileSources []string) (policy.Document, error) {
	sb, ok := st.GetSandbox(sandbox)
	if !ok {
		return policy.Document{}, fmt.Errorf("sandbox %q not found", sandbox)
	}
	var base policy.Document
	if strings.TrimSpace(sb.BasePolicyYAML) != "" {
		doc, err := policy.Parse([]byte(sb.BasePolicyYAML))
		if err != nil {
			return policy.Document{}, err
		}
		base = doc
	} else {
		base = policy.Document{Version: 1}
	}
	globalYAML := st.GetGlobalPolicy()
	suppress := false
	if strings.TrimSpace(globalYAML) != "" {
		gdoc, err := policy.Parse([]byte(globalYAML))
		if err != nil {
			return policy.Document{}, err
		}
		if len(gdoc.NetworkAllows()) > 0 {
			suppress = true
		}
		base, err = policy.MergeGlobal(base, gdoc)
		if err != nil {
			return policy.Document{}, err
		}
	}
	var layers []provider.Layer
	for _, name := range sb.AttachedProviders {
		inst, ok := st.GetProvider(name)
		if !ok {
			continue
		}
		prof, _, err := resolveProfileForWorkspaceWithSources(st, builtinDir, inst.Type, sb.Workspace, profileSources)
		if err != nil {
			return policy.Document{}, err
		}
		layers = append(layers, provider.Layer{
			InstanceName: name,
			Profile:      prof,
			EnvVars:      inst.EnvVars,
		})
	}
	return provider.EffectivePolicy(base, layers, suppress)
}

// BuiltinProvidersDir tries to locate cauteum-cli/providers next to the module.
func BuiltinProvidersDir() string {
	return provider.FindBuiltinDir()
}

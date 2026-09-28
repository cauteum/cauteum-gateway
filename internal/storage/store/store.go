// Package store persists whaleshell-gateway registry state as JSON on disk.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// State is durable gateway registry state (JSON on disk).
type State struct {
	GatewayID        string                     `json:"gateway_id"`
	UpdatedAt        time.Time                  `json:"updated_at"`
	Sandboxes        map[string]Sandbox         `json:"sandboxes"`
	Labels           map[string]string          `json:"labels,omitempty"`
	GlobalPolicyYAML string                     `json:"global_policy_yaml,omitempty"`
	Profiles         map[string]ProfileRecord   `json:"profiles,omitempty"`
	Providers        map[string]ProviderRecord  `json:"providers,omitempty"`
	Inference        *InferenceRoute            `json:"inference,omitempty"`
	Settings         map[string]string          `json:"settings,omitempty"`
	AuthToken        string                     `json:"auth_token,omitempty"` // local-dev bearer
	Templates        map[string]TemplateRecord  `json:"templates,omitempty"`
	Services         map[string]ServiceRecord   `json:"services,omitempty"`
	Workspaces       map[string]WorkspaceRecord `json:"workspaces,omitempty"`
	Proposals        map[string]Proposal        `json:"proposals,omitempty"`
	// SandboxTokens holds sha256(supervisor token) per sandbox name.
	SandboxTokens map[string]SandboxToken `json:"sandbox_tokens,omitempty"`
	// SSHSessions is keyed by session id; tokens are stored as sha256 only.
	SSHSessions map[string]SSHSession `json:"ssh_sessions,omitempty"`
}

// InferenceRoute is the gateway-scoped inference.local backend (OpenShell inference set).
type InferenceRoute struct {
	Provider   string `json:"provider"`
	Model      string `json:"model,omitempty"`
	TimeoutSec int    `json:"timeout_sec,omitempty"`
	Version    int    `json:"version,omitempty"`
}

// TemplateRecord is a gateway-stored workload template.
type TemplateRecord struct {
	Name      string            `json:"name"`
	Image     string            `json:"image,omitempty"`
	From      string            `json:"from,omitempty"`
	Policy    string            `json:"policy,omitempty"`
	CPU       float64           `json:"cpu,omitempty"`
	Memory    string            `json:"memory,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	Providers []string          `json:"providers,omitempty"`
	Forwards  []int             `json:"forwards,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	YAML      string            `json:"yaml,omitempty"` // optional raw
}

// Sandbox is one registered sandbox record.
type Sandbox struct {
	Name              string            `json:"name"`
	ID                string            `json:"id,omitempty"`
	Image             string            `json:"image,omitempty"`
	Workspace         string            `json:"workspace,omitempty"`
	Network           string            `json:"network,omitempty"`
	Status            string            `json:"status,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	BasePolicyYAML    string            `json:"base_policy_yaml,omitempty"`
	AttachedProviders []string          `json:"attached_providers,omitempty"`
	PolicyRev         int               `json:"policy_rev,omitempty"`
	PolicyRevisions   []PolicyRevision  `json:"policy_revisions,omitempty"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

// PolicyRevision is one loaded base-policy generation (OpenShell policy list).
type PolicyRevision struct {
	Rev       int       `json:"rev"`
	UpdatedAt time.Time `json:"updated_at"`
	Bytes     int       `json:"bytes"`
	Status    string    `json:"status"`
	YAML      string    `json:"yaml,omitempty"`
}

// MaxPolicyRevisions caps retained revision history per sandbox.
const MaxPolicyRevisions = 32

// PolicyStatusLoaded is recorded after a successful base policy store.
const PolicyStatusLoaded = "loaded"

// ProfileRecord is a custom (imported) provider profile stored as YAML.
type ProfileRecord struct {
	ID              string `json:"id"`
	Scope           string `json:"scope,omitempty"`
	Workspace       string `json:"workspace,omitempty"`
	YAML            string `json:"yaml"`
	ResourceVersion string `json:"resource_version,omitempty"`
	Version         uint64 `json:"version,omitempty"`
}

// ProviderRecord is a named instance referencing a profile.
// EnvVars are key names only; values live in the encrypted secrets store.
type ProviderRecord struct {
	Name                  string                           `json:"name"`
	Type                  string                           `json:"type"`
	Workspace             string                           `json:"workspace,omitempty"`
	EnvVars               []string                         `json:"env_vars,omitempty"`
	CredentialExpiresAtMS map[string]int64                 `json:"credential_expires_at_ms,omitempty"`
	RuntimeCredentials    bool                             `json:"runtime_credentials,omitempty"`
	Config                map[string]string                `json:"config,omitempty"`
	Refresh               map[string]ProviderRefreshConfig `json:"refresh,omitempty"`
}

// ProviderRefreshConfig is gateway-managed credential refresh metadata (OpenShell).
type ProviderRefreshConfig struct {
	CredentialKey string            `json:"credential_key"`
	Strategy      string            `json:"strategy"` // env | oauth2-refresh-token | oauth2-client-credentials | aws-sts-assume-role
	Material      map[string]string `json:"material,omitempty"`
	ExpiresAtMS   int64             `json:"expires_at_ms,omitempty"`
}

// Store persists State under DataDir/state.json.
type Store struct {
	mu      sync.Mutex
	DataDir string
	path    string
	state   State
}

// Open loads or initializes state in dataDir.
func Open(dataDir, gatewayID string) (*Store, error) {
	// State carries provider metadata, auth and session hashes: owner-only.
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dataDir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{
		DataDir: dataDir,
		path:    filepath.Join(dataDir, "state.json"),
		state: State{
			GatewayID:  gatewayID,
			Sandboxes:  map[string]Sandbox{},
			Labels:     map[string]string{},
			Profiles:   map[string]ProfileRecord{},
			Providers:  map[string]ProviderRecord{},
			Settings:   map[string]string{},
			Templates:  map[string]TemplateRecord{},
			Services:   map[string]ServiceRecord{},
			Workspaces: map[string]WorkspaceRecord{},
			Proposals:  map[string]Proposal{},

			SandboxTokens: map[string]SandboxToken{},
			SSHSessions:   map[string]SSHSession{},
		},
	}
	b, err := os.ReadFile(s.path)
	if err == nil {
		if err := json.Unmarshal(b, &s.state); err != nil {
			return nil, fmt.Errorf("gateway store: parse: %w", err)
		}
		if s.state.Sandboxes == nil {
			s.state.Sandboxes = map[string]Sandbox{}
		}
		if s.state.Profiles == nil {
			s.state.Profiles = map[string]ProfileRecord{}
		}
		if s.state.Providers == nil {
			s.state.Providers = map[string]ProviderRecord{}
		}
		if s.state.Settings == nil {
			s.state.Settings = map[string]string{}
		}
		if s.state.Templates == nil {
			s.state.Templates = map[string]TemplateRecord{}
		}
		if s.state.Services == nil {
			s.state.Services = map[string]ServiceRecord{}
		}
		if s.state.Workspaces == nil {
			s.state.Workspaces = map[string]WorkspaceRecord{}
		}
		if s.state.Proposals == nil {
			s.state.Proposals = map[string]Proposal{}
		}
		if s.state.SandboxTokens == nil {
			s.state.SandboxTokens = map[string]SandboxToken{}
		}
		if s.state.SSHSessions == nil {
			s.state.SSHSessions = map[string]SSHSession{}
		}
		if s.state.GatewayID == "" {
			s.state.GatewayID = gatewayID
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return s, s.flushLocked()
}

func (s *Store) flushLocked() error {
	s.state.UpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Snapshot returns a copy of current state.
func (s *Store) Snapshot() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.state
	out.Sandboxes = map[string]Sandbox{}
	for k, v := range s.state.Sandboxes {
		out.Sandboxes[k] = v
	}
	out.Profiles = map[string]ProfileRecord{}
	for k, v := range s.state.Profiles {
		out.Profiles[k] = v
	}
	out.Providers = map[string]ProviderRecord{}
	for k, v := range s.state.Providers {
		out.Providers[k] = v
	}
	out.Settings = map[string]string{}
	for k, v := range s.state.Settings {
		out.Settings[k] = v
	}
	out.Templates = map[string]TemplateRecord{}
	for k, v := range s.state.Templates {
		out.Templates[k] = v
	}
	out.Services = map[string]ServiceRecord{}
	for k, v := range s.state.Services {
		out.Services[k] = v
	}
	out.Workspaces = map[string]WorkspaceRecord{}
	for k, v := range s.state.Workspaces {
		out.Workspaces[k] = v
	}
	if s.state.Inference != nil {
		inf := *s.state.Inference
		out.Inference = &inf
	}
	out.SandboxTokens = nil
	out.SSHSessions = nil
	return out
}

// UpsertSandbox records or updates a sandbox.
func (s *Store) UpsertSandbox(sb Sandbox) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.state.Sandboxes[sb.Name]; ok {
		if sb.Workspace == "" {
			sb.Workspace = prev.Workspace
		}
		if len(sb.AttachedProviders) == 0 && len(prev.AttachedProviders) > 0 {
			sb.AttachedProviders = prev.AttachedProviders
		}
		if sb.BasePolicyYAML == "" && prev.BasePolicyYAML != "" {
			sb.BasePolicyYAML = prev.BasePolicyYAML
		}
		if sb.PolicyRev == 0 && prev.PolicyRev > 0 {
			sb.PolicyRev = prev.PolicyRev
		}
		if len(sb.PolicyRevisions) == 0 && len(prev.PolicyRevisions) > 0 {
			sb.PolicyRevisions = prev.PolicyRevisions
		}
	}
	sb.UpdatedAt = time.Now().UTC()
	s.state.Sandboxes[sb.Name] = sb
	return s.flushLocked()
}

// DeleteSandbox removes a sandbox by name.
func (s *Store) DeleteSandbox(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.state.Sandboxes, name)
	delete(s.state.SandboxTokens, name)
	for id, sess := range s.state.SSHSessions {
		if sess.Sandbox == name {
			delete(s.state.SSHSessions, id)
		}
	}
	return s.flushLocked()
}

// GetSandbox returns a sandbox if present.
func (s *Store) GetSandbox(name string) (Sandbox, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	return sb, ok
}

// SetBasePolicy stores sandbox base policy YAML (OpenShell-style editable layer).
// Attached providers are unchanged; callers build effective policy via provider.EffectivePolicy.
// Each successful store appends a policy revision (capped at MaxPolicyRevisions).
func (s *Store) SetBasePolicy(sandbox, yaml string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[sandbox]
	if !ok {
		return fmt.Errorf("sandbox %q not found", sandbox)
	}
	sb.BasePolicyYAML = yaml
	sb.UpdatedAt = time.Now().UTC()
	sb.PolicyRev++
	rev := PolicyRevision{
		Rev:       sb.PolicyRev,
		UpdatedAt: sb.UpdatedAt,
		Bytes:     len(yaml),
		Status:    PolicyStatusLoaded,
		YAML:      yaml,
	}
	sb.PolicyRevisions = append(sb.PolicyRevisions, rev)
	if len(sb.PolicyRevisions) > MaxPolicyRevisions {
		sb.PolicyRevisions = sb.PolicyRevisions[len(sb.PolicyRevisions)-MaxPolicyRevisions:]
	}
	s.state.Sandboxes[sandbox] = sb
	return s.flushLocked()
}

// ListPolicyRevisions returns revision metadata (newest last).
func (s *Store) ListPolicyRevisions(sandbox string) ([]PolicyRevision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[sandbox]
	if !ok {
		return nil, fmt.Errorf("sandbox %q not found", sandbox)
	}
	out := make([]PolicyRevision, len(sb.PolicyRevisions))
	copy(out, sb.PolicyRevisions)
	return out, nil
}

// GetPolicyRevision returns base YAML for a revision number.
func (s *Store) GetPolicyRevision(sandbox string, rev int) (PolicyRevision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[sandbox]
	if !ok {
		return PolicyRevision{}, fmt.Errorf("sandbox %q not found", sandbox)
	}
	for _, r := range sb.PolicyRevisions {
		if r.Rev == rev {
			return r, nil
		}
	}
	return PolicyRevision{}, fmt.Errorf("sandbox %q: policy revision %d not found", sandbox, rev)
}

// GetGlobalPolicy returns the stored global policy YAML (may be empty).
func (s *Store) GetGlobalPolicy() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.GlobalPolicyYAML
}

// SetGlobalPolicy stores global policy YAML bytes as a string.
func (s *Store) SetGlobalPolicy(yaml string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.GlobalPolicyYAML = yaml
	return s.flushLocked()
}

// UpsertProfile stores a custom profile YAML.
func (s *Store) UpsertProfile(id, yaml string) error {
	return s.UpsertProfileScoped("global", "", id, yaml)
}

func (s *Store) UpsertProfileScoped(scope, workspace, id, yaml string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Profiles == nil {
		s.state.Profiles = map[string]ProfileRecord{}
	}
	key := profileStorageKey(scope, workspace, id)
	version := s.state.Profiles[key].Version + 1
	s.state.Profiles[key] = ProfileRecord{ID: id, Scope: scope, Workspace: workspace, YAML: yaml, ResourceVersion: strconv.FormatUint(version, 10), Version: version}
	return s.flushLocked()
}

// CreateProfile stores a custom profile only when its ID is not already imported.
func (s *Store) CreateProfile(id, yaml string) error {
	return s.CreateProfileScoped("global", "", id, yaml)
}

func (s *Store) CreateProfileScoped(scope, workspace, id, yaml string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Profiles == nil {
		s.state.Profiles = map[string]ProfileRecord{}
	}
	key := profileStorageKey(scope, workspace, id)
	if _, exists := s.state.Profiles[key]; exists {
		return fmt.Errorf("provider profile %q already exists; use profile update", id)
	}
	s.state.Profiles[key] = ProfileRecord{ID: id, Scope: scope, Workspace: workspace, YAML: yaml, ResourceVersion: "1", Version: 1}
	return s.flushLocked()
}

// ReplaceProfile updates an existing imported profile without silently creating it.
func (s *Store) ReplaceProfile(id, yaml string) error {
	return s.ReplaceProfileIfVersion(id, yaml, "")
}

// ReplaceProfileIfVersion atomically updates a profile when its current version
// matches expected. An empty expected value is retained for internal callers.
func (s *Store) ReplaceProfileIfVersion(id, yaml, expected string) error {
	return s.ReplaceProfileIfVersionScoped("global", "", id, yaml, expected)
}

func (s *Store) ReplaceProfileIfVersionScoped(scope, workspace, id, yaml, expected string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := profileStorageKey(scope, workspace, id)
	current, exists := s.state.Profiles[key]
	if !exists {
		return fmt.Errorf("provider profile %q not found; use profile import", id)
	}
	currentVersion := strconv.FormatUint(current.Version, 10)
	if current.Version == 0 {
		currentVersion = "1" // legacy profile records start at the first numeric version
	}
	if expected != "" && currentVersion != expected {
		return fmt.Errorf("provider profile %q changed since it was read", id)
	}
	version := current.Version + 1
	if version == 1 {
		version = 2 // migrate records written before numeric profile versions
	}
	s.state.Profiles[key] = ProfileRecord{ID: id, Scope: scope, Workspace: workspace, YAML: yaml, ResourceVersion: strconv.FormatUint(version, 10), Version: version}
	return s.flushLocked()
}

// DeleteProfile removes a custom profile.
func (s *Store) DeleteProfile(id string) error {
	return s.DeleteProfileScoped("global", "", id)
}

func (s *Store) DeleteProfileScoped(scope, workspace, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.state.Profiles, profileStorageKey(scope, workspace, id))
	return s.flushLocked()
}

// GetProfile returns a custom profile if present.
func (s *Store) GetProfile(id string) (ProfileRecord, bool) {
	return s.GetProfileInScope("global", "", id)
}

// GetProfileScoped resolves a workspace override before the global catalog.
func (s *Store) GetProfileScoped(id, workspace string) (ProfileRecord, bool) {
	if workspace != "" {
		if p, ok := s.GetProfileInScope("workspace", workspace, id); ok {
			return p, true
		}
	}
	return s.GetProfileInScope("global", "", id)
}

// GetProfileInScope reads one exact catalog scope without applying fallback.
func (s *Store) GetProfileInScope(scope, workspace, id string) (ProfileRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := profileStorageKey(scope, workspace, id)
	p, ok := s.state.Profiles[key]
	if !ok && scope == "global" {
		p, ok = s.state.Profiles[id] // legacy records were keyed directly by ID
	}
	if ok {
		if p.Version > 0 {
			p.ResourceVersion = strconv.FormatUint(p.Version, 10)
		} else {
			p.Version = 1
			p.ResourceVersion = "1"
		}
	}
	return p, ok
}

func profileStorageKey(scope, workspace, id string) string {
	if scope == "workspace" {
		return "workspace/" + workspace + "/" + id
	}
	return id
}

// UpsertProvider stores a provider instance (env refs only).
func (s *Store) UpsertProvider(rec ProviderRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Providers == nil {
		s.state.Providers = map[string]ProviderRecord{}
	}
	if prev, ok := s.state.Providers[rec.Name]; ok {
		if rec.Refresh == nil && prev.Refresh != nil {
			rec.Refresh = prev.Refresh
		}
		if rec.CredentialExpiresAtMS == nil && prev.CredentialExpiresAtMS != nil {
			rec.CredentialExpiresAtMS = prev.CredentialExpiresAtMS
		}
	}
	s.state.Providers[rec.Name] = rec
	return s.flushLocked()
}

// DeleteProvider removes a provider instance.
func (s *Store) DeleteProvider(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.state.Providers, name)
	return s.flushLocked()
}

// GetProvider returns a provider instance.
func (s *Store) GetProvider(name string) (ProviderRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.state.Providers[name]
	return p, ok
}

// SetInferenceRoute stores the gateway inference.local route.
func (s *Store) SetInferenceRoute(r InferenceRoute) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.Version++
	if s.state.Inference != nil {
		r.Version = s.state.Inference.Version + 1
	}
	if r.TimeoutSec <= 0 {
		r.TimeoutSec = 60
	}
	s.state.Inference = &r
	return s.flushLocked()
}

// GetInferenceRoute returns the inference route if set.
func (s *Store) GetInferenceRoute() (InferenceRoute, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Inference == nil {
		return InferenceRoute{}, false
	}
	return *s.state.Inference, true
}

// ClearInferenceRoute deletes the inference route.
func (s *Store) ClearInferenceRoute() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Inference = nil
	return s.flushLocked()
}

// SetSetting stores a gateway setting key.
func (s *Store) SetSetting(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Settings == nil {
		s.state.Settings = map[string]string{}
	}
	s.state.Settings[key] = value
	return s.flushLocked()
}

// GetSetting returns a setting.
func (s *Store) GetSetting(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.state.Settings[key]
	return v, ok
}

// DeleteSetting removes a setting.
func (s *Store) DeleteSetting(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.state.Settings, key)
	return s.flushLocked()
}

// AllSettings returns a copy of settings.
func (s *Store) AllSettings() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for k, v := range s.state.Settings {
		out[k] = v
	}
	return out
}

// UpsertTemplate stores a workload template.
func (s *Store) UpsertTemplate(t TemplateRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Templates == nil {
		s.state.Templates = map[string]TemplateRecord{}
	}
	s.state.Templates[t.Name] = t
	return s.flushLocked()
}

// GetTemplate returns a template.
func (s *Store) GetTemplate(name string) (TemplateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.state.Templates[name]
	return t, ok
}

// DeleteTemplate removes a template.
func (s *Store) DeleteTemplate(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.state.Templates, name)
	return s.flushLocked()
}

// ListTemplates returns all templates.
func (s *Store) ListTemplates() []TemplateRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]TemplateRecord, 0, len(s.state.Templates))
	for _, t := range s.state.Templates {
		out = append(out, t)
	}
	return out
}

// EnsureAuthToken returns (and creates if needed) a local-dev bearer token.
func (s *Store) EnsureAuthToken() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.AuthToken == "" {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		s.state.AuthToken = hex.EncodeToString(b[:])
		if err := s.flushLocked(); err != nil {
			return "", err
		}
	}
	return s.state.AuthToken, nil
}

// AuthToken returns the configured bearer token (may be empty).
func (s *Store) AuthToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.AuthToken
}

// AttachProvider appends a provider name to a sandbox attachment list.
func (s *Store) AttachProvider(sandbox, provider string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[sandbox]
	if !ok {
		return fmt.Errorf("sandbox %q not found", sandbox)
	}
	for _, p := range sb.AttachedProviders {
		if p == provider {
			return nil
		}
	}
	sb.AttachedProviders = append(sb.AttachedProviders, provider)
	sb.UpdatedAt = time.Now().UTC()
	s.state.Sandboxes[sandbox] = sb
	return s.flushLocked()
}

// DetachProvider removes a provider from a sandbox attachment list.
func (s *Store) DetachProvider(sandbox, provider string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[sandbox]
	if !ok {
		return fmt.Errorf("sandbox %q not found", sandbox)
	}
	out := sb.AttachedProviders[:0]
	for _, p := range sb.AttachedProviders {
		if p != provider {
			out = append(out, p)
		}
	}
	sb.AttachedProviders = out
	sb.UpdatedAt = time.Now().UTC()
	s.state.Sandboxes[sandbox] = sb
	return s.flushLocked()
}

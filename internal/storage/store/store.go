// Package store persists cautem-gateway registry state as JSON on disk.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// State is durable gateway registry state (JSON on disk).
type State struct {
	GatewayID             string                     `json:"gateway_id"`
	UpdatedAt             time.Time                  `json:"updated_at"`
	Sandboxes             map[string]Sandbox         `json:"sandboxes"`
	Labels                map[string]string          `json:"labels,omitempty"`
	GlobalPolicyYAML      string                     `json:"global_policy_yaml,omitempty"`
	GlobalPolicyRevision  uint64                     `json:"global_policy_revision,omitempty"`
	GlobalPolicyRevisions []PolicyRevision           `json:"global_policy_revisions,omitempty"`
	Profiles              map[string]ProfileRecord   `json:"profiles,omitempty"`
	Providers             map[string]ProviderRecord  `json:"providers,omitempty"`
	Inference             *InferenceRoute            `json:"inference,omitempty"`
	Settings              map[string]string          `json:"settings,omitempty"`
	SettingsRevision      uint64                     `json:"settings_revision,omitempty"`
	AuthToken             string                     `json:"auth_token,omitempty"` // local-dev bearer
	Templates             map[string]TemplateRecord  `json:"templates,omitempty"`
	Services              map[string]ServiceRecord   `json:"services,omitempty"`
	Workspaces            map[string]WorkspaceRecord `json:"workspaces,omitempty"`
	Proposals             map[string]Proposal        `json:"proposals,omitempty"`
	// SandboxTokens holds sha256(supervisor token) per sandbox name.
	SandboxTokens map[string]SandboxToken `json:"sandbox_tokens,omitempty"`
	// SSHSessions is keyed by session id; tokens are stored as sha256 only.
	SSHSessions     map[string]SSHSession `json:"ssh_sessions,omitempty"`
	AuditEvents     []AuditEvent          `json:"audit_events,omitempty"`
	AuditNextID     uint64                `json:"audit_next_id,omitempty"`
	Operations      map[string]Operation  `json:"operations,omitempty"`
	OperationNextID uint64                `json:"operation_next_id,omitempty"`
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
	Name            string            `json:"name"`
	Workspace       string            `json:"workspace,omitempty"`
	ID              string            `json:"id,omitempty"`
	SpecJSON        string            `json:"spec_json,omitempty"`
	CreatedAt       time.Time         `json:"created_at,omitempty"`
	ResourceVersion uint64            `json:"resource_version,omitempty"`
	Image           string            `json:"image,omitempty"`
	From            string            `json:"from,omitempty"`
	Policy          string            `json:"policy,omitempty"`
	CPU             float64           `json:"cpu,omitempty"`
	Memory          string            `json:"memory,omitempty"`
	Env             map[string]string `json:"env,omitempty"`
	Providers       []string          `json:"providers,omitempty"`
	Forwards        []int             `json:"forwards,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	YAML            string            `json:"yaml,omitempty"` // optional raw
}

// CreateScopedTemplate atomically creates a workspace-owned template.
func (s *Store) CreateScopedTemplate(t TemplateRecord) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Templates == nil {
		s.state.Templates = map[string]TemplateRecord{}
	}
	key := scopedTemplateKey(t.Workspace, t.Name)
	if _, exists := s.state.Templates[key]; exists {
		return false, nil
	}
	count := 0
	for _, existing := range s.state.Templates {
		if existing.Workspace == t.Workspace {
			count++
		}
	}
	if count >= 1000 {
		return false, ErrTemplateWorkspaceLimit
	}
	if t.ResourceVersion == 0 {
		t.ResourceVersion = 1
	}
	s.state.Templates[key] = cloneTemplate(t)
	return true, s.flushLocked()
}

func scopedTemplateKey(workspace, name string) string { return workspace + "\x00" + name }

// GetScopedTemplate reads a workspace-owned template.
func (s *Store) GetScopedTemplate(workspace, name string) (TemplateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.state.Templates[scopedTemplateKey(workspace, name)]
	return cloneTemplate(t), ok
}

// DeleteScopedTemplate removes only a template in the given workspace.
func (s *Store) DeleteScopedTemplate(workspace, name string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scopedTemplateKey(workspace, name)
	if _, ok := s.state.Templates[key]; !ok {
		return false, nil
	}
	delete(s.state.Templates, key)
	return true, s.flushLocked()
}

// ListScopedTemplates returns templates in deterministic name order.
func (s *Store) ListScopedTemplates(workspace string) []TemplateRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]TemplateRecord, 0)
	for _, t := range s.state.Templates {
		if workspace == "" || t.Workspace == workspace {
			out = append(out, cloneTemplate(t))
		}
	}
	slices.SortFunc(out, func(a, b TemplateRecord) int {
		if byName := strings.Compare(a.Name, b.Name); byName != 0 {
			return byName
		}
		return strings.Compare(a.Workspace, b.Workspace)
	})
	return out
}

// Sandbox is one registered sandbox record.
type Sandbox struct {
	Name                  string            `json:"name"`
	ID                    string            `json:"id,omitempty"`
	RuntimeID             string            `json:"runtime_id,omitempty"`
	ComputeDriver         string            `json:"compute_driver,omitempty"`
	Image                 string            `json:"image,omitempty"`
	Workspace             string            `json:"workspace,omitempty"`
	Network               string            `json:"network,omitempty"`
	Status                string            `json:"status,omitempty"`
	SupervisorInstanceID  string            `json:"supervisor_instance_id,omitempty"`
	MainProcessInstanceID string            `json:"main_process_instance_id,omitempty"`
	MainProcessExitCode   *int32            `json:"main_process_exit_code,omitempty"`
	MainProcessFinalized  bool              `json:"main_process_finalized,omitempty"`
	SpecJSON              string            `json:"spec_json,omitempty"`
	Labels                map[string]string `json:"labels,omitempty"`
	Settings              map[string]string `json:"settings,omitempty"`
	SettingsRevision      uint64            `json:"settings_revision,omitempty"`
	ResourceVersion       uint64            `json:"resource_version,omitempty"`
	Annotations           map[string]string `json:"annotations,omitempty"`
	CreatedAt             time.Time         `json:"created_at,omitempty"`
	BasePolicyYAML        string            `json:"base_policy_yaml,omitempty"`
	AttachedProviders     []string          `json:"attached_providers,omitempty"`
	PolicyRev             int               `json:"policy_rev,omitempty"`
	ActivePolicyVersion   uint32            `json:"active_policy_version,omitempty"`
	PolicyRevisions       []PolicyRevision  `json:"policy_revisions,omitempty"`
	UpdatedAt             time.Time         `json:"updated_at"`
}

// PolicyRevision is one loaded base-policy generation (OpenShell policy list).
type PolicyRevision struct {
	Rev               int               `json:"rev"`
	GlobalRevision    uint64            `json:"global_revision,omitempty"`
	Cleared           bool              `json:"cleared,omitempty"`
	UpdatedAt         time.Time         `json:"updated_at"`
	LoadedAt          time.Time         `json:"loaded_at,omitempty"`
	Bytes             int               `json:"bytes"`
	Status            string            `json:"status"`
	LoadError         string            `json:"load_error,omitempty"`
	YAML              string            `json:"yaml,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty"`
	ExpectedSandboxes []string          `json:"expected_sandboxes,omitempty"`
	AppliedSandboxes  []string          `json:"applied_sandboxes,omitempty"`
}

// ErrResourceVersionConflict indicates that a config mutation used a stale resource version.
var ErrResourceVersionConflict = fmt.Errorf("sandbox resource version conflict")
var ErrSandboxPolicyManagedGlobally = fmt.Errorf("sandbox policy is managed by the global policy")

// ErrSandboxProviderLimit indicates a sandbox exceeds OpenShell's provider cap.
var ErrSandboxProviderLimit = fmt.Errorf("sandbox provider limit reached")

// ErrTemplateWorkspaceLimit is returned when a workspace already owns 1000 templates.
var ErrTemplateWorkspaceLimit = fmt.Errorf("workspace sandbox template limit reached")

// ApplySandboxConfig atomically applies a sandbox setting or base-policy update,
// annotation projection, and optimistic resource-version check.
func (s *Store) ApplySandboxConfig(name string, expectedResourceVersion uint64, annotations map[string]string, settingKey, settingValue string, deleteSetting bool, policyYAML *string) (Sandbox, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return Sandbox{}, false, fmt.Errorf("sandbox %q not found", name)
	}
	if expectedResourceVersion != 0 && expectedResourceVersion != sb.ResourceVersion {
		return Sandbox{}, false, ErrResourceVersionConflict
	}
	if policyYAML != nil && strings.TrimSpace(s.state.GlobalPolicyYAML) != "" {
		return Sandbox{}, false, ErrSandboxPolicyManagedGlobally
	}
	previous := cloneSandbox(sb)
	sb = cloneSandbox(sb)
	changed := false
	policyChanged := false
	deleted := false
	if policyYAML != nil {
		provenanceChanged := false
		if len(annotations) > 0 && len(sb.PolicyRevisions) > 0 {
			latest := sb.PolicyRevisions[len(sb.PolicyRevisions)-1].Annotations
			for key, value := range annotations {
				if latest[key] != value {
					provenanceChanged = true
					break
				}
			}
		}
		if sb.BasePolicyYAML != *policyYAML || sb.PolicyRev == 0 || len(sb.PolicyRevisions) == 0 || provenanceChanged {
			if sb.PolicyRev == int(^uint(0)>>1) {
				return Sandbox{}, false, fmt.Errorf("sandbox policy revision overflow")
			}
			sb.BasePolicyYAML = *policyYAML
			sb.PolicyRev++
			changed, policyChanged = true, true
		}
	} else if settingKey != "" {
		if deleteSetting {
			_, deleted = sb.Settings[settingKey]
			if deleted {
				delete(sb.Settings, settingKey)
				if sb.SettingsRevision == ^uint64(0) {
					return Sandbox{}, false, fmt.Errorf("sandbox settings revision overflow")
				}
				sb.SettingsRevision++
				changed = true
			}
		} else {
			if sb.Settings == nil {
				sb.Settings = map[string]string{}
			}
			if current, exists := sb.Settings[settingKey]; !exists || current != settingValue {
				if sb.SettingsRevision == ^uint64(0) {
					return Sandbox{}, false, fmt.Errorf("sandbox settings revision overflow")
				}
				sb.Settings[settingKey] = settingValue
				sb.SettingsRevision++
				changed = true
			}
		}
	}
	annotationChanged := false
	if len(annotations) > 0 {
		if sb.Annotations == nil {
			sb.Annotations = map[string]string{}
		}
		for key, value := range annotations {
			if old, exists := sb.Annotations[key]; !exists || old != value {
				sb.Annotations[key] = value
				annotationChanged = true
			}
		}
	}
	changed = changed || annotationChanged
	if changed {
		if sb.ResourceVersion == ^uint64(0) {
			return Sandbox{}, false, fmt.Errorf("sandbox resource version overflow")
		}
		sb.ResourceVersion++
		sb.UpdatedAt = time.Now().UTC()
		if policyChanged {
			rev := PolicyRevision{Rev: sb.PolicyRev, UpdatedAt: sb.UpdatedAt, Bytes: len(sb.BasePolicyYAML), Status: PolicyStatusPending, YAML: sb.BasePolicyYAML, Annotations: maps.Clone(annotations)}
			sb.PolicyRevisions = append(sb.PolicyRevisions, rev)
			if len(sb.PolicyRevisions) > MaxPolicyRevisions {
				sb.PolicyRevisions = sb.PolicyRevisions[len(sb.PolicyRevisions)-MaxPolicyRevisions:]
			}
		}
		s.state.Sandboxes[name] = sb
		if err := s.flushLocked(); err != nil {
			s.state.Sandboxes[name] = previous
			return Sandbox{}, false, err
		}
	}
	return cloneSandbox(sb), deleted, nil
}

// ApplySandboxProvider atomically updates the provider attachment list and its
// serialized sandbox spec under an optional resource-version precondition.
func (s *Store) ApplySandboxProvider(name string, expectedResourceVersion uint64, provider string, attach bool) (Sandbox, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return Sandbox{}, false, fmt.Errorf("sandbox %q not found", name)
	}
	if expectedResourceVersion != 0 && expectedResourceVersion != sb.ResourceVersion {
		return Sandbox{}, false, ErrResourceVersionConflict
	}
	previous := cloneSandbox(sb)
	sb = cloneSandbox(sb)
	var spec map[string]json.RawMessage
	if strings.TrimSpace(sb.SpecJSON) != "" {
		if err := json.Unmarshal([]byte(sb.SpecJSON), &spec); err != nil {
			return Sandbox{}, false, fmt.Errorf("decode stored sandbox spec: %w", err)
		}
	}
	baseProviders := sb.AttachedProviders
	if baseProviders == nil && spec != nil {
		if encoded, exists := spec["providers"]; exists {
			if err := json.Unmarshal(encoded, &baseProviders); err != nil {
				return Sandbox{}, false, fmt.Errorf("decode stored sandbox providers: %w", err)
			}
		}
	}
	providers := make([]string, 0, len(baseProviders)+1)
	for _, current := range baseProviders {
		if !slices.Contains(providers, current) {
			providers = append(providers, current)
		}
	}
	changed := len(providers) != len(baseProviders)
	if attach {
		if !slices.Contains(providers, provider) {
			if len(providers) >= 32 {
				return Sandbox{}, false, ErrSandboxProviderLimit
			}
			providers = append(providers, provider)
			changed = true
		}
	} else {
		filtered := make([]string, 0, len(providers))
		for _, current := range providers {
			if current == provider {
				changed = true
				continue
			}
			if !slices.Contains(filtered, current) {
				filtered = append(filtered, current)
			}
		}
		providers = filtered
	}
	if !changed {
		return cloneSandbox(sb), false, nil
	}
	if sb.ResourceVersion == ^uint64(0) {
		return Sandbox{}, false, fmt.Errorf("sandbox resource version overflow")
	}
	sb.AttachedProviders = providers
	if spec == nil {
		spec = make(map[string]json.RawMessage)
	}
	providerJSON, err := json.Marshal(providers)
	if err != nil {
		return Sandbox{}, false, err
	}
	spec["providers"] = providerJSON
	updatedSpec, err := json.Marshal(spec)
	if err != nil {
		return Sandbox{}, false, err
	}
	sb.SpecJSON = string(updatedSpec)
	sb.ResourceVersion++
	sb.UpdatedAt = time.Now().UTC()
	s.state.Sandboxes[name] = sb
	if err := s.flushLocked(); err != nil {
		s.state.Sandboxes[name] = previous
		return Sandbox{}, false, err
	}
	return cloneSandbox(sb), true, nil
}

// MaxPolicyRevisions caps retained revision history per sandbox.
const MaxPolicyRevisions = 32

// PolicyStatusLoaded is recorded after a successful base policy store.
const PolicyStatusLoaded = "loaded"
const PolicyStatusPending = "pending"
const PolicyStatusFailed = "failed"
const PolicyStatusSuperseded = "superseded"

// ReportPolicyStatus records the supervisor's load result for a stored policy revision.
func (s *Store) ReportPolicyStatus(sandboxID string, revision int, status, loadError string, loadedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	name := sandboxID
	if _, ok := s.state.Sandboxes[name]; !ok {
		for key, sandbox := range s.state.Sandboxes {
			if sandbox.ID == sandboxID {
				name = key
				break
			}
		}
	}
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return fmt.Errorf("sandbox %q not found", sandboxID)
	}
	found := false
	globalRevision := uint64(0)
	for i := range sb.PolicyRevisions {
		if sb.PolicyRevisions[i].Rev == revision {
			sb.PolicyRevisions[i].Status = status
			sb.PolicyRevisions[i].LoadError = loadError
			sb.PolicyRevisions[i].LoadedAt = loadedAt
			globalRevision = sb.PolicyRevisions[i].GlobalRevision
			found = true
		} else if status == PolicyStatusLoaded && sb.PolicyRevisions[i].Rev < revision && sb.PolicyRevisions[i].Status != PolicyStatusSuperseded {
			sb.PolicyRevisions[i].Status = PolicyStatusSuperseded
		}
	}
	if !found {
		return fmt.Errorf("sandbox %q policy revision %d not found", sandboxID, revision)
	}
	if status == PolicyStatusLoaded && uint32(revision) >= sb.ActivePolicyVersion {
		sb.ActivePolicyVersion = uint32(revision)
	}
	if globalRevision != 0 {
		for i := range s.state.GlobalPolicyRevisions {
			global := &s.state.GlobalPolicyRevisions[i]
			if uint64(global.Rev) != globalRevision || (global.Status != PolicyStatusPending && global.Status != PolicyStatusFailed) {
				continue
			}
			if status == PolicyStatusFailed {
				global.Status = PolicyStatusFailed
				global.LoadError = loadError
				continue
			}
			if status == PolicyStatusLoaded && !slices.Contains(global.AppliedSandboxes, name) {
				global.AppliedSandboxes = append(global.AppliedSandboxes, name)
				slices.Sort(global.AppliedSandboxes)
			}
			if status == PolicyStatusLoaded && len(global.AppliedSandboxes) == len(global.ExpectedSandboxes) {
				global.Status = PolicyStatusLoaded
				global.LoadError = ""
				global.LoadedAt = loadedAt
			}
		}
	}
	if sb.ResourceVersion == ^uint64(0) {
		return fmt.Errorf("sandbox resource version overflow")
	}
	sb.ResourceVersion++
	sb.UpdatedAt = time.Now().UTC()
	s.state.Sandboxes[name] = sb
	return s.flushLocked()
}

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
	CredentialDriver      string                           `json:"credential_driver,omitempty"`
	CredentialHandles     map[string]CredentialHandle      `json:"credential_handles,omitempty"`
	CredentialExpiresAtMS map[string]int64                 `json:"credential_expires_at_ms,omitempty"`
	RuntimeCredentials    bool                             `json:"runtime_credentials,omitempty"`
	Config                map[string]string                `json:"config,omitempty"`
	Refresh               map[string]ProviderRefreshConfig `json:"refresh,omitempty"`
}

// CredentialHandle is the durable non-secret reference owned by a configured
// CredentialDriver. Values are never persisted here.
type CredentialHandle struct {
	Driver   string            `json:"driver"`
	Handle   string            `json:"handle"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ProviderRefreshConfig is gateway-managed credential refresh metadata (OpenShell).
type ProviderRefreshConfig struct {
	CredentialKey          string            `json:"credential_key"`
	Strategy               string            `json:"strategy"` // env | oauth2-refresh-token | oauth2-client-credentials | aws-sts-assume-role
	Material               map[string]string `json:"material,omitempty"`
	MaterialSecretKeys     []string          `json:"material_secret_keys,omitempty"`
	MaterialCredentialKeys map[string]string `json:"material_credential_keys,omitempty"`
	Outputs                map[string]string `json:"outputs,omitempty"` // response field -> provider env key
	RefreshBeforeSeconds   int64             `json:"refresh_before_seconds,omitempty"`
	MaxLifetimeSeconds     int64             `json:"max_lifetime_seconds,omitempty"`
	ExpiresAtMS            int64             `json:"expires_at_ms,omitempty"`
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
	if err := restrictOwnerAccess(dataDir, true); err != nil {
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
			Operations: map[string]Operation{},

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
		for name, sandbox := range s.state.Sandboxes {
			if sandbox.ResourceVersion == 0 {
				sandbox.ResourceVersion = 1
				s.state.Sandboxes[name] = sandbox
			}
			if sandbox.SettingsRevision == 0 && len(sandbox.Settings) > 0 {
				sandbox.SettingsRevision = 1
				s.state.Sandboxes[name] = sandbox
			}
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
		// Older store files predate revision tracking. Treat their non-empty
		// settings snapshot as the first revision.
		if s.state.SettingsRevision == 0 && len(s.state.Settings) > 0 {
			s.state.SettingsRevision = 1
		}
		if s.state.GlobalPolicyRevision == 0 && strings.TrimSpace(s.state.GlobalPolicyYAML) != "" {
			s.state.GlobalPolicyRevision = 1
		}
		if len(s.state.GlobalPolicyRevisions) == 0 && strings.TrimSpace(s.state.GlobalPolicyYAML) != "" {
			s.state.GlobalPolicyRevisions = []PolicyRevision{{Rev: int(s.state.GlobalPolicyRevision), UpdatedAt: time.Now().UTC(), Bytes: len(s.state.GlobalPolicyYAML), Status: PolicyStatusLoaded, YAML: s.state.GlobalPolicyYAML}}
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
		if s.state.Operations == nil {
			s.state.Operations = map[string]Operation{}
		}
		for id, operation := range s.state.Operations {
			if operation.State == OperationRunning {
				operation.State = OperationUncertain
				operation.UpdatedAt = time.Now().UTC()
				s.state.Operations[id] = operation
			}
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
	return writeOwnerOnlyAtomic(s.path, b)
}

// Snapshot returns an independent copy of registry state without authentication secrets.
func (s *Store) Snapshot() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.state
	out.Sandboxes = map[string]Sandbox{}
	for name, sb := range s.state.Sandboxes {
		out.Sandboxes[name] = cloneSandbox(sb)
	}
	out.Profiles = map[string]ProfileRecord{}
	maps.Copy(out.Profiles, s.state.Profiles)
	out.Providers = map[string]ProviderRecord{}
	for name, rec := range s.state.Providers {
		out.Providers[name] = cloneProvider(rec)
	}
	out.Settings = map[string]string{}
	maps.Copy(out.Settings, s.state.Settings)
	out.Templates = map[string]TemplateRecord{}
	for name, record := range s.state.Templates {
		out.Templates[name] = cloneTemplate(record)
	}
	out.Services = map[string]ServiceRecord{}
	maps.Copy(out.Services, s.state.Services)
	out.Workspaces = map[string]WorkspaceRecord{}
	for name, ws := range s.state.Workspaces {
		out.Workspaces[name] = cloneWorkspace(ws)
	}
	if s.state.Inference != nil {
		inf := *s.state.Inference
		out.Inference = &inf
	}
	out.Labels = maps.Clone(s.state.Labels)
	out.GlobalPolicyRevisions = clonePolicyRevisions(s.state.GlobalPolicyRevisions)
	out.AuditEvents = slices.Clone(s.state.AuditEvents)
	out.Operations = maps.Clone(s.state.Operations)
	out.Proposals = maps.Clone(s.state.Proposals)
	for id, proposal := range out.Proposals {
		out.Proposals[id] = cloneProposal(proposal)
	}
	out.AuthToken = ""
	out.SandboxTokens = nil
	out.SSHSessions = nil
	return out
}

// UpsertSandbox records or updates a sandbox.
func (s *Store) UpsertSandbox(sb Sandbox) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.state.Sandboxes[sb.Name]; ok {
		if sb.ResourceVersion == 0 {
			sb.ResourceVersion = prev.ResourceVersion
		}
		if sb.Annotations == nil && prev.Annotations != nil {
			sb.Annotations = prev.Annotations
		}
		if sb.Workspace == "" {
			sb.Workspace = prev.Workspace
		}
		if sb.Settings == nil && prev.Settings != nil {
			sb.Settings = prev.Settings
		}
		if sb.SettingsRevision == 0 && prev.SettingsRevision > 0 {
			sb.SettingsRevision = prev.SettingsRevision
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
		if sb.MainProcessInstanceID == "" {
			sb.MainProcessInstanceID = prev.MainProcessInstanceID
		}
		if sb.SupervisorInstanceID == "" {
			sb.SupervisorInstanceID = prev.SupervisorInstanceID
		}
		if sb.MainProcessExitCode == nil && prev.MainProcessExitCode != nil {
			code := *prev.MainProcessExitCode
			sb.MainProcessExitCode = &code
		}
		if prev.MainProcessFinalized {
			sb.MainProcessFinalized = true
		}
	} else if sb.ResourceVersion == 0 {
		sb.ResourceVersion = 1
	}
	if sb.CreatedAt.IsZero() {
		sb.CreatedAt = sb.UpdatedAt
	}
	sb.UpdatedAt = time.Now().UTC()
	s.state.Sandboxes[sb.Name] = cloneSandbox(sb)
	return s.flushLocked()
}

// RecordMainProcessExit durably stores the canonical process result. Repeated
// reports are idempotent; the first result wins if duplicate reports conflict.
func (s *Store) RecordMainProcessExit(name, instanceID string, exitCode int32) (Sandbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return Sandbox{}, fmt.Errorf("sandbox %q not found", name)
	}
	if sb.MainProcessExitCode != nil {
		return cloneSandbox(sb), nil
	}
	code := exitCode
	sb.MainProcessInstanceID = instanceID
	sb.MainProcessExitCode = &code
	sb.MainProcessFinalized = false
	if !strings.EqualFold(sb.Status, "error") && !strings.EqualFold(sb.Status, "failed") {
		if exitCode == 0 {
			sb.Status = "completed"
		} else {
			sb.Status = "error"
		}
	}
	sb.ResourceVersion++
	sb.UpdatedAt = time.Now().UTC()
	s.state.Sandboxes[name] = cloneSandbox(sb)
	if err := s.flushLocked(); err != nil {
		return Sandbox{}, err
	}
	return cloneSandbox(sb), nil
}

// BeginSandboxStart clears the previous process result before a restarted
// runtime can report an early exit under its new supervisor instance.
func (s *Store) BeginSandboxStart(name string) (Sandbox, error) {
	return s.BeginSandboxStartCAS(name, 0)
}

// BeginSandboxStartCAS rejects a stale UI transition atomically with the
// registry's starting transition. Zero retains OpenShell's legacy behavior.
func (s *Store) BeginSandboxStartCAS(name string, expectedVersion uint64) (Sandbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return Sandbox{}, fmt.Errorf("sandbox %q not found", name)
	}
	if expectedVersion != 0 && sb.ResourceVersion != expectedVersion {
		return Sandbox{}, ErrResourceVersionConflict
	}
	sb.Status = "starting"
	sb.SupervisorInstanceID = ""
	sb.MainProcessInstanceID = ""
	sb.MainProcessExitCode = nil
	sb.MainProcessFinalized = false
	sb.ResourceVersion++
	sb.UpdatedAt = time.Now().UTC()
	s.state.Sandboxes[name] = cloneSandbox(sb)
	if err := s.flushLocked(); err != nil {
		return Sandbox{}, err
	}
	return cloneSandbox(sb), nil
}

// SetSupervisorInstance records the latest accepted control-session instance
// so reports from a disconnected, superseded supervisor cannot become canonical.
func (s *Store) SetSupervisorInstance(name, instanceID string) (Sandbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return Sandbox{}, fmt.Errorf("sandbox %q not found", name)
	}
	if sb.SupervisorInstanceID != instanceID {
		sb.SupervisorInstanceID = instanceID
		sb.ResourceVersion++
		sb.UpdatedAt = time.Now().UTC()
		s.state.Sandboxes[name] = cloneSandbox(sb)
		if err := s.flushLocked(); err != nil {
			return Sandbox{}, err
		}
	}
	return cloneSandbox(sb), nil
}

// MarkSandboxRunning avoids overwriting a main-process exit reported while
// the runtime's supervisor readiness handshake was in progress.
func (s *Store) MarkSandboxRunning(name string) (Sandbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return Sandbox{}, fmt.Errorf("sandbox %q not found", name)
	}
	if sb.MainProcessExitCode == nil {
		sb.Status = "running"
		sb.ResourceVersion++
		sb.UpdatedAt = time.Now().UTC()
		s.state.Sandboxes[name] = cloneSandbox(sb)
		if err := s.flushLocked(); err != nil {
			return Sandbox{}, err
		}
	}
	return cloneSandbox(sb), nil
}

// BeginSandboxStop records the stopping transition before a backend stop call.
// Persisting the intermediate state lets recovery/watchers distinguish an
// intentional stop from a daemon outage or an unexpected process exit.
func (s *Store) BeginSandboxStop(name string) (Sandbox, error) {
	return s.BeginSandboxStopCAS(name, 0)
}

// BeginSandboxStopCAS checks the expected version under the store lock.
func (s *Store) BeginSandboxStopCAS(name string, expectedVersion uint64) (Sandbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return Sandbox{}, fmt.Errorf("sandbox %q not found", name)
	}
	if expectedVersion != 0 && sb.ResourceVersion != expectedVersion {
		return Sandbox{}, ErrResourceVersionConflict
	}
	if strings.EqualFold(sb.Status, "stopping") {
		return Sandbox{}, fmt.Errorf("sandbox %q is already stopping", name)
	}
	sb.Status = "stopping"
	sb.ResourceVersion++
	sb.UpdatedAt = time.Now().UTC()
	s.state.Sandboxes[name] = cloneSandbox(sb)
	if err := s.flushLocked(); err != nil {
		return Sandbox{}, err
	}
	return cloneSandbox(sb), nil
}

// RestoreSandboxStatusCAS rolls back a failed stop transition only when the
// registry still contains that transition. It preserves an earlier error
// state instead of claiming the runtime is running after a failed stop.
func (s *Store) RestoreSandboxStatusCAS(name string, transitionVersion uint64, previousStatus string) (Sandbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return Sandbox{}, fmt.Errorf("sandbox %q not found", name)
	}
	if sb.ResourceVersion != transitionVersion || !strings.EqualFold(sb.Status, "stopping") {
		return Sandbox{}, ErrResourceVersionConflict
	}
	if sb.ResourceVersion == ^uint64(0) {
		return Sandbox{}, fmt.Errorf("sandbox resource version overflow")
	}
	if strings.TrimSpace(previousStatus) == "" {
		previousStatus = "error"
	}
	sb.Status = previousStatus
	sb.ResourceVersion++
	sb.UpdatedAt = time.Now().UTC()
	s.state.Sandboxes[name] = sb
	if err := s.flushLocked(); err != nil {
		return Sandbox{}, err
	}
	return cloneSandbox(sb), nil
}

// BeginSandboxDeleteCAS reserves a deletion before backend side effects.
// Zero expectedVersion retains OpenShell's legacy unversioned behavior.
func (s *Store) BeginSandboxDeleteCAS(name string, expectedVersion uint64) (Sandbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return Sandbox{}, fmt.Errorf("sandbox %q not found", name)
	}
	if expectedVersion != 0 && sb.ResourceVersion != expectedVersion {
		return Sandbox{}, ErrResourceVersionConflict
	}
	if strings.EqualFold(sb.Status, "deleting") {
		return Sandbox{}, fmt.Errorf("sandbox %q is already deleting", name)
	}
	sb.Status = "deleting"
	sb.ResourceVersion++
	sb.UpdatedAt = time.Now().UTC()
	s.state.Sandboxes[name] = cloneSandbox(sb)
	if err := s.flushLocked(); err != nil {
		return Sandbox{}, err
	}
	return cloneSandbox(sb), nil
}

// MarkSandboxStopped records a completed backend stop.
func (s *Store) MarkSandboxStopped(name string) (Sandbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return Sandbox{}, fmt.Errorf("sandbox %q not found", name)
	}
	sb.Status = "stopped"
	sb.ResourceVersion++
	sb.UpdatedAt = time.Now().UTC()
	s.state.Sandboxes[name] = cloneSandbox(sb)
	if err := s.flushLocked(); err != nil {
		return Sandbox{}, err
	}
	return cloneSandbox(sb), nil
}

// FinalizeMainProcessExit marks terminal delivery complete after the result
// was recorded. Repeated finalization for the same instance is harmless.
func (s *Store) FinalizeMainProcessExit(name, instanceID string) (Sandbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return Sandbox{}, fmt.Errorf("sandbox %q not found", name)
	}
	if sb.MainProcessExitCode == nil {
		return Sandbox{}, fmt.Errorf("main-process exit has not been reported")
	}
	if sb.MainProcessInstanceID != "" && sb.MainProcessInstanceID != instanceID {
		return Sandbox{}, fmt.Errorf("main-process instance does not match the terminal result")
	}
	if !sb.MainProcessFinalized {
		sb.MainProcessFinalized = true
		sb.ResourceVersion++
		sb.UpdatedAt = time.Now().UTC()
		s.state.Sandboxes[name] = cloneSandbox(sb)
		if err := s.flushLocked(); err != nil {
			return Sandbox{}, err
		}
	}
	return cloneSandbox(sb), nil
}

// DeleteSandbox removes a sandbox by name.
func (s *Store) DeleteSandbox(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.state.Sandboxes, name)
	delete(s.state.SandboxTokens, name)
	now := time.Now().UTC()
	for i := range s.state.GlobalPolicyRevisions {
		revision := &s.state.GlobalPolicyRevisions[i]
		if revision.Status != PolicyStatusPending && revision.Status != PolicyStatusFailed {
			continue
		}
		revision.ExpectedSandboxes = slices.DeleteFunc(revision.ExpectedSandboxes, func(candidate string) bool { return candidate == name })
		revision.AppliedSandboxes = slices.DeleteFunc(revision.AppliedSandboxes, func(candidate string) bool { return candidate == name })
		if len(revision.AppliedSandboxes) == len(revision.ExpectedSandboxes) {
			revision.Status = PolicyStatusLoaded
			revision.LoadError = ""
			revision.LoadedAt = now
		}
	}
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
	return cloneSandbox(sb), ok
}

// GetSandboxByID resolves the gateway's durable sandbox ID while retaining
// GetSandbox's name-keyed storage contract.
func (s *Store) GetSandboxByID(id string) (Sandbox, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sb := range s.state.Sandboxes {
		if sb.ID == id {
			return cloneSandbox(sb), true
		}
	}
	return Sandbox{}, false
}

// ListSandboxes returns sandbox records in stable name order.
func (s *Store) ListSandboxes() []Sandbox {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0, len(s.state.Sandboxes))
	for name := range s.state.Sandboxes {
		names = append(names, name)
	}
	slices.Sort(names)
	out := make([]Sandbox, 0, len(names))
	for _, name := range names {
		out = append(out, cloneSandbox(s.state.Sandboxes[name]))
	}
	return out
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
	if sb.BasePolicyYAML == yaml && sb.PolicyRev > 0 && len(sb.PolicyRevisions) > 0 {
		return nil
	}
	if sb.ResourceVersion == ^uint64(0) {
		return fmt.Errorf("sandbox resource version overflow")
	}
	if sb.PolicyRev == int(^uint(0)>>1) {
		return fmt.Errorf("sandbox policy revision overflow")
	}
	previous := cloneSandbox(sb)
	sb.ResourceVersion++
	sb.BasePolicyYAML = yaml
	sb.UpdatedAt = time.Now().UTC()
	sb.PolicyRev++
	rev := PolicyRevision{
		Rev:       sb.PolicyRev,
		UpdatedAt: sb.UpdatedAt,
		Bytes:     len(yaml),
		Status:    PolicyStatusPending,
		YAML:      yaml,
	}
	sb.PolicyRevisions = append(sb.PolicyRevisions, rev)
	if len(sb.PolicyRevisions) > MaxPolicyRevisions {
		sb.PolicyRevisions = sb.PolicyRevisions[len(sb.PolicyRevisions)-MaxPolicyRevisions:]
	}
	s.state.Sandboxes[sandbox] = sb
	if err := s.flushLocked(); err != nil {
		s.state.Sandboxes[sandbox] = previous
		return err
	}
	return nil
}

// SetBasePolicyIfRevision stores the policy only when the observed revision is current.
func (s *Store) SetBasePolicyIfRevision(sandbox, yaml string, expected int) (int, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[sandbox]
	if !ok {
		return 0, false, fmt.Errorf("sandbox %q not found", sandbox)
	}
	if strings.TrimSpace(s.state.GlobalPolicyYAML) != "" {
		return sb.PolicyRev, false, ErrSandboxPolicyManagedGlobally
	}
	if sb.PolicyRev != expected {
		return sb.PolicyRev, false, nil
	}
	if sb.BasePolicyYAML == yaml && sb.PolicyRev > 0 && len(sb.PolicyRevisions) > 0 {
		return sb.PolicyRev, true, nil
	}
	if sb.ResourceVersion == ^uint64(0) || sb.PolicyRev == int(^uint(0)>>1) {
		return sb.PolicyRev, false, fmt.Errorf("sandbox policy revision overflow")
	}
	previous := cloneSandbox(sb)
	sb.ResourceVersion++
	sb.BasePolicyYAML = yaml
	sb.UpdatedAt = time.Now().UTC()
	sb.PolicyRev++
	revision := PolicyRevision{Rev: sb.PolicyRev, UpdatedAt: sb.UpdatedAt, Bytes: len(yaml), Status: PolicyStatusPending, YAML: yaml}
	sb.PolicyRevisions = append(sb.PolicyRevisions, revision)
	if len(sb.PolicyRevisions) > MaxPolicyRevisions {
		sb.PolicyRevisions = sb.PolicyRevisions[len(sb.PolicyRevisions)-MaxPolicyRevisions:]
	}
	s.state.Sandboxes[sandbox] = sb
	if err := s.flushLocked(); err != nil {
		s.state.Sandboxes[sandbox] = previous
		return 0, false, err
	}
	return sb.PolicyRev, true, nil
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

// GlobalPolicySnapshot returns the global policy and its monotonic revision.
func (s *Store) GlobalPolicySnapshot() (string, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.GlobalPolicyYAML, s.state.GlobalPolicyRevision
}

// SetGlobalPolicy stores global policy YAML bytes as a string.
func (s *Store) SetGlobalPolicy(yaml string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.GlobalPolicyYAML == yaml {
		return nil
	}
	if s.state.GlobalPolicyRevision == ^uint64(0) {
		return fmt.Errorf("global policy revision overflow")
	}
	if s.state.GlobalPolicyRevision >= uint64(int(^uint(0)>>1)) {
		return fmt.Errorf("global policy revision overflow")
	}
	s.state.GlobalPolicyYAML = yaml
	s.state.GlobalPolicyRevision++
	updatedAt := time.Now().UTC()
	s.state.GlobalPolicyRevisions = append(s.state.GlobalPolicyRevisions, PolicyRevision{Rev: int(s.state.GlobalPolicyRevision), UpdatedAt: updatedAt, Bytes: len(yaml), Status: PolicyStatusLoaded, YAML: yaml})
	if len(s.state.GlobalPolicyRevisions) > MaxPolicyRevisions {
		s.state.GlobalPolicyRevisions = s.state.GlobalPolicyRevisions[len(s.state.GlobalPolicyRevisions)-MaxPolicyRevisions:]
	}
	return s.flushLocked()
}

// SetGlobalPolicyIfRevision atomically compares the current version and stores a new policy.
func (s *Store) SetGlobalPolicyIfRevision(yaml string, expected uint64) (uint64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.GlobalPolicyRevision != expected {
		return s.state.GlobalPolicyRevision, false, nil
	}
	if s.state.GlobalPolicyYAML == yaml {
		return s.state.GlobalPolicyRevision, true, nil
	}
	if s.state.GlobalPolicyRevision == ^uint64(0) || s.state.GlobalPolicyRevision >= uint64(int(^uint(0)>>1)) {
		return s.state.GlobalPolicyRevision, false, fmt.Errorf("global policy revision overflow")
	}
	previousYAML := s.state.GlobalPolicyYAML
	previousRevision := s.state.GlobalPolicyRevision
	previousHistory := clonePolicyRevisions(s.state.GlobalPolicyRevisions)
	s.state.GlobalPolicyYAML = yaml
	s.state.GlobalPolicyRevision++
	updatedAt := time.Now().UTC()
	s.state.GlobalPolicyRevisions = append(s.state.GlobalPolicyRevisions, PolicyRevision{Rev: int(s.state.GlobalPolicyRevision), UpdatedAt: updatedAt, Bytes: len(yaml), Status: PolicyStatusLoaded, YAML: yaml})
	if len(s.state.GlobalPolicyRevisions) > MaxPolicyRevisions {
		s.state.GlobalPolicyRevisions = s.state.GlobalPolicyRevisions[len(s.state.GlobalPolicyRevisions)-MaxPolicyRevisions:]
	}
	if err := s.flushLocked(); err != nil {
		s.state.GlobalPolicyYAML = previousYAML
		s.state.GlobalPolicyRevision = previousRevision
		s.state.GlobalPolicyRevisions = previousHistory
		return 0, false, err
	}
	return s.state.GlobalPolicyRevision, true, nil
}

// GlobalPolicyHistory returns a detached oldest-first snapshot of retained global revisions.
func (s *Store) GlobalPolicyHistory() []PolicyRevision {
	s.mu.Lock()
	defer s.mu.Unlock()
	return clonePolicyRevisions(s.state.GlobalPolicyRevisions)
}

// GetGlobalPolicyRevision returns one retained global policy revision.
func (s *Store) GetGlobalPolicyRevision(revision int) (PolicyRevision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.state.GlobalPolicyRevisions {
		if item.Rev == revision {
			return clonePolicyRevisions([]PolicyRevision{item})[0], nil
		}
	}
	return PolicyRevision{}, fmt.Errorf("global policy revision %d not found", revision)
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
	s.state.Providers[rec.Name] = cloneProvider(rec)
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
	return cloneProvider(p), ok
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
		r.TimeoutSec = defaultInferenceTimeoutSeconds
	}
	s.state.Inference = &r
	return s.flushLocked()
}

// SetInferenceRouteExpected atomically updates the route if its current
// resource version matches expectedVersion (zero means no current route).
func (s *Store) SetInferenceRouteExpected(r InferenceRoute, expectedVersion uint64) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var current uint64
	if s.state.Inference != nil {
		current = uint64(s.state.Inference.Version)
	}
	if current != expectedVersion {
		return current, ErrInferenceRouteConflict
	}
	if current >= uint64(^uint(0)>>1) {
		return current, fmt.Errorf("inference route version overflow")
	}
	r.Version = int(current + 1)
	if r.TimeoutSec <= 0 {
		r.TimeoutSec = defaultInferenceTimeoutSeconds
	}
	s.state.Inference = &r
	return uint64(r.Version), s.flushLocked()
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

// ClearInferenceRouteExpected atomically clears the route at the expected
// version. Clearing an already absent route at version zero is idempotent.
func (s *Store) ClearInferenceRouteExpected(expectedVersion uint64) (bool, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var current uint64
	if s.state.Inference != nil {
		current = uint64(s.state.Inference.Version)
	}
	if current != expectedVersion {
		return false, current, ErrInferenceRouteConflict
	}
	if s.state.Inference == nil {
		return false, current, nil
	}
	s.state.Inference = nil
	return true, current, s.flushLocked()
}

// SetSetting stores a gateway setting key.
func (s *Store) SetSetting(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Settings == nil {
		s.state.Settings = map[string]string{}
	}
	if current, exists := s.state.Settings[key]; exists && current == value {
		return nil
	}
	if s.state.SettingsRevision == ^uint64(0) {
		return fmt.Errorf("settings revision overflow")
	}
	s.state.Settings[key] = value
	s.state.SettingsRevision++
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
	if _, exists := s.state.Settings[key]; !exists {
		return nil
	}
	if s.state.SettingsRevision == ^uint64(0) {
		return fmt.Errorf("settings revision overflow")
	}
	delete(s.state.Settings, key)
	s.state.SettingsRevision++
	return s.flushLocked()
}

// AllSettings returns a copy of settings.
func (s *Store) AllSettings() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	maps.Copy(out, s.state.Settings)
	return out
}

// SettingsSnapshot returns global settings and their monotonic revision from
// one consistent store snapshot.
func (s *Store) SettingsSnapshot() (map[string]string, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	maps.Copy(out, s.state.Settings)
	return out, s.state.SettingsRevision
}

// SandboxSettingsSnapshot returns one sandbox's scoped settings and revision.
func (s *Store) SandboxSettingsSnapshot(name string) (map[string]string, uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return nil, 0, false
	}
	return maps.Clone(sb.Settings), sb.SettingsRevision, true
}

// SetSandboxSetting writes one setting and increments its sandbox revision only
// when the value changes.
func (s *Store) SetSandboxSetting(name, key, value string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return 0, fmt.Errorf("sandbox %q not found", name)
	}
	if sb.Settings == nil {
		sb.Settings = map[string]string{}
	}
	if current, exists := sb.Settings[key]; exists && current == value {
		return sb.SettingsRevision, nil
	}
	if sb.SettingsRevision == ^uint64(0) {
		return sb.SettingsRevision, fmt.Errorf("sandbox settings revision overflow")
	}
	if sb.ResourceVersion == ^uint64(0) {
		return sb.SettingsRevision, fmt.Errorf("sandbox resource version overflow")
	}
	sb.Settings[key] = value
	sb.SettingsRevision++
	sb.ResourceVersion++
	s.state.Sandboxes[name] = sb
	return sb.SettingsRevision, s.flushLocked()
}

// UpsertTemplate stores a workload template.
func (s *Store) UpsertTemplate(t TemplateRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Templates == nil {
		s.state.Templates = map[string]TemplateRecord{}
	}
	s.state.Templates[t.Name] = cloneTemplate(t)
	return s.flushLocked()
}

// GetTemplate returns a template.
func (s *Store) GetTemplate(name string) (TemplateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.state.Templates[name]
	return cloneTemplate(t), ok
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
		out = append(out, cloneTemplate(t))
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
	if slices.Contains(sb.AttachedProviders, provider) {
		return nil
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

// defaultInferenceTimeoutSeconds is the default provider request deadline.
const defaultInferenceTimeoutSeconds = 60

package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/whaleshell/whaleshell-core/defaults"
	coreenv "github.com/whaleshell/whaleshell-core/env"
	"github.com/whaleshell/whaleshell-core/policy"
	"github.com/whaleshell/whaleshell-driver/driver"
	"github.com/whaleshell/whaleshell-providers/provider"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"gopkg.in/yaml.v3"
)

type sandboxRuntimeInputs struct {
	basePolicy      policy.Document
	effectivePolicy policy.Document
	baseYAML        []byte
	effectiveYAML   []byte
	attached        []string
	env             []string
	proxyEnv        []string
	policyPath      string
	gatewayURL      string
	proxyBin        string
	initBin         string
	sshBin          string
	supervisorBin   string
}

func (s *openShellRPC) prepareSandboxRuntime(req *openshellv1.CreateSandboxRequest, driverName, name, workspace string) (sandboxRuntimeInputs, error) {
	var out sandboxRuntimeInputs
	var err error
	var sandboxPolicy policy.Document
	hasSandboxPolicy := req.GetSpec().GetPolicy() != nil
	if hasSandboxPolicy {
		sandboxPolicy, err = parseOpenShellSandboxPolicy(req.GetSpec().GetPolicy())
		if err != nil {
			return out, err
		}
		out.baseYAML, err = yaml.Marshal(sandboxPolicy)
		if err != nil {
			return out, err
		}
	}
	globalYAML, _ := s.runtime.st.GlobalPolicySnapshot()
	hasGlobalPolicy := strings.TrimSpace(globalYAML) != ""
	var effective policy.Document
	switch {
	case hasGlobalPolicy:
		effective, err = parseGlobalPolicyYAML(globalYAML)
		if err != nil {
			return out, err
		}
		// A global policy is complete and takes precedence over both sandbox
		// policy and provider layers. Keep any explicit sandbox policy as its
		// own stored source policy, but do not compose it into the runtime one.
	case hasSandboxPolicy:
		effective = sandboxPolicy
	default:
		effective = restrictiveDefaultPolicy()
	}
	if err = enrichProxyBaselineFilesystem(&effective); err != nil {
		return out, err
	}
	out.basePolicy = sandboxPolicy
	out.effectivePolicy = effective
	var layers []provider.Layer
	for _, providerName := range req.GetSpec().GetProviders() {
		if hasGlobalPolicy || !hasSandboxPolicy {
			break
		}
		providerName = strings.TrimSpace(providerName)
		if providerName == "" {
			return out, fmt.Errorf("provider name must not be empty")
		}
		inst, ok := s.runtime.st.GetProvider(providerName)
		if !ok || !providerInWorkspace(inst, workspace) {
			return out, fmt.Errorf("provider %q is not available in workspace", providerName)
		}
		profile, _, err := resolveProfileForWorkspaceWithSources(s.runtime.st, BuiltinProvidersDir(), inst.Type, workspace, s.runtime.opt.ProviderProfileSources)
		if err != nil {
			return out, fmt.Errorf("provider %q profile is unavailable", providerName)
		}
		keys := append([]string(nil), inst.EnvVars...)
		if len(keys) == 0 {
			keys, err = profile.DiscoverEnvVars()
			if err != nil {
				return out, fmt.Errorf("provider %q credentials are invalid", providerName)
			}
		}
		out.attached = append(out.attached, providerName)
		layers = append(layers, provider.Layer{InstanceName: providerName, Profile: profile, EnvVars: keys})
	}
	if len(layers) > 0 {
		out.effectivePolicy, err = provider.EffectivePolicy(effective, layers, false)
		if err != nil {
			return out, fmt.Errorf("provider policy composition failed: %w", err)
		}
	}
	if err = out.effectivePolicy.Validate(); err != nil {
		return out, fmt.Errorf("sandbox policy is invalid: %w", err)
	}
	policyMessage, err := policyDocumentToProto(out.effectivePolicy)
	if err != nil {
		return out, fmt.Errorf("sandbox policy middleware config is invalid: %w", err)
	}
	middlewareEnv, err := s.supervisorMiddlewareProxyEnv(policyMessage)
	if err != nil {
		return out, err
	}
	out.effectiveYAML, err = yaml.Marshal(out.effectivePolicy)
	if err != nil {
		return out, err
	}
	policyDir := filepath.Join(s.runtime.opt.DataDir, "sandboxes", name)
	if err = os.MkdirAll(policyDir, 0o700); err != nil {
		return out, fmt.Errorf("sandbox policy storage unavailable")
	}
	out.policyPath = filepath.Join(policyDir, "policy.yaml")
	if err = os.WriteFile(out.policyPath, out.effectiveYAML, 0o600); err != nil {
		return out, fmt.Errorf("sandbox policy storage unavailable")
	}
	for _, helper := range []string{"whaleshell", "whaleshell-init", "whaleshell-sshd", "whaleshell-supervisor"} {
		path, err := sandboxHelperPath(helper)
		if err != nil {
			return out, err
		}
		switch helper {
		case "whaleshell":
			out.proxyBin = path
		case "whaleshell-init":
			out.initBin = path
		case "whaleshell-sshd":
			out.sshBin = path
		case "whaleshell-supervisor":
			out.supervisorBin = path
		}
	}
	out.gatewayURL, err = sandboxGatewayURL(s.runtime.opt, s.runtime.compute.configured[driverName])
	if err != nil {
		return out, err
	}
	out.env = coreenv.FromHostForGuest(out.effectivePolicy.CredentialEnvKeys()...)
	guestEnv := map[string]string{}
	for _, entry := range out.env {
		k, v, ok := strings.Cut(entry, "=")
		if ok {
			guestEnv[k] = v
		}
	}
	for k, v := range req.GetSpec().GetTemplate().GetEnvironment() {
		guestEnv[k] = v
	}
	for k, v := range req.GetSpec().GetEnvironment() {
		guestEnv[k] = v
	}
	for _, key := range out.effectivePolicy.CredentialEnvKeys() {
		guestEnv[key] = coreenv.PlaceholderPrefix + key
	}
	out.env = out.env[:0]
	for k, v := range guestEnv {
		if !validEnvKey(k) || strings.ContainsRune(v, '\x00') {
			return out, fmt.Errorf("invalid environment entry %q", k)
		}
		out.env = append(out.env, k+"="+v)
	}
	// Keep secrets and token grant metadata in the proxy sidecar only.
	out.proxyEnv = coreenv.SecretsFromHost(out.effectivePolicy.CredentialEnvKeys()...)
	for _, key := range defaults.ProxyEnvKeys {
		if value, ok := os.LookupEnv(key); ok && value != "" {
			out.proxyEnv = append(out.proxyEnv, key+"="+value)
		}
	}
	grants := map[string]sandboxTokenGrant{}
	for _, layer := range layers {
		for _, credential := range layer.Profile.Credentials {
			if credential.TokenGrant == nil {
				continue
			}
			g := credential.TokenGrant
			for _, key := range credential.EnvVars {
				if key == "" {
					continue
				}
				entry := sandboxTokenGrant{Provider: layer.InstanceName, CredentialKey: credential.Name, TokenEndpoint: g.TokenEndpoint, GrantType: g.GrantType, Audience: g.Audience, JWTSVIDAudience: g.JWTSVIDAudience, ClientAssertionType: g.ClientAssertionType, RequestedTokenType: g.RequestedTokenType, Scopes: append([]string(nil), g.Scopes...)}
				if ttl, e := time.ParseDuration(g.CacheTTL); e == nil && ttl > 0 {
					entry.CacheTTLSeconds = int64(ttl / time.Second)
				}
				if g.SubjectToken != nil {
					entry.SubjectTokenType = g.SubjectToken.SubjectTokenType
					entry.SubjectTokenCredential = g.SubjectToken.Credential
				}
				for _, override := range g.AudienceOverrides {
					entry.AudienceOverrides = append(entry.AudienceOverrides, sandboxTokenGrantOverride{Host: override.Host, Path: override.Path, Port: override.Port, Audience: override.Audience, Scopes: append([]string(nil), override.Scopes...)})
				}
				grants[key] = entry
			}
		}
	}
	if len(grants) > 0 {
		b, e := json.Marshal(grants)
		if e != nil {
			return out, fmt.Errorf("token grant configuration is invalid")
		}
		out.proxyEnv = append(out.proxyEnv, "WHALESHELL_TOKEN_GRANTS="+string(b))
	}
	out.proxyEnv = append(out.proxyEnv, middlewareEnv...)
	sort.Strings(out.env)
	sort.Strings(out.proxyEnv)
	return out, nil
}

func (s *openShellRPC) supervisorMiddlewareProxyEnv(policy *sandboxv1.SandboxPolicy) ([]string, error) {
	if policy == nil || len(policy.GetNetworkMiddlewares()) == 0 {
		return nil, nil
	}
	services := make(map[string]*sandboxv1.SupervisorMiddlewareService, len(s.options.SupervisorMiddlewareServices))
	for _, service := range s.options.SupervisorMiddlewareServices {
		if service != nil {
			services[service.GetName()] = service
		}
	}
	type item struct {
		Name            string         `json:"name"`
		Endpoint        string         `json:"endpoint"`
		Timeout         string         `json:"timeout,omitempty"`
		FailClosed      bool           `json:"fail_closed"`
		MaxPayloadBytes uint64         `json:"max_payload_bytes,omitempty"`
		Config          map[string]any `json:"config,omitempty"`
		TLSCAPEM        string         `json:"tls_ca_cert_pem,omitempty"`
		Order           int32          `json:"order"`
		Include         []string       `json:"include,omitempty"`
		Exclude         []string       `json:"exclude,omitempty"`
	}
	items := make([]item, 0, len(policy.GetNetworkMiddlewares()))
	for _, config := range policy.GetNetworkMiddlewares() {
		if config == nil {
			continue
		}
		service, ok := services[config.GetMiddleware()]
		if !ok {
			return nil, fmt.Errorf("middleware %q is not registered", config.GetMiddleware())
		}
		var fields map[string]any
		if config.GetConfig() != nil {
			fields = config.GetConfig().AsMap()
		}
		selector := config.GetEndpoints()
		var include, exclude []string
		if selector != nil {
			include = append([]string(nil), selector.GetInclude()...)
			exclude = append([]string(nil), selector.GetExclude()...)
		}
		items = append(items, item{Name: config.GetMiddleware(), Endpoint: service.GetGrpcEndpoint(), Timeout: service.GetTimeout(), FailClosed: strings.ToLower(config.GetOnError()) != "fail_open", MaxPayloadBytes: service.GetMaxPayloadBytes(), Config: fields, TLSCAPEM: base64.StdEncoding.EncodeToString(service.GetTlsCaCertPem()), Order: config.GetOrder(), Include: include, Exclude: exclude})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Order != items[j].Order {
			return items[i].Order < items[j].Order
		}
		return items[i].Name < items[j].Name
	})
	encoded, err := json.Marshal(items)
	if err != nil {
		return nil, fmt.Errorf("serialize supervisor middleware configuration: %w", err)
	}
	return []string{"WHALESHELL_SUPERVISOR_MIDDLEWARES=" + string(encoded)}, nil
}

func parseGlobalPolicyYAML(source string) (policy.Document, error) {
	doc, err := policy.Parse([]byte(source))
	if err != nil {
		return policy.Document{}, fmt.Errorf("global policy is invalid: %w", err)
	}
	if err := doc.Validate(); err != nil {
		return policy.Document{}, fmt.Errorf("global policy is invalid: %w", err)
	}
	return doc, nil
}

// restrictiveDefaultPolicy mirrors OpenShell's restrictive_default_policy
// for sandboxes without a global or sandbox policy. It is runtime-only and is
// deliberately not written to the sandbox policy history.
func restrictiveDefaultPolicy() policy.Document {
	return policy.Document{
		Version: 1,
		FilesystemPolicy: &policy.FilesystemPolicy{
			IncludeWorkdir: true,
			ReadOnly:       []string{"/usr", "/lib", "/proc", "/dev/urandom", "/app", "/etc", "/var/log"},
			ReadWrite:      []string{"/tmp", "/dev/null"},
		},
		Landlock: &policy.Landlock{Compatibility: "best_effort"},
	}
}

// enrichProxyBaselineFilesystem mirrors OpenShell's system-injected baseline
// for proxy-mode sandboxes. The Engine adapter always runs the supervisor
// proxy, so the workload needs its standard runtime paths even when the user
// policy only grants the workspace.
func enrichProxyBaselineFilesystem(doc *policy.Document) error {
	return enrichProxyBaselineFilesystemWith(doc, func(path string) bool {
		_, err := os.Stat(path)
		return err == nil
	})
}

func enrichProxyBaselineFilesystemWith(doc *policy.Document, exists func(string) bool) error {
	if doc == nil {
		return fmt.Errorf("sandbox policy is required")
	}
	if doc.FilesystemPolicy == nil {
		doc.FilesystemPolicy = &policy.FilesystemPolicy{IncludeWorkdir: true}
	}
	fs := doc.FilesystemPolicy
	for _, path := range []string{"/usr", "/lib", "/etc", "/app", "/var/log", "/proc", "/dev/urandom"} {
		if !exists(path) || containsString(fs.ReadOnly, path) || containsString(fs.ReadWrite, path) {
			continue
		}
		fs.ReadOnly = append(fs.ReadOnly, path)
	}
	if exists("/tmp") && !containsString(fs.ReadOnly, "/tmp") && !containsString(fs.ReadWrite, "/tmp") {
		fs.ReadWrite = append(fs.ReadWrite, "/tmp")
	}
	// The Engine adapter mounts a persistent home/data volume at this path;
	// supervisor-created profile files and agent installs must remain usable
	// under the workload's Landlock domain.
	if !containsString(fs.ReadOnly, "/whaleshell/data") && !containsString(fs.ReadWrite, "/whaleshell/data") {
		fs.ReadWrite = append(fs.ReadWrite, "/whaleshell/data")
	}
	return nil
}

type sandboxTokenGrant struct {
	Provider               string                      `json:"provider"`
	CredentialKey          string                      `json:"credential_key"`
	TokenEndpoint          string                      `json:"token_endpoint"`
	GrantType              string                      `json:"grant_type"`
	Audience               string                      `json:"audience"`
	JWTSVIDAudience        string                      `json:"jwt_svid_audience"`
	ClientAssertionType    string                      `json:"client_assertion_type"`
	RequestedTokenType     string                      `json:"requested_token_type"`
	CacheTTLSeconds        int64                       `json:"cache_ttl_seconds"`
	Scopes                 []string                    `json:"scopes"`
	SubjectTokenType       string                      `json:"subject_token_type"`
	SubjectTokenCredential string                      `json:"subject_token_credential"`
	AudienceOverrides      []sandboxTokenGrantOverride `json:"audience_overrides"`
}
type sandboxTokenGrantOverride struct {
	Host     string   `json:"host"`
	Path     string   `json:"path"`
	Port     int      `json:"port"`
	Audience string   `json:"audience"`
	Scopes   []string `json:"scopes"`
}

func parseOpenShellSandboxPolicy(src *sandboxv1.SandboxPolicy) (policy.Document, error) {
	if src == nil || src.GetVersion() == 0 {
		return policy.Document{}, fmt.Errorf("sandbox policy version is required")
	}
	b, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(src)
	if err != nil {
		return policy.Document{}, fmt.Errorf("sandbox policy is invalid")
	}
	var fields map[string]any
	if err = json.Unmarshal(b, &fields); err != nil {
		return policy.Document{}, fmt.Errorf("sandbox policy is invalid")
	}
	if filesystem, ok := fields["filesystem"]; ok {
		fields["filesystem_policy"] = filesystem
		delete(fields, "filesystem")
	}
	yml, err := yaml.Marshal(fields)
	if err != nil {
		return policy.Document{}, fmt.Errorf("sandbox policy is invalid")
	}
	doc, err := policy.Parse(yml)
	if err != nil {
		return policy.Document{}, err
	}
	if err = doc.Validate(); err != nil {
		return policy.Document{}, err
	}
	return doc, nil
}

func sandboxHelperPath(name string) (string, error) {
	root := strings.TrimSpace(os.Getenv("WHALESHELL_HELPERS_DIR"))
	if root == "" {
		root = filepath.Join("/usr/local/lib/whaleshell", "linux-"+runtime.GOARCH)
	}
	path := filepath.Join(root, name)
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("gateway helper %s is unavailable; install gateway helper bundle or set WHALESHELL_HELPERS_DIR", name)
	}
	return path, nil
}

func sandboxGatewayURL(opt Options, driverConfig map[string]any) (string, error) {
	for _, value := range []any{driverConfig["grpc_endpoint"], os.Getenv("OPENSHELL_GATEWAY_URL"), os.Getenv("WHALESHELL_GATEWAY_URL")} {
		raw, ok := value.(string)
		if !ok || strings.TrimSpace(raw) == "" {
			continue
		}
		if !strings.Contains(raw, "://") {
			raw = "http://" + raw
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return "", fmt.Errorf("gateway gRPC endpoint is invalid")
		}
		if err := validateGuestTLSForEndpoint(driverConfig, u.Scheme); err != nil {
			return "", err
		}
		if ip := net.ParseIP(u.Hostname()); ip != nil && ip.IsLoopback() || strings.EqualFold(u.Hostname(), "localhost") {
			port := u.Port()
			if port == "" {
				return "", fmt.Errorf("gateway gRPC endpoint needs an explicit port")
			}
			u.Host = net.JoinHostPort("host.docker.internal", port)
		}
		return strings.TrimRight(u.String(), "/"), nil
	}
	_, port, err := net.SplitHostPort(opt.Listen)
	if err != nil {
		return "", fmt.Errorf("gateway listener endpoint is unavailable")
	}
	scheme := "http"
	if opt.TLSCert != "" {
		scheme = "https"
	}
	if err := validateGuestTLSForEndpoint(driverConfig, scheme); err != nil {
		return "", err
	}
	return scheme + "://host.docker.internal:" + port, nil
}

func validateGuestTLSForEndpoint(driverConfig map[string]any, scheme string) error {
	fields := []string{"guest_tls_ca", "guest_tls_cert", "guest_tls_key"}
	configured := 0
	for _, field := range fields {
		value, exists := driverConfig[field]
		if !exists {
			continue
		}
		path, ok := value.(string)
		if !ok || strings.TrimSpace(path) == "" {
			return fmt.Errorf("gateway guest TLS field %s must be a non-empty path", field)
		}
		configured++
	}
	if configured != 0 && configured != len(fields) {
		return fmt.Errorf("gateway guest TLS CA, certificate and key must be configured together")
	}
	if scheme == "https" && configured != len(fields) {
		return fmt.Errorf("https gateway endpoint requires guest_tls_ca, guest_tls_cert and guest_tls_key")
	}
	if scheme != "https" && configured != 0 {
		return fmt.Errorf("guest TLS materials require an https gateway endpoint")
	}
	return nil
}

func buildGatewayDriverSpec(req *openshellv1.CreateSandboxRequest, inputs sandboxRuntimeInputs, name, image, workspaceRoot, driverName, driverConfigJSON string) (driver.Spec, error) {
	spec := req.GetSpec()
	tmpl := spec.GetTemplate()
	out := driver.Spec{Name: name, Image: image, Workspace: workspaceRoot, Command: append([]string(nil), spec.GetCommand()...), Env: append([]string(nil), inputs.env...), ProxyBin: inputs.proxyBin, InitBin: inputs.initBin, SSHBin: inputs.sshBin, EnableSSH: true, PolicyPath: inputs.policyPath, ProxyEnv: append([]string(nil), inputs.proxyEnv...), GatewayURL: inputs.gatewayURL, PersistVolume: true, DriverConfigJSON: driverConfigJSON, Labels: map[string]string{}, SupervisorBin: inputs.supervisorBin}
	if len(out.Command) == 0 {
		out.Command = []string{"/bin/sh"}
	}
	if gpu := spec.GetResourceRequirements().GetGpu(); gpu != nil {
		out.GPU = true
		if gpu.Count != nil {
			out.GPUCount = int(*gpu.Count)
		}
	}
	cpu, memory, err := engineResourceLimits(tmpl.GetResources(), driverName)
	if err != nil {
		return driver.Spec{}, err
	}
	out.CPU, out.MemoryBytes = cpu, memory
	return out, nil
}

func engineResourceLimits(raw *structpb.Struct, driverName string) (float64, int64, error) {
	if raw == nil {
		return 0, 0, nil
	}
	fields := raw.AsMap()
	for key := range fields {
		if key != "limits" && key != "requests" {
			return 0, 0, fmt.Errorf("template.resources contains unsupported field %q", key)
		}
	}
	limits, err := resourceSection(fields["limits"], "limits")
	if err != nil {
		return 0, 0, err
	}
	requests, err := resourceSection(fields["requests"], "requests")
	if err != nil {
		return 0, 0, err
	}
	if driverName == "docker" && (requests["cpu"] != "" || requests["memory"] != "") {
		return 0, 0, fmt.Errorf("docker Engine backend does not support template.resources.requests")
	}
	cpu, err := parseCPUQuantity(limits["cpu"])
	if err != nil {
		return 0, 0, err
	}
	memory, err := parseMemoryQuantity(limits["memory"])
	return cpu, memory, err
}

func resourceSection(value any, name string) (map[string]string, error) {
	out := map[string]string{}
	if value == nil {
		return out, nil
	}
	fields, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("template.resources.%s must be an object", name)
	}
	for key, raw := range fields {
		if key != "cpu" && key != "memory" {
			return nil, fmt.Errorf("template.resources.%s.%s is unsupported by the Engine backend", name, key)
		}
		quantity, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("template.resources.%s.%s must be a string quantity", name, key)
		}
		out[key] = quantity
	}
	return out, nil
}

func parseCPUQuantity(value string) (float64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	if strings.HasSuffix(value, "m") {
		millicores, err := strconv.ParseInt(strings.TrimSuffix(value, "m"), 10, 64)
		if err != nil || millicores <= 0 || millicores > math.MaxInt64/1_000_000 {
			return 0, fmt.Errorf("template.resources.limits.cpu must be a positive integer CPU or millicore quantity")
		}
		return float64(millicores) / 1000, nil
	}
	cores, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(cores) || math.IsInf(cores, 0) || cores <= 0 || cores > float64(math.MaxInt64)/1e9 {
		return 0, fmt.Errorf("template.resources.limits.cpu must be a positive CPU quantity")
	}
	return cores, nil
}

func parseMemoryQuantity(value string) (int64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	numberEnd := 0
	for numberEnd < len(value) && (value[numberEnd] >= '0' && value[numberEnd] <= '9' || value[numberEnd] == '.') {
		numberEnd++
	}
	amount, err := strconv.ParseFloat(value[:numberEnd], 64)
	if err != nil || math.IsNaN(amount) || math.IsInf(amount, 0) || amount <= 0 {
		return 0, fmt.Errorf("template.resources.limits.memory must be a positive memory quantity")
	}
	multipliers := map[string]float64{"": 1, "Ki": 1024, "Mi": 1024 * 1024, "Gi": 1024 * 1024 * 1024, "Ti": 1024 * 1024 * 1024 * 1024, "Pi": 1024 * 1024 * 1024 * 1024 * 1024, "Ei": 1024 * 1024 * 1024 * 1024 * 1024 * 1024, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18}
	multiplier, ok := multipliers[value[numberEnd:]]
	bytes := amount * multiplier
	if !ok || math.IsNaN(bytes) || math.IsInf(bytes, 0) || bytes > math.MaxInt64 || bytes < 1 {
		return 0, fmt.Errorf("template.resources.limits.memory has an unsupported or out-of-range quantity")
	}
	return int64(math.Round(bytes)), nil
}

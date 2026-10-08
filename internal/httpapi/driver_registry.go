package httpapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	datamodelv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/cauteum/cauteum-gateway/internal/gatewayconfig"
	"github.com/cauteum/cauteum-gateway/internal/storage/store"
	computev1 "github.com/cauteum/cauteum-gateway/internal/upstreamproto/computev1"
	credentialsv1 "github.com/cauteum/cauteum-gateway/internal/upstreamproto/credentialsv1"
	interceptorv1 "github.com/cauteum/cauteum-gateway/internal/upstreamproto/interceptorv1"
	middlewarev1 "github.com/cauteum/cauteum-gateway/internal/upstreamproto/middlewarev1"
	"github.com/cauteum/cauteum-runtime/secrets"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
)

// driverRegistry is the typed boundary for configured built-in and external
// OpenShell drivers. Built-ins keep their existing lazy Engine path; remote
// entries are represented by generated clients and are probed explicitly.
// Keeping this registry separate from the public gateway server is important:
// ComputeDriver and CredentialDriver are plugin-side contracts, not public
// OpenShell RPCs.
type driverRegistry struct {
	mu          sync.Mutex
	compute     map[string]computeDriverRegistration
	credential  map[string]credentialDriverRegistration
	middleware  map[string]middlewareRegistration
	interceptor map[string]interceptorRegistration
}

type computeDriverRegistration struct {
	name   string
	config map[string]any
	client computev1.ComputeDriverClient
	conn   *grpc.ClientConn
}

type credentialDriverRegistration struct {
	name   string
	config map[string]any
	client credentialsv1.CredentialDriverClient
	conn   *grpc.ClientConn
}

type middlewareRegistration struct {
	service *sandboxv1.SupervisorMiddlewareService
	client  middlewarev1.SupervisorMiddlewareClient
	conn    *grpc.ClientConn
}

type interceptorRegistration struct {
	config   gatewayInterceptorConfig
	client   interceptorv1.GatewayInterceptorClient
	conn     *grpc.ClientConn
	manifest *interceptorv1.InterceptorManifest
}

type gatewayInterceptorConfig struct {
	name            string
	endpoint        string
	tlsCACertPath   string
	audience        string
	allowInsecure   bool
	order           int32
	failurePolicy   string
	timeout         string
	maxResponseSize uint64
	maxPatches      uint64
	bindingPolicy   string
	bindings        []gatewayInterceptorBinding
}

type gatewayInterceptorBinding struct {
	id            string
	rpc           string
	service       string
	method        string
	phases        []string
	disabled      bool
	failurePolicy string
}

func newDriverRegistry(opt Options) (*driverRegistry, error) {
	computeNames := opt.ComputeDriverNames
	if len(computeNames) == 0 {
		computeNames = []string{"docker"}
	}
	r := &driverRegistry{
		compute:     map[string]computeDriverRegistration{},
		credential:  map[string]credentialDriverRegistration{},
		middleware:  map[string]middlewareRegistration{},
		interceptor: map[string]interceptorRegistration{},
	}
	for _, name := range computeNames {
		key := normalizeDriverName(name)
		if key == "" {
			return nil, fmt.Errorf("compute driver name must not be empty")
		}
		if _, exists := r.compute[key]; exists {
			return nil, fmt.Errorf("duplicate compute driver %q", name)
		}
		config := driverConfig(opt.ComputeDriverConfigs, name)
		registration := computeDriverRegistration{name: key, config: config}
		if !isBuiltinComputeDriver(key) {
			endpoint := stringConfig(config, "grpc_endpoint")
			if endpoint == "" {
				return nil, fmt.Errorf("compute driver %q: grpc_endpoint is required for an external driver", name)
			}
			client, conn, err := openComputeDriverClient(endpoint, config)
			if err != nil {
				return nil, fmt.Errorf("compute driver %q: %w", name, err)
			}
			registration.client, registration.conn = client, conn
		}
		r.compute[key] = registration
	}
	for _, name := range opt.CredentialDriverNames {
		key := normalizeDriverName(name)
		if key == "" {
			return nil, fmt.Errorf("credential driver name must not be empty")
		}
		if _, exists := r.credential[key]; exists {
			return nil, fmt.Errorf("duplicate credential driver %q", name)
		}
		config := driverConfig(opt.CredentialDriverConfigs, name)
		registration := credentialDriverRegistration{name: key, config: config}
		if endpoint := stringConfig(config, "grpc_endpoint"); endpoint != "" {
			client, conn, err := openCredentialDriverClient(endpoint, config)
			if err != nil {
				return nil, fmt.Errorf("credential driver %q: %w", name, err)
			}
			registration.client, registration.conn = client, conn
		} else if !isBuiltinCredentialDriver(key, config) {
			return nil, fmt.Errorf("credential driver %q: grpc_endpoint is required for an external driver", name)
		}
		r.credential[key] = registration
	}
	for _, service := range opt.SupervisorMiddlewareServices {
		if service == nil {
			return nil, fmt.Errorf("middleware registration must not be nil")
		}
		key := strings.TrimSpace(service.GetName())
		if key == "" {
			return nil, fmt.Errorf("middleware registration name must not be empty")
		}
		if _, exists := r.middleware[key]; exists {
			return nil, fmt.Errorf("duplicate middleware registration %q", key)
		}
		client, conn, err := openMiddlewareClient(service)
		if err != nil {
			return nil, fmt.Errorf("middleware %q: %w", key, err)
		}
		r.middleware[key] = middlewareRegistration{service: service, client: client, conn: conn}
	}
	for _, configured := range opt.GatewayInterceptors {
		config, err := normalizeGatewayInterceptorConfig(configured)
		if err != nil {
			return nil, err
		}
		if _, exists := r.interceptor[config.name]; exists {
			return nil, fmt.Errorf("duplicate gateway interceptor %q", config.name)
		}
		client, conn, err := openGatewayInterceptorClient(config)
		if err != nil {
			return nil, fmt.Errorf("interceptor %q: %w", config.name, err)
		}
		r.interceptor[config.name] = interceptorRegistration{config: config, client: client, conn: conn}
	}
	return r, nil
}

func (r *driverRegistry) close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var first error
	for name, registration := range r.compute {
		if registration.conn != nil {
			if err := registration.conn.Close(); err != nil && first == nil {
				first = fmt.Errorf("close compute driver %q: %w", name, err)
			}
		}
	}
	for name, registration := range r.credential {
		if registration.conn != nil {
			if err := registration.conn.Close(); err != nil && first == nil {
				first = fmt.Errorf("close credential driver %q: %w", name, err)
			}
		}
	}
	for name, registration := range r.middleware {
		if registration.conn != nil {
			if err := registration.conn.Close(); err != nil && first == nil {
				first = fmt.Errorf("close middleware %q: %w", name, err)
			}
		}
	}
	for name, registration := range r.interceptor {
		if registration.conn != nil {
			if err := registration.conn.Close(); err != nil && first == nil {
				first = fmt.Errorf("close interceptor %q: %w", name, err)
			}
		}
	}
	return first
}

// Probe calls the related protocol capability methods. It is intentionally
// explicit and bounded: gateway startup must not hang on an unavailable
// optional plugin, while an operator-requested probe gets a useful error.
func (r *driverRegistry) probe(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	for name, registration := range r.compute {
		if registration.client == nil {
			continue
		}
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, err := registration.client.GetCapabilities(probeCtx, &computev1.GetCapabilitiesRequest{})
		cancel()
		if err != nil {
			return fmt.Errorf("compute driver %q capability probe: %w", name, err)
		}
	}
	for name, registration := range r.credential {
		if registration.client == nil {
			continue
		}
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		capabilities, err := registration.client.GetCapabilities(probeCtx, &credentialsv1.GetCredentialDriverCapabilitiesRequest{})
		cancel()
		if err != nil {
			return fmt.Errorf("credential driver %q capability probe: %w", name, err)
		}
		if capabilities != nil && capabilities.GetSupportsList() {
			if _, err := r.listCredentialDriverCredentials(ctx, name); err != nil {
				return fmt.Errorf("credential driver %q list probe: %w", name, err)
			}
		}
	}
	for name, registration := range r.middleware {
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		manifest, err := registration.client.Describe(probeCtx, &emptypb.Empty{})
		cancel()
		if err != nil {
			return fmt.Errorf("middleware %q Describe: %w", name, err)
		}
		if err := validateMiddlewareManifest(name, registration.service, manifest); err != nil {
			return err
		}
	}
	for name, registration := range r.interceptor {
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		manifest, err := registration.client.Describe(probeCtx, &interceptorv1.DescribeRequest{})
		cancel()
		if err != nil {
			return fmt.Errorf("interceptor %q Describe: %w", name, err)
		}
		if err := validateGatewayInterceptorManifest(registration.config, manifest); err != nil {
			return err
		}
		r.mu.Lock()
		current := r.interceptor[name]
		current.manifest = manifest
		r.interceptor[name] = current
		r.mu.Unlock()
	}
	return nil
}

// listCredentialDriverCredentials exercises the optional ListCredentials
// contract without ever exposing credential values. The protocol deliberately
// returns handles, keys, and metadata only; validating handles here catches a
// misbehaving external driver during startup or an explicit probe.
func (r *driverRegistry) listCredentialDriverCredentials(ctx context.Context, name string) ([]*credentialsv1.ListedCredential, error) {
	if r == nil {
		return nil, fmt.Errorf("credential driver registry is nil")
	}
	name = normalizeDriverName(name)
	r.mu.Lock()
	registration, ok := r.credential[name]
	r.mu.Unlock()
	if !ok || registration.client == nil {
		return nil, fmt.Errorf("credential driver %q is not an external driver", name)
	}
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	response, err := registration.client.ListCredentials(probeCtx, &credentialsv1.ListCredentialsRequest{})
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, fmt.Errorf("driver returned an empty ListCredentials response")
	}
	for index, credential := range response.GetCredentials() {
		if credential == nil || strings.TrimSpace(credential.GetHandle()) == "" {
			return nil, fmt.Errorf("driver returned credential %d without a handle", index)
		}
	}
	return response.GetCredentials(), nil
}

// evaluateGatewayInterceptors runs the configured validate phase after the
// gateway has prepared an operation but before it performs durable or backend
// side effects. Only bindings selected by the service manifest are called.
// Failure policy is resolved per binding, then manifest, then registration.
func (r *driverRegistry) evaluateGatewayInterceptors(ctx context.Context, service, method string, principal map[string]string, operation proto.Message) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	registrations := make([]interceptorRegistration, 0, len(r.interceptor))
	for _, registration := range r.interceptor {
		registrations = append(registrations, registration)
	}
	r.mu.Unlock()
	if len(registrations) == 0 {
		return nil
	}
	raw, err := protojson.Marshal(operation)
	if err != nil {
		return fmt.Errorf("interceptor operation serialization: %w", err)
	}
	var values map[string]any
	if err := json.Unmarshal(raw, &values); err != nil {
		return fmt.Errorf("interceptor operation conversion: %w", err)
	}
	proposed, err := structpb.NewStruct(values)
	if err != nil {
		return fmt.Errorf("interceptor operation struct: %w", err)
	}
	for _, registration := range registrations {
		for _, binding := range registration.manifest.GetBindings() {
			if !interceptorBindingMatches(binding, registration.config, service, method) || !interceptorBindingWantsValidate(binding) {
				continue
			}
			callCtx := ctx
			cancel := func() {}
			if timeout := interceptorTimeout(registration.config.timeout); timeout > 0 {
				callCtx, cancel = context.WithTimeout(ctx, timeout)
			}
			result, callErr := registration.client.Evaluate(callCtx, &interceptorv1.InterceptorEvaluation{
				InterceptorName: registration.config.name,
				BindingId:       binding.GetId(),
				Service:         service,
				Method:          method,
				Principal:       principal,
				Phase:           &interceptorv1.InterceptorEvaluation_Validate{Validate: &interceptorv1.ValidateEvaluation{ProposedOperation: proposed}},
			})
			cancel()
			if callErr != nil {
				if interceptorFailurePolicy(binding, registration) == "fail_open" {
					continue
				}
				return status.Errorf(codes.FailedPrecondition, "gateway interceptor %q failed: %v", registration.config.name, callErr)
			}
			if result == nil || !result.GetAllowed() {
				reason := "operation denied by gateway interceptor"
				if result != nil && strings.TrimSpace(result.GetReason()) != "" {
					reason = result.GetReason()
				}
				return status.Errorf(interceptorStatusCode(result.GetStatusCode()), "gateway interceptor %q denied %s/%s: %s", registration.config.name, service, method, reason)
			}
		}
	}
	return nil
}

// evaluateGatewayInterceptorPhases is the mutation-aware path used by
// gateway operations. It preserves the legacy validate helper above for
// callers that only need a decision.
func (r *driverRegistry) evaluateGatewayInterceptorPhases(ctx context.Context, service, method string, principal map[string]string, operation proto.Message, postCommit bool) (proto.Message, error) {
	if r == nil {
		return operation, nil
	}
	r.mu.Lock()
	registrations := make([]interceptorRegistration, 0, len(r.interceptor))
	for _, registration := range r.interceptor {
		registrations = append(registrations, registration)
	}
	r.mu.Unlock()
	sort.SliceStable(registrations, func(i, j int) bool {
		if registrations[i].config.order != registrations[j].config.order {
			return registrations[i].config.order < registrations[j].config.order
		}
		return registrations[i].config.name < registrations[j].config.name
	})
	working := proto.Clone(operation)
	for _, registration := range registrations {
		for _, binding := range registration.manifest.GetBindings() {
			if !interceptorBindingMatches(binding, registration.config, service, method) {
				continue
			}
			phases := make([]interceptorv1.GatewayInterceptorPhase, 0, 3)
			if !postCommit && interceptorBindingWantsPhase(binding, interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_MODIFY_OPERATION) {
				phases = append(phases, interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_MODIFY_OPERATION)
			}
			if !postCommit && interceptorBindingWantsValidate(binding) {
				phases = append(phases, interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_VALIDATE)
			}
			if postCommit && interceptorBindingWantsPhase(binding, interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_POST_COMMIT) {
				phases = append(phases, interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_POST_COMMIT)
			}
			for _, phase := range phases {
				proposed, err := interceptorProposedStruct(working)
				if err != nil {
					return nil, err
				}
				evaluation := &interceptorv1.InterceptorEvaluation{InterceptorName: registration.config.name, BindingId: binding.GetId(), Service: service, Method: method, Principal: principal}
				switch phase {
				case interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_MODIFY_OPERATION:
					evaluation.Phase = &interceptorv1.InterceptorEvaluation_ModifyOperation{ModifyOperation: &interceptorv1.ModifyOperationEvaluation{ProposedOperation: proposed}}
				case interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_POST_COMMIT:
					evaluation.Phase = &interceptorv1.InterceptorEvaluation_PostCommit{PostCommit: &interceptorv1.PostCommitEvaluation{CommittedResponse: proposed}}
				default:
					evaluation.Phase = &interceptorv1.InterceptorEvaluation_Validate{Validate: &interceptorv1.ValidateEvaluation{ProposedOperation: proposed}}
				}
				callCtx := ctx
				cancel := func() {}
				if timeout := interceptorTimeout(registration.config.timeout); timeout > 0 {
					callCtx, cancel = context.WithTimeout(ctx, timeout)
				}
				result, callErr := registration.client.Evaluate(callCtx, evaluation)
				cancel()
				if callErr != nil {
					if phase == interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_POST_COMMIT || interceptorFailurePolicy(binding, registration) == "fail_open" {
						continue
					}
					return nil, status.Errorf(codes.FailedPrecondition, "gateway interceptor %q failed: %v", registration.config.name, callErr)
				}
				if phase == interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_POST_COMMIT {
					continue
				}
				if result == nil || !result.GetAllowed() {
					reason := "operation denied by gateway interceptor"
					if result != nil && strings.TrimSpace(result.GetReason()) != "" {
						reason = result.GetReason()
					}
					return nil, status.Errorf(interceptorStatusCode(result.GetStatusCode()), "gateway interceptor %q denied %s/%s: %s", registration.config.name, service, method, reason)
				}
				if phase == interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_MODIFY_OPERATION {
					if err := applyInterceptorPatches(&working, result.GetPatches()); err != nil {
						if interceptorFailurePolicy(binding, registration) == "fail_open" {
							continue
						}
						return nil, status.Errorf(codes.FailedPrecondition, "gateway interceptor %q returned invalid patches: %v", registration.config.name, err)
					}
				}
			}
		}
	}
	return working, nil
}

func interceptorProposedStruct(message proto.Message) (*structpb.Struct, error) {
	raw, err := protojson.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("interceptor operation serialization: %w", err)
	}
	var values map[string]any
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, fmt.Errorf("interceptor operation conversion: %w", err)
	}
	return structpb.NewStruct(values)
}

func interceptorBindingWantsPhase(binding *interceptorv1.InterceptorBinding, phase interceptorv1.GatewayInterceptorPhase) bool {
	for _, candidate := range binding.GetPhases() {
		if candidate == phase {
			return true
		}
	}
	return false
}

func applyInterceptorPatches(target *proto.Message, patches []*interceptorv1.JsonPatch) error {
	if len(patches) == 0 {
		return nil
	}
	raw, err := protojson.Marshal(*target)
	if err != nil {
		return err
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		return err
	}
	for _, patch := range patches {
		if patch == nil {
			return fmt.Errorf("nil patch")
		}
		parts, err := jsonPointerParts(patch.GetPath())
		if err != nil || len(parts) == 0 {
			if err != nil {
				return err
			}
			return fmt.Errorf("root JSON patches are not supported")
		}
		current := document
		for _, part := range parts[:len(parts)-1] {
			next, ok := current[part].(map[string]any)
			if !ok {
				return fmt.Errorf("JSON patch parent %q is missing or not an object", part)
			}
			current = next
		}
		leaf := parts[len(parts)-1]
		op := strings.ToLower(strings.TrimSpace(patch.GetOp()))
		_, exists := current[leaf]
		switch op {
		case "add":
			if patch.GetValue() == nil {
				return fmt.Errorf("JSON patch add value is missing")
			}
			current[leaf] = patch.GetValue().AsInterface()
		case "replace":
			if !exists || patch.GetValue() == nil {
				return fmt.Errorf("JSON patch replace target %q is missing", leaf)
			}
			current[leaf] = patch.GetValue().AsInterface()
		case "remove":
			if !exists {
				return fmt.Errorf("JSON patch remove target %q is missing", leaf)
			}
			delete(current, leaf)
		default:
			return fmt.Errorf("unsupported JSON patch operation %q", patch.GetOp())
		}
	}
	patched, err := json.Marshal(document)
	if err != nil {
		return err
	}
	updated := proto.Clone(*target)
	if err := protojson.Unmarshal(patched, updated); err != nil {
		return err
	}
	*target = updated
	return nil
}

func jsonPointerParts(path string) ([]string, error) {
	if path == "" || !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("JSON patch path must start with /")
	}
	parts := strings.Split(path[1:], "/")
	for i := range parts {
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(parts[i], "~1", "/"), "~0", "~")
	}
	return parts, nil
}

func interceptorBindingMatches(binding *interceptorv1.InterceptorBinding, config gatewayInterceptorConfig, service, method string) bool {
	if binding == nil || binding.GetSelector() == nil {
		return false
	}
	selector := binding.GetSelector()
	rpc := service + "/" + method
	if selector.GetRpc() != "" && selector.GetRpc() != rpc {
		return false
	}
	if selector.GetRpc() == "" && (selector.GetService() != service || selector.GetMethod() != method) {
		return false
	}
	if config.bindingPolicy == "exact" {
		for _, configured := range config.bindings {
			if !configured.disabled && configured.id == binding.GetId() {
				return true
			}
		}
		return false
	}
	return true
}

func interceptorBindingWantsValidate(binding *interceptorv1.InterceptorBinding) bool {
	for _, phase := range binding.GetPhases() {
		if phase == interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_VALIDATE {
			return true
		}
	}
	return false
}

func interceptorTimeout(configured string) time.Duration {
	raw := strings.TrimSpace(configured)
	if raw == "" {
		return 500 * time.Millisecond
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 500 * time.Millisecond
	}
	return d
}

func interceptorFailurePolicy(binding *interceptorv1.InterceptorBinding, registration interceptorRegistration) string {
	if value := strings.TrimSpace(binding.GetFailurePolicy()); value != "" {
		return value
	}
	if value := strings.TrimSpace(registration.manifest.GetFailurePolicy()); value != "" {
		return value
	}
	return registration.config.failurePolicy
}

func interceptorStatusCode(value string) codes.Code {
	switch strings.TrimSpace(value) {
	case "INVALID_ARGUMENT":
		return codes.InvalidArgument
	case "UNAUTHENTICATED":
		return codes.Unauthenticated
	case "PERMISSION_DENIED":
		return codes.PermissionDenied
	case "ABORTED":
		return codes.Aborted
	case "RESOURCE_EXHAUSTED":
		return codes.ResourceExhausted
	default:
		return codes.PermissionDenied
	}
}

func normalizeGatewayInterceptorConfig(config gatewayconfig.Interceptor) (gatewayInterceptorConfig, error) {
	value := func(p *string) string {
		if p == nil {
			return ""
		}
		return strings.TrimSpace(*p)
	}
	out := gatewayInterceptorConfig{
		name:          value(config.Name),
		endpoint:      value(config.GRPCEndpoint),
		tlsCACertPath: value(config.TLSCACertPath),
		audience:      value(config.Audience),
		allowInsecure: config.AllowInsecureTransport,
		order:         config.Order,
		failurePolicy: value(config.FailurePolicy),
		timeout:       value(config.Timeout),
		bindingPolicy: value(config.BindingPolicy),
	}
	if config.MaxResponseBytes != nil {
		out.maxResponseSize = *config.MaxResponseBytes
	}
	if config.MaxPatches != nil {
		out.maxPatches = *config.MaxPatches
	}
	if out.name == "" || out.endpoint == "" {
		return gatewayInterceptorConfig{}, fmt.Errorf("gateway interceptor name and grpc_endpoint are required")
	}
	if out.failurePolicy == "" {
		out.failurePolicy = "fail_closed"
	}
	if out.bindingPolicy == "" {
		out.bindingPolicy = "dynamic"
	}
	for _, binding := range config.Bindings {
		item := gatewayInterceptorBinding{id: value(binding.ID), rpc: value(binding.RPC), service: value(binding.Service), method: value(binding.Method), disabled: binding.Disabled, failurePolicy: value(binding.FailurePolicy)}
		if binding.Phases != nil {
			item.phases = append([]string(nil), (*binding.Phases)...)
		}
		out.bindings = append(out.bindings, item)
	}
	return out, nil
}

func openGatewayInterceptorClient(config gatewayInterceptorConfig) (interceptorv1.GatewayInterceptorClient, *grpc.ClientConn, error) {
	u, err := url.Parse(config.endpoint)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, nil, fmt.Errorf("grpc_endpoint must be an http(s) URL without credentials")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, nil, fmt.Errorf("grpc_endpoint must not contain a path")
	}
	var opts []grpc.DialOption
	if u.Scheme == "http" {
		if !config.allowInsecure {
			return nil, nil, fmt.Errorf("plain-text grpc_endpoint requires allow_insecure_transport=true")
		}
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
		if config.tlsCACertPath != "" {
			pemBytes, err := os.ReadFile(config.tlsCACertPath)
			if err != nil {
				return nil, nil, fmt.Errorf("tls_ca_cert_path: %w", err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(pemBytes) {
				return nil, nil, fmt.Errorf("tls_ca_cert_path contains no certificates")
			}
			tlsConfig.RootCAs = roots
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	}
	conn, err := grpc.NewClient(u.Host, opts...)
	if err != nil {
		return nil, nil, err
	}
	return interceptorv1.NewGatewayInterceptorClient(conn), conn, nil
}

func validateGatewayInterceptorManifest(config gatewayInterceptorConfig, manifest *interceptorv1.InterceptorManifest) error {
	if manifest == nil {
		return fmt.Errorf("interceptor %q Describe returned an empty manifest", config.name)
	}
	if expected := strings.TrimSpace(manifest.GetExpectedAudience()); expected != "" && expected != config.audience {
		return fmt.Errorf("interceptor %q expected_audience %q does not match configured audience", config.name, expected)
	}
	if policy := strings.TrimSpace(manifest.GetFailurePolicy()); policy != "" && policy != "fail_open" && policy != "fail_closed" {
		return fmt.Errorf("interceptor %q returned invalid failure_policy %q", config.name, policy)
	}
	seen := map[string]struct{}{}
	for _, binding := range manifest.GetBindings() {
		if binding == nil || strings.TrimSpace(binding.GetId()) == "" {
			return fmt.Errorf("interceptor %q Describe returned a binding without id", config.name)
		}
		if _, exists := seen[binding.GetId()]; exists {
			return fmt.Errorf("interceptor %q Describe returned duplicate binding %q", config.name, binding.GetId())
		}
		seen[binding.GetId()] = struct{}{}
		if binding.GetSelector() == nil || (binding.GetSelector().GetRpc() == "" && (binding.GetSelector().GetService() == "" || binding.GetSelector().GetMethod() == "")) {
			return fmt.Errorf("interceptor %q binding %q has an incomplete selector", config.name, binding.GetId())
		}
		if binding.GetFailurePolicy() != "" && binding.GetFailurePolicy() != "fail_open" && binding.GetFailurePolicy() != "fail_closed" {
			return fmt.Errorf("interceptor %q binding %q has invalid failure_policy", config.name, binding.GetId())
		}
		for _, phase := range binding.GetPhases() {
			if phase == interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_POST_COMMIT && binding.GetFailurePolicy() == "fail_closed" {
				return fmt.Errorf("interceptor %q binding %q cannot use fail_closed for post_commit", config.name, binding.GetId())
			}
		}
	}
	if config.bindingPolicy == "exact" {
		configured := map[string]struct{}{}
		for _, binding := range config.bindings {
			if !binding.disabled {
				configured[binding.id] = struct{}{}
			}
		}
		for id := range configured {
			if _, ok := seen[id]; !ok {
				return fmt.Errorf("interceptor %q exact binding %q is not declared by service", config.name, id)
			}
		}
	}
	return nil
}

func openMiddlewareClient(service *sandboxv1.SupervisorMiddlewareService) (middlewarev1.SupervisorMiddlewareClient, *grpc.ClientConn, error) {
	endpoint := strings.TrimSpace(service.GetGrpcEndpoint())
	if endpoint == "" {
		return nil, nil, fmt.Errorf("grpc_endpoint is required")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, nil, fmt.Errorf("grpc_endpoint must be an http(s) URL without credentials")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, nil, fmt.Errorf("grpc_endpoint must not contain a path")
	}
	var opts []grpc.DialOption
	if u.Scheme == "http" {
		if !service.GetAllowInsecureTransport() {
			return nil, nil, fmt.Errorf("plain-text grpc_endpoint requires allow_insecure_transport=true")
		}
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
		if pemBytes := service.GetTlsCaCertPem(); len(pemBytes) > 0 {
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(pemBytes) {
				return nil, nil, fmt.Errorf("tls_ca_cert_pem contains no certificates")
			}
			tlsConfig.RootCAs = roots
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	}
	conn, err := grpc.NewClient(u.Host, opts...)
	if err != nil {
		return nil, nil, err
	}
	return middlewarev1.NewSupervisorMiddlewareClient(conn), conn, nil
}

func validateMiddlewareManifest(name string, service *sandboxv1.SupervisorMiddlewareService, manifest *middlewarev1.MiddlewareManifest) error {
	if manifest == nil {
		return fmt.Errorf("middleware %q Describe returned an empty manifest", name)
	}
	seen := map[string]struct{}{}
	for _, binding := range manifest.GetBindings() {
		if binding == nil {
			return fmt.Errorf("middleware %q Describe returned a nil binding", name)
		}
		key := fmt.Sprintf("%d/%d", binding.GetOperation(), binding.GetPhase())
		if _, exists := seen[key]; exists {
			return fmt.Errorf("middleware %q Describe returned duplicate binding %s", name, key)
		}
		seen[key] = struct{}{}
		if binding.GetMaxPayloadBytes() == 0 || binding.GetMaxPayloadBytes() > service.GetMaxPayloadBytes() {
			return fmt.Errorf("middleware %q binding %s exceeds configured max_payload_bytes", name, key)
		}
	}
	return nil
}

// validateMiddlewareConfigs asks every selected middleware to validate its
// service-specific policy before the sandbox receives the effective config.
// This keeps policy acceptance fail-closed and exercises the pinned related
// RPC instead of treating Describe as the whole integration.
func (r *driverRegistry) validateMiddlewareConfigs(ctx context.Context, policy *sandboxv1.SandboxPolicy) error {
	if r == nil || policy == nil || len(policy.GetNetworkMiddlewares()) == 0 {
		return nil
	}
	names := make([]string, 0, len(policy.GetNetworkMiddlewares()))
	for _, config := range policy.GetNetworkMiddlewares() {
		if config != nil {
			names = append(names, config.GetMiddleware())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		r.mu.Lock()
		registration, ok := r.middleware[name]
		r.mu.Unlock()
		if !ok {
			return fmt.Errorf("middleware %q is not registered", name)
		}
		var config *structpb.Struct
		for _, candidate := range policy.GetNetworkMiddlewares() {
			if candidate != nil && candidate.GetMiddleware() == name {
				config = candidate.GetConfig()
				break
			}
		}
		callCtx, cancel := context.WithTimeout(ctx, interceptorTimeout(registration.service.GetTimeout()))
		response, err := registration.client.ValidateConfig(callCtx, &middlewarev1.ValidateConfigRequest{Config: config, MiddlewareName: name})
		cancel()
		if err != nil {
			return fmt.Errorf("middleware %q ValidateConfig: %w", name, err)
		}
		if response == nil || !response.GetValid() {
			reason := "middleware rejected policy configuration"
			if response != nil && strings.TrimSpace(response.GetReason()) != "" {
				reason = response.GetReason()
			}
			return fmt.Errorf("middleware %q: %s", name, reason)
		}
	}
	return nil
}

func (r *driverRegistry) credentialDriver(name string) (credentialDriverRegistration, bool) {
	key := normalizeDriverName(name)
	r.mu.Lock()
	defer r.mu.Unlock()
	registration, ok := r.credential[key]
	return registration, ok
}

func (r *driverRegistry) selectedCredentialDriver(opt Options) (credentialDriverRegistration, string, error) {
	name := normalizeDriverName(opt.DefaultCredentialDriver)
	if name == "" && len(opt.CredentialDriverNames) == 1 {
		name = normalizeDriverName(opt.CredentialDriverNames[0])
	}
	if name == "" {
		if len(opt.CredentialDriverNames) > 1 {
			return credentialDriverRegistration{}, "", fmt.Errorf("multiple credential drivers are configured; default_credential_driver is required")
		}
		return credentialDriverRegistration{}, "", nil
	}
	registration, ok := r.credentialDriver(name)
	if !ok {
		return credentialDriverRegistration{}, "", fmt.Errorf("credential driver %q is not configured", name)
	}
	return registration, name, nil
}

func (r *driverRegistry) storeProviderCredentials(ctx context.Context, opt Options, sec *secrets.LocalEncrypted, provider, workspace string, values map[string]string, existing map[string]store.CredentialHandle) (string, map[string]store.CredentialHandle, error) {
	registration, driverName, err := r.selectedCredentialDriver(opt)
	if err != nil {
		return "", nil, err
	}
	if registration.client == nil {
		if sec == nil {
			return "", nil, fmt.Errorf("local credential storage is not initialized")
		}
		if err := sec.PutProviderCredentials(ctx, provider, values); err != nil {
			return "", nil, err
		}
		return "", nil, nil
	}
	handles := make(map[string]store.CredentialHandle, len(values))
	for key, value := range values {
		request := &credentialsv1.StoreCredentialRequest{ProviderName: provider, CredentialKey: key, Value: value, Workspace: workspace, ProviderId: provider}
		if old := existing[key]; old.Handle != "" {
			request.ExistingHandle = &datamodelv1.CredentialHandle{Driver: old.Driver, Handle: old.Handle, Metadata: old.Metadata}
		}
		response, callErr := registration.client.StoreCredential(ctx, request)
		if callErr != nil {
			return "", nil, fmt.Errorf("credential driver %q store %s: %w", driverName, key, callErr)
		}
		if response == nil || response.GetHandle() == nil || strings.TrimSpace(response.GetHandle().GetHandle()) == "" {
			return "", nil, fmt.Errorf("credential driver %q store %s returned an empty handle", driverName, key)
		}
		handle := response.GetHandle()
		handleDriver := strings.TrimSpace(handle.GetDriver())
		if handleDriver == "" {
			handleDriver = driverName
		}
		handles[key] = store.CredentialHandle{Driver: handleDriver, Handle: handle.GetHandle(), Metadata: handle.GetMetadata()}
	}
	return driverName, handles, nil
}

func (r *driverRegistry) deleteProviderCredential(ctx context.Context, provider, workspace string, handle store.CredentialHandle) error {
	if handle.Driver == "" || handle.Handle == "" {
		return nil
	}
	registration, ok := r.credentialDriver(handle.Driver)
	if !ok || registration.client == nil {
		return fmt.Errorf("credential driver %q is not configured", handle.Driver)
	}
	_, err := registration.client.DeleteCredential(ctx, &credentialsv1.DeleteCredentialRequest{ProviderName: provider, CredentialKey: "", Workspace: workspace, ProviderId: provider, Handle: &datamodelv1.CredentialHandle{Driver: handle.Driver, Handle: handle.Handle, Metadata: handle.Metadata}})
	return err
}

func (r *driverRegistry) resolveProviderCredentials(ctx context.Context, record store.ProviderRecord, keys []string, sec *secrets.LocalEncrypted) (map[string]string, error) {
	values, _, err := r.resolveProviderCredentialsWithExpiry(ctx, record, keys, sec)
	return values, err
}

// resolveProviderCredentialsWithExpiry preserves the optional expiry returned
// by CredentialDriver. An external driver is authoritative for the lifetime of
// a handle: an expired value must never cross the sandbox environment boundary,
// even when the gateway has not persisted the expiry yet.
func (r *driverRegistry) resolveProviderCredentialsWithExpiry(ctx context.Context, record store.ProviderRecord, keys []string, sec *secrets.LocalEncrypted) (map[string]string, map[string]int64, error) {
	if record.CredentialDriver == "" {
		if sec == nil {
			return nil, nil, fmt.Errorf("local credential storage is not initialized")
		}
		values, err := sec.GetProviderCredentials(ctx, record.Name, keys)
		return values, nil, err
	}
	registration, ok := r.credentialDriver(record.CredentialDriver)
	if !ok || registration.client == nil {
		return nil, nil, fmt.Errorf("credential driver %q is not configured", record.CredentialDriver)
	}
	requests := make([]*credentialsv1.ResolveCredentialRequest, 0, len(keys))
	for _, key := range keys {
		handle, ok := record.CredentialHandles[key]
		if !ok || handle.Handle == "" {
			return nil, nil, fmt.Errorf("provider %s credential %s has no driver handle", record.Name, key)
		}
		requests = append(requests, &credentialsv1.ResolveCredentialRequest{RequestId: key, ProviderName: record.Name, CredentialKey: key, Workspace: record.Workspace, ProviderId: record.Name, Handle: &datamodelv1.CredentialHandle{Driver: handle.Driver, Handle: handle.Handle, Metadata: handle.Metadata}})
	}
	response, err := registration.client.ResolveCredentials(ctx, &credentialsv1.ResolveCredentialsRequest{Credentials: requests})
	if err != nil {
		return nil, nil, err
	}
	if response == nil {
		return nil, nil, fmt.Errorf("credential driver %q returned an empty resolve response", record.CredentialDriver)
	}
	values := make(map[string]string, len(response.GetCredentials()))
	expires := make(map[string]int64)
	for _, credential := range response.GetCredentials() {
		if credential == nil || credential.GetRequestId() == "" {
			return nil, nil, fmt.Errorf("credential driver %q returned an invalid resolve response", record.CredentialDriver)
		}
		if credential.GetExpiresAtMs() < 0 {
			return nil, nil, fmt.Errorf("credential driver %q returned an invalid expiry for %s", record.CredentialDriver, credential.GetRequestId())
		}
		values[credential.GetRequestId()] = credential.GetValue()
		if credential.GetExpiresAtMs() > 0 {
			expires[credential.GetRequestId()] = credential.GetExpiresAtMs()
		}
	}
	for _, key := range keys {
		if _, ok := values[key]; !ok {
			return nil, nil, fmt.Errorf("credential driver %q omitted credential %s", record.CredentialDriver, key)
		}
		if expiresAt := expires[key]; expiresAt > 0 && expiresAt <= time.Now().UnixMilli() {
			return nil, nil, fmt.Errorf("credential %s is expired", key)
		}
	}
	return values, expires, nil
}

func driverConfig(configs DriverConfigs, name string) map[string]any {
	if config := configs[name]; config != nil {
		return config
	}
	return configs[normalizeDriverName(name)]
}

func normalizeDriverName(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

func isBuiltinComputeDriver(name string) bool {
	switch normalizeDriverName(name) {
	case "docker", "podman", "kubernetes", "vm":
		return true
	default:
		return false
	}
}

func isBuiltinCredentialDriver(name string, config map[string]any) bool {
	if normalizeDriverName(name) == "local" {
		return true
	}
	return strings.EqualFold(stringConfig(config, "type"), "local_encrypted")
}

func stringConfig(config map[string]any, key string) string {
	value, _ := config[key].(string)
	return strings.TrimSpace(value)
}

func openComputeDriverClient(endpoint string, config map[string]any) (computev1.ComputeDriverClient, *grpc.ClientConn, error) {
	conn, err := dialDriverEndpoint(endpoint, config)
	if err != nil {
		return nil, nil, err
	}
	return computev1.NewComputeDriverClient(conn), conn, nil
}

func openCredentialDriverClient(endpoint string, config map[string]any) (credentialsv1.CredentialDriverClient, *grpc.ClientConn, error) {
	conn, err := dialDriverEndpoint(endpoint, config)
	if err != nil {
		return nil, nil, err
	}
	return credentialsv1.NewCredentialDriverClient(conn), conn, nil
}

func dialDriverEndpoint(raw string, config map[string]any) (*grpc.ClientConn, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("grpc_endpoint must be an http(s) URL without credentials")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("grpc_endpoint scheme must be http or https")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("grpc_endpoint must not contain a path")
	}
	var opts []grpc.DialOption
	if u.Scheme == "https" {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()})))
	} else if boolConfig(config, "allow_insecure_transport") {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		return nil, fmt.Errorf("plain-text grpc_endpoint requires allow_insecure_transport=true")
	}
	return grpc.NewClient(u.Host, opts...)
}

func boolConfig(config map[string]any, key string) bool {
	value, _ := config[key].(bool)
	return value
}

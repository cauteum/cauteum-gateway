package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	datamodelv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/cauteum-haven/cauteum-core"
	"github.com/cauteum-haven/cauteum-driver/driver"
	_ "github.com/cauteum-haven/cauteum-driver/driver/all"
	"github.com/cauteum-haven/cauteum-gateway/internal/logbuf"
	"github.com/cauteum-haven/cauteum-gateway/internal/sshrelay"
	"github.com/cauteum-haven/cauteum-gateway/internal/storage/store"
	"github.com/cauteum-haven/cauteum-providers/provider"
	"github.com/cauteum-haven/cauteum-runtime/idp"
	"github.com/cauteum-haven/cauteum-runtime/secrets"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// openShellRPC exposes the pinned OpenShell protobuf service. Backend-specific
// capabilities that have no safe implementation return an explicit status
// rather than silently accepting an ineffective request.
type openShellRPC struct {
	openshellv1.UnimplementedOpenShellServer
	options Options
	runtime *grpcRuntime
}

type grpcRuntime struct {
	st                  *store.Store
	sec                 *secrets.LocalEncrypted
	oidc                *idp.OIDC
	logs                *logbuf.Hub
	relay               *sshrelay.Hub
	opt                 Options
	compute             *computeRegistry
	drivers             *driverRegistry
	sandboxMu           sync.Mutex
	globalPolicyMu      sync.Mutex
	waitSupervisorReady func(context.Context, string) error
	policyApplyTimeout  time.Duration
	sshSessionTTL       time.Duration
	forwardLimitMu      sync.Mutex
	forwardActive       int
	forwardBySandbox    map[string]int
	stagingMu           sync.Mutex
	rootfsStaging       map[string]rootfsTarStagingSlot
}

// computeRegistry resolves only configured engines. Engine construction is lazy so
// gateway health/config inspection remains available while a daemon is restarting.
type computeRegistry struct {
	mu         sync.Mutex
	configured DriverConfigs
	engines    map[string]driver.Engine
	remote     map[string]driver.Engine
}

func newComputeRegistry(opt Options) *computeRegistry {
	names := opt.ComputeDriverNames
	if len(names) == 0 {
		names = []string{"docker"}
	}
	r := &computeRegistry{configured: make(DriverConfigs), engines: map[string]driver.Engine{}, remote: map[string]driver.Engine{}}
	for _, name := range names {
		key := strings.ToLower(strings.TrimSpace(name))
		config := opt.ComputeDriverConfigs[name]
		if config == nil {
			config = opt.ComputeDriverConfigs[key]
		}
		r.configured[key] = config
	}
	return r
}

func (r *computeRegistry) engine(name string) (driver.Engine, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	r.mu.Lock()
	defer r.mu.Unlock()
	if engine := r.engines[name]; engine != nil {
		return engine, nil
	}
	if engine := r.remote[name]; engine != nil {
		r.engines[name] = engine
		return engine, nil
	}
	config, ok := r.configured[name]
	if !ok {
		return nil, fmt.Errorf("compute driver %q is not configured", name)
	}
	engine, err := driver.OpenEngineWithConfig(name, config)
	if err != nil {
		return nil, err
	}
	r.engines[name] = engine
	return engine, nil
}

func (r *computeRegistry) bindRemote(name string, engine driver.Engine) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || engine == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.remote[name] = engine
}

func (r *computeRegistry) isRemote(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.remote[name]
	return ok
}

func (s *openShellRPC) Health(context.Context, *openshellv1.HealthRequest) (*openshellv1.HealthResponse, error) {
	return &openshellv1.HealthResponse{Status: openshellv1.ServiceStatus_SERVICE_STATUS_HEALTHY, Version: "cauteum-alpha"}, nil
}

// ConnectSupervisor accepts the pinned OpenShell supervisor control protocol.
// Sandbox identity is bound by the gRPC auth interceptor and checked against
// the mandatory first Hello payload before the session is registered.
func (s *openShellRPC) ConnectSupervisor(stream grpc.BidiStreamingServer[openshellv1.SupervisorMessage, openshellv1.GatewayMessage]) error {
	principal := PrincipalFrom(stream.Context())
	if principal.Kind != PrincipalSandbox || s.runtime == nil || s.runtime.st == nil || s.runtime.relay == nil {
		return status.Error(codes.PermissionDenied, "sandbox supervisor identity required")
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil || strings.TrimSpace(hello.GetInstanceId()) == "" {
		_ = stream.Send(&openshellv1.GatewayMessage{Payload: &openshellv1.GatewayMessage_SessionRejected{SessionRejected: &openshellv1.SessionRejected{Reason: "supervisor Hello is incomplete"}}})
		return status.Error(codes.PermissionDenied, "supervisor Hello requires an instance id")
	}
	sandbox, ok := s.runtime.st.GetSandbox(principal.Sandbox)
	if !ok {
		sandbox, ok = s.runtime.st.GetSandboxByID(principal.Sandbox)
	}
	if !ok {
		return status.Error(codes.NotFound, "sandbox not found")
	}
	if hello.GetSandboxId() != sandbox.Name && hello.GetSandboxId() != sandbox.ID {
		_ = stream.Send(&openshellv1.GatewayMessage{Payload: &openshellv1.GatewayMessage_SessionRejected{SessionRejected: &openshellv1.SessionRejected{Reason: "supervisor sandbox identity mismatch"}}})
		return status.Error(codes.PermissionDenied, "supervisor Hello sandbox does not match token")
	}
	if sandbox.PolicyRev > 0 {
		if err := s.syncSandboxRuntimePolicy(sandbox.Name, sandbox.PolicyRev); err != nil {
			return status.Error(codes.Unavailable, "current sandbox policy could not be synchronized")
		}
	}
	if _, err := s.runtime.st.SetSupervisorInstance(sandbox.Name, hello.GetInstanceId()); err != nil {
		return status.Error(codes.Internal, "could not record supervisor instance")
	}
	openRequests := make(chan *openshellv1.GatewayMessage, 32)
	done := make(chan struct{})
	var closeOnce sync.Once
	closeDone := func() { closeOnce.Do(func() { close(done) }) }
	defer closeDone()
	remove := s.runtime.relay.RegisterOpenShellSupervisor(sandbox.Name, hello.GetInstanceId(), func(channel, target string) error {
		msg, targetErr := openShellRelayOpenMessage(channel, target)
		if targetErr != nil {
			return targetErr
		}
		select {
		case openRequests <- msg:
			return nil
		case <-done:
			return sshrelay.ErrNotConnected
		}
	}, done, closeDone)
	defer remove()
	if err := stream.Send(&openshellv1.GatewayMessage{Payload: &openshellv1.GatewayMessage_SessionAccepted{SessionAccepted: &openshellv1.SessionAccepted{SessionId: newGatewayID(), HeartbeatIntervalSecs: 15}}}); err != nil {
		return err
	}
	type recvResult struct {
		msg *openshellv1.SupervisorMessage
		err error
	}
	recv := make(chan recvResult, 1)
	go func() {
		for {
			m, e := stream.Recv()
			select {
			case recv <- recvResult{m, e}:
			case <-done:
				return
			}
			if e != nil {
				return
			}
		}
	}()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return nil
		case <-stream.Context().Done():
			return stream.Context().Err()
		case result := <-recv:
			if result.err != nil {
				return result.err
			}
			if result.msg.GetHeartbeat() != nil {
				continue
			}
			if relayClose := result.msg.GetRelayClose(); relayClose != nil {
				if strings.TrimSpace(relayClose.GetChannelId()) == "" {
					return status.Error(codes.InvalidArgument, "relay_close requires channel_id")
				}
				s.runtime.relay.CloseOpenShellRelay(principal.Sandbox, relayClose.GetChannelId(), errors.New("supervisor aborted relay"))
				continue
			}
			if openResult := result.msg.GetRelayOpenResult(); openResult != nil {
				if !openResult.GetSuccess() {
					s.runtime.relay.RejectOpenShellRelay(principal.Sandbox, openResult.GetChannelId(), fmt.Errorf("supervisor rejected relay open: %s", openResult.GetError()))
				}
				continue
			}
			return status.Error(codes.InvalidArgument, "unexpected supervisor control message")
		case msg := <-openRequests:
			if err := stream.Send(msg); err != nil {
				return err
			}
		case <-ticker.C:
			if err := stream.Send(&openshellv1.GatewayMessage{Payload: &openshellv1.GatewayMessage_Heartbeat{Heartbeat: &openshellv1.GatewayHeartbeat{}}}); err != nil {
				return err
			}
		}
	}
}

// RelayStream binds a supervisor's outbound data stream to the pending channel
// created by the gateway. The first frame must claim a channel with RelayInit.
func (s *openShellRPC) RelayStream(stream grpc.BidiStreamingServer[openshellv1.RelayFrame, openshellv1.RelayFrame]) error {
	p := PrincipalFrom(stream.Context())
	if p.Kind != PrincipalSandbox || s.runtime == nil || s.runtime.relay == nil {
		return status.Error(codes.PermissionDenied, "sandbox supervisor identity required")
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if first.GetInit() == nil || strings.TrimSpace(first.GetInit().GetChannelId()) == "" {
		return status.Error(codes.InvalidArgument, "first relay frame must contain init.channel_id")
	}
	conn, err := s.runtime.relay.AcceptOpenShellRelay(p.Sandbox, first.GetInit().GetChannelId())
	if err != nil {
		return status.Error(codes.NotFound, "relay channel is not pending for this sandbox")
	}
	defer conn.Close()
	defer s.runtime.relay.CloseOpenShellRelay(p.Sandbox, first.GetInit().GetChannelId(), nil)
	readDone := make(chan error, 1)
	go func() {
		for {
			frame, recvErr := stream.Recv()
			if recvErr != nil {
				if recvErr == io.EOF {
					if closer, ok := conn.(interface{ CloseWrite() error }); ok {
						_ = closer.CloseWrite()
					}
				} else {
					_ = conn.Close()
				}
				readDone <- recvErr
				return
			}
			if _, ok := frame.GetPayload().(*openshellv1.RelayFrame_Data); !ok {
				_ = conn.Close()
				readDone <- status.Error(codes.InvalidArgument, "relay data frame expected after init")
				return
			}
			data := frame.GetData()
			if len(data) == 0 {
				// Pinned OpenShell treats empty Data frames as no-ops. RelayFrame
				// has no FIN payload; only gRPC request EOF half-closes this side.
				continue
			}
			if writeErr := writeAll(conn, data); writeErr != nil {
				_ = conn.Close()
				readDone <- writeErr
				return
			}
		}
	}()
	type relayRead struct {
		data []byte
		err  error
	}
	readFrames := make(chan relayRead, 1)
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, readErr := conn.Read(buf)
			var data []byte
			if n > 0 {
				data = append([]byte(nil), buf[:n]...)
			}
			select {
			case readFrames <- relayRead{data: data, err: readErr}:
			case <-stream.Context().Done():
				return
			}
			if readErr != nil {
				return
			}
		}
	}()
	requestEOF, responseEOF := false, false
	for {
		select {
		case event := <-readFrames:
			if len(event.data) > 0 {
				if err := stream.Send(&openshellv1.RelayFrame{Payload: &openshellv1.RelayFrame_Data{Data: event.data}}); err != nil {
					return err
				}
			}
			if event.err == io.EOF {
				// The peer may have closed its write direction while still
				// expecting request bytes. Keep the RPC alive until both halves end.
				responseEOF = true
				readFrames = nil
				if requestEOF {
					return nil
				}
				continue
			}
			if event.err != nil {
				return event.err
			}
		case recvErr := <-readDone:
			if recvErr == io.EOF {
				// CloseWrite on the relay pipe has delivered the caller's FIN
				// to the target. Keep the response stream alive until the target
				// closes its own write side.
				readDone = nil
				requestEOF = true
				if responseEOF {
					return nil
				}
				continue
			}
			if recvErr != nil {
				return recvErr
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

// CreateSandbox provisions a named workspace-backed sandbox through the selected
// gateway compute engine and records the resulting runtime identity.
func (s *openShellRPC) CreateSandbox(ctx context.Context, req *openshellv1.CreateSandboxRequest) (*openshellv1.SandboxResponse, error) {
	return (&sandboxLifecycle{rpc: s}).Create(ctx, req)
}

func (l *sandboxLifecycle) Create(ctx context.Context, req *openshellv1.CreateSandboxRequest) (*openshellv1.SandboxResponse, error) {
	s := l.rpc
	if s.runtime == nil || s.runtime.st == nil || s.runtime.compute == nil {
		return nil, status.Error(codes.Unavailable, "compute runtime is not initialized")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	p := PrincipalFrom(ctx)
	if p.Kind != PrincipalUser {
		return nil, status.Error(codes.Unauthenticated, "authenticated user required")
	}
	workspace := strings.TrimSpace(req.GetWorkspace())
	if workspace == "" {
		workspace = "default"
	}
	if !validSandboxName(workspace) {
		return nil, status.Error(codes.InvalidArgument, "workspace must be a simple name")
	}
	if err := s.requireSandboxWrite(ctx, workspace); err != nil {
		return nil, err
	}
	if err := s.requireWorkspaceActive(workspace); err != nil {
		return nil, err
	}
	requestedSpec := req.GetSpec()
	workloadTemplateName := strings.TrimSpace(req.GetWorkloadTemplateName())
	var spec *openshellv1.SandboxSpec
	if workloadTemplateName != "" {
		if !validDNSLabel(workloadTemplateName) {
			return nil, status.Error(codes.InvalidArgument, "workload_template_name must be a DNS label")
		}
		if err := validateTemplateGovernanceSpec(requestedSpec); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		record, ok := s.runtime.st.GetScopedTemplate(workspace, workloadTemplateName)
		if !ok {
			return nil, status.Error(codes.NotFound, "sandbox template not found")
		}
		stored, err := templateRecordToProto(record)
		if err != nil {
			return nil, status.Error(codes.Internal, "stored sandbox template is invalid")
		}
		if err := validateSandboxWorkloadTemplate(stored); err != nil {
			return nil, status.Error(codes.Internal, "stored sandbox template is invalid")
		}
		resolved, err := sandboxSpecFromWorkloadTemplate(stored)
		if err != nil {
			return nil, err
		}
		if requestedSpec != nil {
			resolved.Policy = requestedSpec.GetPolicy()
			resolved.Providers = append([]string(nil), requestedSpec.GetProviders()...)
			resolved.Command = append([]string(nil), requestedSpec.GetCommand()...)
			resolved.Tty = requestedSpec.GetTty()
		}
		spec = resolved
	} else {
		if requestedSpec == nil || requestedSpec.GetTemplate() == nil {
			return nil, status.Error(codes.InvalidArgument, "spec.template is required")
		}
		spec = requestedSpec
	}
	tmpl := spec.GetTemplate()
	if req.GetAwaitMainProcessAttachment() || spec.GetTty() {
		return nil, status.Error(codes.Unimplemented, "interactive supervisor lifecycle is not available in gateway compute runtime")
	}
	if tmpl.GetRuntimeClassName() != "" || tmpl.GetAgentSocket() != "" || tmpl.UserNamespaces != nil {
		return nil, status.Error(codes.Unimplemented, "requested template isolation/socket fields are not supported by this engine")
	}
	driverName := "docker"
	if _, ok := s.runtime.compute.configured[driverName]; !ok {
		names := make([]string, 0, len(s.runtime.compute.configured))
		for name := range s.runtime.compute.configured {
			names = append(names, name)
		}
		sort.Strings(names)
		if len(names) == 0 {
			return nil, status.Error(codes.FailedPrecondition, "no compute driver is configured")
		}
		driverName = names[0]
	}
	if tmpl.GetDriverConfig() != nil {
		allCfg := tmpl.GetDriverConfig().AsMap()
		selected, ok := allCfg[driverName].(map[string]any)
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "template.driver_config has no %q configuration", driverName)
		}
		if _, err := json.Marshal(selected); err != nil {
			return nil, status.Error(codes.InvalidArgument, "template driver config is invalid")
		}
	}
	name := strings.TrimSpace(req.GetName())
	if name == "" {
		name = newGatewayID()
	}
	if err := validateOpenShellCreateSandbox(name, req.GetLabels(), req.GetAnnotations(), spec, driverName); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	effectiveReq := proto.Clone(req).(*openshellv1.CreateSandboxRequest)
	effectiveReq.Spec = spec
	principal := PrincipalFrom(ctx)
	modified, err := s.runtime.drivers.evaluateGatewayInterceptorPhases(ctx, "openshell.v1.OpenShell", "CreateSandbox", map[string]string{
		"subject": principal.Subject,
		"idp":     principal.IDP,
		"kind":    fmt.Sprintf("%d", principal.Kind),
	}, effectiveReq, false)
	if err != nil {
		return nil, err
	}
	effectiveReq = modified.(*openshellv1.CreateSandboxRequest)
	spec = effectiveReq.GetSpec()
	tmpl = spec.GetTemplate()
	stagedRootfs, err := s.resolveRootfsTarStaging(ctx, effectiveReq, driverName, workspace)
	if err != nil {
		return nil, err
	}
	if stagedRootfs != "" {
		defer s.releaseRootfsTarStaging(stagedRootfs)
	}
	if globalYAML, _ := s.runtime.st.GlobalPolicySnapshot(); strings.TrimSpace(globalYAML) != "" {
		if _, policyErr := parseGlobalPolicyYAML(globalYAML); policyErr != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "global policy is invalid: %v", policyErr)
		}
	}
	engine, err := s.runtime.compute.engine(driverName)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "compute driver %q unavailable: %v", driverName, err)
	}
	s.runtime.sandboxMu.Lock()
	defer s.runtime.sandboxMu.Unlock()
	if _, exists := s.runtime.st.GetSandbox(name); exists {
		return nil, status.Error(codes.AlreadyExists, "sandbox already exists")
	}
	image := strings.TrimSpace(tmpl.GetImage())
	if image == "" {
		if configured := s.runtime.compute.configured[driverName]["default_image"]; configured != nil {
			image, _ = configured.(string)
			image = strings.TrimSpace(image)
		}
	}
	if image == "" {
		return nil, status.Error(codes.InvalidArgument, "spec.template.image is required")
	}
	workspaceRoot := filepath.Join(s.runtime.opt.DataDir, "workspaces", workspace)
	if err := os.MkdirAll(workspaceRoot, 0o700); err != nil {
		return nil, status.Error(codes.Internal, "workspace storage could not be prepared")
	}
	runtimeInputs, err := s.prepareSandboxRuntime(effectiveReq, driverName, name, workspace)
	if err != nil {
		_ = os.RemoveAll(filepath.Join(s.runtime.opt.DataDir, "sandboxes", name))
		return nil, status.Errorf(codes.FailedPrecondition, "sandbox runtime preparation failed: %v", err)
	}
	labels := make(map[string]string, len(req.GetLabels())+len(tmpl.GetLabels()))
	for k, v := range tmpl.GetLabels() {
		labels[k] = v
	}
	for k, v := range req.GetLabels() {
		labels[k] = v
	}
	command := append([]string(nil), spec.GetCommand()...)
	if len(command) == 0 {
		command = []string{"/bin/sh"}
	}
	var driverConfigJSON string
	if tmpl.GetDriverConfig() != nil {
		if selected, ok := tmpl.GetDriverConfig().AsMap()[driverName].(map[string]any); ok {
			b, e := json.Marshal(selected)
			if e != nil {
				return nil, status.Error(codes.InvalidArgument, "template driver config is invalid")
			}
			driverConfigJSON = string(b)
		}
	}
	driverSpec, err := buildGatewayDriverSpec(effectiveReq, runtimeInputs, name, image, workspaceRoot, driverName, driverConfigJSON)
	if err != nil {
		_ = os.RemoveAll(filepath.Join(s.runtime.opt.DataDir, "sandboxes", name))
		return nil, status.Errorf(codes.InvalidArgument, "sandbox resource settings are invalid: %v", err)
	}
	driverSpec.Command = command
	driverSpec.Labels = labels
	now := time.Now().UTC()
	specJSON, err := protojson.Marshal(spec)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "sandbox spec cannot be serialized")
	}
	record := store.Sandbox{Name: name, ID: newGatewayID(), ComputeDriver: driverName, Image: image, Workspace: workspace, Status: "provisioning", Labels: labels, Annotations: req.GetAnnotations(), SpecJSON: string(specJSON), BasePolicyYAML: string(runtimeInputs.baseYAML), AttachedProviders: runtimeInputs.attached, CreatedAt: now, UpdatedAt: now}
	if err = s.runtime.st.UpsertSandbox(record); err == nil {
		if len(runtimeInputs.baseYAML) != 0 {
			err = s.runtime.st.SetBasePolicy(name, string(runtimeInputs.baseYAML))
			if err == nil {
				stored, ok := s.runtime.st.GetSandbox(name)
				if !ok {
					err = fmt.Errorf("sandbox record disappeared after policy update")
				} else {
					err = s.syncSandboxRuntimePolicy(name, stored.PolicyRev)
				}
			}
		}
	}
	if err != nil {
		_ = s.runtime.st.DeleteSandbox(name)
		_ = os.RemoveAll(filepath.Join(s.runtime.opt.DataDir, "sandboxes", name))
		return nil, status.Error(codes.Internal, "sandbox registry update failed")
	}
	token, err := s.runtime.st.IssueSandboxToken(name)
	if err != nil {
		_ = s.runtime.st.DeleteSandbox(name)
		_ = os.RemoveAll(filepath.Join(s.runtime.opt.DataDir, "sandboxes", name))
		return nil, status.Error(codes.Internal, "sandbox supervisor token could not be issued")
	}
	if _, err := s.runtime.st.BeginSandboxStart(name); err != nil {
		_ = s.runtime.st.DeleteSandbox(name)
		_ = os.RemoveAll(filepath.Join(s.runtime.opt.DataDir, "sandboxes", name))
		return nil, status.Error(codes.Internal, "sandbox lifecycle transition failed")
	}
	driverSpec.ProxyEnv = append(driverSpec.ProxyEnv, "CAUTEUM_GATEWAY_URL="+runtimeInputs.gatewayURL, "CAUTEUM_SANDBOX="+name, "CAUTEUM_SANDBOX_TOKEN="+token, "CAUTEUM_LOG_DIR=/var/log")
	h, err := engine.Create(ctx, driverSpec)
	if err != nil {
		_ = s.runtime.st.DeleteSandbox(name)
		_ = os.RemoveAll(filepath.Join(s.runtime.opt.DataDir, "sandboxes", name))
		return nil, status.Errorf(codes.FailedPrecondition, "sandbox create failed: %v", err)
	}
	if err = engine.Start(ctx, h.ID); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_ = engine.Delete(cleanupCtx, h.ID)
		_ = s.runtime.st.DeleteSandbox(name)
		_ = os.RemoveAll(filepath.Join(s.runtime.opt.DataDir, "sandboxes", name))
		return nil, status.Errorf(codes.FailedPrecondition, "sandbox start failed: %v", err)
	}
	if !s.runtime.compute.isRemote(driverName) {
		if err = awaitProxySidecar(ctx, engine, name); err != nil {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			_ = engine.Stop(cleanupCtx, h.ID)
			_ = engine.Delete(cleanupCtx, h.ID)
			_ = s.runtime.st.DeleteSandbox(name)
			_ = os.RemoveAll(filepath.Join(s.runtime.opt.DataDir, "sandboxes", name))
			return nil, status.Error(codes.FailedPrecondition, "sandbox proxy supervisor did not start")
		}
	}
	if !s.runtime.compute.isRemote(driverName) {
		if err = s.waitForSupervisorReady(ctx, name); err != nil {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			_ = engine.Stop(cleanupCtx, h.ID)
			_ = engine.Delete(cleanupCtx, h.ID)
			_ = s.runtime.st.DeleteSandbox(name)
			_ = os.RemoveAll(filepath.Join(s.runtime.opt.DataDir, "sandboxes", name))
			return nil, status.Error(codes.FailedPrecondition, "sandbox supervisor relay did not become ready; check that compute driver's grpc_endpoint is reachable from the container and that guest TLS settings are complete (Docker Desktop/WSL2 typically uses host.docker.internal)")
		}
	}
	if persisted, ok := s.runtime.st.GetSandbox(name); ok {
		record = persisted
	}
	record.RuntimeID = string(h.ID)
	record.Network = h.Network
	record.Status = "running"
	record.UpdatedAt = time.Now().UTC()
	if err = s.runtime.st.UpsertSandbox(record); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_ = engine.Stop(cleanupCtx, h.ID)
		_ = engine.Delete(cleanupCtx, h.ID)
		_ = s.runtime.st.DeleteSandbox(name)
		_ = os.RemoveAll(filepath.Join(s.runtime.opt.DataDir, "sandboxes", name))
		return nil, status.Error(codes.Internal, "sandbox registry update failed")
	}
	metadata := &datamodelv1.ObjectMeta{Id: record.ID, Name: name, CreatedAtMs: record.CreatedAt.UnixMilli(), Labels: labels, Annotations: record.Annotations, Workspace: workspace, ResourceVersion: record.ResourceVersion}
	response := &openshellv1.SandboxResponse{Sandbox: &openshellv1.Sandbox{Metadata: metadata, Spec: effectiveReq.GetSpec(), Status: &openshellv1.SandboxStatus{SandboxName: name, Phase: openshellv1.SandboxPhase_SANDBOX_PHASE_PROVISIONING, CurrentPolicyVersion: uint32(record.PolicyRev)}}}
	// post_commit is observational by contract: the sandbox is already durable
	// and running, so an unavailable interceptor must not roll it back.
	_, _ = s.runtime.drivers.evaluateGatewayInterceptorPhases(ctx, "openshell.v1.OpenShell", "CreateSandbox", map[string]string{
		"subject": principal.Subject,
		"idp":     principal.IDP,
		"kind":    fmt.Sprintf("%d", principal.Kind),
	}, response, true)
	return response, nil
}

func (s *openShellRPC) waitForSupervisorReady(ctx context.Context, sandbox string) error {
	if s.runtime.waitSupervisorReady != nil {
		return s.runtime.waitSupervisorReady(ctx, sandbox)
	}
	if s.runtime.relay == nil {
		return sshrelay.ErrNotConnected
	}
	return s.runtime.relay.WaitConnected(ctx, sandbox, 15*time.Second)
}

func validSandboxName(name string) bool {
	if len(name) == 0 || len(name) > 63 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

func awaitProxySidecar(ctx context.Context, engine driver.Engine, sandbox string) error {
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		info, err := engine.Inspect(ctx, "cauteum-proxy-"+sandbox)
		if err == nil {
			state := strings.ToLower(strings.TrimSpace(info.Status))
			if strings.Contains(state, "running") || strings.HasPrefix(state, "up ") {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("proxy sidecar is not running")
		case <-ticker.C:
		}
	}
}
func validEnvKey(k string) bool {
	if k == "" {
		return false
	}
	for i, r := range k {
		switch {
		case r == '_', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

func (s *openShellRPC) requireSandboxWrite(ctx context.Context, workspace string) error {
	p := PrincipalFrom(ctx)
	_, workspaceExists := s.runtime.st.GetWorkspace(workspace)
	if !workspaceExists && workspace != "default" {
		return status.Error(codes.NotFound, "workspace not found")
	}
	if p.IDP == "local" || p.IDP == "local_dev" {
		return nil
	}
	if !containsString(p.Scopes, "sandbox:write") && !containsString(p.Scopes, "openshell:all") {
		return status.Error(codes.PermissionDenied, "sandbox:write scope required")
	}
	ws, ok := s.runtime.st.GetWorkspace(workspace)
	if !ok {
		return status.Error(codes.NotFound, "workspace not found")
	}
	for _, m := range ws.Members {
		if m.Subject == p.Subject {
			role := strings.ToLower(strings.TrimSpace(m.Role))
			if role == "owner" || role == "admin" || role == "user" || role == "member" {
				return nil
			}
		}
	}
	return status.Error(codes.PermissionDenied, "workspace sandbox access required")
}

func (s *openShellRPC) loadSandboxForMutation(ctx context.Context, name, workspace string) (store.Sandbox, driver.Engine, error) {
	if s.runtime == nil || s.runtime.st == nil || s.runtime.compute == nil {
		return store.Sandbox{}, nil, status.Error(codes.Unavailable, "compute runtime is not initialized")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return store.Sandbox{}, nil, status.Error(codes.InvalidArgument, "sandbox name is required")
	}
	rec, ok := s.runtime.st.GetSandbox(name)
	if !ok {
		return store.Sandbox{}, nil, status.Error(codes.NotFound, "sandbox not found")
	}
	workspace = strings.TrimSpace(workspace)
	if workspace == "" {
		workspace = "default"
	}
	if rec.Workspace == "" {
		rec.Workspace = "default"
	}
	if rec.Workspace != workspace {
		return store.Sandbox{}, nil, status.Error(codes.NotFound, "sandbox not found")
	}
	if err := s.requireSandboxWrite(ctx, workspace); err != nil {
		return store.Sandbox{}, nil, err
	}
	engine, err := s.runtime.compute.engine(rec.ComputeDriver)
	if err != nil {
		return store.Sandbox{}, nil, status.Errorf(codes.FailedPrecondition, "compute driver unavailable: %v", err)
	}
	return rec, engine, nil
}

func sandboxLifecycleResponse(rec store.Sandbox, phase openshellv1.SandboxPhase) *openshellv1.SandboxResponse {
	status := &openshellv1.SandboxStatus{SandboxName: rec.Name, Phase: phase, MainProcessInstanceId: rec.MainProcessInstanceID}
	if rec.MainProcessExitCode != nil {
		code := *rec.MainProcessExitCode
		status.ExitCode = &code
	}
	return &openshellv1.SandboxResponse{Sandbox: &openshellv1.Sandbox{Metadata: &datamodelv1.ObjectMeta{Id: rec.ID, Name: rec.Name, Labels: rec.Labels, Annotations: rec.Annotations, Workspace: rec.Workspace, ResourceVersion: rec.ResourceVersion}, Status: status}}
}

// sandboxLifecycle owns the runtime transitions shared by the OpenShell and
// user-facing control transports. expectedVersion is zero only for legacy
// OpenShell callers, whose pinned request schema has no version field.
type sandboxLifecycle struct{ rpc *openShellRPC }

func (s *openShellRPC) StartSandbox(ctx context.Context, req *openshellv1.StartSandboxRequest) (*openshellv1.SandboxResponse, error) {
	return (&sandboxLifecycle{rpc: s}).Start(ctx, req, 0)
}

func (l *sandboxLifecycle) Start(ctx context.Context, req *openshellv1.StartSandboxRequest, expectedVersion uint64) (*openshellv1.SandboxResponse, error) {
	s := l.rpc
	if s.runtime == nil {
		return nil, status.Error(codes.Unavailable, "compute runtime is not initialized")
	}
	s.runtime.sandboxMu.Lock()
	defer s.runtime.sandboxMu.Unlock()
	rec, engine, err := s.loadSandboxForMutation(ctx, req.GetName(), req.GetWorkspace())
	if err != nil {
		return nil, err
	}
	if expectedVersion != 0 && rec.ResourceVersion != expectedVersion {
		return nil, status.Error(codes.Aborted, "sandbox resource version changed")
	}
	if err := s.requireWorkspaceActive(rec.Workspace); err != nil {
		return nil, err
	}
	if rec.RuntimeID == "" {
		rec, err = s.recreateMissingSandboxRuntime(ctx, rec, engine)
		if err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "sandbox recovery failed: %v", err)
		}
		return sandboxLifecycleResponse(rec, openshellv1.SandboxPhase_SANDBOX_PHASE_READY), nil
	}
	if rec.PolicyRev > 0 {
		if err := s.syncSandboxRuntimePolicy(rec.Name, rec.PolicyRev); err != nil {
			return nil, status.Error(codes.FailedPrecondition, "current sandbox policy could not be synchronized")
		}
	}
	rec, err = s.runtime.st.BeginSandboxStartCAS(rec.Name, expectedVersion)
	if err != nil {
		if errors.Is(err, store.ErrResourceVersionConflict) {
			return nil, status.Error(codes.Aborted, "sandbox resource version changed")
		}
		return nil, status.Error(codes.Internal, "sandbox registry update failed")
	}
	if err = engine.Start(ctx, core.ID(rec.RuntimeID)); err != nil {
		rec.Status = "error"
		_ = s.runtime.st.UpsertSandbox(rec)
		return nil, status.Errorf(codes.FailedPrecondition, "sandbox start failed: %v", err)
	}
	if err = s.waitForSupervisorReady(ctx, rec.Name); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_ = engine.Stop(cleanupCtx, core.ID(rec.RuntimeID))
		rec.Status = "error"
		_ = s.runtime.st.UpsertSandbox(rec)
		return nil, status.Error(codes.FailedPrecondition, "sandbox supervisor relay did not reconnect")
	}
	rec, err = s.runtime.st.MarkSandboxRunning(rec.Name)
	if err != nil {
		return nil, status.Error(codes.Internal, "sandbox registry update failed")
	}
	phase := openshellv1.SandboxPhase_SANDBOX_PHASE_READY
	switch rec.Status {
	case "completed":
		phase = openshellv1.SandboxPhase_SANDBOX_PHASE_COMPLETED
	case "error", "failed":
		phase = openshellv1.SandboxPhase_SANDBOX_PHASE_ERROR
	}
	return sandboxLifecycleResponse(rec, phase), nil
}

func (s *openShellRPC) StopSandbox(ctx context.Context, req *openshellv1.StopSandboxRequest) (*openshellv1.SandboxResponse, error) {
	return (&sandboxLifecycle{rpc: s}).Stop(ctx, req, 0)
}

func (l *sandboxLifecycle) Stop(ctx context.Context, req *openshellv1.StopSandboxRequest, expectedVersion uint64) (*openshellv1.SandboxResponse, error) {
	s := l.rpc
	if s.runtime == nil {
		return nil, status.Error(codes.Unavailable, "compute runtime is not initialized")
	}
	s.runtime.sandboxMu.Lock()
	defer s.runtime.sandboxMu.Unlock()
	rec, engine, err := s.loadSandboxForMutation(ctx, req.GetName(), req.GetWorkspace())
	if err != nil {
		return nil, err
	}
	if expectedVersion != 0 && rec.ResourceVersion != expectedVersion {
		return nil, status.Error(codes.Aborted, "sandbox resource version changed")
	}
	if rec.RuntimeID == "" {
		return nil, status.Error(codes.FailedPrecondition, "sandbox has no runtime identity")
	}
	previousStatus := rec.Status
	if rec, err = s.runtime.st.BeginSandboxStopCAS(rec.Name, expectedVersion); err != nil {
		if errors.Is(err, store.ErrResourceVersionConflict) {
			return nil, status.Error(codes.Aborted, "sandbox resource version changed")
		}
		return nil, status.Error(codes.Internal, "sandbox registry update failed")
	}
	if err = engine.Stop(ctx, core.ID(rec.RuntimeID)); err != nil {
		if _, restoreErr := s.runtime.st.RestoreSandboxStatusCAS(rec.Name, rec.ResourceVersion, previousStatus); restoreErr != nil {
			return nil, status.Error(codes.Internal, "sandbox stop failed and registry state could not be restored")
		}
		return nil, status.Errorf(codes.FailedPrecondition, "sandbox stop failed: %v", err)
	}
	if s.runtime.relay != nil {
		s.runtime.relay.Disconnect(rec.Name)
	}
	if rec, err = s.runtime.st.MarkSandboxStopped(rec.Name); err != nil {
		return nil, status.Error(codes.Internal, "sandbox registry update failed")
	}
	return sandboxLifecycleResponse(rec, openshellv1.SandboxPhase_SANDBOX_PHASE_STOPPED), nil
}

func (s *openShellRPC) DeleteSandbox(ctx context.Context, req *openshellv1.DeleteSandboxRequest) (*openshellv1.DeleteSandboxResponse, error) {
	return (&sandboxLifecycle{rpc: s}).Delete(ctx, req, 0)
}

func (l *sandboxLifecycle) Delete(ctx context.Context, req *openshellv1.DeleteSandboxRequest, expectedVersion uint64) (*openshellv1.DeleteSandboxResponse, error) {
	s := l.rpc
	if req == nil || strings.TrimSpace(req.GetName()) == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if s.runtime == nil {
		return nil, status.Error(codes.Unavailable, "compute runtime is not initialized")
	}
	s.runtime.sandboxMu.Lock()
	defer s.runtime.sandboxMu.Unlock()
	// Reconciliation may have marked a durable record as runtime-missing. It
	// is already orphan-free, so allow an authorized operator to remove the
	// record without trying to call a backend that no longer owns it.
	if s.runtime != nil && s.runtime.st != nil {
		if orphan, ok := s.runtime.st.GetSandbox(req.GetName()); ok && orphan.RuntimeID == "" {
			workspace := defaultWorkspace(req.GetWorkspace())
			if defaultWorkspace(orphan.Workspace) == workspace {
				if err := s.requireSandboxWrite(ctx, workspace); err != nil {
					return nil, err
				}
				if expectedVersion != 0 && orphan.ResourceVersion != expectedVersion {
					return nil, status.Error(codes.Aborted, "sandbox resource version changed")
				}
				if _, err := s.runtime.st.BeginSandboxDeleteCAS(orphan.Name, expectedVersion); err != nil {
					if errors.Is(err, store.ErrResourceVersionConflict) {
						return nil, status.Error(codes.Aborted, "sandbox resource version changed")
					}
					return nil, status.Error(codes.FailedPrecondition, "sandbox deletion could not begin")
				}
				if err := s.runtime.st.DeleteSandbox(orphan.Name); err != nil {
					return nil, status.Error(codes.Internal, "sandbox registry update failed")
				}
				if s.runtime.relay != nil {
					s.runtime.relay.Disconnect(orphan.Name)
				}
				_ = os.RemoveAll(filepath.Join(s.runtime.opt.DataDir, "sandboxes", orphan.Name))
				return &openshellv1.DeleteSandboxResponse{Deleted: true}, nil
			}
		}
	}
	rec, engine, err := s.loadSandboxForMutation(ctx, req.GetName(), req.GetWorkspace())
	if err != nil {
		return nil, err
	}
	if expectedVersion != 0 && rec.ResourceVersion != expectedVersion {
		return nil, status.Error(codes.Aborted, "sandbox resource version changed")
	}
	rec, err = s.runtime.st.BeginSandboxDeleteCAS(rec.Name, expectedVersion)
	if err != nil {
		if errors.Is(err, store.ErrResourceVersionConflict) {
			return nil, status.Error(codes.Aborted, "sandbox resource version changed")
		}
		return nil, status.Error(codes.FailedPrecondition, "sandbox deletion could not begin")
	}
	_ = engine.Stop(ctx, core.ID(rec.RuntimeID))
	if err = engine.Delete(ctx, core.ID(rec.RuntimeID)); err != nil {
		rec.Status = "error"
		_ = s.runtime.st.UpsertSandbox(rec)
		return nil, status.Errorf(codes.FailedPrecondition, "sandbox delete failed: %v", err)
	}
	if s.runtime.relay != nil {
		s.runtime.relay.Disconnect(rec.Name)
	}
	if err = s.runtime.st.DeleteSandbox(rec.Name); err != nil {
		return nil, status.Error(codes.Internal, "sandbox registry update failed")
	}
	_ = os.RemoveAll(filepath.Join(s.runtime.opt.DataDir, "sandboxes", rec.Name))
	return &openshellv1.DeleteSandboxResponse{Deleted: true}, nil
}

func (s *openShellRPC) GetCurrentUser(ctx context.Context, _ *openshellv1.GetCurrentUserRequest) (*openshellv1.GetCurrentUserResponse, error) {
	p := PrincipalFrom(ctx)
	if p.Kind == PrincipalNone {
		return nil, status.Error(codes.Unauthenticated, "authenticated identity required")
	}
	return &openshellv1.GetCurrentUserResponse{Subject: p.Subject, Roles: append([]string(nil), p.Roles...), Scopes: append([]string(nil), p.Scopes...), IdentityProvider: p.IDP}, nil
}

func (s *openShellRPC) GetGatewayInfo(context.Context, *openshellv1.GetGatewayInfoRequest) (*openshellv1.GetGatewayInfoResponse, error) {
	return &openshellv1.GetGatewayInfoResponse{
		Status:         openshellv1.ServiceStatus_SERVICE_STATUS_DEGRADED,
		GatewayVersion: "cauteum-alpha",
		ComputeDrivers: rpcComputeDriverInfo(s.options),
	}, nil
}

func (s *openShellRPC) GetGatewayConfig(context.Context, *sandboxv1.GetGatewayConfigRequest) (*sandboxv1.GetGatewayConfigResponse, error) {
	if s.runtime == nil || s.runtime.st == nil {
		return nil, status.Error(codes.Unavailable, "gateway settings runtime is not initialized")
	}
	settings := make(map[string]*sandboxv1.SettingValue, len(registeredOpenShellSettings))
	for key := range registeredOpenShellSettings {
		settings[key] = &sandboxv1.SettingValue{}
	}
	stored, revision := s.runtime.st.SettingsSnapshot()
	for key, raw := range stored {
		kind, ok := registeredOpenShellSettings[key]
		if !ok || key == "policy" {
			continue
		}
		value, err := settingValue(kind, raw)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "stored setting %q is invalid", key)
		}
		settings[key] = value
	}
	return &sandboxv1.GetGatewayConfigResponse{Settings: settings, SettingsRevision: revision}, nil
}

func (s *openShellRPC) GetSandboxProviderEnvironment(ctx context.Context, req *openshellv1.GetSandboxProviderEnvironmentRequest) (*openshellv1.GetSandboxProviderEnvironmentResponse, error) {
	if s.runtime == nil || s.runtime.st == nil || s.runtime.sec == nil {
		return nil, status.Error(codes.Unavailable, "credential runtime is not initialized")
	}
	principal := PrincipalFrom(ctx)
	if principal.Kind != PrincipalSandbox || principal.Sandbox != req.GetSandboxId() {
		return nil, status.Error(codes.PermissionDenied, "sandbox supervisor identity required")
	}
	env, err := resolveSandboxSecretsWithSourcesAndDrivers(ctx, s.runtime.st, s.runtime.sec, s.runtime.drivers, s.runtime.opt, BuiltinProvidersDir(), req.GetSandboxId(), s.runtime.opt.ProviderProfileSources)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "provider environment is unavailable")
	}
	return &openshellv1.GetSandboxProviderEnvironmentResponse{Environment: env}, nil
}

// ExchangeProviderSubjectToken performs the gateway half of OpenShell's
// workload-identity token exchange. Both SVIDs are verified against the local
// Workload API bundle before any provider credential is read or sent upstream.
func (s *openShellRPC) ExchangeProviderSubjectToken(ctx context.Context, req *openshellv1.ExchangeProviderSubjectTokenRequest) (*openshellv1.ExchangeProviderSubjectTokenResponse, error) {
	if s.runtime == nil || s.runtime.st == nil || s.runtime.sec == nil {
		return nil, status.Error(codes.Unavailable, "credential runtime is not initialized")
	}
	p := PrincipalFrom(ctx)
	if p.Kind != PrincipalSandbox || p.Sandbox != req.GetSandboxId() {
		return nil, status.Error(codes.PermissionDenied, "sandbox supervisor identity required")
	}
	if req.GetProvider() == "" || req.GetCredentialKey() == "" || req.GetSupervisorJwtSvid() == "" {
		return nil, status.Error(codes.InvalidArgument, "provider, credential_key and supervisor_jwt_svid are required")
	}
	sb, ok := s.runtime.st.GetSandbox(req.GetSandboxId())
	if !ok {
		return nil, status.Error(codes.NotFound, "sandbox not found")
	}
	if !containsString(sb.AttachedProviders, req.GetProvider()) {
		return nil, status.Error(codes.PermissionDenied, "provider is not attached to this sandbox")
	}
	inst, ok := s.runtime.st.GetProvider(req.GetProvider())
	if !ok || !providerInWorkspace(inst, sb.Workspace) {
		return nil, status.Error(codes.NotFound, "provider not found")
	}
	profile, _, err := resolveProfileForWorkspaceWithSources(s.runtime.st, BuiltinProvidersDir(), inst.Type, inst.Workspace, s.runtime.opt.ProviderProfileSources)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "provider profile not found")
	}
	var dynamic, subject *provider.Credential
	for i := range profile.Credentials {
		c := &profile.Credentials[i]
		if c.Name == req.GetCredentialKey() {
			dynamic = c
		}
	}
	if dynamic == nil || dynamic.TokenGrant == nil || !strings.EqualFold(dynamic.TokenGrant.GrantType, "token_exchange") {
		return nil, status.Error(codes.FailedPrecondition, "credential does not declare a token_exchange grant")
	}
	g := dynamic.TokenGrant
	if g.SubjectToken == nil || g.SubjectToken.Source != "provider_credential" || g.SubjectToken.Credential == "" {
		return nil, status.Error(codes.FailedPrecondition, "unsupported or missing subject_token")
	}
	for i := range profile.Credentials {
		if profile.Credentials[i].Name == g.SubjectToken.Credential {
			subject = &profile.Credentials[i]
		}
	}
	if subject == nil {
		return nil, status.Error(codes.FailedPrecondition, "subject token credential is not declared")
	}
	keys := append([]string(nil), subject.EnvVars...)
	if len(keys) == 0 {
		keys = []string{subject.Name}
	}
	values, err := resolveProviderCredentialsForRecord(ctx, s.runtime.sec, s.runtime.drivers, inst, keys)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "subject token credential is unavailable")
	}
	subjectToken := ""
	for _, k := range keys {
		if values[k] != "" {
			subjectToken = values[k]
			break
		}
	}
	if subjectToken == "" {
		return nil, status.Error(codes.FailedPrecondition, "subject token credential is empty")
	}
	aud := strings.TrimSpace(g.JWTSVIDAudience)
	if aud == "" {
		aud = deriveTokenGrantAudience(g.TokenEndpoint)
	}
	if aud == "" {
		return nil, status.Error(codes.FailedPrecondition, "JWT-SVID audience is missing")
	}
	socket := strings.TrimSpace(os.Getenv("OPENSHELL_GATEWAY_SPIFFE_WORKLOAD_API_SOCKET"))
	if socket == "" {
		socket = strings.TrimSpace(os.Getenv("CAUTEUM_GATEWAY_SPIFFE_WORKLOAD_API_SOCKET"))
	}
	if socket == "" {
		return nil, status.Error(codes.FailedPrecondition, "SPIFFE Workload API socket is not configured")
	}
	source, err := workloadapi.NewJWTSource(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr("unix://"+strings.TrimPrefix(socket, "unix://"))))
	if err != nil {
		return nil, status.Error(codes.Unavailable, "SPIFFE Workload API is unavailable")
	}
	defer source.Close()
	gatewaySVID, err := source.FetchJWTSVID(ctx, jwtsvid.Params{Audience: aud})
	if err != nil {
		return nil, status.Error(codes.Unavailable, "gateway JWT-SVID could not be obtained")
	}
	verifiedGateway, err := jwtsvid.ParseAndValidate(gatewaySVID.Marshal(), source, []string{aud})
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "gateway JWT-SVID validation failed")
	}
	supervisor, err := jwtsvid.ParseAndValidate(req.GetSupervisorJwtSvid(), source, []string{aud})
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "supervisor JWT-SVID validation failed")
	}
	if verifiedGateway.ID.TrustDomain() != supervisor.ID.TrustDomain() || verifiedGateway.Claims["iss"] != supervisor.Claims["iss"] {
		return nil, status.Error(codes.PermissionDenied, "supervisor SPIFFE issuer or trust domain mismatch")
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "client_assertion_type": {firstNonEmpty(g.ClientAssertionType, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")}, "client_assertion": {gatewaySVID.Marshal()}, "subject_token": {subjectToken}, "subject_token_type": {firstNonEmpty(g.SubjectToken.SubjectTokenType, "urn:ietf:params:oauth:token-type:access_token")}, "audience": {supervisor.ID.String()}, "requested_token_type": {firstNonEmpty(g.RequestedTokenType, "urn:ietf:params:oauth:token-type:access_token")}}
	reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodPost, g.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "token endpoint is invalid")
	}
	reqHTTP.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqHTTP.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: oauthRequestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(reqHTTP)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "provider token exchange request failed")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, status.Error(codes.FailedPrecondition, "provider token endpoint rejected the exchange")
	}
	var token struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &token); err != nil || token.AccessToken == "" {
		return nil, status.Error(codes.FailedPrecondition, "provider token response is invalid")
	}
	return &openshellv1.ExchangeProviderSubjectTokenResponse{AccessToken: token.AccessToken, ExpiresIn: token.ExpiresIn, TokenType: token.TokenType}, nil
}

func deriveTokenGrantAudience(tokenEndpoint string) string {
	if i := strings.Index(tokenEndpoint, "/realms/"); i >= 0 {
		rest := tokenEndpoint[i+len("/realms/"):]
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			return tokenEndpoint[:i+len("/realms/")+slash]
		}
	}
	return tokenEndpoint
}

func (s *openShellRPC) GetProviderRefreshStatus(ctx context.Context, req *openshellv1.GetProviderRefreshStatusRequest) (*openshellv1.GetProviderRefreshStatusResponse, error) {
	if err := s.requireProviderAccess(ctx, req.GetWorkspace(), false); err != nil {
		return nil, err
	}
	rec, ok := s.runtime.st.GetProvider(req.GetProvider())
	if !ok {
		return nil, status.Error(codes.NotFound, "provider not found")
	}
	if !providerInWorkspace(rec, req.GetWorkspace()) {
		return nil, status.Error(codes.NotFound, "provider not found")
	}
	keys := make([]string, 0, len(rec.Refresh))
	for key := range rec.Refresh {
		if req.GetCredentialKey() == "" || key == req.GetCredentialKey() {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	result := &openshellv1.GetProviderRefreshStatusResponse{}
	for _, key := range keys {
		result.Credentials = append(result.Credentials, providerRefreshStatus(rec, key))
	}
	return result, nil
}

func (s *openShellRPC) ConfigureProviderRefresh(ctx context.Context, req *openshellv1.ConfigureProviderRefreshRequest) (*openshellv1.ConfigureProviderRefreshResponse, error) {
	if err := s.requireProviderAccess(ctx, req.GetWorkspace(), true); err != nil {
		return nil, err
	}
	if err := s.requireWorkspaceActive(defaultWorkspace(req.GetWorkspace())); err != nil {
		return nil, err
	}
	if s.runtime == nil || s.runtime.st == nil || s.runtime.sec == nil {
		return nil, status.Error(codes.Unavailable, "credential runtime is not initialized")
	}
	if strings.TrimSpace(req.GetProvider()) == "" || strings.TrimSpace(req.GetCredentialKey()) == "" {
		return nil, status.Error(codes.InvalidArgument, "provider and credential_key are required")
	}
	rec, ok := s.runtime.st.GetProvider(req.GetProvider())
	if !ok {
		return nil, status.Error(codes.NotFound, "provider not found")
	}
	if !providerInWorkspace(rec, req.GetWorkspace()) {
		return nil, status.Error(codes.NotFound, "provider not found")
	}
	strategy, ok := refreshStrategyName(req.GetStrategy())
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "unsupported credential refresh strategy")
	}
	declared := false
	for _, key := range rec.EnvVars {
		if key == req.GetCredentialKey() {
			declared = true
			break
		}
	}
	if !declared {
		return nil, status.Error(codes.InvalidArgument, "credential_key is not declared by provider")
	}
	cfg := rec.Refresh[req.GetCredentialKey()]
	cfg.CredentialKey, cfg.Strategy, cfg.Material = req.GetCredentialKey(), strategy, req.GetMaterial()
	if profile, _, profileErr := resolveProfileForWorkspaceWithSources(s.runtime.st, BuiltinProvidersDir(), rec.Type, rec.Workspace, s.runtime.opt.ProviderProfileSources); profileErr == nil {
		if metadata, found := credentialRefreshMetadata(profile, req.GetCredentialKey()); found {
			if metadata.Strategy != "" && strings.ReplaceAll(metadata.Strategy, "-", "_") != strategy {
				return nil, status.Error(codes.InvalidArgument, "refresh strategy does not match provider profile")
			}
			cfg.RefreshBeforeSeconds, cfg.MaxLifetimeSeconds = metadata.RefreshBeforeSeconds, metadata.MaxLifetimeSeconds
			cfg.Outputs = map[string]string{metadata.PrimaryOutput: req.GetCredentialKey()}
			for output, credential := range metadata.AdditionalOutputs {
				cfg.Outputs[output] = credential
			}
			if cfg.Material == nil {
				cfg.Material = map[string]string{}
			}
			if cfg.Material["token_url"] == "" && metadata.TokenURL != "" {
				cfg.Material["token_url"] = metadata.TokenURL
			}
			if cfg.Material["scope"] == "" && len(metadata.Scopes) > 0 {
				cfg.Material["scope"] = strings.Join(metadata.Scopes, " ")
			}
		}
	}
	if cfg.Outputs == nil && (strategy == "oauth2_refresh_token" || strategy == "oauth2_client_credentials" || strategy == "google_service_account_jwt") {
		cfg.Outputs = map[string]string{"access_token": req.GetCredentialKey()}
	}
	if req.ExpiresAtMs != nil {
		cfg.ExpiresAtMS = req.GetExpiresAtMs()
	}
	if err := validateRefreshMaterialNames(cfg.Material, req.GetSecretMaterialKeys()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	cfg, err := protectProviderRefreshMaterial(ctx, s.runtime.sec, rec.Name, cfg)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "could not store refresh material")
	}
	if rec.Refresh == nil {
		rec.Refresh = map[string]store.ProviderRefreshConfig{}
	}
	rec.Refresh[req.GetCredentialKey()] = cfg
	if cfg.ExpiresAtMS > 0 {
		if rec.CredentialExpiresAtMS == nil {
			rec.CredentialExpiresAtMS = map[string]int64{}
		}
		rec.CredentialExpiresAtMS[req.GetCredentialKey()] = cfg.ExpiresAtMS
	}
	if err := s.runtime.st.UpsertProvider(rec); err != nil {
		return nil, status.Error(codes.Internal, "could not persist refresh configuration")
	}
	return &openshellv1.ConfigureProviderRefreshResponse{Status: providerRefreshStatus(rec, req.GetCredentialKey())}, nil
}

func (s *openShellRPC) RotateProviderCredential(ctx context.Context, req *openshellv1.RotateProviderCredentialRequest) (*openshellv1.RotateProviderCredentialResponse, error) {
	if err := s.requireProviderAccess(ctx, req.GetWorkspace(), true); err != nil {
		return nil, err
	}
	if err := s.requireWorkspaceActive(defaultWorkspace(req.GetWorkspace())); err != nil {
		return nil, err
	}
	if s.runtime == nil || s.runtime.st == nil || s.runtime.sec == nil {
		return nil, status.Error(codes.Unavailable, "credential runtime is not initialized")
	}
	if err := refreshStoredProviderCredentialWithDrivers(ctx, s.runtime.st, s.runtime.sec, s.runtime.drivers, s.runtime.opt, req.GetProvider(), req.GetCredentialKey()); err != nil {
		return nil, status.Error(codes.FailedPrecondition, "credential refresh failed")
	}
	rec, ok := s.runtime.st.GetProvider(req.GetProvider())
	if !ok {
		return nil, status.Error(codes.NotFound, "provider not found")
	}
	if !providerInWorkspace(rec, req.GetWorkspace()) {
		return nil, status.Error(codes.NotFound, "provider not found")
	}
	return &openshellv1.RotateProviderCredentialResponse{Status: providerRefreshStatus(rec, req.GetCredentialKey())}, nil
}

func (s *openShellRPC) DeleteProviderRefresh(ctx context.Context, req *openshellv1.DeleteProviderRefreshRequest) (*openshellv1.DeleteProviderRefreshResponse, error) {
	if err := s.requireProviderAccess(ctx, req.GetWorkspace(), true); err != nil {
		return nil, err
	}
	if s.runtime == nil || s.runtime.st == nil || s.runtime.sec == nil {
		return nil, status.Error(codes.Unavailable, "credential runtime is not initialized")
	}
	rec, ok := s.runtime.st.GetProvider(req.GetProvider())
	if !ok || !providerInWorkspace(rec, req.GetWorkspace()) {
		return &openshellv1.DeleteProviderRefreshResponse{}, nil
	}
	_, exists := rec.Refresh[req.GetCredentialKey()]
	if !exists {
		return &openshellv1.DeleteProviderRefreshResponse{}, nil
	}
	if err := s.runtime.sec.DeletePrefix(ctx, refreshMaterialKey(rec.Name, req.GetCredentialKey(), "")); err != nil {
		return nil, status.Error(codes.Internal, "could not delete refresh material")
	}
	delete(rec.Refresh, req.GetCredentialKey())
	if err := s.runtime.st.UpsertProvider(rec); err != nil {
		return nil, status.Error(codes.Internal, "could not delete refresh configuration")
	}
	return &openshellv1.DeleteProviderRefreshResponse{Deleted: true}, nil
}

func (s *openShellRPC) requireProviderAccess(ctx context.Context, workspace string, write bool) error {
	if s.runtime == nil || s.runtime.st == nil {
		return status.Error(codes.Unavailable, "credential runtime is not initialized")
	}
	p := PrincipalFrom(ctx)
	if p.Kind != PrincipalUser {
		return status.Error(codes.Unauthenticated, "authenticated user required")
	}
	workspace = strings.TrimSpace(workspace)
	if workspace == "" {
		workspace = "default"
	}
	ws, ok := s.runtime.st.GetWorkspace(workspace)
	if p.IDP == "local" || p.IDP == "local_dev" {
		return nil
	}
	verb := "provider:read"
	if write {
		verb = "provider:write"
	}
	if !containsString(p.Scopes, verb) && !containsString(p.Scopes, "openshell:all") {
		return status.Error(codes.PermissionDenied, "provider scope required")
	}
	if !ok {
		return status.Error(codes.NotFound, "workspace not found")
	}
	for _, member := range ws.Members {
		if member.Subject != p.Subject {
			continue
		}
		role := strings.ToLower(strings.TrimSpace(member.Role))
		if role == "owner" || role == "admin" || !write && (role == "user" || role == "member" || role == "reader" || role == "viewer") {
			return nil
		}
	}
	return status.Error(codes.PermissionDenied, "workspace provider access required")
}

func providerInWorkspace(rec store.ProviderRecord, workspace string) bool {
	if strings.TrimSpace(workspace) == "" {
		workspace = "default"
	}
	providerWorkspace := strings.TrimSpace(rec.Workspace)
	if providerWorkspace == "" {
		providerWorkspace = "default"
	}
	return providerWorkspace == workspace
}

func refreshStrategyName(strategy openshellv1.ProviderCredentialRefreshStrategy) (string, bool) {
	switch strategy {
	case openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_STATIC:
		return "static", true
	case openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_EXTERNAL:
		return "external", true
	case openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_REFRESH_TOKEN:
		return "oauth2_refresh_token", true
	case openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_CLIENT_CREDENTIALS:
		return "oauth2_client_credentials", true
	case openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_GOOGLE_SERVICE_ACCOUNT_JWT:
		return "google_service_account_jwt", true
	case openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_AWS_STS_ASSUME_ROLE:
		return "aws_sts_assume_role", true
	default:
		return "", false
	}
}

func providerRefreshStatus(rec store.ProviderRecord, key string) *openshellv1.ProviderCredentialRefreshStatus {
	cfg := rec.Refresh[key]
	strategy := openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_UNSPECIFIED
	strategies := map[openshellv1.ProviderCredentialRefreshStrategy]string{
		openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_STATIC:                     "static",
		openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_EXTERNAL:                   "external",
		openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_REFRESH_TOKEN:       "oauth2_refresh_token",
		openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_CLIENT_CREDENTIALS:  "oauth2_client_credentials",
		openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_GOOGLE_SERVICE_ACCOUNT_JWT: "google_service_account_jwt",
		openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_AWS_STS_ASSUME_ROLE:        "aws_sts_assume_role",
	}
	for value, name := range strategies {
		if name == cfg.Strategy {
			strategy = value
		}
	}
	expires := cfg.ExpiresAtMS
	if rec.CredentialExpiresAtMS[key] > expires {
		expires = rec.CredentialExpiresAtMS[key]
	}
	state := "unconfigured"
	if _, ok := rec.Refresh[key]; ok {
		state = "configured"
	}
	if expires > 0 && expires <= time.Now().UnixMilli() {
		state = "expired"
	}
	return &openshellv1.ProviderCredentialRefreshStatus{ProviderName: rec.Name, ProviderId: rec.Name, CredentialKey: key, Strategy: strategy, Status: state, ExpiresAtMs: expires}
}

func validateRefreshMaterialNames(material map[string]string, names []string) error {
	seen := map[string]bool{}
	for _, name := range names {
		if strings.TrimSpace(name) == "" || seen[name] {
			return fmt.Errorf("secret_material_keys must be non-empty and unique")
		}
		if _, ok := material[name]; !ok {
			return fmt.Errorf("secret material %q is missing", name)
		}
		seen[name] = true
	}
	return nil
}

type credentialRefreshMeta struct {
	Strategy             string
	TokenURL             string
	Scopes               []string
	RefreshBeforeSeconds int64
	MaxLifetimeSeconds   int64
	PrimaryOutput        string
	AdditionalOutputs    map[string]string
}

func credentialRefreshMetadata(profile provider.Profile, key string) (credentialRefreshMeta, bool) {
	for _, credential := range profile.Credentials {
		declaresKey := false
		for _, envKey := range credential.EnvVars {
			if envKey == key {
				declaresKey = true
				break
			}
		}
		if !declaresKey || credential.Refresh == nil {
			continue
		}
		refresh := credential.Refresh
		primary := "access_token"
		if refresh.Strategy == "aws_sts_assume_role" || refresh.Strategy == "aws-sts-assume-role" {
			primary = "access_key_id"
		}
		meta := credentialRefreshMeta{Strategy: refresh.Strategy, TokenURL: firstNonEmpty(refresh.TokenURL, refresh.TokenURI), Scopes: append([]string(nil), refresh.Scopes...), RefreshBeforeSeconds: refresh.RefreshBeforeSeconds, MaxLifetimeSeconds: refresh.MaxLifetimeSeconds, PrimaryOutput: primary, AdditionalOutputs: map[string]string{}}
		for _, output := range refresh.AdditionalOutputs {
			meta.AdditionalOutputs[output.Output] = output.Credential
		}
		return meta, true
	}
	return credentialRefreshMeta{}, false
}

func registerOpenShellRPC(server *grpc.Server) { registerOpenShellRPCWithOptions(server, Options{}) }

func registerOpenShellRPCWithOptions(server *grpc.Server, opt Options) {
	openshellv1.RegisterOpenShellServer(server, &openShellRPC{options: opt, runtime: opt.grpcRuntime})
}

func rpcComputeDriverInfo(opt Options) []*openshellv1.ComputeDriverInfo {
	names := opt.ComputeDriverNames
	if len(names) == 0 {
		names = []string{"docker"}
	}
	out := make([]*openshellv1.ComputeDriverInfo, 0, len(names))
	for _, name := range names {
		out = append(out, &openshellv1.ComputeDriverInfo{Name: name})
	}
	return out
}

package httpapi

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/cauteum/cauteum-gateway/internal/storage/store"
)

func TestControlAPIWorkspaceAuthorization(t *testing.T) {
	st, err := store.Open(t.TempDir(), "control-api-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateWorkspace(store.WorkspaceRecord{Name: "team"}); err != nil {
		t.Fatal(err)
	}
	if err := st.WorkspaceMemberUpsert("team", "alice", "member"); err != nil {
		t.Fatal(err)
	}
	api := &controlAPI{store: st, opt: Options{OIDC: OIDCOptions{ScopesClaim: "scope", AdminRole: "admin", UserRole: "user"}}}
	actor := func(subject string, roles, scopes []string) context.Context {
		return withPrincipal(context.Background(), Principal{Kind: PrincipalUser, Subject: subject, IDP: "oidc", Roles: roles, Scopes: scopes})
	}
	if _, err := api.requireWorkspace(actor("alice", []string{"user"}, []string{"sandbox:read"}), "team"); err != nil {
		t.Fatalf("workspace member denied: %v", err)
	}
	if _, err := api.requireWorkspace(actor("bob", []string{"user"}, []string{"sandbox:read"}), "team"); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("nonmember error = %v, want permission denied", err)
	}
	if _, err := api.requireWorkspace(actor("alice", []string{"user"}, nil), "team"); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("missing scope error = %v, want permission denied", err)
	}
	if _, err := api.requireWorkspace(actor("alice", nil, []string{"sandbox:read"}), "team"); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("missing role error = %v, want permission denied", err)
	}
	if _, err := api.requireWorkspace(withPrincipal(context.Background(), Principal{Kind: PrincipalSandbox, Sandbox: "team"}), "team"); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("sandbox principal error = %v, want permission denied", err)
	}
}

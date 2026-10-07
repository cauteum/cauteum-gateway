package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whaleshell/whaleshell-gateway/internal/storage/store"
)

func TestConfiguredProfileSourcesSelectBuiltinAndUserCatalogs(t *testing.T) {
	st, err := store.Open(t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateProfileScoped("global", "", "user-profile", "id: user-profile\ndisplay_name: User\n"); err != nil {
		t.Fatal(err)
	}
	builtinDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(builtinDir, "builtin-profile.yaml"), []byte("id: builtin-profile\ndisplay_name: Builtin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, source, included, excluded string
	}{
		{"builtin only", "builtin", "builtin-profile", "user-profile"},
		{"user only", "user", "user-profile", "builtin-profile"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profiles := listProfilesWithSources(st, builtinDir, "", []string{tc.source})
			if ids := profilesToIDs(profiles); !strings.Contains(ids, tc.included) || strings.Contains(ids, tc.excluded) {
				t.Fatalf("source %s catalog=%v", tc.source, profiles)
			}
			if _, _, err := resolveProfileForWorkspaceWithSources(st, builtinDir, tc.excluded, "", []string{tc.source}); err == nil {
				t.Fatalf("excluded profile %q resolved for source %q", tc.excluded, tc.source)
			}
		})
	}
}

func profilesToIDs(profiles []map[string]string) string {
	var ids []string
	for _, profile := range profiles {
		ids = append(ids, profile["id"])
	}
	return strings.Join(ids, ",")
}

func TestProfileCatalogImportUpdateAndRead(t *testing.T) {
	st, err := store.Open(t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mountProviderAPI(mux, st, nil, "")
	request := func(method, body, version string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/v1/profiles/openai", strings.NewReader(body))
		if version != "" {
			req.Header.Set("If-Match", version)
		}
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		return res
	}
	profile := "id: openai\ndisplay_name: OpenAI\nsource: builtin\nscope: workspace\n"
	if got := request(http.MethodPost, profile, ""); got.Code != http.StatusCreated {
		t.Fatalf("import status=%d body=%s", got.Code, got.Body.String())
	}
	if got := request(http.MethodPost, profile, ""); got.Code != http.StatusConflict {
		t.Fatalf("duplicate import status=%d body=%s", got.Code, got.Body.String())
	}
	updated := "id: openai\ndisplay_name: Updated\n"
	if got := request(http.MethodPut, updated, ""); got.Code != http.StatusPreconditionRequired {
		t.Fatalf("update without version status=%d body=%s", got.Code, got.Body.String())
	}
	current := request(http.MethodGet, "", "")
	if current.Code != http.StatusOK || !strings.Contains(current.Body.String(), `"resource_version":1`) {
		t.Fatalf("read status=%d body=%s", current.Code, current.Body.String())
	}
	if !strings.Contains(current.Body.String(), `"source":"user"`) || !strings.Contains(current.Body.String(), `"scope":"platform"`) {
		t.Fatalf("imported metadata must not override catalog provenance/visibility: %s", current.Body.String())
	}
	version := current.Header().Get("ETag")
	staleBody := "resource_version: 7\nid: openai\ndisplay_name: Stale\n"
	if got := request(http.MethodPut, staleBody, `"1"`); got.Code != http.StatusConflict {
		t.Fatalf("stale update status=%d body=%s", got.Code, got.Body.String())
	}
	versionedUpdate := "resource_version: 1\nid: openai\ndisplay_name: Updated\n"
	if got := request(http.MethodPut, versionedUpdate, version); got.Code != http.StatusNoContent {
		t.Fatalf("update status=%d body=%s", got.Code, got.Body.String())
	}
	if got := request(http.MethodGet, "", ""); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "Updated") || !strings.Contains(got.Body.String(), `"resource_version":2`) {
		t.Fatalf("read status=%d body=%s", got.Code, got.Body.String())
	}
	if got := request(http.MethodPut, versionedUpdate, `"1"`); got.Code != http.StatusConflict {
		t.Fatalf("stale exported file status=%d body=%s", got.Code, got.Body.String())
	}
	missing := httptest.NewRecorder()
	missingReq := httptest.NewRequest(http.MethodPut, "/v1/profiles/missing", strings.NewReader("resource_version: 1\nid: missing\n"))
	missingReq.Header.Set("If-Match", `"1"`)
	mux.ServeHTTP(missing, missingReq)
	if missing.Code != http.StatusNotFound {
		t.Fatal("update of missing profile should fail")
	}
}

func TestProfileWorkspaceScopeAndAuthorization(t *testing.T) {
	st, err := store.Open(t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertWorkspace(store.WorkspaceRecord{Name: "team-ml"}); err != nil {
		t.Fatal(err)
	}
	if err := st.WorkspaceMemberUpsert("team-ml", "alice", "user"); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mountProviderAPI(mux, st, nil, "")
	serve := func(method, target, body string, principal Principal) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req = req.WithContext(withPrincipal(context.Background(), principal))
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		return res
	}
	wsPath := "/v1/profiles?scope=workspace&workspace=team-ml"
	if got := serve(http.MethodGet, wsPath, "", Principal{Kind: PrincipalUser, Subject: "alice", IDP: "oidc"}); got.Code != http.StatusOK {
		t.Fatalf("workspace member read status=%d body=%s", got.Code, got.Body.String())
	}
	profile := "id: openai\ndescription: workspace profile\nsource: builtin\nscope: platform\n"
	if got := serve(http.MethodPost, "/v1/profiles/openai?scope=workspace&workspace=team-ml", profile, Principal{Kind: PrincipalUser, Subject: "alice", IDP: "oidc"}); got.Code != http.StatusForbidden {
		t.Fatalf("workspace user should not write catalog; status=%d", got.Code)
	}
	if err := st.WorkspaceMemberUpsert("team-ml", "bob", "admin"); err != nil {
		t.Fatal(err)
	}
	if got := serve(http.MethodPost, "/v1/profiles/openai?scope=workspace&workspace=team-ml", profile, Principal{Kind: PrincipalUser, Subject: "bob", IDP: "oidc"}); got.Code != http.StatusCreated {
		t.Fatalf("workspace admin import status=%d body=%s", got.Code, got.Body.String())
	}
	globalPath := "/v1/profiles?scope=global"
	if got := serve(http.MethodGet, globalPath, "", Principal{Kind: PrincipalUser, Subject: "alice", IDP: "oidc"}); got.Code != http.StatusForbidden {
		t.Fatalf("workspace user should not read global catalog; status=%d", got.Code)
	}
	if got := serve(http.MethodGet, globalPath, "", Principal{Kind: PrincipalUser, Subject: "ops", IDP: "oidc", Roles: []string{"platform-admin"}}); got.Code != http.StatusOK {
		t.Fatalf("platform admin read status=%d body=%s", got.Code, got.Body.String())
	}
	if got := serve(http.MethodGet, "/v1/profiles/openai?scope=workspace&workspace=team-ml", "", Principal{Kind: PrincipalUser, Subject: "alice", IDP: "oidc"}); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "workspace profile") {
		t.Fatalf("workspace catalog resolution status=%d body=%s", got.Code, got.Body.String())
	} else if !strings.Contains(got.Body.String(), `"source":"user"`) || !strings.Contains(got.Body.String(), `"scope":"workspace"`) {
		t.Fatalf("workspace metadata must come from storage: %s", got.Body.String())
	}
}

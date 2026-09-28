package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/whaleshell/whaleshell-gateway/internal/storage/store"
	"github.com/whaleshell/whaleshell-runtime/secrets"
)

func TestProviderRefreshUsesEncryptedMaterialAndStoresMappedOutputs(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		if errors.Is(err, net.ErrClosed) || strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skipf("sandbox does not permit binding a local HTTP test endpoint: %v", err)
		}
		t.Fatal(err)
	}
	tokenEndpoint := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if got := r.Form.Get("refresh_token"); got != "refresh-secret" && got != "refresh-new" {
			t.Errorf("refresh_token = %q", got)
		}
		if got := r.Form.Get("grant_type"); got != "refresh_token" {
			t.Errorf("grant_type = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"access-new","refresh_token":"refresh-new","id_token":"identity-new","expires_in":3600}`)
	}))
	tokenEndpoint.Listener = listener
	tokenEndpoint.Start()
	t.Cleanup(tokenEndpoint.Close)

	st, err := store.Open(t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.OpenLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := sec.PutProviderCredentials(context.Background(), "sample", map[string]string{
		"ACCESS_TOKEN": "access-old", "REFRESH_TOKEN": "refresh-secret", "ID_TOKEN": "identity-old",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateProfile("sample", "id: sample\n"); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mountProviderAPI(mux, st, sec, "")
	createBody := providerWriteBody{
		Name: "sample", Type: "sample", EnvVars: []string{"ACCESS_TOKEN", "REFRESH_TOKEN", "ID_TOKEN"},
		Refresh: map[string]store.ProviderRefreshConfig{
			"ACCESS_TOKEN": {
				CredentialKey: "ACCESS_TOKEN", Strategy: "oauth2-refresh-token",
				Material:               map[string]string{"token_url": tokenEndpoint.URL},
				MaterialCredentialKeys: map[string]string{"refresh_token": "REFRESH_TOKEN"},
				RefreshBeforeSeconds:   300,
				ExpiresAtMS:            time.Now().Add(-time.Minute).UnixMilli(),
				Outputs: map[string]string{
					"access_token": "ACCESS_TOKEN", "refresh_token": "REFRESH_TOKEN", "id_token": "ID_TOKEN",
				},
			},
		},
	}
	createJSON, err := json.Marshal(createBody)
	if err != nil {
		t.Fatal(err)
	}
	createReq := httptest.NewRequest(http.MethodPut, "/v1/providers/sample", strings.NewReader(string(createJSON)))
	createRes := httptest.NewRecorder()
	mux.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusNoContent {
		t.Fatalf("provider create status=%d body=%s", createRes.Code, createRes.Body.String())
	}
	storedProvider, ok := st.GetProvider("sample")
	if !ok {
		t.Fatal("provider was not stored")
	}
	storedRefresh := storedProvider.Refresh["ACCESS_TOKEN"]
	if storedRefresh.Material != nil || len(storedRefresh.MaterialSecretKeys) != 1 || storedRefresh.MaterialSecretKeys[0] != "token_url" {
		t.Fatalf("refresh material must be stored encrypted: %#v", storedRefresh)
	}
	if secret, err := sec.Get(context.Background(), refreshMaterialKey("sample", "ACCESS_TOKEN", "token_url")); err != nil || secret != tokenEndpoint.URL {
		t.Fatalf("encrypted refresh material lookup = %q, %v", secret, err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "sb", AttachedProviders: []string{"sample"}}); err != nil {
		t.Fatal(err)
	}
	sandboxSecrets, err := resolveSandboxSecrets(context.Background(), st, sec, "", "sb")
	if err != nil {
		t.Fatalf("sandbox secret resolution: %v", err)
	}
	if sandboxSecrets["ACCESS_TOKEN"] != "access-new" || sandboxSecrets["REFRESH_TOKEN"] != "refresh-new" || sandboxSecrets["ID_TOKEN"] != "identity-new" {
		t.Fatalf("sandbox secret resolution did not refresh mapped outputs: %#v", sandboxSecrets)
	}
	target := "/v1/providers/sample/refresh/ACCESS_TOKEN/rotate"
	req := httptest.NewRequest(http.MethodPost, target, nil)
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	if res.Code != http.StatusNoContent {
		t.Fatalf("rotate status=%d body=%s", res.Code, res.Body.String())
	}
	got, err := sec.GetProviderCredentials(context.Background(), "sample", []string{"ACCESS_TOKEN", "REFRESH_TOKEN", "ID_TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"ACCESS_TOKEN": "access-new", "REFRESH_TOKEN": "refresh-new", "ID_TOKEN": "identity-new",
	} {
		if got[key] != want {
			t.Errorf("credential %s = %q, want %q", key, got[key], want)
		}
	}

	get := httptest.NewRequest(http.MethodGet, "/v1/providers/sample", nil)
	getRes := httptest.NewRecorder()
	mux.ServeHTTP(getRes, get)
	if getRes.Code != http.StatusOK {
		t.Fatalf("provider read status=%d body=%s", getRes.Code, getRes.Body.String())
	}
	if strings.Contains(getRes.Body.String(), "refresh-secret") || strings.Contains(getRes.Body.String(), tokenEndpoint.URL) {
		t.Fatalf("refresh material leaked through provider read: %s", getRes.Body.String())
	}
	refreshGet := httptest.NewRequest(http.MethodGet, "/v1/providers/sample/refresh", nil)
	refreshGetRes := httptest.NewRecorder()
	mux.ServeHTTP(refreshGetRes, refreshGet)
	if refreshGetRes.Code != http.StatusOK {
		t.Fatalf("refresh config read status=%d body=%s", refreshGetRes.Code, refreshGetRes.Body.String())
	}
	if strings.Contains(refreshGetRes.Body.String(), "refresh-secret") || strings.Contains(refreshGetRes.Body.String(), tokenEndpoint.URL) {
		t.Fatalf("refresh material leaked through refresh config read: %s", refreshGetRes.Body.String())
	}
}

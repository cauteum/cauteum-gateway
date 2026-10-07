package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whaleshell/whaleshell-gateway/internal/httpapi"
	"github.com/whaleshell/whaleshell-gateway/internal/storage/store"
)

type testGateway struct {
	t     *testing.T
	srv   *httptest.Server
	token string
	dir   string
}

func newTestGateway(t *testing.T, opt httpapi.Options) *testGateway {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	opt.DataDir = filepath.Join(t.TempDir(), "gw")
	h, err := httpapi.NewHandler(ctx, opt)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	b, err := os.ReadFile(filepath.Join(opt.DataDir, store.AuthTokenFile))
	if err != nil {
		t.Fatal(err)
	}
	return &testGateway{t: t, srv: srv, token: strings.TrimSpace(string(b)), dir: opt.DataDir}
}

func (g *testGateway) do(method, path, token string, body any) (int, []byte) {
	g.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			g.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, g.srv.URL+path, rd)
	if err != nil {
		g.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		g.t.Fatal(err)
	}
	defer res.Body.Close()
	out, err := io.ReadAll(res.Body)
	if err != nil {
		g.t.Fatal(err)
	}
	return res.StatusCode, out
}

func (g *testGateway) mustJSON(method, path, token string, body any, want int, into any) {
	g.t.Helper()
	code, out := g.do(method, path, token, body)
	if code != want {
		g.t.Fatalf("%s %s = %d (%s), want %d", method, path, code, out, want)
	}
	if into != nil {
		if err := json.Unmarshal(out, into); err != nil {
			g.t.Fatalf("%s %s: decode %q: %v", method, path, out, err)
		}
	}
}

func (g *testGateway) createSandbox(name string) {
	g.t.Helper()
	g.mustJSON(http.MethodPut, "/v1/sandboxes/"+name, g.token, map[string]any{}, http.StatusNoContent, nil)
}

func (g *testGateway) sandboxToken(name string) string {
	g.t.Helper()
	var out struct {
		Token string `json:"sandbox_token"`
	}
	g.mustJSON(http.MethodPost, "/v1/sandboxes/"+name+"/supervisor-token", g.token, nil, http.StatusOK, &out)
	return out.Token
}

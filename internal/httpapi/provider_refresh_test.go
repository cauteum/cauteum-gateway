package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestOAuthRefreshDoesNotLeakSecretsOrFollowCredentialRedirects(t *testing.T) {
	const refreshToken = "refresh-secret-do-not-print"
	const querySecret = "url-query-secret-do-not-print"
	var redirected atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Store(true)
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if r.Form.Get("refresh_token") != refreshToken {
			t.Errorf("refresh token not sent to configured endpoint")
		}
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	_, _, err := oauth2CredentialOutputs(map[string]string{
		"token_url":     source.URL + "?key=" + querySecret,
		"refresh_token": refreshToken,
	}, "refresh_token", nil)
	if err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("refresh error = %v, want redacted HTTP 307 error", err)
	}
	if strings.Contains(err.Error(), refreshToken) || strings.Contains(err.Error(), querySecret) {
		t.Fatalf("refresh error leaked credential material: %v", err)
	}
	if redirected.Load() {
		t.Fatal("credential-bearing token request followed a 307 redirect")
	}
}

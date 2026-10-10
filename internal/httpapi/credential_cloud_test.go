package httpapi

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

func TestGoogleServiceAccountJWTRefresh(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: func() []byte { b, _ := x509.MarshalPKCS8PrivateKey(key); return b }()}))
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Errorf("grant type=%q", r.Form.Get("grant_type"))
		}
		parts := strings.Split(r.Form.Get("assertion"), ".")
		if len(parts) != 3 {
			t.Errorf("JWT segments=%d", len(parts))
			return
		}
		unsigned := parts[0] + "." + parts[1]
		digest := sha256.Sum256([]byte(unsigned))
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Error(err)
			return
		}
		if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
			t.Errorf("JWT signature invalid: %v", err)
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Error(err)
			return
		}
		var claims map[string]any
		if err := json.Unmarshal(payload, &claims); err != nil {
			t.Error(err)
		}
		if claims["iss"] != "svc@example.test" || claims["scope"] != "scope:a scope:b" || claims["aud"] != server.URL {
			t.Errorf("claims=%v", claims)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"google-access-token","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer server.Close()
	got, expires, err := googleServiceAccountCredential(map[string]string{"client_email": "svc@example.test", "private_key": pemKey, "token_url": server.URL, "scopes": "scope:a scope:b"}, map[string]string{"access_token": "GOOGLE_TOKEN"})
	if err != nil || got["GOOGLE_TOKEN"] != "google-access-token" || expires == 0 {
		t.Fatalf("got=%v expires=%d err=%v", got, expires, err)
	}
}

type fakeSTS struct{ input *sts.AssumeRoleInput }

func (f *fakeSTS) AssumeRole(_ context.Context, input *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.input = input
	expiration := time.Now().Add(time.Hour)
	return &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{AccessKeyId: aws.String("ASIA123"), SecretAccessKey: aws.String("secret"), SessionToken: aws.String("session"), Expiration: &expiration}}, nil
}

func TestAWSSTSAssumeRoleMapsTemporaryCredentialsAndExpiry(t *testing.T) {
	fake := &fakeSTS{}
	input := &sts.AssumeRoleInput{RoleArn: aws.String("arn:aws:iam::123456789012:role/test"), RoleSessionName: aws.String("test-session"), ExternalId: aws.String("external")}
	got, expires, err := awsSTSAssumeRoleWithClient(context.Background(), fake, input, map[string]string{"access_key_id": "AWS_ACCESS_KEY_ID", "secret_access_key": "AWS_SECRET_ACCESS_KEY", "session_token": "AWS_SESSION_TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(fake.input.RoleArn) != aws.ToString(input.RoleArn) || aws.ToString(fake.input.RoleSessionName) != aws.ToString(input.RoleSessionName) || aws.ToString(fake.input.ExternalId) != aws.ToString(input.ExternalId) {
		t.Fatalf("AssumeRole input=%v", fake.input)
	}
	if got["AWS_ACCESS_KEY_ID"] != "ASIA123" || got["AWS_SECRET_ACCESS_KEY"] != "secret" || got["AWS_SESSION_TOKEN"] != "session" || expires <= time.Now().UnixMilli() {
		t.Fatalf("result=%v expires=%d", got, expires)
	}
}

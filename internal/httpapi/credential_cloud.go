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
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// googleServiceAccountCredential obtains OAuth access tokens with the Google
// service-account JWT bearer grant. Key material is expected to be vault-loaded.
func googleServiceAccountCredential(material map[string]string, outputs map[string]string) (map[string]string, int64, error) {
	clientEmail := strings.TrimSpace(material["client_email"])
	tokenURL := strings.TrimSpace(firstNonEmpty(material["token_url"], material["token_uri"]))
	privateKey := strings.TrimSpace(material["private_key"])
	scope := strings.TrimSpace(firstNonEmpty(material["scope"], material["scopes"]))
	if clientEmail == "" || tokenURL == "" || privateKey == "" || scope == "" {
		return nil, 0, fmt.Errorf("google_service_account_jwt: client_email, private_key, token_url and scope are required")
	}
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return nil, 0, fmt.Errorf("google_service_account_jwt: invalid private key encoding")
	}
	var key *rsa.PrivateKey
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		key, _ = parsed.(*rsa.PrivateKey)
	} else if parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = parsed
	}
	if key == nil {
		return nil, 0, fmt.Errorf("google_service_account_jwt: expected RSA private key")
	}
	now := time.Now()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims := map[string]any{"iss": clientEmail, "scope": strings.Join(strings.Fields(scope), " "), "aud": tokenURL, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	if subject := strings.TrimSpace(material["subject"]); subject != "" {
		claims["sub"] = subject
	}
	if keyID := strings.TrimSpace(material["private_key_id"]); keyID != "" {
		headerBytes, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": keyID})
		header = headerBytes
	}
	payload, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return nil, 0, fmt.Errorf("google_service_account_jwt: assertion signing failed")
	}
	materialWithAssertion := make(map[string]string, len(material)+1)
	for name, value := range material {
		materialWithAssertion[name] = value
	}
	materialWithAssertion["assertion"] = unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
	return oauth2CredentialOutputs(materialWithAssertion, "urn:ietf:params:oauth:grant-type:jwt-bearer", outputs)
}

// stsAssumeRoleClient keeps AWS response handling testable without external calls.
type stsAssumeRoleClient interface {
	AssumeRole(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

func awsSTSAssumeRole(ctx context.Context, material map[string]string, outputs map[string]string) (map[string]string, int64, error) {
	roleARN := strings.TrimSpace(material["role_arn"])
	if roleARN == "" {
		return nil, 0, fmt.Errorf("aws_sts_assume_role: role_arn is required")
	}
	region := strings.TrimSpace(firstNonEmpty(material["aws_region"], os.Getenv("AWS_REGION"), os.Getenv("AWS_DEFAULT_REGION")))
	if region == "" {
		return nil, 0, fmt.Errorf("aws_sts_assume_role: aws_region is required")
	}
	cfgOptions := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
	accessKey, secretKey := strings.TrimSpace(material["aws_access_key_id"]), strings.TrimSpace(material["aws_secret_access_key"])
	if (accessKey == "") != (secretKey == "") {
		return nil, 0, fmt.Errorf("aws_sts_assume_role: both source credential keys are required")
	}
	if accessKey != "" {
		cfgOptions = append(cfgOptions, awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, strings.TrimSpace(material["aws_session_token"]))))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, cfgOptions...)
	if err != nil {
		return nil, 0, fmt.Errorf("aws_sts_assume_role: AWS credentials unavailable")
	}
	client := sts.NewFromConfig(cfg)
	input := &sts.AssumeRoleInput{RoleArn: aws.String(roleARN), RoleSessionName: aws.String(firstNonEmpty(strings.TrimSpace(material["session_name"]), "cauteum-provider-refresh"))}
	if externalID := strings.TrimSpace(material["external_id"]); externalID != "" {
		input.ExternalId = aws.String(externalID)
	}
	if duration := strings.TrimSpace(material["duration_seconds"]); duration != "" {
		seconds, parseErr := strconv.ParseInt(duration, 10, 32)
		if parseErr != nil || seconds < 900 || seconds > 43200 {
			return nil, 0, fmt.Errorf("aws_sts_assume_role: duration_seconds must be between 900 and 43200")
		}
		input.DurationSeconds = aws.Int32(int32(seconds))
	}
	return awsSTSAssumeRoleWithClient(ctx, client, input, outputs)
}

func awsSTSAssumeRoleWithClient(ctx context.Context, client stsAssumeRoleClient, input *sts.AssumeRoleInput, outputs map[string]string) (map[string]string, int64, error) {
	result, err := client.AssumeRole(ctx, input)
	if err != nil || result == nil || result.Credentials == nil {
		return nil, 0, fmt.Errorf("aws_sts_assume_role: STS request failed")
	}
	all := map[string]string{"access_key_id": aws.ToString(result.Credentials.AccessKeyId), "secret_access_key": aws.ToString(result.Credentials.SecretAccessKey), "session_token": aws.ToString(result.Credentials.SessionToken)}
	selected := make(map[string]string, len(outputs))
	if len(outputs) == 0 {
		return nil, 0, fmt.Errorf("aws_sts_assume_role: profile output mapping is required")
	}
	for output, credentialKey := range outputs {
		value, ok := all[output]
		if !ok || value == "" || strings.TrimSpace(credentialKey) == "" {
			return nil, 0, fmt.Errorf("aws_sts_assume_role: invalid output mapping")
		}
		selected[credentialKey] = value
	}
	var expiry int64
	if result.Credentials.Expiration != nil {
		expiry = result.Credentials.Expiration.UnixMilli()
	}
	return selected, expiry, nil
}

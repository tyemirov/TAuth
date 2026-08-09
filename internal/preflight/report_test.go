package preflight

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	preflightpkg "github.com/tyemirov/utils/preflight"
)

const (
	testTenantID          = "demo"
	testSessionCookieName = "app_session_demo"
	testRefreshCookieName = "app_refresh_demo"
	testSigningKey        = "demo-signing-key"
	testTenantOrigin      = "https://demo.localhost"
)

func writeConfigFile(testingHandle *testing.T, contents string) string {
	testingHandle.Helper()
	configPath := filepath.Join(testingHandle.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		testingHandle.Fatalf("write config: %v", err)
	}
	return configPath
}

func buildConfigPayload(databaseURL string) string {
	return strings.TrimSpace(strings.ReplaceAll(`
server:
  listen_addr: ":8080"
  database_url: "{{DB_URL}}"
  enable_cors: true
  cors_allowed_origins:
    - "https://accounts.google.com"
  cors_allowed_origin_exceptions:
    - "https://accounts.google.com"
  enable_tenant_header_override: true

tenants:
  - id: "`+testTenantID+`"
    display_name: "Demo"
    tenant_origins: ["`+testTenantOrigin+`"]
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    google_native_client_id: "demo-native.apps.googleusercontent.com"
    apple_oauth:
      enabled: true
      client_id: "com.example.web"
      team_id: "TEAMID1234"
      key_id: "KEYID12345"
      private_key: |
        -----BEGIN PRIVATE KEY-----
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOtX4DboO+3EK3QiI
        gcyd4R5kCEvi1tpUe/KUYMzR6aWhRANCAARPSwbYVpecI9G3UW5MFq+4gx/PkWAC
        Y2c91Z0fHH9N5PRVUNFolUdxFmc8dR6Av/dpUVOicqcc0HT9DpQfIPeT
        -----END PRIVATE KEY-----
      redirect_uri: "https://tauth.example.com/auth/apple/callback"
    jwt_signing_key: "`+testSigningKey+`"
    cookie_domain: "demo.localhost"
    session_cookie_name: "`+testSessionCookieName+`"
    refresh_cookie_name: "`+testRefreshCookieName+`"
    session_ttl: "15m"
    refresh_ttl: "720h"
    nonce_ttl: "5m"
    allow_insecure_http: true
`, "{{DB_URL}}", databaseURL)) + "\n"
}

type testReportPayload struct {
	SchemaVersion   string                          `json:"schema_version"`
	Service         testServicePayload              `json:"service"`
	EffectiveConfig testEffectiveConfigPayload      `json:"effective_config"`
	Dependencies    []preflightpkg.DependencyStatus `json:"dependencies"`
}

type testServicePayload struct {
	Name string `json:"service_name"`
}

type testEffectiveConfigPayload struct {
	Server  testServerPayload   `json:"server"`
	Tenants []testTenantPayload `json:"tenants"`
}

type testServerPayload struct {
	EnableCORS                  bool     `json:"enable_cors"`
	CORSAllowedOrigins          []string `json:"cors_allowed_origins"`
	CORSAllowedOriginExceptions []string `json:"cors_allowed_origin_exceptions"`
	EnableTenantHeaderOverride  bool     `json:"enable_tenant_header_override"`
}

type testTenantPayload struct {
	TenantID                   string                          `json:"tenant_id"`
	DisplayName                string                          `json:"display_name"`
	TenantOrigins              []string                        `json:"tenant_origins"`
	TenantOriginsRedacted      bool                            `json:"tenant_origins_redacted"`
	TenantOriginsCount         int                             `json:"tenant_origins_count"`
	TenantOriginHashes         []string                        `json:"tenant_origin_hashes"`
	GoogleWebClientID          string                          `json:"google_web_client_id"`
	GoogleNativeClientID       string                          `json:"google_native_client_id"`
	GoogleNativeClientIDs      []string                        `json:"google_native_client_ids"`
	GoogleNativeClients        []testNativeGoogleClientPayload `json:"google_native_clients"`
	AppleOAuthEnabled          bool                            `json:"apple_oauth_enabled"`
	AppleClientID              string                          `json:"apple_client_id"`
	AppleTeamID                string                          `json:"apple_team_id"`
	AppleKeyID                 string                          `json:"apple_key_id"`
	ApplePrivateKeyFingerprint string                          `json:"apple_private_key_fingerprint"`
	AppleRedirectURI           string                          `json:"apple_redirect_uri"`
	AppleScopes                []string                        `json:"apple_scopes"`
	AppleAuthorizationEndpoint string                          `json:"apple_authorization_endpoint"`
	AppleTokenEndpoint         string                          `json:"apple_token_endpoint"`
	AppleJWKSURL               string                          `json:"apple_jwks_url"`
	PasswordAuthEnabled        bool                            `json:"password_auth_enabled"`
	PasswordUserCount          int                             `json:"password_user_count"`
	AccountManagementEnabled   bool                            `json:"account_management_enabled"`
	PasswordSignupEnabled      bool                            `json:"password_signup_enabled"`
	ReturnChallengeTokens      bool                            `json:"return_challenge_tokens"`
	EmailVerificationTTL       string                          `json:"email_verification_ttl"`
	PasswordResetTTL           string                          `json:"password_reset_ttl"`
	CookieDomain               string                          `json:"cookie_domain"`
	SessionCookieName          string                          `json:"session_cookie_name"`
	RefreshCookieName          string                          `json:"refresh_cookie_name"`
	SessionTTL                 string                          `json:"session_ttl"`
	RefreshTTL                 string                          `json:"refresh_ttl"`
	NonceTTL                   string                          `json:"nonce_ttl"`
	AllowInsecureHTTP          bool                            `json:"allow_insecure_http"`
	SameSiteMode               string                          `json:"same_site_mode"`
	JWTIssuer                  string                          `json:"jwt_issuer"`
	JWTSigningKeyFingerprint   string                          `json:"jwt_signing_key_fingerprint"`
}

type testNativeGoogleClientPayload struct {
	Platform     string   `json:"platform"`
	ClientID     string   `json:"client_id"`
	RedirectURIs []string `json:"redirect_uris"`
}

func TestBuildRedactedReportRedactsOrigins(testingHandle *testing.T) {
	configPath := writeConfigFile(testingHandle, buildConfigPayload(""))
	reportBytes, err := BuildRedactedReport(configPath)
	if err != nil {
		testingHandle.Fatalf("build report: %v", err)
	}
	var payload testReportPayload
	if err := json.Unmarshal(reportBytes, &payload); err != nil {
		testingHandle.Fatalf("decode report: %v", err)
	}
	if payload.SchemaVersion == "" || payload.Service.Name == "" {
		testingHandle.Fatalf("expected schema + service metadata")
	}
	if len(payload.EffectiveConfig.Tenants) != 1 {
		testingHandle.Fatalf("expected one tenant, got %d", len(payload.EffectiveConfig.Tenants))
	}
	tenant := payload.EffectiveConfig.Tenants[0]
	if !tenant.TenantOriginsRedacted {
		testingHandle.Fatalf("expected origins to be redacted")
	}
	if len(tenant.TenantOrigins) != 0 {
		testingHandle.Fatalf("expected no tenant_origins when redacted")
	}
	if tenant.TenantOriginsCount != 1 {
		testingHandle.Fatalf("expected tenant origin count 1, got %d", tenant.TenantOriginsCount)
	}
	if len(tenant.TenantOriginHashes) != 1 {
		testingHandle.Fatalf("expected one origin hash")
	}
	expectedFingerprint := preflightpkg.HashSHA256Hex([]byte(testSigningKey))
	if tenant.JWTSigningKeyFingerprint != expectedFingerprint {
		testingHandle.Fatalf("expected signing key fingerprint %s, got %s", expectedFingerprint, tenant.JWTSigningKeyFingerprint)
	}
	if len(payload.Dependencies) != 1 {
		testingHandle.Fatalf("expected one dependency, got %d", len(payload.Dependencies))
	}
	dependency := payload.Dependencies[0]
	if dependency.Name != refreshStoreName || dependency.Type != refreshStoreTypeMemory || !dependency.Ready {
		testingHandle.Fatalf("expected memory refresh store to be ready")
	}
	if dependency.Details[refreshStoreDriverKey] != refreshStoreTypeMemory {
		testingHandle.Fatalf("expected memory refresh store driver")
	}
	if tenant.SameSiteMode == "" || tenant.JWTIssuer == "" {
		testingHandle.Fatalf("expected same_site_mode and jwt_issuer")
	}
	if tenant.GoogleNativeClientID == "" {
		testingHandle.Fatalf("expected google_native_client_id")
	}
	if len(tenant.GoogleNativeClientIDs) != 1 || tenant.GoogleNativeClientIDs[0] != tenant.GoogleNativeClientID {
		testingHandle.Fatalf("unexpected google_native_client_ids: %#v", tenant.GoogleNativeClientIDs)
	}
	if len(tenant.GoogleNativeClients) != 1 || tenant.GoogleNativeClients[0].Platform != "desktop" {
		testingHandle.Fatalf("unexpected google_native_clients: %#v", tenant.GoogleNativeClients)
	}
	if !tenant.AppleOAuthEnabled || tenant.AppleClientID != "com.example.web" || tenant.AppleRedirectURI != "https://tauth.example.com/auth/apple/callback" {
		testingHandle.Fatalf("unexpected Apple OAuth report fields: %#v", tenant)
	}
	if tenant.ApplePrivateKeyFingerprint == "" || len(tenant.AppleScopes) != 3 {
		testingHandle.Fatalf("expected Apple private key fingerprint and default scopes")
	}
	if tenant.PasswordAuthEnabled || tenant.PasswordUserCount != 0 {
		testingHandle.Fatalf("unexpected password auth report fields")
	}
	if tenant.AccountManagementEnabled || tenant.PasswordSignupEnabled || tenant.ReturnChallengeTokens {
		testingHandle.Fatalf("unexpected account management report fields")
	}
	if tenant.EmailVerificationTTL == "" || tenant.PasswordResetTTL == "" {
		testingHandle.Fatalf("expected account management TTL fields")
	}
}

func TestBuildFullReportIncludesOrigins(testingHandle *testing.T) {
	configPath := writeConfigFile(testingHandle, buildConfigPayload(""))
	reportBytes, err := BuildFullReport(configPath)
	if err != nil {
		testingHandle.Fatalf("build report: %v", err)
	}
	var payload testReportPayload
	if err := json.Unmarshal(reportBytes, &payload); err != nil {
		testingHandle.Fatalf("decode report: %v", err)
	}
	tenant := payload.EffectiveConfig.Tenants[0]
	if tenant.TenantOriginsRedacted {
		testingHandle.Fatalf("expected origins to be included")
	}
	if len(tenant.TenantOrigins) != 1 || tenant.TenantOrigins[0] != testTenantOrigin {
		testingHandle.Fatalf("expected tenant_origins to include %s", testTenantOrigin)
	}
}

func TestBuildReportIncludesOAuthPolicyWithoutPrivateKey(t *testing.T) {
	privateKey, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if keyErr != nil {
		t.Fatalf("generate OAuth key: %v", keyErr)
	}
	keyDER, marshalErr := x509.MarshalPKCS8PrivateKey(privateKey)
	if marshalErr != nil {
		t.Fatalf("marshal OAuth key: %v", marshalErr)
	}
	keyBase64 := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	config := fmt.Sprintf(`server:
  listen_addr: ":8080"
  database_url: ""
oauth:
  enabled: true
  issuer: "https://auth.example.com"
  authorization_endpoint: "https://auth.example.com/oauth/authorize"
  token_endpoint: "https://auth.example.com/oauth/token"
  revocation_endpoint: "https://auth.example.com/oauth/revoke"
  jwks_uri: "https://auth.example.com/oauth/jwks"
  login_endpoint: "https://auth.example.com/oauth/login"
  consent_endpoint: "https://auth.example.com/oauth/consent"
  authorization_request_ttl: "5m"
  authorization_code_ttl: "1m"
  active_signing_key_id: "active"
  signing_keys:
    - id: "active"
      private_key_base64: %q
  client_metadata:
    request_timeout: "2s"
    maximum_bytes: 5120
    minimum_cache_ttl: "1m"
    maximum_cache_ttl: "1h"
tenants:
  - id: "oauth"
    tenant_origins: ["https://app.example.com"]
    password_auth:
      enabled: true
      users: []
    oauth:
      enabled: true
      access_token_ttl: "5m"
      refresh_token_ttl: "24h"
      consent_ttl: "12h"
      allow_client_metadata_documents: false
      resources:
        - identifier: "https://api.example.com"
          display_name: "API"
          scopes:
            - identifier: "api:use"
              display_name: "Use API"
              description: "Use the API."
      clients:
        - id: "oauth-client"
          display_name: "OAuth Client"
          application_type: "web"
          redirect_uris: ["https://client.example.com/callback"]
          grants:
            - resource: "https://api.example.com"
              scopes: ["api:use"]
    jwt_signing_key: "session-signing-key"
    session_cookie_name: "session_oauth"
    refresh_cookie_name: "refresh_oauth"
    session_ttl: "15m"
    refresh_ttl: "24h"
    nonce_ttl: "5m"
`, keyBase64)
	report, reportErr := BuildRedactedReport(writeConfigFile(t, config))
	if reportErr != nil {
		t.Fatalf("build OAuth report: %v", reportErr)
	}
	if strings.Contains(string(report), keyBase64) || strings.Contains(string(report), "PRIVATE KEY") {
		t.Fatal("preflight report exposed OAuth private key")
	}
	var payload map[string]any
	if decodeErr := json.Unmarshal(report, &payload); decodeErr != nil {
		t.Fatalf("decode OAuth report: %v", decodeErr)
	}
	effective := payload["effective_config"].(map[string]any)
	server := effective["server"].(map[string]any)
	oauth := server["oauth"].(map[string]any)
	if oauth["enabled"] != true || oauth["active_signing_key_id"] != "active" || len(oauth["signing_keys"].([]any)) != 1 {
		t.Fatalf("unexpected OAuth preflight payload: %#v", oauth)
	}
}

func TestBuildReportRejectsInvalidDatabaseURL(testingHandle *testing.T) {
	configPath := writeConfigFile(testingHandle, buildConfigPayload("bad://invalid"))
	_, err := BuildRedactedReport(configPath)
	if err == nil {
		testingHandle.Fatalf("expected error for invalid database url")
	}
}

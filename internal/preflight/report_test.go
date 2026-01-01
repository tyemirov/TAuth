package preflight

import (
	"encoding/json"
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
	TenantID                 string   `json:"tenant_id"`
	DisplayName              string   `json:"display_name"`
	TenantOrigins            []string `json:"tenant_origins"`
	TenantOriginsRedacted    bool     `json:"tenant_origins_redacted"`
	TenantOriginsCount       int      `json:"tenant_origins_count"`
	TenantOriginHashes       []string `json:"tenant_origin_hashes"`
	GoogleWebClientID        string   `json:"google_web_client_id"`
	CookieDomain             string   `json:"cookie_domain"`
	SessionCookieName        string   `json:"session_cookie_name"`
	RefreshCookieName        string   `json:"refresh_cookie_name"`
	SessionTTL               string   `json:"session_ttl"`
	RefreshTTL               string   `json:"refresh_ttl"`
	NonceTTL                 string   `json:"nonce_ttl"`
	AllowInsecureHTTP        bool     `json:"allow_insecure_http"`
	SameSiteMode             string   `json:"same_site_mode"`
	JWTIssuer                string   `json:"jwt_issuer"`
	JWTSigningKeyFingerprint string   `json:"jwt_signing_key_fingerprint"`
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

func TestBuildReportRejectsInvalidDatabaseURL(testingHandle *testing.T) {
	configPath := writeConfigFile(testingHandle, buildConfigPayload("bad://invalid"))
	_, err := BuildRedactedReport(configPath)
	if err == nil {
		testingHandle.Fatalf("expected error for invalid database url")
	}
}

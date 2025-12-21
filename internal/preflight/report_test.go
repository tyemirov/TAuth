package preflight

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testTenantID          = "demo"
	testSessionCookieName = "app_session_demo"
	testRefreshCookieName = "app_refresh_demo"
	testSigningKey        = "demo-signing-key"
	testAllowedHost       = "demo.localhost"
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
  enable_tenant_header_override: true

tenants:
  - id: "`+testTenantID+`"
    display_name: "Demo"
    allowed_hosts: ["`+testAllowedHost+`"]
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

func TestBuildRedactedReportRedactsHosts(testingHandle *testing.T) {
	configPath := writeConfigFile(testingHandle, buildConfigPayload(""))
	reportBytes, err := BuildRedactedReport(configPath)
	if err != nil {
		testingHandle.Fatalf("build report: %v", err)
	}
	var payload reportPayload
	if err := json.Unmarshal(reportBytes, &payload); err != nil {
		testingHandle.Fatalf("decode report: %v", err)
	}
	if payload.SchemaVersion == "" || payload.Service.Name == "" {
		testingHandle.Fatalf("expected schema + service metadata")
	}
	if len(payload.Tenants) != 1 {
		testingHandle.Fatalf("expected one tenant, got %d", len(payload.Tenants))
	}
	tenant := payload.Tenants[0]
	if !tenant.AllowedHostsRedacted {
		testingHandle.Fatalf("expected hosts to be redacted")
	}
	if len(tenant.AllowedHosts) != 0 {
		testingHandle.Fatalf("expected no allowed_hosts when redacted")
	}
	if tenant.AllowedHostsCount != 1 {
		testingHandle.Fatalf("expected allowed host count 1, got %d", tenant.AllowedHostsCount)
	}
	if len(tenant.AllowedHostHashes) != 1 {
		testingHandle.Fatalf("expected one host hash")
	}
	expectedFingerprint := sha256Hex([]byte(testSigningKey))
	if tenant.JWTSigningKeyFingerprint != expectedFingerprint {
		testingHandle.Fatalf("expected signing key fingerprint %s, got %s", expectedFingerprint, tenant.JWTSigningKeyFingerprint)
	}
	if payload.Dependencies.RefreshStore.Type != "memory" || !payload.Dependencies.RefreshStore.Ready {
		testingHandle.Fatalf("expected memory refresh store to be ready")
	}
	if tenant.SameSiteMode == "" || tenant.JWTIssuer == "" {
		testingHandle.Fatalf("expected same_site_mode and jwt_issuer")
	}
}

func TestBuildFullReportIncludesHosts(testingHandle *testing.T) {
	configPath := writeConfigFile(testingHandle, buildConfigPayload(""))
	reportBytes, err := BuildFullReport(configPath)
	if err != nil {
		testingHandle.Fatalf("build report: %v", err)
	}
	var payload reportPayload
	if err := json.Unmarshal(reportBytes, &payload); err != nil {
		testingHandle.Fatalf("decode report: %v", err)
	}
	tenant := payload.Tenants[0]
	if tenant.AllowedHostsRedacted {
		testingHandle.Fatalf("expected hosts to be included")
	}
	if len(tenant.AllowedHosts) != 1 || tenant.AllowedHosts[0] != testAllowedHost {
		testingHandle.Fatalf("expected allowed_hosts to include %s", testAllowedHost)
	}
}

func TestBuildReportRejectsInvalidDatabaseURL(testingHandle *testing.T) {
	configPath := writeConfigFile(testingHandle, buildConfigPayload("bad://invalid"))
	_, err := BuildRedactedReport(configPath)
	if err == nil {
		testingHandle.Fatalf("expected error for invalid database url")
	}
}

package sessionvalidator

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyemirov/tauth/internal/appconfig"
)

const (
	sampleTenantID          = "demo"
	unknownTenantID         = "missing"
	sampleSessionCookieName = "app_session_demo"
	sampleRefreshCookieName = "app_refresh_demo"
	sampleSigningKey        = "demo-signing-key"
)

func writeConfigFile(testingHandle *testing.T, payload string) string {
	testingHandle.Helper()
	configPath := filepath.Join(testingHandle.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(payload), 0o600); err != nil {
		testingHandle.Fatalf("write config: %v", err)
	}
	return configPath
}

func buildConfigPayload(tenantID string) string {
	return fmt.Sprintf(`
server:
  listen_addr: ":8080"

tenants:
  - id: "%s"
    display_name: "Demo"
    allowed_hosts: ["demo.localhost"]
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    jwt_signing_key: "%s"
    cookie_domain: "demo.localhost"
    session_cookie_name: "%s"
    refresh_cookie_name: "%s"
    session_ttl: "15m"
    refresh_ttl: "720h"
    nonce_ttl: "5m"
    allow_insecure_http: true
`, tenantID, sampleSigningKey, sampleSessionCookieName, sampleRefreshCookieName)
}

func TestLoadTenantAuthConfigRequiresConfigPath(testingHandle *testing.T) {
	_, err := LoadTenantAuthConfig("  ", sampleTenantID)
	if err == nil || !strings.Contains(err.Error(), errorCodeMissingConfigPath) {
		testingHandle.Fatalf("expected missing path error, got %v", err)
	}
}

func TestLoadTenantAuthConfigRequiresTenantID(testingHandle *testing.T) {
	configPath := writeConfigFile(testingHandle, buildConfigPayload(sampleTenantID))
	_, err := LoadTenantAuthConfig(configPath, " ")
	if err == nil || !strings.Contains(err.Error(), errorCodeMissingTenantID) {
		testingHandle.Fatalf("expected missing tenant id error, got %v", err)
	}
}

func TestLoadTenantAuthConfigRejectsUnknownTenant(testingHandle *testing.T) {
	configPath := writeConfigFile(testingHandle, buildConfigPayload(sampleTenantID))
	_, err := LoadTenantAuthConfig(configPath, unknownTenantID)
	if err == nil || !strings.Contains(err.Error(), errorCodeUnknownTenantID) {
		testingHandle.Fatalf("expected unknown tenant error, got %v", err)
	}
}

func TestLoadTenantAuthConfigLoadsTenantSettings(testingHandle *testing.T) {
	configPath := writeConfigFile(testingHandle, buildConfigPayload(sampleTenantID))
	authConfig, err := LoadTenantAuthConfig(configPath, sampleTenantID)
	if err != nil {
		testingHandle.Fatalf("load tenant config: %v", err)
	}
	if authConfig.TenantID() != sampleTenantID {
		testingHandle.Fatalf("expected tenant id %s, got %s", sampleTenantID, authConfig.TenantID())
	}
	if authConfig.Issuer() != appconfig.DefaultJWTIssuer {
		testingHandle.Fatalf("expected issuer %s, got %s", appconfig.DefaultJWTIssuer, authConfig.Issuer())
	}
	if authConfig.SessionCookieName() != sampleSessionCookieName {
		testingHandle.Fatalf("expected session cookie %s, got %s", sampleSessionCookieName, authConfig.SessionCookieName())
	}
	if authConfig.RefreshCookieName() != sampleRefreshCookieName {
		testingHandle.Fatalf("expected refresh cookie %s, got %s", sampleRefreshCookieName, authConfig.RefreshCookieName())
	}
	if string(authConfig.SigningKey()) != sampleSigningKey {
		testingHandle.Fatalf("expected signing key %s", sampleSigningKey)
	}
	validatorConfig := authConfig.ValidatorConfig()
	if validatorConfig.Issuer != appconfig.DefaultJWTIssuer {
		testingHandle.Fatalf("expected validator issuer %s, got %s", appconfig.DefaultJWTIssuer, validatorConfig.Issuer)
	}
	if validatorConfig.CookieName != sampleSessionCookieName {
		testingHandle.Fatalf("expected validator cookie %s, got %s", sampleSessionCookieName, validatorConfig.CookieName)
	}
	if _, validatorErr := New(validatorConfig); validatorErr != nil {
		testingHandle.Fatalf("expected validator to build: %v", validatorErr)
	}
}

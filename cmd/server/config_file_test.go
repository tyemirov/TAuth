package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/tenants"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

func writeTempConfig(testingHandle *testing.T, contents string) string {
	testingHandle.Helper()
	path := filepath.Join(testingHandle.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		testingHandle.Fatalf("failed to write config: %v", err)
	}
	return path
}

func TestLoadApplicationConfigParsesServerAndTenants(testingHandle *testing.T) {
	testingHandle.Setenv("LISTEN_ADDR", ":9090")
	testingHandle.Setenv("SIGNING_KEY", "env-signing")
	testingHandle.Setenv("DB_URL", "sqlite:///data/tauth.db")

	configPath := writeTempConfig(testingHandle, `
server:
  listen_addr: "${LISTEN_ADDR}"
  database_url: "${DB_URL}"
  enable_cors: "true"
  cors_allowed_origins:
    - "https://one.example"
    - "https://two.example"
  cors_allowed_origin_exceptions:
    - "https://accounts.google.com"
  enable_tenant_header_override: "true"

tenants:
  - id: "demo"
    display_name: "Demo"
    tenant_origins: ["https://demo.localhost"]
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    google_native_client_id: "demo-native.apps.googleusercontent.com"
    jwt_signing_key: "demo-tenant-key"
    cookie_domain: "demo.localhost"
    session_cookie_name: "app_session_demo"
    refresh_cookie_name: "app_refresh_demo"
    session_ttl: "15m"
    refresh_ttl: "720h"
    nonce_ttl: "5m"
    allow_insecure_http: "true"
`)

	config, loadErr := appconfig.LoadConfig(configPath)
	if loadErr != nil {
		testingHandle.Fatalf("expected config to load, got %v", loadErr)
	}
	if config.Server.ListenAddr != ":9090" {
		testingHandle.Fatalf("unexpected listen addr: %s", config.Server.ListenAddr)
	}
	if config.Server.DatabaseURL != "sqlite:///data/tauth.db" {
		testingHandle.Fatalf("unexpected db url")
	}
	if !config.Server.EnableCORS || len(config.Server.CORSAllowedOrigins) != 2 {
		testingHandle.Fatalf("expected CORS origins to be parsed")
	}
	if len(config.Server.CORSAllowedOriginExceptions) != 1 {
		testingHandle.Fatalf("expected CORS origin exceptions to be parsed")
	}
	if !config.Server.EnableTenantHeaderOverride {
		testingHandle.Fatalf("expected header override to be enabled")
	}
	if len(config.Tenants) != 1 || config.Tenants[0].ID != "demo" {
		testingHandle.Fatalf("expected single demo tenant")
	}
	if config.Tenants[0].GoogleNativeClientID != "demo-native.apps.googleusercontent.com" {
		testingHandle.Fatalf("expected native google client id to be parsed")
	}
}

func TestLoadApplicationConfigDefaults(testingHandle *testing.T) {
	configPath := writeTempConfig(testingHandle, `
server:
  database_url: ""

tenants:
  - id: "demo"
    tenant_origins: ["https://demo.localhost"]
    google_web_client_id: "demo-client"
    jwt_signing_key: "demo-tenant-key"
    cookie_domain: "demo.localhost"
    session_cookie_name: "app_session_demo"
    refresh_cookie_name: "app_refresh_demo"
    session_ttl: "15m"
    refresh_ttl: "720h"
    nonce_ttl: "5m"
`)

	config, loadErr := appconfig.LoadConfig(configPath)
	if loadErr != nil {
		testingHandle.Fatalf("expected config to load, got %v", loadErr)
	}
	if config.Server.ListenAddr != appconfig.DefaultListenAddr {
		testingHandle.Fatalf("expected default listen addr, got %s", config.Server.ListenAddr)
	}
}

func TestLoadApplicationConfigPreservesLiteralPasswordHash(testingHandle *testing.T) {
	hashBytes, hashErr := bcrypt.GenerateFromPassword([]byte("secret-password"), bcrypt.MinCost)
	if hashErr != nil {
		testingHandle.Fatalf("failed to generate password hash: %v", hashErr)
	}
	passwordHash := string(hashBytes)
	configPath := writeTempConfig(testingHandle, fmt.Sprintf(`
server:
  database_url: ""
  enable_cors: false

tenants:
  - id: "demo"
    display_name: "Demo"
    tenant_origins: ["https://demo.localhost"]
    google_web_client_id: "demo-client"
    password_auth:
      enabled: true
      users:
        - email: "user@example.com"
          display_name: "Demo User"
          password_hash: "%s"
    jwt_signing_key: "demo-tenant-key"
    cookie_domain: "demo.localhost"
    session_cookie_name: "app_session_demo"
    refresh_cookie_name: "app_refresh_demo"
    session_ttl: "15m"
    refresh_ttl: "720h"
`, passwordHash))

	config, loadErr := appconfig.LoadConfig(configPath)
	if loadErr != nil {
		testingHandle.Fatalf("expected config to load, got %v", loadErr)
	}
	tenantConfig, tenantErr := tenants.LoadConfigFromDocument(config.TenantDocument())
	if tenantErr != nil {
		testingHandle.Fatalf("expected tenant document to load, got %v", tenantErr)
	}
	tenant, exists := tenantConfig.TenantByID("demo")
	if !exists {
		testingHandle.Fatalf("expected demo tenant")
	}
	users := tenant.PasswordUsers()
	if len(users) != 1 {
		testingHandle.Fatalf("expected one password user, got %d", len(users))
	}
	if users[0].PasswordHash() != passwordHash {
		testingHandle.Fatalf("expected literal password hash to survive app config loading")
	}
}

func TestLoadApplicationConfigRejectsEmptyPath(testingHandle *testing.T) {
	if _, err := appconfig.LoadConfig("  "); err == nil {
		testingHandle.Fatalf("expected error for empty path")
	}
}

func TestLoadApplicationConfigMultiTenantFixture(testingHandle *testing.T) {
	testingHandle.Setenv("TAUTH_LISTEN_ADDR", ":8082")
	testingHandle.Setenv("TAUTH_DATABASE_URL", "sqlite:///data/example.db")
	testingHandle.Setenv("TAUTH_ENABLE_CORS", "true")
	testingHandle.Setenv("TAUTH_CORS_ORIGIN_1", "http://localhost:8000")
	testingHandle.Setenv("TAUTH_CORS_ORIGIN_2", "http://127.0.0.1:8000")
	testingHandle.Setenv("TAUTH_CORS_ORIGIN_3", "http://localhost:4173")
	testingHandle.Setenv("TAUTH_CORS_EXCEPTION_1", "https://accounts.google.com")
	testingHandle.Setenv("TAUTH_GOOGLE_WEB_CLIENT_ID1", "notes-client")
	testingHandle.Setenv("TAUTH_NOTES_JWT_SIGNING_KEY", "notes-signing-key")
	testingHandle.Setenv("TAUTH_GOOGLE_WEB_CLIENT_ID2", "portal-client")
	testingHandle.Setenv("TAUTH_PORTAL_JWT_SIGNING_KEY", "portal-signing-key")
	testingHandle.Setenv("TAUTH_ALLOW_INSECURE_HTTP", "true")

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		testingHandle.Fatalf("runtime caller unavailable")
	}
	baseDir := filepath.Dir(filename)
	configPath := filepath.Join(baseDir, "..", "..", "tests", "fixtures", "multi-tenant", "config.yaml")
	if _, err := os.Stat(configPath); err != nil {
		testingHandle.Fatalf("fixture config missing: %v", err)
	}

	config, loadErr := appconfig.LoadConfig(configPath)
	if loadErr != nil {
		testingHandle.Fatalf("expected config to load, got %v", loadErr)
	}
	if config.Server.ListenAddr != ":8082" {
		testingHandle.Fatalf("unexpected listen addr: %s", config.Server.ListenAddr)
	}
	if !config.Server.EnableCORS {
		testingHandle.Fatalf("expected CORS to be enabled")
	}
	if len(config.Server.CORSAllowedOrigins) != 3 {
		testingHandle.Fatalf("expected three CORS origins, got %d", len(config.Server.CORSAllowedOrigins))
	}
	if len(config.Tenants) != 2 {
		testingHandle.Fatalf("expected two tenants in example config")
	}

	tenantConfig, tenantErr := tenants.LoadConfigFromDocument(config.TenantDocument())
	if tenantErr != nil {
		testingHandle.Fatalf("expected tenant document to load, got %v", tenantErr)
	}
	if tenant, ok := tenantConfig.OriginOwner("http://localhost:8000"); !ok || tenant != "notes" {
		testingHandle.Fatalf("expected notes tenant for gravity origin, got %s", tenant)
	}
	if tenant, ok := tenantConfig.OriginOwner("http://localhost:4173"); !ok || tenant != "portal" {
		testingHandle.Fatalf("expected portal tenant for demo origin, got %s", tenant)
	}
	if notesTenant, ok := tenantConfig.TenantByID("notes"); !ok || string(notesTenant.SigningKey()) != "notes-signing-key" {
		testingHandle.Fatalf("expected notes tenant signing key to be applied")
	}
	if portalTenant, ok := tenantConfig.TenantByID("portal"); !ok || string(portalTenant.SigningKey()) != "portal-signing-key" {
		testingHandle.Fatalf("expected portal tenant signing key to be applied")
	}
}

func TestYamlBoolUnmarshalYAMLSupportsBoolAndString(testingHandle *testing.T) {
	testCases := []struct {
		name      string
		payload   string
		expected  bool
		expectErr bool
	}{
		{
			name:     "bool_tag",
			payload:  "value: true\n",
			expected: true,
		},
		{
			name:     "string_tag",
			payload:  "value: \"true\"\n",
			expected: true,
		},
		{
			name:      "default_tag_error",
			payload:   "value: 1\n",
			expectErr: true,
		},
		{
			name:      "string_tag_error",
			payload:   "value: \"notabool\"\n",
			expectErr: true,
		},
	}

	for _, testCase := range testCases {
		testingHandle.Run(testCase.name, func(testingHandle *testing.T) {
			var wrapper struct {
				Value appconfig.YamlBool `yaml:"value"`
			}
			err := yaml.Unmarshal([]byte(testCase.payload), &wrapper)
			if testCase.expectErr {
				if err == nil {
					testingHandle.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				testingHandle.Fatalf("unexpected error: %v", err)
			}
			if bool(wrapper.Value) != testCase.expected {
				testingHandle.Fatalf("expected %v, got %v", testCase.expected, bool(wrapper.Value))
			}
		})
	}
}

func TestYamlBoolUnmarshalYAMLDefaultTagSupportsNull(testingHandle *testing.T) {
	var value appconfig.YamlBool
	node := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: ""}
	if err := value.UnmarshalYAML(node); err != nil {
		testingHandle.Fatalf("unexpected error: %v", err)
	}
	if bool(value) {
		testingHandle.Fatalf("expected false, got true")
	}
}

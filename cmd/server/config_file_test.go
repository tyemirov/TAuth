package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/tenants"
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
  enable_tenant_header_override: "true"

tenants:
  - id: "demo"
    display_name: "Demo"
    allowed_hosts: ["https://demo.localhost"]
    google_web_client_id: "demo-client.apps.googleusercontent.com"
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
	if !config.Server.EnableTenantHeaderOverride {
		testingHandle.Fatalf("expected header override to be enabled")
	}
	if len(config.Tenants) != 1 || config.Tenants[0].ID != "demo" {
		testingHandle.Fatalf("expected single demo tenant")
	}
}

func TestLoadApplicationConfigDefaults(testingHandle *testing.T) {
	configPath := writeTempConfig(testingHandle, `
server:
  database_url: ""

tenants:
  - id: "demo"
    allowed_hosts: ["https://demo.localhost"]
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

func TestLoadApplicationConfigRejectsEmptyPath(testingHandle *testing.T) {
	if _, err := appconfig.LoadConfig("  "); err == nil {
		testingHandle.Fatalf("expected error for empty path")
	}
}

func TestLoadApplicationConfigMultiTenantExample(testingHandle *testing.T) {
	testingHandle.Setenv("TAUTH_LISTEN_ADDR", ":8082")
	testingHandle.Setenv("TAUTH_DATABASE_URL", "sqlite:///data/example.db")
	testingHandle.Setenv("TAUTH_ENABLE_CORS", "true")
	testingHandle.Setenv("TAUTH_CORS_ORIGIN_1", "http://localhost:8000")
	testingHandle.Setenv("TAUTH_CORS_ORIGIN_2", "http://127.0.0.1:8000")
	testingHandle.Setenv("TAUTH_CORS_ORIGIN_3", "http://localhost:4173")
	testingHandle.Setenv("TAUTH_GOOGLE_WEB_CLIENT_ID1", "notes-client")
	testingHandle.Setenv("TAUTH_GOOGLE_WEB_CLIENT_ID2", "mpr-client")
	testingHandle.Setenv("TAUTH_NOTES_JWT_SIGNING_KEY", "notes-signing-key")
	testingHandle.Setenv("TAUTH_MPR_JWT_SIGNING_KEY", "mpr-signing-key")
	testingHandle.Setenv("TAUTH_ALLOW_INSECURE_HTTP", "true")

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		testingHandle.Fatalf("runtime caller unavailable")
	}
	baseDir := filepath.Dir(filename)
	configPath := filepath.Join(baseDir, "..", "..", "examples", "multi-tenant", "config.yaml")
	if _, err := os.Stat(configPath); err != nil {
		testingHandle.Fatalf("example config missing: %v", err)
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
	if tenant, ok := tenantConfig.OriginOwner("http://localhost:4173"); !ok || tenant != "mpr-sites" {
		testingHandle.Fatalf("expected mpr-sites tenant for demo origin, got %s", tenant)
	}
	if notesTenant, ok := tenantConfig.TenantByID("notes"); !ok || string(notesTenant.SigningKey()) != "notes-signing-key" {
		testingHandle.Fatalf("expected notes tenant signing key to be applied")
	}
	if mprTenant, ok := tenantConfig.TenantByID("mpr-sites"); !ok || string(mprTenant.SigningKey()) != "mpr-signing-key" {
		testingHandle.Fatalf("expected mpr tenant signing key to be applied")
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

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/tyemirov/tauth/internal/tenants"
)

func writeTempConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	return path
}

func TestLoadApplicationConfigParsesServerAndTenants(t *testing.T) {
	t.Setenv("LISTEN_ADDR", ":9090")
	t.Setenv("SIGNING_KEY", "env-signing")
	t.Setenv("DB_URL", "sqlite:///data/tauth.db")

	configPath := writeTempConfig(t, `
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
    allowed_hosts: ["demo.localhost"]
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

	cfg, err := loadApplicationConfig(configPath)
	if err != nil {
		t.Fatalf("expected config to load, got %v", err)
	}
	if cfg.Server.ListenAddr != ":9090" {
		t.Fatalf("unexpected listen addr: %s", cfg.Server.ListenAddr)
	}
	if cfg.Server.DatabaseURL != "sqlite:///data/tauth.db" {
		t.Fatalf("unexpected db url")
	}
	if !cfg.Server.EnableCORS || len(cfg.Server.CORSAllowedOrigins) != 2 {
		t.Fatalf("expected CORS origins to be parsed")
	}
	if !cfg.Server.EnableTenantHeaderOverride {
		t.Fatalf("expected header override to be enabled")
	}
	if len(cfg.Tenants) != 1 || cfg.Tenants[0].ID != "demo" {
		t.Fatalf("expected single demo tenant")
	}
}

func TestLoadApplicationConfigDefaults(t *testing.T) {
	configPath := writeTempConfig(t, `
server:
  database_url: ""

tenants:
  - id: "demo"
    allowed_hosts: ["demo.localhost"]
    google_web_client_id: "demo-client"
    jwt_signing_key: "demo-tenant-key"
    cookie_domain: "demo.localhost"
    session_cookie_name: "app_session_demo"
    refresh_cookie_name: "app_refresh_demo"
    session_ttl: "15m"
    refresh_ttl: "720h"
    nonce_ttl: "5m"
`)

	cfg, err := loadApplicationConfig(configPath)
	if err != nil {
		t.Fatalf("expected config to load, got %v", err)
	}
	if cfg.Server.ListenAddr != ":8080" {
		t.Fatalf("expected default listen addr, got %s", cfg.Server.ListenAddr)
	}
}

func TestLoadApplicationConfigRejectsEmptyPath(t *testing.T) {
	if _, err := loadApplicationConfig("  "); err == nil {
		t.Fatalf("expected error for empty path")
	}
}

func TestLoadApplicationConfigMultiTenantExample(t *testing.T) {
	t.Setenv("TAUTH_LISTEN_ADDR", ":8082")
	t.Setenv("TAUTH_DATABASE_URL", "sqlite:///data/example.db")
	t.Setenv("TAUTH_ENABLE_CORS", "true")
	t.Setenv("TAUTH_CORS_ORIGIN_1", "http://localhost:8000")
	t.Setenv("TAUTH_CORS_ORIGIN_2", "http://127.0.0.1:8000")
	t.Setenv("TAUTH_CORS_ORIGIN_3", "http://localhost:4173")
	t.Setenv("TAUTH_GOOGLE_WEB_CLIENT_ID1", "notes-client")
	t.Setenv("TAUTH_GOOGLE_WEB_CLIENT_ID2", "mpr-client")
	t.Setenv("TAUTH_NOTES_JWT_SIGNING_KEY", "notes-signing-key")
	t.Setenv("TAUTH_MPR_JWT_SIGNING_KEY", "mpr-signing-key")
	t.Setenv("TAUTH_ALLOW_INSECURE_HTTP", "true")

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime caller unavailable")
	}
	baseDir := filepath.Dir(filename)
	configPath := filepath.Join(baseDir, "..", "..", "examples", "multi-tenant", "config.yaml")
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("example config missing: %v", err)
	}

	cfg, err := loadApplicationConfig(configPath)
	if err != nil {
		t.Fatalf("expected config to load, got %v", err)
	}
	if cfg.Server.ListenAddr != ":8082" {
		t.Fatalf("unexpected listen addr: %s", cfg.Server.ListenAddr)
	}
	if !cfg.Server.EnableCORS {
		t.Fatalf("expected CORS to be enabled")
	}
	if len(cfg.Server.CORSAllowedOrigins) != 3 {
		t.Fatalf("expected three CORS origins, got %d", len(cfg.Server.CORSAllowedOrigins))
	}
	if len(cfg.Tenants) != 2 {
		t.Fatalf("expected two tenants in example config")
	}

	tenantConfig, err := tenants.LoadConfigFromDocument(cfg.tenantDocument())
	if err != nil {
		t.Fatalf("expected tenant document to load, got %v", err)
	}
	if tenant, ok := tenantConfig.OriginOwner("http://localhost:8000"); !ok || tenant != "notes" {
		t.Fatalf("expected notes tenant for gravity origin, got %s", tenant)
	}
	if tenant, ok := tenantConfig.OriginOwner("http://localhost:4173"); !ok || tenant != "mpr-sites" {
		t.Fatalf("expected mpr-sites tenant for demo origin, got %s", tenant)
	}
	if notesTenant, ok := tenantConfig.TenantByID("notes"); !ok || string(notesTenant.SigningKey()) != "notes-signing-key" {
		t.Fatalf("expected notes tenant signing key to be applied")
	}
	if mprTenant, ok := tenantConfig.TenantByID("mpr-sites"); !ok || string(mprTenant.SigningKey()) != "mpr-signing-key" {
		t.Fatalf("expected mpr tenant signing key to be applied")
	}
}

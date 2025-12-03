package main

import (
	"os"
	"path/filepath"
	"testing"
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
  jwt_signing_key: "${SIGNING_KEY}"
  database_url: "${DB_URL}"
  enable_cors: "true"
  cors_allowed_origins:
    - "https://one.example"
    - "https://two.example"
  enable_tenant_header_override: "true"

tenants:
  - id: "demo"
    display_name: "Demo"
    hosts: ["demo.localhost"]
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    cookie_domain: "demo.localhost"
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
	if cfg.Server.JWTSigningKey != "env-signing" {
		t.Fatalf("unexpected signing key")
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
  jwt_signing_key: "default-key"

tenants:
  - id: "demo"
    hosts: ["demo.localhost"]
    google_web_client_id: "demo-client"
    cookie_domain: "demo.localhost"
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

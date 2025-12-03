package tenants

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfigSuccess(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "tenants.yaml")
	configYAML := []byte(`tenants:
  - id: "demo"
    display_name: "Demo Tenant"
    hosts:
      - "demo.localhost"
      - "demo.example.com"
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    cookie_domain: "demo.example.com"
    session_ttl: "30m"
    refresh_ttl: "720h"
    nonce_ttl: "10m"
    allow_insecure_http: "true"

  - id: "prod"
    display_name: "Production Tenant"
    hosts:
      - "app.example.com"
      - "app.mprlab.com"
    google_web_client_id: "prod-client.apps.googleusercontent.com"
    cookie_domain: ".example.com"
    session_ttl: "15m"
    refresh_ttl: "1440h"
    nonce_ttl: "5m"
`)
	if writeErr := os.WriteFile(configPath, configYAML, 0o600); writeErr != nil {
		t.Fatalf("failed to write config: %v", writeErr)
	}

	config, loadErr := LoadConfig(configPath)
	if loadErr != nil {
		t.Fatalf("expected config to load, got error: %v", loadErr)
	}

	tenantsList := config.Tenants()
	if len(tenantsList) != 2 {
		t.Fatalf("expected 2 tenants, got %d", len(tenantsList))
	}

	demoTenant := tenantsList[0]
	if demoTenant.ID() != "demo" {
		t.Fatalf("expected demo tenant id, got %s", demoTenant.ID())
	}
	if demoTenant.DisplayName() != "Demo Tenant" {
		t.Fatalf("unexpected display name: %s", demoTenant.DisplayName())
	}
	if demoTenant.GoogleWebClientID() != "demo-client.apps.googleusercontent.com" {
		t.Fatalf("unexpected google web client id: %s", demoTenant.GoogleWebClientID())
	}
	if !sameStringSlices(demoTenant.Hosts(), []string{"demo.localhost", "demo.example.com"}) {
		t.Fatalf("unexpected hosts: %#v", demoTenant.Hosts())
	}
	if demoTenant.CookieDomain() != "demo.example.com" {
		t.Fatalf("unexpected cookie domain: %s", demoTenant.CookieDomain())
	}
	if demoTenant.SessionTTL() != 30*time.Minute {
		t.Fatalf("unexpected session ttl: %s", demoTenant.SessionTTL())
	}
	if demoTenant.RefreshTTL() != 30*24*time.Hour {
		t.Fatalf("unexpected refresh ttl: %s", demoTenant.RefreshTTL())
	}
	if demoTenant.NonceTTL() != 10*time.Minute {
		t.Fatalf("unexpected nonce ttl: %s", demoTenant.NonceTTL())
	}
	if !demoTenant.AllowInsecureHTTP() {
		t.Fatalf("expected allow insecure http to be true")
	}

	prodTenant := tenantsList[1]
	if prodTenant.ID() != "prod" {
		t.Fatalf("expected prod tenant id, got %s", prodTenant.ID())
	}
	if prodTenant.AllowInsecureHTTP() {
		t.Fatalf("expected allow insecure http to default to false")
	}
}

func TestLoadConfigValidationErrors(t *testing.T) {
	testCases := []struct {
		name         string
		content      string
		expectedCode string
	}{
		{
			name: "missing_id",
			content: `tenants:
  - id: ""
    display_name: "Demo Tenant"
    hosts: ["demo.localhost"]
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    cookie_domain: "demo.example.com"
    session_ttl: "30m"
    refresh_ttl: "720h"
    nonce_ttl: "10m"
`,
			expectedCode: "tenant.invalid_id",
		},
		{
			name: "duplicate_host",
			content: `tenants:
  - id: "demo"
    display_name: "Demo Tenant"
    hosts: ["demo.example.com"]
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    cookie_domain: "demo.example.com"
    session_ttl: "30m"
    refresh_ttl: "720h"
    nonce_ttl: "10m"

  - id: "prod"
    display_name: "Production Tenant"
    hosts: ["demo.example.com"]
    google_web_client_id: "prod-client.apps.googleusercontent.com"
    cookie_domain: ".example.com"
    session_ttl: "15m"
    refresh_ttl: "1440h"
    nonce_ttl: "5m"
`,
			expectedCode: "tenant.duplicate_host",
		},
		{
			name: "invalid_session_ttl",
			content: `tenants:
  - id: "demo"
    display_name: "Demo Tenant"
    hosts: ["demo.example.com"]
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    cookie_domain: "demo.example.com"
    session_ttl: "0"
    refresh_ttl: "720h"
    nonce_ttl: "10m"
`,
			expectedCode: "tenant.invalid_session_ttl",
		},
		{
			name: "unknown_field",
			content: `tenants:
  - id: "demo"
    unknown_field: "unexpected"
    hosts: ["demo.example.com"]
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    cookie_domain: "demo.example.com"
    session_ttl: "30m"
    refresh_ttl: "720h"
    nonce_ttl: "10m"
`,
			expectedCode: "field unknown_field not found",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			tempDir := t.TempDir()
			configPath := filepath.Join(tempDir, "tenants.yaml")
			if err := os.WriteFile(configPath, []byte(testCase.content), 0o600); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			_, loadErr := LoadConfig(configPath)
			if loadErr == nil {
				t.Fatalf("expected load to fail")
			}
			if !errors.Is(loadErr, ErrInvalidTenantConfig) {
				t.Fatalf("expected ErrInvalidTenantConfig, got %v", loadErr)
			}
			if !containsStableCode(loadErr, testCase.expectedCode) {
				t.Fatalf("expected error to contain code %s, got %v", testCase.expectedCode, loadErr)
			}
		})
	}
}

func TestBuildTenantErrors(t *testing.T) {
	testCases := []struct {
		name    string
		tenant  FileTenant
		wantErr string
	}{
		{
			name: "missing google client",
			tenant: FileTenant{
				ID:                "demo",
				DisplayName:       "Demo",
				Hosts:             []string{"demo.localhost"},
				CookieDomain:      "demo.localhost",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
				AllowInsecureHTTP: true,
			},
			wantErr: errorCodeInvalidGoogleID,
		},
		{
			name: "invalid session ttl",
			tenant: FileTenant{
				ID:                "demo",
				DisplayName:       "Demo",
				Hosts:             []string{"demo.localhost"},
				GoogleWebClientID: "client",
				CookieDomain:      "demo.localhost",
				SessionTTL:        "-1m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
			},
			wantErr: errorCodeInvalidSessionTTL,
		},
		{
			name: "invalid nonce ttl",
			tenant: FileTenant{
				ID:                "demo",
				DisplayName:       "Demo",
				Hosts:             []string{"demo.localhost"},
				GoogleWebClientID: "client",
				CookieDomain:      "demo.localhost",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "-5m",
			},
			wantErr: errorCodeInvalidNonceTTL,
		},
		{
			name: "duplicate hosts",
			tenant: FileTenant{
				ID:                "demo",
				DisplayName:       "Demo",
				Hosts:             []string{"demo.localhost", "DEMO.LOCALHOST"},
				GoogleWebClientID: "client",
				CookieDomain:      "demo.localhost",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
			},
			wantErr: errorCodeDuplicateHost,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadConfigFromDocument(FileDocument{Tenants: []FileTenant{tc.tenant}})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error %s, got %v", tc.wantErr, err)
			}
		})
	}

	invalidHostConfig := FileDocument{
		Tenants: []FileTenant{
			{
				ID:                "demo",
				DisplayName:       "Demo",
				Hosts:             []string{"demo.localhost", "demo.example.com"},
				GoogleWebClientID: "client",
				CookieDomain:      "demo.localhost",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
			},
			{
				ID:                "prod",
				DisplayName:       "Prod",
				Hosts:             []string{"demo.localhost"},
				GoogleWebClientID: "prod-client",
				CookieDomain:      "prod.localhost",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
			},
		},
	}
	_, err := LoadConfigFromDocument(invalidHostConfig)
	if err == nil || !strings.Contains(err.Error(), errorCodeDuplicateHost) {
		t.Fatalf("expected duplicate host error, got %v", err)
	}
}

func TestLoadConfigExpandsEnvVars(t *testing.T) {
	t.Setenv("TENANT_COOKIE_DOMAIN", ".example.com")
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "tenants.yaml")
	configYAML := []byte(`tenants:
  - id: "demo"
    display_name: ""
    hosts: ["demo.localhost"]
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    cookie_domain: "${TENANT_COOKIE_DOMAIN}"
    session_ttl: "30m"
    refresh_ttl: "720h"
    nonce_ttl: "10m"
`)
	if writeErr := os.WriteFile(configPath, configYAML, 0o600); writeErr != nil {
		t.Fatalf("failed to write config: %v", writeErr)
	}

	config, loadErr := LoadConfig(configPath)
	if loadErr != nil {
		t.Fatalf("expected config to load, got error: %v", loadErr)
	}

	tenant, exists := config.TenantByID("demo")
	if !exists {
		t.Fatalf("expected demo tenant to exist")
	}
	if tenant.CookieDomain() != ".example.com" {
		t.Fatalf("expected cookie domain from env, got %s", tenant.CookieDomain())
	}
	if tenant.DisplayName() != "demo" {
		t.Fatalf("expected fallback display name, got %s", tenant.DisplayName())
	}
}

func TestLoadConfigTrimsQuotedPath(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "quoted.yaml")
	configYAML := []byte(`tenants:
  - id: "demo"
    display_name: "Demo"
    hosts: ["demo.localhost"]
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    cookie_domain: "demo.localhost"
    session_ttl: "30m"
    refresh_ttl: "720h"
    nonce_ttl: "10m"
`)
	if writeErr := os.WriteFile(configPath, configYAML, 0o600); writeErr != nil {
		t.Fatalf("failed to write config: %v", writeErr)
	}

	if _, loadErr := LoadConfig(fmt.Sprintf("  \"%s\"  ", configPath)); loadErr != nil {
		t.Fatalf("expected config to load with quoted path, got %v", loadErr)
	}
}

func TestConfigTenantsReturnsCopy(t *testing.T) {
	config := Config{
		tenants: []Tenant{
			{id: "demo"},
		},
	}
	list := config.Tenants()
	if len(list) != 1 || list[0].ID() != "demo" {
		t.Fatalf("expected one tenant copy")
	}
	list[0].id = "mutated"
	if config.tenants[0].ID() != "demo" {
		t.Fatalf("expected original slice to remain unchanged")
	}
}

func sameStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func containsStableCode(err error, code string) bool {
	return strings.Contains(err.Error(), code)
}

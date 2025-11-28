package tenants

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfigSuccess(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "tenants.json")
	configJSON := []byte(`{
		"tenants": [
			{
				"id": "demo",
				"display_name": "Demo Tenant",
				"hosts": ["demo.localhost", "demo.example.com"],
				"google_web_client_id": "demo-client.apps.googleusercontent.com",
				"cookie_domain": "demo.example.com",
				"session_ttl": "30m",
				"refresh_ttl": "720h",
				"nonce_ttl": "10m",
				"allow_insecure_http": true
			},
			{
				"id": "prod",
				"display_name": "Production Tenant",
				"hosts": ["app.example.com", "app.mprlab.com"],
				"google_web_client_id": "prod-client.apps.googleusercontent.com",
				"cookie_domain": ".example.com",
				"session_ttl": "15m",
				"refresh_ttl": "1440h",
				"nonce_ttl": "5m"
			}
		]
	}`)
	if writeErr := os.WriteFile(configPath, configJSON, 0o600); writeErr != nil {
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
			content: `{
				"tenants": [
					{
						"id": "",
						"display_name": "Demo Tenant",
						"hosts": ["demo.localhost"],
						"google_web_client_id": "demo-client.apps.googleusercontent.com",
						"cookie_domain": "demo.example.com",
						"session_ttl": "30m",
						"refresh_ttl": "720h",
						"nonce_ttl": "10m"
					}
				]
			}`,
			expectedCode: "tenant.invalid_id",
		},
		{
			name: "duplicate_host",
			content: `{
				"tenants": [
					{
						"id": "demo",
						"display_name": "Demo Tenant",
						"hosts": ["demo.example.com"],
						"google_web_client_id": "demo-client.apps.googleusercontent.com",
						"cookie_domain": "demo.example.com",
						"session_ttl": "30m",
						"refresh_ttl": "720h",
						"nonce_ttl": "10m"
					},
					{
						"id": "prod",
						"display_name": "Production Tenant",
						"hosts": ["demo.example.com"],
						"google_web_client_id": "prod-client.apps.googleusercontent.com",
						"cookie_domain": ".example.com",
						"session_ttl": "15m",
						"refresh_ttl": "1440h",
						"nonce_ttl": "5m"
					}
				]
			}`,
			expectedCode: "tenant.duplicate_host",
		},
		{
			name: "invalid_session_ttl",
			content: `{
				"tenants": [
					{
						"id": "demo",
						"display_name": "Demo Tenant",
						"hosts": ["demo.example.com"],
						"google_web_client_id": "demo-client.apps.googleusercontent.com",
						"cookie_domain": "demo.example.com",
						"session_ttl": "0",
						"refresh_ttl": "720h",
						"nonce_ttl": "10m"
					}
				]
			}`,
			expectedCode: "tenant.invalid_session_ttl",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			tempDir := t.TempDir()
			configPath := filepath.Join(tempDir, "tenants.json")
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

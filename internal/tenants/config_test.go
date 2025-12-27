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

const (
	testGoogleWebClientID = "client.apps.googleusercontent.com"
	testSessionTTL        = "30m"
	testRefreshTTL        = "720h"
)

func TestLoadConfigSuccess(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "tenants.yaml")
	configYAML := []byte(`tenants:
  - id: "demo"
    display_name: "Demo Tenant"
    allowed_hosts:
      - "https://demo.localhost"
      - "https://demo.example.com"
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    jwt_signing_key: "demo-tenant-key"
    cookie_domain: "demo.example.com"
    session_cookie_name: "app_session_demo"
    refresh_cookie_name: "app_refresh_demo"
    session_ttl: "30m"
    refresh_ttl: "720h"
    nonce_ttl: "10m"
    allow_insecure_http: "true"

  - id: "prod"
    display_name: "Production Tenant"
    allowed_hosts:
      - "https://app.example.com"
      - "https://app.mprlab.com"
    google_web_client_id: "prod-client.apps.googleusercontent.com"
    jwt_signing_key: "prod-tenant-key"
    cookie_domain: ".example.com"
    session_cookie_name: "app_session_prod"
    refresh_cookie_name: "app_refresh_prod"
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
	if string(demoTenant.SigningKey()) != "demo-tenant-key" {
		t.Fatalf("unexpected signing key: %s", demoTenant.SigningKey())
	}
	if !sameStringSlices(demoTenant.Hosts(), []string{"https://demo.localhost", "https://demo.example.com"}) {
		t.Fatalf("unexpected allowed_hosts: %#v", demoTenant.Hosts())
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
	if string(prodTenant.SigningKey()) != "prod-tenant-key" {
		t.Fatalf("expected prod signing key to be set")
	}
}

func TestLoadConfigAllowsHostOnlyCookieDomain(t *testing.T) {
	document := FileDocument{
		Tenants: []FileTenant{
			{
				ID:                "host-only",
				DisplayName:       "Host Only",
				AllowedHosts:      []string{"http://localhost"},
				GoogleWebClientID: "demo-client.apps.googleusercontent.com",
				JWTSigningKey:     "host-only-key",
				CookieDomain:      "",
				SessionCookieName: "app_session_host",
				RefreshCookieName: "app_refresh_host",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				AllowInsecureHTTP: true,
			},
		},
	}

	config, err := LoadConfigFromDocument(document)
	if err != nil {
		t.Fatalf("expected host-only cookie domain to load, got %v", err)
	}
	tenant, exists := config.TenantByID("host-only")
	if !exists {
		t.Fatalf("expected tenant to exist")
	}
	if tenant.CookieDomain() != "" {
		t.Fatalf("expected empty cookie domain, got %s", tenant.CookieDomain())
	}
}

func TestLoadConfigSupportsCustomCookieNames(t *testing.T) {
	document := FileDocument{
		Tenants: []FileTenant{
			{
				ID:                "custom",
				DisplayName:       "Custom",
				AllowedHosts:      []string{"https://custom.localhost"},
				GoogleWebClientID: "custom-client.apps.googleusercontent.com",
				JWTSigningKey:     "custom-key",
				CookieDomain:      "",
				SessionCookieName: "app_session",
				RefreshCookieName: "app_refresh",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				AllowInsecureHTTP: true,
			},
		},
	}
	config, err := LoadConfigFromDocument(document)
	if err != nil {
		t.Fatalf("expected config to load, got %v", err)
	}
	tenant, exists := config.TenantByID("custom")
	if !exists {
		t.Fatalf("tenant not found")
	}
	if tenant.SessionCookieName() != "app_session" {
		t.Fatalf("expected session cookie override, got %s", tenant.SessionCookieName())
	}
	if tenant.RefreshCookieName() != "app_refresh" {
		t.Fatalf("expected refresh cookie override, got %s", tenant.RefreshCookieName())
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
    allowed_hosts: ["https://demo.localhost"]
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    jwt_signing_key: "signing"
    cookie_domain: "demo.example.com"
    session_cookie_name: "app_session_demo"
    refresh_cookie_name: "app_refresh_demo"
    session_ttl: "30m"
    refresh_ttl: "720h"
    nonce_ttl: "10m"
`,
			expectedCode: "tenant.invalid_id",
		},
		{
			name: "invalid_session_ttl",
			content: `tenants:
  - id: "demo"
    display_name: "Demo Tenant"
    allowed_hosts: ["https://demo.example.com"]
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    jwt_signing_key: "signing"
    cookie_domain: "demo.example.com"
    session_cookie_name: "app_session_demo"
    refresh_cookie_name: "app_refresh_demo"
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
    allowed_hosts: ["https://demo.example.com"]
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    jwt_signing_key: "signing"
    cookie_domain: "demo.example.com"
    session_cookie_name: "app_session_demo"
    refresh_cookie_name: "app_refresh_demo"
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

func TestConfigAllowsSharedOrigins(t *testing.T) {
	document := FileDocument{
		Tenants: []FileTenant{
			{
				ID:                "demo",
				DisplayName:       "Demo",
				AllowedHosts:      []string{"https://shared.localhost", "http://localhost:8000"},
				GoogleWebClientID: "demo-client.apps.googleusercontent.com",
				JWTSigningKey:     "demo-key",
				CookieDomain:      "",
				SessionCookieName: "app_session_demo",
				RefreshCookieName: "app_refresh_demo",
				SessionTTL:        "30m",
				RefreshTTL:        "720h",
			},
			{
				ID:                "admin",
				DisplayName:       "Admin",
				AllowedHosts:      []string{"https://shared.localhost", "http://localhost:4173"},
				GoogleWebClientID: "admin-client.apps.googleusercontent.com",
				JWTSigningKey:     "admin-key",
				CookieDomain:      "",
				SessionCookieName: "app_session_admin",
				RefreshCookieName: "app_refresh_admin",
				SessionTTL:        "30m",
				RefreshTTL:        "720h",
			},
		},
	}

	config, err := LoadConfigFromDocument(document)
	if err != nil {
		t.Fatalf("expected shared host config to load, got %v", err)
	}
	if tenant, ok := config.OriginOwner("http://localhost:8000"); !ok || tenant != "demo" {
		t.Fatalf("expected origin to resolve to demo, got %s", tenant)
	}
	if tenant, ok := config.OriginOwner("http://localhost:4173"); !ok || tenant != "admin" {
		t.Fatalf("expected origin to resolve to admin, got %s", tenant)
	}
	if tenant, ok := config.OriginOwner("https://shared.localhost"); !ok || tenant != "demo" {
		t.Fatalf("expected shared origin to resolve to demo, got %s", tenant)
	}
}

func TestLoadConfigRejectsOverlappingCookieNames(testContext *testing.T) {
	const (
		alphaTenantID           = "alpha"
		betaTenantID            = "beta"
		alphaSigningKey         = "alpha-key"
		betaSigningKey          = "beta-key"
		alphaHost               = "https://alpha.example.com"
		betaHost                = "https://beta.example.com"
		sharedHost              = "https://shared.localhost"
		sharedSessionCookieName = "app_session_shared"
		sharedRefreshCookieName = "app_refresh_shared"
		alphaSessionCookieName  = "app_session_alpha"
		betaSessionCookieName   = "app_session_beta"
		alphaRefreshCookieName  = "app_refresh_alpha"
		betaRefreshCookieName   = "app_refresh_beta"
		exampleCookieDomain     = ".example.com"
		subdomainCookieDomain   = "beta.example.com"
	)

	testCases := []struct {
		name         string
		document     FileDocument
		expectedCode string
	}{
		{
			name: "shared_host_duplicate_session_cookie",
			document: FileDocument{
				Tenants: []FileTenant{
					buildTestTenant(alphaTenantID, []string{sharedHost}, "", sharedSessionCookieName, alphaRefreshCookieName, alphaSigningKey),
					buildTestTenant(betaTenantID, []string{sharedHost}, "", sharedSessionCookieName, betaRefreshCookieName, betaSigningKey),
				},
			},
			expectedCode: errorCodeDuplicateSessionCookieName,
		},
		{
			name: "overlapping_domain_duplicate_refresh_cookie",
			document: FileDocument{
				Tenants: []FileTenant{
					buildTestTenant(alphaTenantID, []string{alphaHost}, exampleCookieDomain, alphaSessionCookieName, sharedRefreshCookieName, alphaSigningKey),
					buildTestTenant(betaTenantID, []string{betaHost}, subdomainCookieDomain, betaSessionCookieName, sharedRefreshCookieName, betaSigningKey),
				},
			},
			expectedCode: errorCodeDuplicateRefreshCookieName,
		},
		{
			name: "domain_host_overlap_duplicate_session_cookie",
			document: FileDocument{
				Tenants: []FileTenant{
					buildTestTenant(alphaTenantID, []string{alphaHost}, exampleCookieDomain, sharedSessionCookieName, alphaRefreshCookieName, alphaSigningKey),
					buildTestTenant(betaTenantID, []string{betaHost}, "", sharedSessionCookieName, betaRefreshCookieName, betaSigningKey),
				},
			},
			expectedCode: errorCodeDuplicateSessionCookieName,
		},
		{
			name: "shared_host_cross_type_cookie_name",
			document: FileDocument{
				Tenants: []FileTenant{
					buildTestTenant(alphaTenantID, []string{sharedHost}, "", sharedSessionCookieName, alphaRefreshCookieName, alphaSigningKey),
					buildTestTenant(betaTenantID, []string{sharedHost}, "", betaSessionCookieName, sharedSessionCookieName, betaSigningKey),
				},
			},
			expectedCode: errorCodeDuplicateCookieNameCross,
		},
	}

	for testCaseIndex := range testCases {
		testCase := testCases[testCaseIndex]
		testContext.Run(testCase.name, func(subTestContext *testing.T) {
			_, loadErr := LoadConfigFromDocument(testCase.document)
			if loadErr == nil {
				subTestContext.Fatalf("expected config error")
			}
			if !errors.Is(loadErr, ErrInvalidTenantConfig) {
				subTestContext.Fatalf("expected ErrInvalidTenantConfig, got %v", loadErr)
			}
			if !containsStableCode(loadErr, testCase.expectedCode) {
				subTestContext.Fatalf("expected error to contain code %s, got %v", testCase.expectedCode, loadErr)
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
				AllowedHosts:      []string{"https://demo.localhost"},
				JWTSigningKey:     "key",
				CookieDomain:      "demo.localhost",
				SessionCookieName: "app_session_demo",
				RefreshCookieName: "app_refresh_demo",
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
				AllowedHosts:      []string{"https://demo.localhost"},
				GoogleWebClientID: "client",
				JWTSigningKey:     "key",
				CookieDomain:      "demo.localhost",
				SessionCookieName: "app_session_demo",
				RefreshCookieName: "app_refresh_demo",
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
				AllowedHosts:      []string{"https://demo.localhost"},
				GoogleWebClientID: "client",
				JWTSigningKey:     "key",
				CookieDomain:      "demo.localhost",
				SessionCookieName: "app_session_demo",
				RefreshCookieName: "app_refresh_demo",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "-5m",
			},
			wantErr: errorCodeInvalidNonceTTL,
		},
		{
			name: "invalid origin",
			tenant: FileTenant{
				ID:                "demo",
				DisplayName:       "Demo",
				AllowedHosts:      []string{"demo.localhost"},
				GoogleWebClientID: "client",
				JWTSigningKey:     "key",
				CookieDomain:      "demo.localhost",
				SessionCookieName: "app_session_demo",
				RefreshCookieName: "app_refresh_demo",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
			},
			wantErr: errorCodeInvalidOrigin,
		},
		{
			name: "duplicate hosts",
			tenant: FileTenant{
				ID:                "demo",
				DisplayName:       "Demo",
				AllowedHosts:      []string{"https://demo.localhost", "https://DEMO.LOCALHOST"},
				GoogleWebClientID: "client",
				JWTSigningKey:     "key",
				CookieDomain:      "demo.localhost",
				SessionCookieName: "app_session_demo",
				RefreshCookieName: "app_refresh_demo",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
			},
			wantErr: errorCodeDuplicateHost,
		},
		{
			name: "missing signing key",
			tenant: FileTenant{
				ID:                "demo",
				DisplayName:       "Demo",
				AllowedHosts:      []string{"https://demo.localhost"},
				GoogleWebClientID: "client",
				CookieDomain:      "demo.localhost",
				SessionCookieName: "app_session_demo",
				RefreshCookieName: "app_refresh_demo",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
			},
			wantErr: errorCodeMissingSigningKey,
		},
		{
			name: "missing session cookie name",
			tenant: FileTenant{
				ID:                "demo",
				DisplayName:       "Demo",
				AllowedHosts:      []string{"https://demo.localhost"},
				GoogleWebClientID: "client",
				JWTSigningKey:     "key",
				CookieDomain:      "demo.localhost",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
				RefreshCookieName: "app_refresh_demo",
			},
			wantErr: errorCodeMissingSessionCookieName,
		},
		{
			name: "missing refresh cookie name",
			tenant: FileTenant{
				ID:                "demo",
				DisplayName:       "Demo",
				AllowedHosts:      []string{"https://demo.localhost"},
				GoogleWebClientID: "client",
				JWTSigningKey:     "key",
				CookieDomain:      "demo.localhost",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
				SessionCookieName: "app_session_demo",
			},
			wantErr: errorCodeMissingRefreshCookieName,
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

	sharedHostConfig := FileDocument{
		Tenants: []FileTenant{
			{
				ID:                "demo",
				DisplayName:       "Demo",
				AllowedHosts:      []string{"https://demo.localhost", "https://demo.example.com"},
				GoogleWebClientID: "client",
				JWTSigningKey:     "key1",
				CookieDomain:      "demo.localhost",
				SessionCookieName: "app_session_demo",
				RefreshCookieName: "app_refresh_demo",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
			},
			{
				ID:                "prod",
				DisplayName:       "Prod",
				AllowedHosts:      []string{"https://demo.localhost"},
				GoogleWebClientID: "prod-client",
				JWTSigningKey:     "key2",
				CookieDomain:      "prod.localhost",
				SessionCookieName: "app_session_prod",
				RefreshCookieName: "app_refresh_prod",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
			},
		},
	}
	config, err := LoadConfigFromDocument(sharedHostConfig)
	if err != nil {
		t.Fatalf("expected shared host config to load, got %v", err)
	}
	if tenant, ok := config.OriginOwner("https://demo.localhost"); !ok || tenant != "demo" {
		t.Fatalf("expected shared origin to resolve to demo, got %s", tenant)
	}
}

func TestLoadConfigExpandsEnvVars(t *testing.T) {
	t.Setenv("TENANT_COOKIE_DOMAIN", ".example.com")
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "tenants.yaml")
	configYAML := []byte(`tenants:
  - id: "demo"
    display_name: ""
    allowed_hosts: ["https://demo.localhost"]
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    jwt_signing_key: "demo-key"
    cookie_domain: "${TENANT_COOKIE_DOMAIN}"
    session_cookie_name: "app_session_demo"
    refresh_cookie_name: "app_refresh_demo"
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

func TestLoadConfigFromDocumentExpandsEnvVars(t *testing.T) {
	t.Setenv("TENANT_ALLOWED_HOST", "https://env.localhost")
	t.Setenv("TENANT_CLIENT_ID", "env-client.apps.googleusercontent.com")
	t.Setenv("TENANT_SIGNING_KEY", "env-signing-key")
	t.Setenv("TENANT_COOKIE_DOMAIN", ".env.example.com")
	t.Setenv("SESSION_COOKIE_NAME", "env_session_cookie")
	t.Setenv("REFRESH_COOKIE_NAME", "env_refresh_cookie")
	t.Setenv("SESSION_TTL", "45m")
	t.Setenv("REFRESH_TTL", "900h")
	t.Setenv("NONCE_TTL", "6m")

	document := FileDocument{
		Tenants: []FileTenant{
			{
				ID:                "env-demo",
				DisplayName:       "Env Demo",
				AllowedHosts:      []string{"${TENANT_ALLOWED_HOST}"},
				GoogleWebClientID: "$TENANT_CLIENT_ID",
				JWTSigningKey:     "${TENANT_SIGNING_KEY}",
				CookieDomain:      "$TENANT_COOKIE_DOMAIN",
				SessionCookieName: "$SESSION_COOKIE_NAME",
				RefreshCookieName: "${REFRESH_COOKIE_NAME}",
				SessionTTL:        "${SESSION_TTL}",
				RefreshTTL:        "$REFRESH_TTL",
				NonceTTL:          "$NONCE_TTL",
			},
		},
	}

	config, err := LoadConfigFromDocument(document)
	if err != nil {
		t.Fatalf("expected document to load with env vars, got %v", err)
	}
	tenant, ok := config.TenantByID("env-demo")
	if !ok {
		t.Fatalf("expected env-demo tenant to exist")
	}
	if tenant.CookieDomain() != ".env.example.com" {
		t.Fatalf("expected env cookie domain, got %s", tenant.CookieDomain())
	}
	if tenant.GoogleWebClientID() != "env-client.apps.googleusercontent.com" {
		t.Fatalf("expected env client id, got %s", tenant.GoogleWebClientID())
	}
	if string(tenant.SigningKey()) != "env-signing-key" {
		t.Fatalf("expected env signing key, got %s", tenant.SigningKey())
	}
	if !sameStringSlices(tenant.Hosts(), []string{"https://env.localhost"}) {
		t.Fatalf("expected env host to be expanded, got %#v", tenant.Hosts())
	}
	if tenant.SessionCookieName() != "env_session_cookie" {
		t.Fatalf("expected env session cookie name, got %s", tenant.SessionCookieName())
	}
	if tenant.RefreshCookieName() != "env_refresh_cookie" {
		t.Fatalf("expected env refresh cookie name, got %s", tenant.RefreshCookieName())
	}
	if tenant.SessionTTL() != 45*time.Minute {
		t.Fatalf("expected env session ttl, got %s", tenant.SessionTTL())
	}
	if tenant.RefreshTTL() != 900*time.Hour {
		t.Fatalf("expected env refresh ttl, got %s", tenant.RefreshTTL())
	}
	if tenant.NonceTTL() != 6*time.Minute {
		t.Fatalf("expected env nonce ttl, got %s", tenant.NonceTTL())
	}
}

func TestLoadConfigHandlesMissingEnvVars(t *testing.T) {
	document := FileDocument{
		Tenants: []FileTenant{
			{
				ID:                "demo",
				DisplayName:       "${MISSING_DISPLAY_NAME}",
				AllowedHosts:      []string{"https://demo.localhost"},
				GoogleWebClientID: "demo-client.apps.googleusercontent.com",
				JWTSigningKey:     "demo-key",
				CookieDomain:      "$UNSET_COOKIE_DOMAIN",
				SessionCookieName: "app_session_demo",
				RefreshCookieName: "app_refresh_demo",
				SessionTTL:        "30m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
			},
		},
	}

	config, err := LoadConfigFromDocument(document)
	if err != nil {
		t.Fatalf("expected config to load with missing env vars, got %v", err)
	}
	tenant, ok := config.TenantByID("demo")
	if !ok {
		t.Fatalf("expected demo tenant to exist")
	}
	if tenant.CookieDomain() != "" {
		t.Fatalf("expected missing cookie domain env to expand to empty string, got %s", tenant.CookieDomain())
	}
	if tenant.DisplayName() != "demo" {
		t.Fatalf("expected fallback display name when env var missing, got %s", tenant.DisplayName())
	}
}

func TestLoadConfigTrimsQuotedPath(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "quoted.yaml")
	configYAML := []byte(`tenants:
  - id: "demo"
    display_name: "Demo"
    allowed_hosts: ["https://demo.localhost"]
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    jwt_signing_key: "demo-key"
    cookie_domain: "demo.localhost"
    session_cookie_name: "app_session_demo"
    refresh_cookie_name: "app_refresh_demo"
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

func buildTestTenant(tenantID string, allowedHosts []string, cookieDomain string, sessionCookieName string, refreshCookieName string, signingKey string) FileTenant {
	return FileTenant{
		ID:                tenantID,
		AllowedHosts:      allowedHosts,
		GoogleWebClientID: testGoogleWebClientID,
		JWTSigningKey:     signingKey,
		CookieDomain:      cookieDomain,
		SessionCookieName: sessionCookieName,
		RefreshCookieName: refreshCookieName,
		SessionTTL:        testSessionTTL,
		RefreshTTL:        testRefreshTTL,
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

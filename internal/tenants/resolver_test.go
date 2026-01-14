package tenants

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestResolverResolvesByOrigin(t *testing.T) {
	config := loadTestConfig(t)
	resolver, err := NewResolver(config)
	if err != nil {
		t.Fatalf("resolver creation failed: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://tauth-api.localhost/api", nil)
	request.Header.Set("Origin", "https://demo.example.com")

	tenant, resolveErr := resolver.Resolve(request)
	if resolveErr != nil {
		t.Fatalf("expected resolve success: %v", resolveErr)
	}
	if tenant.ID() != "demo" {
		t.Fatalf("expected demo tenant, got %s", tenant.ID())
	}
}

func TestResolverHeaderOverride(t *testing.T) {
	config := loadTestConfig(t)
	resolver, err := NewResolver(config, WithHeaderOverride(""))
	if err != nil {
		t.Fatalf("resolver creation failed: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://tauth-api.localhost/api", nil)
	request.Header.Set(defaultTenantHeader, "demo")

	tenant, resolveErr := resolver.Resolve(request)
	if resolveErr != nil {
		t.Fatalf("expected resolve success: %v", resolveErr)
	}
	if tenant.ID() != "demo" {
		t.Fatalf("expected demo tenant via override, got %s", tenant.ID())
	}
}

func TestResolverHeaderOverrideMatchesOrigin(testingHandle *testing.T) {
	config := loadTestConfig(testingHandle)
	resolver, err := NewResolver(config, WithHeaderOverride(""))
	if err != nil {
		testingHandle.Fatalf("resolver creation failed: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://tauth-api.localhost/api", nil)
	request.Header.Set("Origin", "https://demo.example.com")
	request.Header.Set(defaultTenantHeader, "demo")

	tenant, resolveErr := resolver.Resolve(request)
	if resolveErr != nil {
		testingHandle.Fatalf("expected resolve success: %v", resolveErr)
	}
	if tenant.ID() != "demo" {
		testingHandle.Fatalf("expected demo tenant via override, got %s", tenant.ID())
	}
}

func TestResolverHeaderOverrideRejectsMismatchedOrigin(testingHandle *testing.T) {
	config := loadTestConfig(testingHandle)
	resolver, err := NewResolver(config, WithHeaderOverride(""))
	if err != nil {
		testingHandle.Fatalf("resolver creation failed: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://tauth-api.localhost/api", nil)
	request.Header.Set("Origin", "https://demo.example.com")
	request.Header.Set(defaultTenantHeader, "prod")

	_, resolveErr := resolver.Resolve(request)
	if resolveErr == nil {
		testingHandle.Fatalf("expected resolve error for mismatched header override")
	}
	if !errors.Is(resolveErr, ErrTenantNotFound) {
		testingHandle.Fatalf("expected ErrTenantNotFound, got %v", resolveErr)
	}
	if !strings.Contains(resolveErr.Error(), errorCodeOverrideMismatch) {
		testingHandle.Fatalf("expected override mismatch error, got %v", resolveErr)
	}
}

func TestResolverUnknownOrigin(t *testing.T) {
	config := loadTestConfig(t)
	resolver, err := NewResolver(config)
	if err != nil {
		t.Fatalf("resolver creation failed: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://tauth-api.localhost/api", nil)
	request.Header.Set("Origin", "https://unknown.example.com")

	_, resolveErr := resolver.Resolve(request)
	if !errors.Is(resolveErr, ErrTenantNotFound) {
		t.Fatalf("expected ErrTenantNotFound, got %v", resolveErr)
	}
}

func TestResolverResolvesIPv6Origin(t *testing.T) {
	config := loadTestConfig(t)
	resolver, err := NewResolver(config)
	if err != nil {
		t.Fatalf("resolver creation failed: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://tauth-api.localhost/api", nil)
	request.Header.Set("Origin", "https://[2001:db8::1]")

	tenant, resolveErr := resolver.Resolve(request)
	if resolveErr != nil {
		t.Fatalf("expected resolve success for ipv6 host: %v", resolveErr)
	}
	if tenant.ID() != "demo" {
		t.Fatalf("expected demo tenant for ipv6 host, got %s", tenant.ID())
	}
}

func TestResolverResolvesOriginWithPort(t *testing.T) {
	config := loadTestConfig(t)
	resolver, err := NewResolver(config)
	if err != nil {
		t.Fatalf("resolver creation failed: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://tauth-api.localhost/api", nil)
	request.Header.Set("Origin", "https://demo.example.com:8443")

	tenant, resolveErr := resolver.Resolve(request)
	if resolveErr != nil {
		t.Fatalf("expected resolve success: %v", resolveErr)
	}
	if tenant.ID() != "demo" {
		t.Fatalf("expected demo tenant, got %s", tenant.ID())
	}
}

func TestResolverRejectsInvalidOverride(t *testing.T) {
	config := loadTestConfig(t)
	resolver, err := NewResolver(config, WithHeaderOverride(""))
	if err != nil {
		t.Fatalf("resolver creation failed: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://tauth-api.localhost/api", nil)
	request.Header.Set(defaultTenantHeader, "missing")

	_, resolveErr := resolver.Resolve(request)
	if !errors.Is(resolveErr, ErrTenantNotFound) {
		t.Fatalf("expected ErrTenantNotFound for invalid override, got %v", resolveErr)
	}
}

func TestResolverHeaderOverrideAcceptsOrigin(t *testing.T) {
	config := loadConfigWithOrigins(t)
	resolver, err := NewResolver(config, WithHeaderOverride(""))
	if err != nil {
		t.Fatalf("resolver creation failed: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://tauth-api.localhost/api", nil)
	request.Header.Set(defaultTenantHeader, "http://localhost:8000")

	tenant, resolveErr := resolver.Resolve(request)
	if resolveErr != nil {
		t.Fatalf("expected resolve success with origin override: %v", resolveErr)
	}
	if tenant.ID() != "notes" {
		t.Fatalf("expected notes tenant via origin override, got %s", tenant.ID())
	}
}

func TestResolverHeaderOverrideRejectsUnknownOrigin(t *testing.T) {
	config := loadConfigWithOrigins(t)
	resolver, err := NewResolver(config, WithHeaderOverride(""))
	if err != nil {
		t.Fatalf("resolver creation failed: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://tauth-api.localhost/api", nil)
	request.Header.Set(defaultTenantHeader, "http://unknown-origin.localhost")

	if _, resolveErr := resolver.Resolve(request); resolveErr == nil {
		t.Fatalf("expected resolve to fail for unknown origin override")
	}
}

func TestResolverRequiresHeaderWhenOriginHostShared(t *testing.T) {
	config := loadConfigWithSharedHost(t)

	resolverWithoutHeader, err := NewResolver(config)
	if err != nil {
		t.Fatalf("resolver creation failed: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://tauth-api.localhost/api", nil)
	request.Header.Set("Origin", "https://shared.localhost")
	if _, resolveErr := resolverWithoutHeader.Resolve(request); resolveErr == nil || !strings.Contains(resolveErr.Error(), errorCodeAmbiguousOrigin) {
		t.Fatalf("expected ambiguous origin error when header override disabled")
	}

	resolver, err := NewResolver(config, WithHeaderOverride(""))
	if err != nil {
		t.Fatalf("resolver creation failed: %v", err)
	}
	if _, err := resolver.Resolve(request); err == nil {
		t.Fatalf("expected resolve to fail when header missing for shared host")
	}
	request.Header.Set(defaultTenantHeader, "admin")
	tenant, err := resolver.Resolve(request)
	if err != nil {
		t.Fatalf("expected resolve success with header, got %v", err)
	}
	if tenant.ID() != "admin" {
		t.Fatalf("expected admin tenant via header, got %s", tenant.ID())
	}
}

func TestResolverOverrideRejectsUnknownOrigin(testingHandle *testing.T) {
	config := loadTestConfig(testingHandle)
	resolver, err := NewResolver(config, WithHeaderOverride(""))
	if err != nil {
		testingHandle.Fatalf("resolver creation failed: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://tauth-api.localhost/api", nil)
	request.Header.Set("Origin", "http://unknown.localhost")
	request.Header.Set(defaultTenantHeader, "demo")

	_, resolveErr := resolver.Resolve(request)
	if resolveErr == nil {
		testingHandle.Fatalf("expected resolve error for unknown origin")
	}
	if !errors.Is(resolveErr, ErrTenantNotFound) {
		testingHandle.Fatalf("expected ErrTenantNotFound, got %v", resolveErr)
	}
	if !strings.Contains(resolveErr.Error(), errorCodeUnknownOrigin) {
		testingHandle.Fatalf("expected unknown origin error, got %v", resolveErr)
	}
}

func TestTenantMiddlewareSetsContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	config := loadTestConfig(t)
	resolver, err := NewResolver(config)
	if err != nil {
		t.Fatalf("resolver creation failed: %v", err)
	}
	router := gin.New()
	router.Use(TenantMiddleware(resolver, 0))
	var capturedID TenantID
	router.GET("/whoami", func(context *gin.Context) {
		tenant, ok := TenantFromContext(context)
		if !ok {
			t.Fatalf("tenant not present in context")
		}
		capturedID = tenant.ID()
		context.Status(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodGet, "/whoami", nil)
	request.Header.Set("Origin", "https://demo.example.com")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", response.Code)
	}
	if capturedID != "demo" {
		t.Fatalf("expected demo tenant, got %s", capturedID)
	}
}

func TestTenantMiddlewareRejectsUnknownOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	config := loadTestConfig(t)
	resolver, err := NewResolver(config)
	if err != nil {
		t.Fatalf("resolver creation failed: %v", err)
	}
	router := gin.New()
	router.Use(TenantMiddleware(resolver, http.StatusTeapot))
	router.GET("/ping", func(context *gin.Context) {
		context.Status(http.StatusOK)
	})

	request := httptest.NewRequest(http.MethodGet, "/ping", nil)
	request.Header.Set("Origin", "https://unknown.example.com")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusTeapot {
		t.Fatalf("expected rejection status 418, got %d", response.Code)
	}
	var payload map[string]string
	decodeErr := json.Unmarshal(response.Body.Bytes(), &payload)
	if decodeErr != nil {
		t.Fatalf("failed to decode response payload: %v", decodeErr)
	}
	if payload[errorPayloadKeyCode] != errorCodeUnknownOrigin {
		t.Fatalf("expected error code %s, got %s", errorCodeUnknownOrigin, payload[errorPayloadKeyCode])
	}
	if payload[errorPayloadKeyOrigin] != "https://unknown.example.com" {
		t.Fatalf("expected origin echo, got %s", payload[errorPayloadKeyOrigin])
	}
	if strings.TrimSpace(payload[errorPayloadKeyMessage]) == "" {
		t.Fatalf("expected error message")
	}
	if strings.TrimSpace(payload[errorPayloadKeyHint]) == "" {
		t.Fatalf("expected error hint")
	}
}

func TestResolverUsesOriginForAmbiguousHosts(t *testing.T) {
	config := loadConfigWithOrigins(t)
	resolver, err := NewResolver(config)
	if err != nil {
		t.Fatalf("resolver creation failed: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://shared.localhost/auth/nonce", nil)
	request.Header.Set("Origin", "http://localhost:8000")

	tenant, resolveErr := resolver.Resolve(request)
	if resolveErr != nil {
		t.Fatalf("expected resolve success via origin, got %v", resolveErr)
	}
	if tenant.ID() != "notes" {
		t.Fatalf("expected notes tenant, got %s", tenant.ID())
	}

	second := httptest.NewRequest(http.MethodGet, "http://shared.localhost/auth/nonce", nil)
	second.Header.Set("Origin", "http://localhost:4173")

	secondTenant, secondErr := resolver.Resolve(second)
	if secondErr != nil {
		t.Fatalf("expected resolve success for second origin, got %v", secondErr)
	}
	if secondTenant.ID() != "mpr-sites" {
		t.Fatalf("expected mpr-sites tenant, got %s", secondTenant.ID())
	}
}

func TestResolverRejectsMissingOrUnknownOrigin(t *testing.T) {
	config := loadConfigWithOrigins(t)
	resolver, err := NewResolver(config)
	if err != nil {
		t.Fatalf("resolver creation failed: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://shared.localhost/auth/nonce", nil)

	if _, resolveErr := resolver.Resolve(request); resolveErr == nil {
		t.Fatalf("expected resolve to fail when origin missing")
	}

	request.Header.Set("Origin", "http://unknown.localhost")
	if _, resolveErr := resolver.Resolve(request); resolveErr == nil {
		t.Fatalf("expected resolve to fail for unknown origin")
	}
}

func TestResolverRejectsMissingOriginWithoutOverride(testingHandle *testing.T) {
	config := loadConfigWithOrigins(testingHandle)
	resolver, err := NewResolver(config, WithHeaderOverride(""))
	if err != nil {
		testingHandle.Fatalf("resolver creation failed: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://shared.localhost/auth/nonce", nil)

	_, resolveErr := resolver.Resolve(request)
	if resolveErr == nil {
		testingHandle.Fatalf("expected resolve to fail without origin and override")
	}
	if !strings.Contains(resolveErr.Error(), errorCodeMissingHeaderOverride) {
		testingHandle.Fatalf("expected missing header override error, got %v", resolveErr)
	}
}
func TestResolverOriginOnlyRouting(testingHandle *testing.T) {
	config := loadConfigWithOriginOnlyHosts(testingHandle)
	resolver, err := NewResolver(config)
	if err != nil {
		testingHandle.Fatalf("resolver creation failed: %v", err)
	}

	testCases := []struct {
		name             string
		origin           string
		expectedTenantID string
		expectErr        bool
	}{
		{
			name:             "ps_origin",
			origin:           "https://ps.localhost",
			expectedTenantID: "ps",
		},
		{
			name:             "loopaware_origin",
			origin:           "https://loopaware.localhost",
			expectedTenantID: "loopaware",
		},
		{
			name:      "unknown_origin",
			origin:    "https://unknown.localhost",
			expectErr: true,
		},
	}

	for _, testCase := range testCases {
		testingHandle.Run(testCase.name, func(testingHandle *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://tauth-api.localhost/auth/nonce", nil)
			if testCase.origin != "" {
				request.Header.Set("Origin", testCase.origin)
			}

			tenant, resolveErr := resolver.Resolve(request)
			if testCase.expectErr {
				if resolveErr == nil {
					testingHandle.Fatalf("expected resolve error")
				}
				return
			}
			if resolveErr != nil {
				testingHandle.Fatalf("expected resolve success, got %v", resolveErr)
			}
			if tenant.ID() != TenantID(testCase.expectedTenantID) {
				testingHandle.Fatalf("expected %s tenant, got %s", testCase.expectedTenantID, tenant.ID())
			}
		})
	}
}

func TestResolverOriginOnlyHeaderOverride(testingHandle *testing.T) {
	config := loadConfigWithOriginOnlyHosts(testingHandle)
	resolver, err := NewResolver(config, WithHeaderOverride(""))
	if err != nil {
		testingHandle.Fatalf("resolver creation failed: %v", err)
	}

	testCases := []struct {
		name             string
		override         string
		expectedTenantID string
		expectErr        bool
	}{
		{
			name:             "header_ps",
			override:         "ps",
			expectedTenantID: "ps",
		},
		{
			name:      "header_unknown",
			override:  "missing",
			expectErr: true,
		},
	}

	for _, testCase := range testCases {
		testingHandle.Run(testCase.name, func(testingHandle *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://tauth-api.localhost/auth/nonce", nil)
			request.Header.Set(defaultTenantHeader, testCase.override)

			tenant, resolveErr := resolver.Resolve(request)
			if testCase.expectErr {
				if resolveErr == nil {
					testingHandle.Fatalf("expected resolve error")
				}
				return
			}
			if resolveErr != nil {
				testingHandle.Fatalf("expected resolve success, got %v", resolveErr)
			}
			if tenant.ID() != TenantID(testCase.expectedTenantID) {
				testingHandle.Fatalf("expected %s tenant, got %s", testCase.expectedTenantID, tenant.ID())
			}
		})
	}
}

func TestResolverOriginOnlyAmbiguousOriginRequiresHeader(testingHandle *testing.T) {
	config := loadConfigWithOriginOnlySharedOrigin(testingHandle)
	resolver, err := NewResolver(config)
	if err != nil {
		testingHandle.Fatalf("resolver creation failed: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://tauth-api.localhost/auth/nonce", nil)
	request.Header.Set("Origin", "https://pinguin.localhost")

	if _, resolveErr := resolver.Resolve(request); resolveErr == nil || !strings.Contains(resolveErr.Error(), errorCodeAmbiguousOrigin) {
		testingHandle.Fatalf("expected ambiguous origin error, got %v", resolveErr)
	}

	headerResolver, headerErr := NewResolver(config, WithHeaderOverride(""))
	if headerErr != nil {
		testingHandle.Fatalf("resolver creation failed: %v", headerErr)
	}
	if _, resolveErr := headerResolver.Resolve(request); resolveErr == nil || !strings.Contains(resolveErr.Error(), errorCodeMissingHeaderOverride) {
		testingHandle.Fatalf("expected missing header override error, got %v", resolveErr)
	}

	request.Header.Set(defaultTenantHeader, "notes")
	tenant, resolveErr := headerResolver.Resolve(request)
	if resolveErr != nil {
		testingHandle.Fatalf("expected resolve success, got %v", resolveErr)
	}
	if tenant.ID() != "notes" {
		testingHandle.Fatalf("expected notes tenant, got %s", tenant.ID())
	}
}

func loadTestConfig(t *testing.T) Config {
	t.Helper()
	content := []byte(`{
		"tenants": [
			{
				"id": "demo",
				"display_name": "Demo",
				"tenant_origins": ["https://demo.example.com", "https://demo.example.com:8443", "https://demo.localhost", "https://[2001:db8::1]"],
				"google_web_client_id": "demo-client.apps.googleusercontent.com",
				"jwt_signing_key": "demo-key",
				"cookie_domain": "demo.example.com",
				"session_cookie_name": "app_session_demo",
				"refresh_cookie_name": "app_refresh_demo",
				"session_ttl": "30m",
				"refresh_ttl": "720h",
				"nonce_ttl": "10m"
			},
			{
				"id": "prod",
				"display_name": "Prod",
				"tenant_origins": ["https://prod.example.com"],
				"google_web_client_id": "prod-client.apps.googleusercontent.com",
				"jwt_signing_key": "prod-key",
				"cookie_domain": ".example.com",
				"session_cookie_name": "app_session_prod",
				"refresh_cookie_name": "app_refresh_prod",
				"session_ttl": "15m",
				"refresh_ttl": "1440h",
				"nonce_ttl": "5m"
			}
		]
	}`)
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "tenants.yaml")
	if writeErr := os.WriteFile(configPath, content, 0o600); writeErr != nil {
		t.Fatalf("failed to write config: %v", writeErr)
	}
	config, loadErr := LoadConfig(configPath)
	if loadErr != nil {
		t.Fatalf("failed to load config: %v", loadErr)
	}
	return config
}

func loadConfigWithOriginOnlyHosts(testingHandle *testing.T) Config {
	testingHandle.Helper()
	content := []byte(`{
		"tenants": [
			{
				"id": "ps",
				"display_name": "PoodleScanner",
				"tenant_origins": ["https://ps.localhost"],
				"google_web_client_id": "ps-client.apps.googleusercontent.com",
				"jwt_signing_key": "ps-key",
				"cookie_domain": "",
				"session_cookie_name": "app_session_ps",
				"refresh_cookie_name": "app_refresh_ps",
				"session_ttl": "30m",
				"refresh_ttl": "720h",
				"nonce_ttl": "10m"
			},
			{
				"id": "loopaware",
				"display_name": "Loopaware",
				"tenant_origins": ["https://loopaware.localhost"],
				"google_web_client_id": "loopaware-client.apps.googleusercontent.com",
				"jwt_signing_key": "loopaware-key",
				"cookie_domain": "",
				"session_cookie_name": "app_session_loopaware",
				"refresh_cookie_name": "app_refresh_loopaware",
				"session_ttl": "30m",
				"refresh_ttl": "720h",
				"nonce_ttl": "10m"
			}
		]
	}`)
	tempDir := testingHandle.TempDir()
	configPath := filepath.Join(tempDir, "tenants.yaml")
	if writeErr := os.WriteFile(configPath, content, 0o600); writeErr != nil {
		testingHandle.Fatalf("failed to write config: %v", writeErr)
	}
	config, loadErr := LoadConfig(configPath)
	if loadErr != nil {
		testingHandle.Fatalf("failed to load config: %v", loadErr)
	}
	return config
}

func loadConfigWithOriginOnlySharedOrigin(testingHandle *testing.T) Config {
	testingHandle.Helper()
	content := []byte(`{
		"tenants": [
			{
				"id": "notes",
				"display_name": "Gravity Notes",
				"tenant_origins": ["https://pinguin.localhost"],
				"google_web_client_id": "notes-client.apps.googleusercontent.com",
				"jwt_signing_key": "notes-key",
				"cookie_domain": "",
				"session_cookie_name": "app_session_notes",
				"refresh_cookie_name": "app_refresh_notes",
				"session_ttl": "30m",
				"refresh_ttl": "720h",
				"nonce_ttl": "10m"
			},
			{
				"id": "mpr-sites",
				"display_name": "MPR Sites",
				"tenant_origins": ["https://pinguin.localhost"],
				"google_web_client_id": "mpr-client.apps.googleusercontent.com",
				"jwt_signing_key": "mpr-key",
				"cookie_domain": "",
				"session_cookie_name": "app_session_mpr",
				"refresh_cookie_name": "app_refresh_mpr",
				"session_ttl": "30m",
				"refresh_ttl": "720h",
				"nonce_ttl": "10m"
			}
		]
	}`)
	tempDir := testingHandle.TempDir()
	configPath := filepath.Join(tempDir, "tenants.yaml")
	if writeErr := os.WriteFile(configPath, content, 0o600); writeErr != nil {
		testingHandle.Fatalf("failed to write config: %v", writeErr)
	}
	config, loadErr := LoadConfig(configPath)
	if loadErr != nil {
		testingHandle.Fatalf("failed to load config: %v", loadErr)
	}
	return config
}

func loadConfigWithSharedHost(t *testing.T) Config {
	t.Helper()
	content := []byte(`{
		"tenants": [
			{
				"id": "demo",
				"display_name": "Demo",
				"tenant_origins": ["https://shared.localhost"],
				"google_web_client_id": "demo-client.apps.googleusercontent.com",
				"jwt_signing_key": "demo-key",
				"cookie_domain": "",
				"session_cookie_name": "app_session_demo",
				"refresh_cookie_name": "app_refresh_demo",
				"session_ttl": "30m",
				"refresh_ttl": "720h"
			},
			{
				"id": "admin",
				"display_name": "Admin",
				"tenant_origins": ["https://shared.localhost"],
				"google_web_client_id": "admin-client.apps.googleusercontent.com",
				"jwt_signing_key": "admin-key",
				"cookie_domain": "",
				"session_cookie_name": "app_session_admin",
				"refresh_cookie_name": "app_refresh_admin",
				"session_ttl": "30m",
				"refresh_ttl": "720h"
			}
		]
	}`)
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "tenants.yaml")
	if writeErr := os.WriteFile(configPath, content, 0o600); writeErr != nil {
		t.Fatalf("failed to write config: %v", writeErr)
	}
	config, loadErr := LoadConfig(configPath)
	if loadErr != nil {
		t.Fatalf("failed to load config: %v", loadErr)
	}
	return config
}

func loadConfigWithOrigins(t *testing.T) Config {
	t.Helper()
	content := []byte(`{
		"tenants": [
			{
				"id": "notes",
				"display_name": "Gravity Notes",
				"tenant_origins": ["https://shared.localhost", "http://localhost:8000"],
				"google_web_client_id": "notes-client.apps.googleusercontent.com",
				"jwt_signing_key": "notes-key",
				"cookie_domain": "",
				"session_cookie_name": "app_session_notes",
				"refresh_cookie_name": "app_refresh_notes",
				"session_ttl": "30m",
				"refresh_ttl": "720h",
				"nonce_ttl": "5m"
			},
			{
				"id": "mpr-sites",
				"display_name": "MPR Sites",
				"tenant_origins": ["https://shared.localhost", "http://localhost:4173"],
				"google_web_client_id": "mpr-client.apps.googleusercontent.com",
				"jwt_signing_key": "mpr-key",
				"cookie_domain": "",
				"session_cookie_name": "app_session_mpr",
				"refresh_cookie_name": "app_refresh_mpr",
				"session_ttl": "30m",
				"refresh_ttl": "720h",
				"nonce_ttl": "5m"
			}
		]
	}`)
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "tenants.yaml")
	if writeErr := os.WriteFile(configPath, content, 0o600); writeErr != nil {
		t.Fatalf("failed to write config: %v", writeErr)
	}
	config, loadErr := LoadConfig(configPath)
	if loadErr != nil {
		t.Fatalf("failed to load config: %v", loadErr)
	}
	return config
}

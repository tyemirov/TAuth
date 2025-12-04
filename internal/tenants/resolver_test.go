package tenants

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestResolverResolvesByHost(t *testing.T) {
	config := loadTestConfig(t)
	resolver, err := NewResolver(config)
	if err != nil {
		t.Fatalf("resolver creation failed: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://demo.example.com/api", nil)
	request.Host = "demo.example.com"

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
	request := httptest.NewRequest(http.MethodGet, "http://demo.example.com/api", nil)
	request.Host = "demo.example.com"
	request.Header.Set(defaultTenantHeader, "demo")

	tenant, resolveErr := resolver.Resolve(request)
	if resolveErr != nil {
		t.Fatalf("expected resolve success: %v", resolveErr)
	}
	if tenant.ID() != "demo" {
		t.Fatalf("expected demo tenant via override, got %s", tenant.ID())
	}
}

func TestResolverUnknownHost(t *testing.T) {
	config := loadTestConfig(t)
	resolver, err := NewResolver(config)
	if err != nil {
		t.Fatalf("resolver creation failed: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://unknown.example.com/api", nil)
	request.Host = "unknown.example.com"

	_, resolveErr := resolver.Resolve(request)
	if !errors.Is(resolveErr, ErrTenantNotFound) {
		t.Fatalf("expected ErrTenantNotFound, got %v", resolveErr)
	}
}

func TestResolverSupportsIPv6Hosts(t *testing.T) {
	config := loadTestConfig(t)
	resolver, err := NewResolver(config)
	if err != nil {
		t.Fatalf("resolver creation failed: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://[2001:db8::1]/api", nil)
	request.Host = "[2001:db8::1]:8443"

	tenant, resolveErr := resolver.Resolve(request)
	if resolveErr != nil {
		t.Fatalf("expected resolve success for ipv6 host: %v", resolveErr)
	}
	if tenant.ID() != "demo" {
		t.Fatalf("expected demo tenant for ipv6 host, got %s", tenant.ID())
	}
}

func TestResolverStripsPortFromHost(t *testing.T) {
	config := loadTestConfig(t)
	resolver, err := NewResolver(config)
	if err != nil {
		t.Fatalf("resolver creation failed: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://demo.example.com/api", nil)
	request.Host = "demo.example.com:8443"

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
	request := httptest.NewRequest(http.MethodGet, "http://demo.example.com/api", nil)
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
	request := httptest.NewRequest(http.MethodGet, "http://shared.localhost/api", nil)
	request.Host = "shared.localhost"
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
	request := httptest.NewRequest(http.MethodGet, "http://shared.localhost/api", nil)
	request.Host = "shared.localhost"
	request.Header.Set(defaultTenantHeader, "http://unknown-origin.localhost")

	if _, resolveErr := resolver.Resolve(request); resolveErr == nil {
		t.Fatalf("expected resolve to fail for unknown origin override")
	}
}

func TestResolverRequiresHeaderWhenHostsShared(t *testing.T) {
	config := loadConfigWithSharedHost(t)

	resolverWithoutHeader, err := NewResolver(config)
	if err != nil {
		t.Fatalf("resolver creation failed: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://shared.localhost/api", nil)
	request.Host = "shared.localhost"
	if _, resolveErr := resolverWithoutHeader.Resolve(request); resolveErr == nil {
		t.Fatalf("expected ambiguous host error when header override disabled")
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

func TestResolverOverrideRejectsUnknownHost(t *testing.T) {
	config := loadConfigWithSharedHost(t)
	resolver, err := NewResolver(config, WithHeaderOverride(""))
	if err != nil {
		t.Fatalf("resolver creation failed: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://unknown.localhost/api", nil)
	request.Host = "unknown.localhost"
	request.Header.Set(defaultTenantHeader, "demo")

	_, resolveErr := resolver.Resolve(request)
	if resolveErr == nil || !strings.Contains(resolveErr.Error(), errorCodeUnknownHost) {
		t.Fatalf("expected unknown host error, got %v", resolveErr)
	}
}

func TestResolverOverrideRejectsHostNotOwnedByTenant(t *testing.T) {
	config := loadTestConfig(t)
	resolver, err := NewResolver(config, WithHeaderOverride(""))
	if err != nil {
		t.Fatalf("resolver creation failed: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://prod.example.com/api", nil)
	request.Host = "prod.example.com"
	request.Header.Set(defaultTenantHeader, "demo")

	_, resolveErr := resolver.Resolve(request)
	if resolveErr == nil || !strings.Contains(resolveErr.Error(), errorCodeUnknownHost) {
		t.Fatalf("expected host mismatch error, got %v", resolveErr)
	}
}

func TestResolverUsesURLHostWhenHostHeaderEmpty(t *testing.T) {
	config := loadTestConfig(t)
	resolver, err := NewResolver(config)
	if err != nil {
		t.Fatalf("resolver creation failed: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://demo.example.com/api", nil)
	request.Host = ""

	tenant, resolveErr := resolver.Resolve(request)
	if resolveErr != nil {
		t.Fatalf("expected resolve success, got %v", resolveErr)
	}
	if tenant.ID() != "demo" {
		t.Fatalf("expected demo tenant, got %s", tenant.ID())
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
	request.Host = "demo.example.com"
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", response.Code)
	}
	if capturedID != "demo" {
		t.Fatalf("expected demo tenant, got %s", capturedID)
	}
}

func TestTenantMiddlewareRejectsUnknownHost(t *testing.T) {
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
	request.Host = "unknown.example.com"
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusTeapot {
		t.Fatalf("expected rejection status 418, got %d", response.Code)
	}
}

func TestResolverUsesOriginForAmbiguousHosts(t *testing.T) {
	config := loadConfigWithOrigins(t)
	resolver, err := NewResolver(config)
	if err != nil {
		t.Fatalf("resolver creation failed: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://shared.localhost/auth/nonce", nil)
	request.Host = "shared.localhost"
	request.Header.Set("Origin", "http://localhost:8000")

	tenant, resolveErr := resolver.Resolve(request)
	if resolveErr != nil {
		t.Fatalf("expected resolve success via origin, got %v", resolveErr)
	}
	if tenant.ID() != "notes" {
		t.Fatalf("expected notes tenant, got %s", tenant.ID())
	}

	second := httptest.NewRequest(http.MethodGet, "http://shared.localhost/auth/nonce", nil)
	second.Host = "shared.localhost"
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
	request.Host = "shared.localhost"

	if _, resolveErr := resolver.Resolve(request); resolveErr == nil {
		t.Fatalf("expected resolve to fail when origin missing")
	}

	request.Header.Set("Origin", "http://unknown.localhost")
	if _, resolveErr := resolver.Resolve(request); resolveErr == nil {
		t.Fatalf("expected resolve to fail for unknown origin")
	}
}

func loadTestConfig(t *testing.T) Config {
	t.Helper()
	content := []byte(`{
		"tenants": [
			{
				"id": "demo",
				"display_name": "Demo",
				"allowed_hosts": ["demo.example.com", "demo.localhost", "[2001:db8::1]"],
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
				"allowed_hosts": ["prod.example.com"],
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

func loadConfigWithSharedHost(t *testing.T) Config {
	t.Helper()
	content := []byte(`{
		"tenants": [
			{
				"id": "demo",
				"display_name": "Demo",
				"allowed_hosts": ["shared.localhost"],
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
				"allowed_hosts": ["shared.localhost"],
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
				"allowed_hosts": ["shared.localhost", "http://localhost:8000"],
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
				"allowed_hosts": ["shared.localhost", "http://localhost:4173"],
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

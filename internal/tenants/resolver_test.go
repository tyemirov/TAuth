package tenants

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	request := httptest.NewRequest(http.MethodGet, "http://prod.example.com/api", nil)
	request.Host = "prod.example.com"
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

func loadTestConfig(t *testing.T) Config {
	t.Helper()
	content := []byte(`{
		"tenants": [
			{
				"id": "demo",
				"display_name": "Demo",
				"hosts": ["demo.example.com", "demo.localhost"],
				"google_web_client_id": "demo-client.apps.googleusercontent.com",
				"cookie_domain": "demo.example.com",
				"session_ttl": "30m",
				"refresh_ttl": "720h",
				"nonce_ttl": "10m"
			},
			{
				"id": "prod",
				"display_name": "Prod",
				"hosts": ["prod.example.com"],
				"google_web_client_id": "prod-client.apps.googleusercontent.com",
				"cookie_domain": ".example.com",
				"session_ttl": "15m",
				"refresh_ttl": "1440h",
				"nonce_ttl": "5m"
			}
		]
	}`)
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "tenants.json")
	if writeErr := os.WriteFile(configPath, content, 0o600); writeErr != nil {
		t.Fatalf("failed to write config: %v", writeErr)
	}
	config, loadErr := LoadConfig(configPath)
	if loadErr != nil {
		t.Fatalf("failed to load config: %v", loadErr)
	}
	return config
}

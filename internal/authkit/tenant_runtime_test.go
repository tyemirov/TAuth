package authkit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/tenants"
)

func TestTenantRegistryDefaultFallback(t *testing.T) {
	config := ServerConfig{TenantID: "default"}
	registry := NewSingleTenantRegistry(config)

	if resolved := registry.Config("missing"); resolved.TenantID != "default" {
		t.Fatalf("expected default config, got %s", resolved.TenantID)
	}

	if id := resolveTenantID(nil, registry); id != "default" {
		t.Fatalf("expected fallback tenant id, got %s", id)
	}

	recorder := httptest.NewRecorder()
	contextGin, _ := gin.CreateTestContext(recorder)
	if id := resolveTenantID(contextGin, registry); id != "default" {
		t.Fatalf("expected fallback tenant id with empty context, got %s", id)
	}
}

func TestNewTenantRegistryFromMapFallback(t *testing.T) {
	configA := ServerConfig{TenantID: "tenant-a"}
	configB := ServerConfig{TenantID: "tenant-b"}

	registry := NewTenantRegistryFromMap("missing", map[string]ServerConfig{
		configA.TenantID: configA,
		configB.TenantID: configB,
	})

	if registry.DefaultTenantID() != "tenant-a" && registry.DefaultTenantID() != "tenant-b" {
		t.Fatalf("expected default tenant to fall back to available configs, got %s", registry.DefaultTenantID())
	}

	if resolved := registry.Config("tenant-b"); resolved.TenantID != "tenant-b" {
		t.Fatalf("expected tenant-b config, got %s", resolved.TenantID)
	}
}

func TestTenantRegistryDefaultConfigReturnsConfiguredTenant(t *testing.T) {
	config := ServerConfig{TenantID: "default"}
	registry := NewSingleTenantRegistry(config)
	if registry.DefaultConfig().TenantID != "default" {
		t.Fatalf("expected default tenant config to be returned")
	}
}

func TestResolveTenantIDUsesResolvedTenantFromContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	document := tenants.FileDocument{
		Tenants: []tenants.FileTenant{
			{
				ID:                "context-tenant",
				DisplayName:       "Context Tenant",
				AllowedHosts:      []string{"https://context.localhost"},
				GoogleWebClientID: "client-id",
				JWTSigningKey:     "signing-key",
				CookieDomain:      "",
				SessionCookieName: "app_session_context",
				RefreshCookieName: "app_refresh_context",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
				AllowInsecureHTTP: true,
			},
		},
	}

	config, err := tenants.LoadConfigFromDocument(document)
	if err != nil {
		t.Fatalf("expected tenants document to load: %v", err)
	}
	resolver, err := tenants.NewResolver(config)
	if err != nil {
		t.Fatalf("expected resolver to construct: %v", err)
	}

	registry := NewSingleTenantRegistry(ServerConfig{
		TenantID:   "default",
		NonceTTL:   5 * time.Minute,
		SessionTTL: time.Minute,
		RefreshTTL: time.Hour,
	})

	router := gin.New()
	router.Use(tenants.TenantMiddleware(resolver, http.StatusNotFound))
	router.GET("/resolved", func(contextGin *gin.Context) {
		contextGin.String(http.StatusOK, resolveTenantID(contextGin, registry))
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/resolved", nil)
	request.Header.Set("Origin", "https://context.localhost")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	if recorder.Body.String() != "context-tenant" {
		t.Fatalf("expected context-tenant, got %q", recorder.Body.String())
	}
}

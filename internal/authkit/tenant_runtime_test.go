package authkit

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
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

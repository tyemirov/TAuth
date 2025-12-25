package authkit

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/tenants"
)

// TenantRegistry stores per-tenant server configurations.
type TenantRegistry struct {
	defaultTenantID string
	configs         map[string]ServerConfig
}

// NewSingleTenantRegistry constructs a registry with a single configuration.
func NewSingleTenantRegistry(config ServerConfig) TenantRegistry {
	configs := map[string]ServerConfig{
		config.TenantID: config,
	}
	return TenantRegistry{
		defaultTenantID: config.TenantID,
		configs:         configs,
	}
}

// NewTenantRegistryFromMap constructs a registry from explicit configurations.
func NewTenantRegistryFromMap(defaultTenantID string, configs map[string]ServerConfig) TenantRegistry {
	copyConfigs := make(map[string]ServerConfig, len(configs))
	for tenantID, config := range configs {
		copyConfigs[tenantID] = config
	}
	if _, exists := copyConfigs[defaultTenantID]; !exists && len(copyConfigs) > 0 {
		for tenantID := range copyConfigs {
			defaultTenantID = tenantID
			break
		}
	}
	return TenantRegistry{
		defaultTenantID: defaultTenantID,
		configs:         copyConfigs,
	}
}

// DefaultTenantID returns the registry's fallback tenant identifier.
func (registry TenantRegistry) DefaultTenantID() string {
	return registry.defaultTenantID
}

// DefaultConfig returns the default tenant configuration.
func (registry TenantRegistry) DefaultConfig() ServerConfig {
	return registry.Config(registry.defaultTenantID)
}

// Config resolves a tenant configuration, falling back to the default when missing.
func (registry TenantRegistry) Config(tenantID string) ServerConfig {
	if config, exists := registry.configs[tenantID]; exists {
		return config
	}
	return registry.configs[registry.defaultTenantID]
}

func resolveTenantID(context *gin.Context, registry TenantRegistry) string {
	if context != nil {
		if tenant, ok := tenants.TenantFromContext(context); ok {
			if id := strings.TrimSpace(string(tenant.ID())); id != "" {
				return id
			}
		}
	}
	return registry.defaultTenantID
}

func resolveTenantIDRequired(context *gin.Context, registry TenantRegistry) (string, bool) {
	if context != nil {
		if tenant, ok := tenants.TenantFromContext(context); ok {
			if tenantID := strings.TrimSpace(string(tenant.ID())); tenantID != "" {
				return tenantID, true
			}
		}
	}
	if len(registry.configs) <= 1 {
		return registry.defaultTenantID, true
	}
	return "", false
}

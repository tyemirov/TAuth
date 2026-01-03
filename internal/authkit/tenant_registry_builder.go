package authkit

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/tyemirov/tauth/internal/tenants"
)

// SameSiteResolver maps tenant settings to cookie SameSite modes.
type SameSiteResolver func(allowInsecureHTTP bool) http.SameSite

// ErrTenantRegistryConfig indicates a registry could not be built from the tenant config.
var ErrTenantRegistryConfig = errors.New("tenantregistry.invalid")

const (
	errorCodeMissingTenants          = "tenantregistry.missing_tenants"
	errorCodeMissingSameSiteResolver = "tenantregistry.missing_same_site_resolver"
)

// NewSameSiteResolver returns a resolver that matches the default TAuth cookie policy.
func NewSameSiteResolver(enableCORS bool) SameSiteResolver {
	return func(allowInsecureHTTP bool) http.SameSite {
		if allowInsecureHTTP {
			return http.SameSiteLaxMode
		}
		if enableCORS {
			return http.SameSiteNoneMode
		}
		return http.SameSiteStrictMode
	}
}

// BuildTenantRegistry constructs a tenant registry from validated tenant config.
func BuildTenantRegistry(base ServerConfig, tenantConfig tenants.Config, sameSiteResolver SameSiteResolver) (TenantRegistry, error) {
	tenantList := tenantConfig.Tenants()
	if len(tenantList) == 0 {
		return TenantRegistry{}, fmt.Errorf("%w: %s", ErrTenantRegistryConfig, errorCodeMissingTenants)
	}
	if sameSiteResolver == nil {
		return TenantRegistry{}, fmt.Errorf("%w: %s", ErrTenantRegistryConfig, errorCodeMissingSameSiteResolver)
	}
	configs := make(map[string]ServerConfig, len(tenantList))
	for _, tenant := range tenantList {
		tenantServerConfig := base
		tenantServerConfig.TenantID = string(tenant.ID())
		tenantServerConfig.GoogleWebClientID = tenant.GoogleWebClientID()
		tenantServerConfig.AppJWTSigningKey = tenant.SigningKey()
		tenantServerConfig.CookieDomain = tenant.CookieDomain()
		tenantServerConfig.SessionCookieName = tenant.SessionCookieName()
		tenantServerConfig.RefreshCookieName = tenant.RefreshCookieName()
		tenantServerConfig.AllowedUsers = buildAllowedUserLookup(tenant.AllowedUsers())
		tenantServerConfig.SessionTTL = tenant.SessionTTL()
		tenantServerConfig.RefreshTTL = tenant.RefreshTTL()
		tenantServerConfig.NonceTTL = tenant.NonceTTL()
		tenantServerConfig.AllowInsecureHTTP = tenant.AllowInsecureHTTP()
		tenantServerConfig.SameSiteMode = sameSiteResolver(tenant.AllowInsecureHTTP())
		configs[tenantServerConfig.TenantID] = tenantServerConfig
	}
	defaultTenantID := string(tenantList[0].ID())
	return NewTenantRegistryFromMap(defaultTenantID, configs), nil
}

func buildAllowedUserLookup(allowedUsers []string) map[string]struct{} {
	if len(allowedUsers) == 0 {
		return nil
	}
	allowedUserLookup := make(map[string]struct{}, len(allowedUsers))
	for _, allowedUserEmail := range allowedUsers {
		allowedUserLookup[allowedUserEmail] = struct{}{}
	}
	return allowedUserLookup
}

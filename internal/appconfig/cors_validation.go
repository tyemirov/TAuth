package appconfig

import (
	"fmt"

	"github.com/tyemirov/tauth/internal/tenants"
)

// ValidateCORSAllowlist ensures CORS origins are tenant origins or explicit exceptions.
func ValidateCORSAllowlist(settings ServerSettings, tenantConfig tenants.Config) error {
	if !bool(settings.EnableCORS) {
		return nil
	}
	allowedOrigins := ExpandCommaSeparatedEntries(settings.CORSAllowedOrigins)
	if len(allowedOrigins) == 0 {
		return fmt.Errorf("%s: cors_allowed_origins must be set when enable_cors is true", ErrorCodeInvalidCORSOrigin)
	}
	exceptionOrigins := ExpandCommaSeparatedEntries(settings.CORSAllowedOriginExceptions)
	exceptionSet, exceptionErr := normalizeExceptionOrigins(exceptionOrigins)
	if exceptionErr != nil {
		return exceptionErr
	}
	tenantOriginSet := buildTenantOriginSet(tenantConfig)
	for _, origin := range allowedOrigins {
		normalizedOrigin, normalizeErr := tenants.NormalizeOrigin(origin)
		if normalizeErr != nil {
			return fmt.Errorf("%s: origin=%s", ErrorCodeInvalidCORSOrigin, origin)
		}
		if _, ok := tenantOriginSet[normalizedOrigin]; ok {
			continue
		}
		if _, ok := exceptionSet[normalizedOrigin]; ok {
			continue
		}
		return fmt.Errorf("%s: origin=%s", ErrorCodeCORSOriginNotAllowed, normalizedOrigin)
	}
	return nil
}

func normalizeExceptionOrigins(exceptionOrigins []string) (map[string]struct{}, error) {
	normalizedExceptions := make(map[string]struct{}, len(exceptionOrigins))
	for _, exceptionOrigin := range exceptionOrigins {
		normalizedOrigin, normalizeErr := tenants.NormalizeOrigin(exceptionOrigin)
		if normalizeErr != nil {
			return nil, fmt.Errorf("%s: exception_origin=%s", ErrorCodeInvalidCORSOrigin, exceptionOrigin)
		}
		normalizedExceptions[normalizedOrigin] = struct{}{}
	}
	return normalizedExceptions, nil
}

func buildTenantOriginSet(tenantConfig tenants.Config) map[string]struct{} {
	tenantOriginSet := make(map[string]struct{})
	for _, tenant := range tenantConfig.Tenants() {
		for _, host := range tenant.Hosts() {
			tenantOriginSet[host] = struct{}{}
		}
	}
	return tenantOriginSet
}

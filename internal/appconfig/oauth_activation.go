package appconfig

import (
	"fmt"

	"github.com/tyemirov/tauth/internal/tenants"
)

// ErrorCodeOAuthServerRequired identifies an OAuth tenant without an authorization server.
const ErrorCodeOAuthServerRequired = "config.oauth_server_required"

// ValidateOAuthActivation validates the issuer-level dependency for enabled OAuth tenants.
func ValidateOAuthActivation(serverConfig OAuthServerConfig, tenantConfig tenants.Config) error {
	if serverConfig.Enabled() {
		return nil
	}
	enabledTenants := 0
	for _, tenant := range tenantConfig.Tenants() {
		if tenant.OAuthAuthorization().Enabled() {
			enabledTenants++
		}
	}
	if enabledTenants != 0 {
		return fmt.Errorf("%s: enabled_tenants=%d", ErrorCodeOAuthServerRequired, enabledTenants)
	}
	return nil
}

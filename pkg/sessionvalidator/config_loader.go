package sessionvalidator

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/tenants"
)

// ErrTenantAuthConfig indicates the tenant auth config could not be loaded.
var ErrTenantAuthConfig = errors.New("session.validator.config.invalid")

const (
	errorCodeMissingConfigPath = "session.validator.config.missing_path"
	errorCodeMissingTenantID   = "session.validator.config.missing_tenant_id"
	errorCodeUnknownTenantID   = "session.validator.config.unknown_tenant_id"
	errorCodeLoadConfig        = "session.validator.config.load"
)

// TenantAuthConfig captures the JWT validation settings for a tenant.
type TenantAuthConfig struct {
	tenantID          string
	signingKey        []byte
	issuer            string
	sessionCookieName string
	refreshCookieName string
}

// LoadTenantAuthConfig loads tenant auth settings from a config.yaml file.
func LoadTenantAuthConfig(configPath string, tenantID string) (TenantAuthConfig, error) {
	cleanedPath := strings.TrimSpace(configPath)
	if cleanedPath == "" {
		return TenantAuthConfig{}, fmt.Errorf("%w: %s", ErrTenantAuthConfig, errorCodeMissingConfigPath)
	}
	cleanedTenantID := strings.TrimSpace(tenantID)
	if cleanedTenantID == "" {
		return TenantAuthConfig{}, fmt.Errorf("%w: %s", ErrTenantAuthConfig, errorCodeMissingTenantID)
	}
	config, loadErr := appconfig.LoadConfig(cleanedPath)
	if loadErr != nil {
		return TenantAuthConfig{}, fmt.Errorf("%w: %s: %w", ErrTenantAuthConfig, errorCodeLoadConfig, loadErr)
	}
	tenantConfig, tenantErr := tenants.LoadConfigFromDocument(config.TenantDocument())
	if tenantErr != nil {
		return TenantAuthConfig{}, fmt.Errorf("%w: %s: %w", ErrTenantAuthConfig, errorCodeLoadConfig, tenantErr)
	}
	tenant, ok := tenantConfig.TenantByID(tenants.TenantID(cleanedTenantID))
	if !ok {
		return TenantAuthConfig{}, fmt.Errorf("%w: %s tenant_id=%s", ErrTenantAuthConfig, errorCodeUnknownTenantID, cleanedTenantID)
	}
	return TenantAuthConfig{
		tenantID:          string(tenant.ID()),
		signingKey:        append([]byte(nil), tenant.SigningKey()...),
		issuer:            appconfig.DefaultJWTIssuer,
		sessionCookieName: tenant.SessionCookieName(),
		refreshCookieName: tenant.RefreshCookieName(),
	}, nil
}

// TenantID returns the tenant identifier.
func (config TenantAuthConfig) TenantID() string {
	return config.tenantID
}

// Issuer returns the JWT issuer.
func (config TenantAuthConfig) Issuer() string {
	return config.issuer
}

// SessionCookieName returns the access cookie name.
func (config TenantAuthConfig) SessionCookieName() string {
	return config.sessionCookieName
}

// RefreshCookieName returns the refresh cookie name.
func (config TenantAuthConfig) RefreshCookieName() string {
	return config.refreshCookieName
}

// SigningKey returns a copy of the tenant signing key.
func (config TenantAuthConfig) SigningKey() []byte {
	return append([]byte(nil), config.signingKey...)
}

// ValidatorConfig returns a validator Config for the tenant.
func (config TenantAuthConfig) ValidatorConfig() Config {
	return Config{
		SigningKey: append([]byte(nil), config.signingKey...),
		Issuer:     config.issuer,
		CookieName: config.sessionCookieName,
	}
}

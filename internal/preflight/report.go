package preflight

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/buildinfo"
	"github.com/tyemirov/tauth/internal/tenants"
	"github.com/tyemirov/utils/preflight"
)

const (
	reportSchemaVersion        = "tauth.preflight.v2"
	endpointContractVersion    = "tauth.http.v1"
	errorCodeLoadConfig        = "preflight.load_config"
	errorCodeLoadTenants       = "preflight.load_tenants"
	errorCodeValidateCORS      = "preflight.validate_cors"
	errorCodeBuildRegistry     = "preflight.build_registry"
	errorCodeRefreshStoreCheck = "preflight.refresh_store"
	errorCodeBuildServiceInfo  = "preflight.build_service_info"
	errorCodeBuildReport       = "preflight.build_report"
	refreshStoreName           = "refresh_store"
	refreshStoreDriverKey      = "driver"
	refreshStoreTypeMemory     = "memory"
	refreshStoreTypeDatabase   = "database"
)

var errPreflight = errors.New("preflight.invalid")

type effectiveConfigPayload struct {
	Server  serverPayload   `json:"server"`
	Tenants []tenantPayload `json:"tenants"`
}

type serverPayload struct {
	EnableCORS                  bool     `json:"enable_cors"`
	CORSAllowedOrigins          []string `json:"cors_allowed_origins"`
	CORSAllowedOriginExceptions []string `json:"cors_allowed_origin_exceptions"`
	EnableTenantHeaderOverride  bool     `json:"enable_tenant_header_override"`
}

type tenantPayload struct {
	TenantID                 string   `json:"tenant_id"`
	DisplayName              string   `json:"display_name"`
	AllowedHosts             []string `json:"allowed_hosts,omitempty"`
	AllowedHostsRedacted     bool     `json:"allowed_hosts_redacted"`
	AllowedHostsCount        int      `json:"allowed_hosts_count"`
	AllowedHostHashes        []string `json:"allowed_host_hashes,omitempty"`
	GoogleWebClientID        string   `json:"google_web_client_id"`
	CookieDomain             string   `json:"cookie_domain"`
	SessionCookieName        string   `json:"session_cookie_name"`
	RefreshCookieName        string   `json:"refresh_cookie_name"`
	SessionTTL               string   `json:"session_ttl"`
	RefreshTTL               string   `json:"refresh_ttl"`
	NonceTTL                 string   `json:"nonce_ttl"`
	AllowInsecureHTTP        bool     `json:"allow_insecure_http"`
	SameSiteMode             string   `json:"same_site_mode"`
	JWTIssuer                string   `json:"jwt_issuer"`
	JWTSigningKeyFingerprint string   `json:"jwt_signing_key_fingerprint"`
}

// BuildRedactedReport builds a preflight report with redacted origins.
func BuildRedactedReport(configPath string) ([]byte, error) {
	return buildReport(configPath, preflight.RedactionModeRedacted)
}

// BuildFullReport builds a preflight report with full origins.
func BuildFullReport(configPath string) ([]byte, error) {
	return buildReport(configPath, preflight.RedactionModeFull)
}

func buildReport(configPath string, mode preflight.RedactionMode) ([]byte, error) {
	config, loadErr := appconfig.LoadConfig(configPath)
	if loadErr != nil {
		return nil, fmt.Errorf("%w: %s: %w", errPreflight, errorCodeLoadConfig, loadErr)
	}
	tenantConfig, tenantErr := tenants.LoadConfigFromDocument(config.TenantDocument())
	if tenantErr != nil {
		return nil, fmt.Errorf("%w: %s: %w", errPreflight, errorCodeLoadTenants, tenantErr)
	}
	if corsErr := appconfig.ValidateCORSAllowlist(config.Server, tenantConfig); corsErr != nil {
		return nil, fmt.Errorf("%w: %s: %w", errPreflight, errorCodeValidateCORS, corsErr)
	}
	registry, registryErr := buildTenantRegistry(config, tenantConfig)
	if registryErr != nil {
		return nil, fmt.Errorf("%w: %s: %w", errPreflight, errorCodeBuildRegistry, registryErr)
	}

	serviceInfo, serviceErr := preflight.NewServiceInfo(
		buildinfo.ServiceName,
		buildinfo.Version,
		buildinfo.Commit,
		buildinfo.BuildTime,
		appconfig.ConfigSchemaVersion,
		endpointContractVersion,
	)
	if serviceErr != nil {
		return nil, fmt.Errorf("%w: %s: %w", errPreflight, errorCodeBuildServiceInfo, serviceErr)
	}

	reporter := configReporter{
		config:       config,
		tenantConfig: tenantConfig,
		registry:     registry,
	}
	refreshStoreChecker := refreshStoreDependency{databaseURL: config.Server.DatabaseURL}

	reportBytes, reportErr := preflight.BuildReport(context.Background(), reportSchemaVersion, serviceInfo, reporter, []preflight.DependencyChecker{refreshStoreChecker}, mode)
	if reportErr != nil {
		return nil, fmt.Errorf("%w: %s: %w", errPreflight, errorCodeBuildReport, reportErr)
	}
	return reportBytes, nil
}

func buildTenantRegistry(config *appconfig.ApplicationConfig, tenantConfig tenants.Config) (authkit.TenantRegistry, error) {
	baseConfig := authkit.ServerConfig{
		AppJWTIssuer: appconfig.DefaultJWTIssuer,
	}
	sameSiteResolver := authkit.NewSameSiteResolver(bool(config.Server.EnableCORS))
	return authkit.BuildTenantRegistry(baseConfig, tenantConfig, sameSiteResolver)
}

type configReporter struct {
	config       *appconfig.ApplicationConfig
	tenantConfig tenants.Config
	registry     authkit.TenantRegistry
}

func (reporter configReporter) Build(mode preflight.RedactionMode) (json.RawMessage, error) {
	payload := effectiveConfigPayload{
		Server: serverPayload{
			EnableCORS:                  bool(reporter.config.Server.EnableCORS),
			CORSAllowedOrigins:          append([]string(nil), reporter.config.Server.CORSAllowedOrigins...),
			CORSAllowedOriginExceptions: append([]string(nil), reporter.config.Server.CORSAllowedOriginExceptions...),
			EnableTenantHeaderOverride:  bool(reporter.config.Server.EnableTenantHeaderOverride),
		},
		Tenants: buildTenantPayloads(reporter.tenantConfig, reporter.registry, mode),
	}
	payloadBytes, marshalErr := json.Marshal(payload)
	if marshalErr != nil {
		return nil, marshalErr
	}
	return payloadBytes, nil
}

func buildTenantPayloads(config tenants.Config, registry authkit.TenantRegistry, mode preflight.RedactionMode) []tenantPayload {
	tenantList := config.Tenants()
	payloads := make([]tenantPayload, 0, len(tenantList))
	for _, tenant := range tenantList {
		tenantID := string(tenant.ID())
		serverConfig := registry.Config(tenantID)
		hosts := tenant.Hosts()
		hostHashes := make([]string, 0, len(hosts))
		for _, host := range hosts {
			hostHashes = append(hostHashes, preflight.HashSHA256Hex([]byte(host)))
		}
		sort.Strings(hostHashes)

		payload := tenantPayload{
			TenantID:                 tenantID,
			DisplayName:              tenant.DisplayName(),
			AllowedHostsRedacted:     mode == preflight.RedactionModeRedacted,
			AllowedHostsCount:        len(hosts),
			AllowedHostHashes:        hostHashes,
			GoogleWebClientID:        tenant.GoogleWebClientID(),
			CookieDomain:             tenant.CookieDomain(),
			SessionCookieName:        tenant.SessionCookieName(),
			RefreshCookieName:        tenant.RefreshCookieName(),
			SessionTTL:               tenant.SessionTTL().String(),
			RefreshTTL:               tenant.RefreshTTL().String(),
			NonceTTL:                 tenant.NonceTTL().String(),
			AllowInsecureHTTP:        tenant.AllowInsecureHTTP(),
			SameSiteMode:             formatSameSiteMode(serverConfig.SameSiteMode),
			JWTIssuer:                serverConfig.AppJWTIssuer,
			JWTSigningKeyFingerprint: preflight.HashSHA256Hex(tenant.SigningKey()),
		}

		if mode == preflight.RedactionModeFull {
			payload.AllowedHosts = append([]string(nil), hosts...)
		}
		payloads = append(payloads, payload)
	}
	return payloads
}

type refreshStoreDependency struct {
	databaseURL string
}

func (dependency refreshStoreDependency) Check(ctx context.Context) (preflight.DependencyStatus, error) {
	trimmedURL := strings.TrimSpace(dependency.databaseURL)
	if trimmedURL == "" {
		return preflight.DependencyStatus{
			Name:  refreshStoreName,
			Type:  refreshStoreTypeMemory,
			Ready: true,
			Details: map[string]string{
				refreshStoreDriverKey: refreshStoreTypeMemory,
			},
		}, nil
	}
	contextDeadline, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	store, storeErr := authkit.NewDatabaseRefreshTokenStore(contextDeadline, trimmedURL)
	if storeErr != nil {
		return preflight.DependencyStatus{}, fmt.Errorf("%w: %s: %w", errPreflight, errorCodeRefreshStoreCheck, storeErr)
	}
	return preflight.DependencyStatus{
		Name:  refreshStoreName,
		Type:  refreshStoreTypeDatabase,
		Ready: true,
		Details: map[string]string{
			refreshStoreDriverKey: store.Driver(),
		},
	}, nil
}

func formatSameSiteMode(mode http.SameSite) string {
	switch mode {
	case http.SameSiteNoneMode:
		return "None"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	default:
		return "Default"
	}
}

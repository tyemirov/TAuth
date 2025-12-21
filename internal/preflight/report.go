package preflight

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
)

const (
	reportSchemaVersion        = "tauth.preflight.v1"
	endpointContractVersion    = "tauth.http.v1"
	errorCodeLoadConfig        = "preflight.load_config"
	errorCodeLoadTenants       = "preflight.load_tenants"
	errorCodeBuildRegistry     = "preflight.build_registry"
	errorCodeRefreshStoreCheck = "preflight.refresh_store"
	errorCodeEncodeReport      = "preflight.encode_report"
)

var errPreflight = errors.New("preflight.invalid")

type hostRedactionMode int

const (
	hostRedactionModeRedacted hostRedactionMode = iota + 1
	hostRedactionModeFull
)

type reportPayload struct {
	SchemaVersion string          `json:"schema_version"`
	Service       servicePayload  `json:"service"`
	Server        serverPayload   `json:"server"`
	Tenants       []tenantPayload `json:"tenants"`
	Dependencies  dependencies    `json:"dependencies"`
}

type servicePayload struct {
	Name                    string `json:"service_name"`
	Version                 string `json:"version"`
	Commit                  string `json:"build_commit"`
	BuildTime               string `json:"build_time"`
	ConfigSchemaVersion     string `json:"config_schema_version"`
	EndpointContractVersion string `json:"endpoint_contract_version"`
}

type serverPayload struct {
	EnableCORS                 bool     `json:"enable_cors"`
	CORSAllowedOrigins         []string `json:"cors_allowed_origins"`
	EnableTenantHeaderOverride bool     `json:"enable_tenant_header_override"`
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

type dependencies struct {
	RefreshStore refreshStorePayload `json:"refresh_store"`
}

type refreshStorePayload struct {
	Type   string `json:"type"`
	Driver string `json:"driver"`
	Ready  bool   `json:"ready"`
}

// BuildRedactedReport builds a preflight report with redacted hostnames.
func BuildRedactedReport(configPath string) ([]byte, error) {
	return buildReport(configPath, hostRedactionModeRedacted)
}

// BuildFullReport builds a preflight report with full hostnames.
func BuildFullReport(configPath string) ([]byte, error) {
	return buildReport(configPath, hostRedactionModeFull)
}

func buildReport(configPath string, mode hostRedactionMode) ([]byte, error) {
	config, loadErr := appconfig.LoadConfig(configPath)
	if loadErr != nil {
		return nil, fmt.Errorf("%w: %s: %w", errPreflight, errorCodeLoadConfig, loadErr)
	}
	tenantConfig, tenantErr := tenants.LoadConfigFromDocument(config.TenantDocument())
	if tenantErr != nil {
		return nil, fmt.Errorf("%w: %s: %w", errPreflight, errorCodeLoadTenants, tenantErr)
	}
	registry, registryErr := buildTenantRegistry(config, tenantConfig)
	if registryErr != nil {
		return nil, fmt.Errorf("%w: %s: %w", errPreflight, errorCodeBuildRegistry, registryErr)
	}

	refreshStore, refreshStoreErr := buildRefreshStorePayload(config.Server.DatabaseURL)
	if refreshStoreErr != nil {
		return nil, fmt.Errorf("%w: %s: %w", errPreflight, errorCodeRefreshStoreCheck, refreshStoreErr)
	}

	report := reportPayload{
		SchemaVersion: reportSchemaVersion,
		Service: servicePayload{
			Name:                    buildinfo.ServiceName,
			Version:                 buildinfo.Version,
			Commit:                  buildinfo.Commit,
			BuildTime:               buildinfo.BuildTime,
			ConfigSchemaVersion:     appconfig.ConfigSchemaVersion,
			EndpointContractVersion: endpointContractVersion,
		},
		Server: serverPayload{
			EnableCORS:                 bool(config.Server.EnableCORS),
			CORSAllowedOrigins:         append([]string(nil), config.Server.CORSAllowedOrigins...),
			EnableTenantHeaderOverride: bool(config.Server.EnableTenantHeaderOverride),
		},
		Tenants:      buildTenantPayloads(tenantConfig, registry, mode),
		Dependencies: dependencies{RefreshStore: refreshStore},
	}

	reportBytes, marshalErr := json.MarshalIndent(report, "", "  ")
	if marshalErr != nil {
		return nil, fmt.Errorf("%w: %s: %w", errPreflight, errorCodeEncodeReport, marshalErr)
	}
	return append(reportBytes, '\n'), nil
}

func buildTenantRegistry(config *appconfig.ApplicationConfig, tenantConfig tenants.Config) (authkit.TenantRegistry, error) {
	baseConfig := authkit.ServerConfig{
		AppJWTIssuer: appconfig.DefaultJWTIssuer,
	}
	sameSiteResolver := authkit.NewSameSiteResolver(bool(config.Server.EnableCORS))
	return authkit.BuildTenantRegistry(baseConfig, tenantConfig, sameSiteResolver)
}

func buildTenantPayloads(config tenants.Config, registry authkit.TenantRegistry, mode hostRedactionMode) []tenantPayload {
	tenantList := config.Tenants()
	payloads := make([]tenantPayload, 0, len(tenantList))
	for _, tenant := range tenantList {
		tenantID := string(tenant.ID())
		serverConfig := registry.Config(tenantID)
		hosts := tenant.Hosts()
		hostHashes := make([]string, 0, len(hosts))
		for _, host := range hosts {
			hostHashes = append(hostHashes, sha256Hex([]byte(host)))
		}
		sort.Strings(hostHashes)

		payload := tenantPayload{
			TenantID:                 tenantID,
			DisplayName:              tenant.DisplayName(),
			AllowedHostsRedacted:     mode == hostRedactionModeRedacted,
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
			JWTSigningKeyFingerprint: sha256Hex(tenant.SigningKey()),
		}

		if mode == hostRedactionModeFull {
			payload.AllowedHosts = append([]string(nil), hosts...)
		}
		payloads = append(payloads, payload)
	}
	return payloads
}

func buildRefreshStorePayload(databaseURL string) (refreshStorePayload, error) {
	trimmedURL := strings.TrimSpace(databaseURL)
	if trimmedURL == "" {
		return refreshStorePayload{
			Type:   "memory",
			Driver: "memory",
			Ready:  true,
		}, nil
	}
	contextDeadline, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	store, storeErr := authkit.NewDatabaseRefreshTokenStore(contextDeadline, trimmedURL)
	if storeErr != nil {
		return refreshStorePayload{}, storeErr
	}
	return refreshStorePayload{
		Type:   "database",
		Driver: store.Driver(),
		Ready:  true,
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

func sha256Hex(payload []byte) string {
	return hex.EncodeToString(hashSHA256(payload))
}

func hashSHA256(payload []byte) []byte {
	hasher := sha256.Sum256(payload)
	return hasher[:]
}

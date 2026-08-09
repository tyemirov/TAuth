// Package doctor provides validation utilities for TAuth configurations across projects.
package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/buildinfo"
	"github.com/tyemirov/tauth/internal/oauthserver"
	"github.com/tyemirov/tauth/internal/tenants"
	"github.com/tyemirov/utils/preflight"
)

const (
	reportSchemaVersion     = "tauth.doctor.v2"
	endpointContractVersion = "tauth.http.v2"
)

var errDoctor = errors.New("doctor.invalid")

// DiagnosticResult represents the outcome of validating a single configuration.
type DiagnosticResult struct {
	ConfigPath string   `json:"config_path"`
	Valid      bool     `json:"valid"`
	Errors     []string `json:"errors,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
	TenantIDs  []string `json:"tenant_ids,omitempty"`
}

// Report represents the complete doctor report for all validated configurations.
type Report struct {
	SchemaVersion   string             `json:"schema_version"`
	Timestamp       string             `json:"timestamp"`
	Service         serviceInfo        `json:"service"`
	Summary         reportSummary      `json:"summary"`
	Diagnostics     []DiagnosticResult `json:"diagnostics"`
	CrossValidation crossValidation    `json:"cross_validation,omitempty"`
}

type serviceInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
}

type reportSummary struct {
	TotalConfigs   int `json:"total_configs"`
	ValidConfigs   int `json:"valid_configs"`
	InvalidConfigs int `json:"invalid_configs"`
	TotalErrors    int `json:"total_errors"`
	TotalWarnings  int `json:"total_warnings"`
}

type crossValidation struct {
	Performed bool     `json:"performed"`
	Errors    []string `json:"errors,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
}

// Options configures the doctor behavior.
type Options struct {
	ConfigPaths          []string
	ValidateCrossConfigs bool
	CheckDatabaseStore   bool
}

// Run executes the doctor validation for the specified configurations.
func Run(ctx context.Context, options Options) (*Report, error) {
	if len(options.ConfigPaths) == 0 {
		return nil, fmt.Errorf("%w: no config paths provided", errDoctor)
	}

	report := &Report{
		SchemaVersion: reportSchemaVersion,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Service: serviceInfo{
			Name:      buildinfo.ServiceName,
			Version:   buildinfo.Version,
			Commit:    buildinfo.Commit,
			BuildTime: buildinfo.BuildTime,
		},
		Diagnostics: make([]DiagnosticResult, 0, len(options.ConfigPaths)),
	}

	allTenantsByConfig := make(map[string]tenants.Config)

	for _, configPath := range options.ConfigPaths {
		diagnostic := validateConfig(ctx, configPath, options.CheckDatabaseStore)
		report.Diagnostics = append(report.Diagnostics, diagnostic)

		if diagnostic.Valid {
			config, loadErr := appconfig.LoadConfig(configPath)
			if loadErr == nil {
				tenantConfig, tenantErr := tenants.LoadConfigFromDocument(config.TenantDocument())
				if tenantErr == nil {
					allTenantsByConfig[configPath] = tenantConfig
				}
			}
		}
	}

	report.Summary = buildSummary(report.Diagnostics)

	if options.ValidateCrossConfigs && len(allTenantsByConfig) > 1 {
		report.CrossValidation = validateCrossConfigs(allTenantsByConfig)
	}

	return report, nil
}

func validateConfig(ctx context.Context, configPath string, checkDatabase bool) DiagnosticResult {
	result := DiagnosticResult{
		ConfigPath: configPath,
		Valid:      true,
	}

	config, loadErr := appconfig.LoadConfig(configPath)
	if loadErr != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("load_config: %v", loadErr))
		return result
	}

	tenantConfig, tenantErr := tenants.LoadConfigFromDocument(config.TenantDocument())
	if tenantErr != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("load_tenants: %v", tenantErr))
		return result
	}

	if corsErr := appconfig.ValidateCORSAllowlist(config.Server, tenantConfig); corsErr != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("cors_validation: %v", corsErr))
	}
	validateOAuthConfig(config.OAuthServer(), tenantConfig, &result)

	baseConfig := authkit.ServerConfig{
		AppJWTIssuer: appconfig.DefaultJWTIssuer,
	}
	sameSiteResolver := authkit.NewSameSiteResolver(bool(config.Server.EnableCORS))
	_, registryErr := authkit.BuildTenantRegistry(baseConfig, tenantConfig, sameSiteResolver)
	if registryErr != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("build_registry: %v", registryErr))
	}

	for _, tenant := range tenantConfig.Tenants() {
		result.TenantIDs = append(result.TenantIDs, string(tenant.ID()))
		validateTenantConfig(tenant, &result)
	}

	if checkDatabase && strings.TrimSpace(config.Server.DatabaseURL) != "" {
		ctxWithTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		_, probeErr := authkit.CheckDatabaseConnectivity(ctxWithTimeout, config.Server.DatabaseURL)
		if probeErr != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("database_store: %v", probeErr))
		}
	}

	sort.Strings(result.Errors)
	sort.Strings(result.Warnings)
	sort.Strings(result.TenantIDs)

	return result
}

func validateOAuthConfig(serverConfig appconfig.OAuthServerConfig, tenantConfig tenants.Config, result *DiagnosticResult) {
	enabledTenants := 0
	for _, tenant := range tenantConfig.Tenants() {
		if tenant.OAuthAuthorization().Enabled() {
			enabledTenants++
		}
	}
	if serverConfig.Enabled() != (enabledTenants != 0) {
		result.Valid = false
		result.Errors = append(result.Errors, "oauth: issuer and tenant OAuth enablement must be configured together")
		return
	}
	if !serverConfig.Enabled() {
		return
	}
	if _, registryErr := oauthserver.NewRegistry(tenantConfig); registryErr != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("oauth_registry: %v", registryErr))
	}
	if _, signerErr := oauthserver.NewSigner(serverConfig); signerErr != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("oauth_signer: %v", signerErr))
	}
}

func validateTenantConfig(tenant tenants.Tenant, result *DiagnosticResult) {
	tenantID := string(tenant.ID())

	if tenant.SessionTTL() <= 0 {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("tenant[%s]: session_ttl must be positive", tenantID))
	}
	if tenant.RefreshTTL() <= 0 {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("tenant[%s]: refresh_ttl must be positive", tenantID))
	}
	if tenant.NonceTTL() <= 0 {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("tenant[%s]: nonce_ttl must be positive", tenantID))
	}

	if len(tenant.SigningKey()) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("tenant[%s]: jwt_signing_key is required", tenantID))
	}

	if tenant.GoogleWebClientID() == "" && len(tenant.NativeGoogleClients()) == 0 && !tenant.AppleOAuth().Enabled() && !tenant.PasswordAuthEnabled() {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("tenant[%s]: at least one auth provider is required", tenantID))
	}
	if tenant.GoogleWebClientID() == "" {
		result.Warnings = append(result.Warnings, fmt.Sprintf("tenant[%s]: google_web_client_id is not configured; browser Google login will return 404", tenantID))
	}
	if len(tenant.NativeGoogleClients()) == 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("tenant[%s]: google_native_client_id/google_native_clients is not configured; native login will return 404", tenantID))
	}

	if len(tenant.Origins()) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("tenant[%s]: tenant_origins is required", tenantID))
	}

	if tenant.SessionCookieName() == "" {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("tenant[%s]: session_cookie_name is required", tenantID))
	}

	if tenant.RefreshCookieName() == "" {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("tenant[%s]: refresh_cookie_name is required", tenantID))
	}

	if tenant.AllowInsecureHTTP() {
		result.Warnings = append(result.Warnings, fmt.Sprintf("tenant[%s]: allow_insecure_http is enabled (use only for development)", tenantID))
	}
}

func validateCrossConfigs(configsByPath map[string]tenants.Config) crossValidation {
	validation := crossValidation{
		Performed: true,
	}

	type tenantLocation struct {
		ConfigPath string
		TenantID   string
	}

	signingKeyFingerprints := make(map[string][]tenantLocation)
	originsByTenant := make(map[string]tenantLocation)
	cookieNamesByDomain := make(map[string]map[string]tenantLocation)

	for configPath, config := range configsByPath {
		for _, tenant := range config.Tenants() {
			tenantID := string(tenant.ID())
			location := tenantLocation{
				ConfigPath: configPath,
				TenantID:   tenantID,
			}

			fingerprint := preflight.HashSHA256Hex(tenant.SigningKey())
			signingKeyFingerprints[fingerprint] = append(signingKeyFingerprints[fingerprint], location)

			for _, origin := range tenant.Origins() {
				normalizedOrigin := strings.ToLower(strings.TrimSpace(origin))
				if existing, exists := originsByTenant[normalizedOrigin]; exists {
					if existing.ConfigPath != configPath || existing.TenantID != tenantID {
						validation.Errors = append(validation.Errors,
							fmt.Sprintf("origin %q claimed by tenant[%s] in %s conflicts with tenant[%s] in %s",
								origin, tenantID, configPath, existing.TenantID, existing.ConfigPath))
					}
				} else {
					originsByTenant[normalizedOrigin] = location
				}
			}

			cookieDomain := tenant.CookieDomain()
			if cookieDomain == "" {
				cookieDomain = "_host_only_"
			}
			if cookieNamesByDomain[cookieDomain] == nil {
				cookieNamesByDomain[cookieDomain] = make(map[string]tenantLocation)
			}
			sessionCookieName := tenant.SessionCookieName()
			if existing, exists := cookieNamesByDomain[cookieDomain][sessionCookieName]; exists {
				if existing.ConfigPath != configPath || existing.TenantID != tenantID {
					validation.Warnings = append(validation.Warnings,
						fmt.Sprintf("session_cookie_name %q on domain %q used by tenant[%s] in %s conflicts with tenant[%s] in %s",
							sessionCookieName, cookieDomain, tenantID, configPath, existing.TenantID, existing.ConfigPath))
				}
			} else {
				cookieNamesByDomain[cookieDomain][sessionCookieName] = location
			}
		}
	}

	for fingerprint, locations := range signingKeyFingerprints {
		if len(locations) > 1 {
			configPaths := make([]string, 0, len(locations))
			for _, loc := range locations {
				configPaths = append(configPaths, fmt.Sprintf("tenant[%s] in %s", loc.TenantID, loc.ConfigPath))
			}
			validation.Warnings = append(validation.Warnings,
				fmt.Sprintf("signing key fingerprint %s...%s shared by: %s",
					fingerprint[:8], fingerprint[len(fingerprint)-8:], strings.Join(configPaths, ", ")))
		}
	}

	sort.Strings(validation.Errors)
	sort.Strings(validation.Warnings)

	return validation
}

func buildSummary(diagnostics []DiagnosticResult) reportSummary {
	summary := reportSummary{
		TotalConfigs: len(diagnostics),
	}
	for _, diag := range diagnostics {
		if diag.Valid {
			summary.ValidConfigs++
		} else {
			summary.InvalidConfigs++
		}
		summary.TotalErrors += len(diag.Errors)
		summary.TotalWarnings += len(diag.Warnings)
	}
	return summary
}

// FormatReport formats the report as indented JSON.
func FormatReport(report *Report) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

// FormatSummary formats a human-readable summary of the report.
func FormatSummary(report *Report) string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("TAuth Doctor Report (%s)\n", report.Timestamp))
	builder.WriteString(strings.Repeat("=", 60))
	builder.WriteString("\n\n")

	builder.WriteString(fmt.Sprintf("Summary: %d/%d configs valid",
		report.Summary.ValidConfigs, report.Summary.TotalConfigs))
	if report.Summary.TotalErrors > 0 {
		builder.WriteString(fmt.Sprintf(", %d errors", report.Summary.TotalErrors))
	}
	if report.Summary.TotalWarnings > 0 {
		builder.WriteString(fmt.Sprintf(", %d warnings", report.Summary.TotalWarnings))
	}
	builder.WriteString("\n\n")

	for _, diag := range report.Diagnostics {
		status := "✓ VALID"
		if !diag.Valid {
			status = "✗ INVALID"
		}
		builder.WriteString(fmt.Sprintf("%s: %s\n", diag.ConfigPath, status))
		if len(diag.TenantIDs) > 0 {
			builder.WriteString(fmt.Sprintf("  Tenants: %s\n", strings.Join(diag.TenantIDs, ", ")))
		}
		for _, err := range diag.Errors {
			builder.WriteString(fmt.Sprintf("  ERROR: %s\n", err))
		}
		for _, warn := range diag.Warnings {
			builder.WriteString(fmt.Sprintf("  WARN: %s\n", warn))
		}
		builder.WriteString("\n")
	}

	if report.CrossValidation.Performed {
		builder.WriteString("Cross-Config Validation:\n")
		if len(report.CrossValidation.Errors) == 0 && len(report.CrossValidation.Warnings) == 0 {
			builder.WriteString("  No cross-config issues detected\n")
		}
		for _, err := range report.CrossValidation.Errors {
			builder.WriteString(fmt.Sprintf("  ERROR: %s\n", err))
		}
		for _, warn := range report.CrossValidation.Warnings {
			builder.WriteString(fmt.Sprintf("  WARN: %s\n", warn))
		}
	}

	return builder.String()
}

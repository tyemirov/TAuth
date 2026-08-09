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
	"github.com/tyemirov/tauth/internal/oauthserver"
	"github.com/tyemirov/tauth/internal/tenants"
	"github.com/tyemirov/utils/preflight"
)

const (
	reportSchemaVersion        = "tauth.preflight.v6"
	endpointContractVersion    = "tauth.http.v2"
	errorCodeLoadConfig        = "preflight.load_config"
	errorCodeLoadTenants       = "preflight.load_tenants"
	errorCodeValidateCORS      = "preflight.validate_cors"
	errorCodeValidateOAuth     = "preflight.validate_oauth"
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
	EnableCORS                  bool               `json:"enable_cors"`
	CORSAllowedOrigins          []string           `json:"cors_allowed_origins"`
	CORSAllowedOriginExceptions []string           `json:"cors_allowed_origin_exceptions"`
	EnableTenantHeaderOverride  bool               `json:"enable_tenant_header_override"`
	OAuth                       oauthServerPayload `json:"oauth"`
}

type oauthServerPayload struct {
	Enabled                 bool                     `json:"enabled"`
	Issuer                  string                   `json:"issuer,omitempty"`
	AuthorizationEndpoint   string                   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint           string                   `json:"token_endpoint,omitempty"`
	RevocationEndpoint      string                   `json:"revocation_endpoint,omitempty"`
	JWKSURI                 string                   `json:"jwks_uri,omitempty"`
	LoginEndpoint           string                   `json:"login_endpoint,omitempty"`
	ConsentEndpoint         string                   `json:"consent_endpoint,omitempty"`
	AuthorizationRequestTTL string                   `json:"authorization_request_ttl,omitempty"`
	AuthorizationCodeTTL    string                   `json:"authorization_code_ttl,omitempty"`
	ActiveSigningKeyID      string                   `json:"active_signing_key_id,omitempty"`
	SigningKeys             []oauthSigningKeyPayload `json:"signing_keys,omitempty"`
	ClientMetadata          oauthMetadataPayload     `json:"client_metadata"`
}

type oauthSigningKeyPayload struct {
	ID                   string `json:"id"`
	Algorithm            string `json:"algorithm"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
}

type oauthMetadataPayload struct {
	RequestTimeout  string `json:"request_timeout,omitempty"`
	MaximumBytes    int64  `json:"maximum_bytes,omitempty"`
	MinimumCacheTTL string `json:"minimum_cache_ttl,omitempty"`
	MaximumCacheTTL string `json:"maximum_cache_ttl,omitempty"`
}

type tenantPayload struct {
	TenantID                   string                      `json:"tenant_id"`
	DisplayName                string                      `json:"display_name"`
	TenantOrigins              []string                    `json:"tenant_origins,omitempty"`
	TenantOriginsRedacted      bool                        `json:"tenant_origins_redacted"`
	TenantOriginsCount         int                         `json:"tenant_origins_count"`
	TenantOriginHashes         []string                    `json:"tenant_origin_hashes,omitempty"`
	GoogleWebClientID          string                      `json:"google_web_client_id"`
	GoogleNativeClientID       string                      `json:"google_native_client_id"`
	GoogleNativeClientIDs      []string                    `json:"google_native_client_ids,omitempty"`
	GoogleNativeClients        []nativeGoogleClientPayload `json:"google_native_clients,omitempty"`
	AppleOAuthEnabled          bool                        `json:"apple_oauth_enabled"`
	AppleClientID              string                      `json:"apple_client_id,omitempty"`
	AppleTeamID                string                      `json:"apple_team_id,omitempty"`
	AppleKeyID                 string                      `json:"apple_key_id,omitempty"`
	ApplePrivateKeyFingerprint string                      `json:"apple_private_key_fingerprint,omitempty"`
	AppleRedirectURI           string                      `json:"apple_redirect_uri,omitempty"`
	AppleScopes                []string                    `json:"apple_scopes,omitempty"`
	AppleAuthorizationEndpoint string                      `json:"apple_authorization_endpoint,omitempty"`
	AppleTokenEndpoint         string                      `json:"apple_token_endpoint,omitempty"`
	AppleJWKSURL               string                      `json:"apple_jwks_url,omitempty"`
	PasswordAuthEnabled        bool                        `json:"password_auth_enabled"`
	PasswordUserCount          int                         `json:"password_user_count"`
	AccountManagementEnabled   bool                        `json:"account_management_enabled"`
	PasswordSignupEnabled      bool                        `json:"password_signup_enabled"`
	ReturnChallengeTokens      bool                        `json:"return_challenge_tokens"`
	EmailVerificationTTL       string                      `json:"email_verification_ttl"`
	PasswordResetTTL           string                      `json:"password_reset_ttl"`
	CookieDomain               string                      `json:"cookie_domain"`
	SessionCookieName          string                      `json:"session_cookie_name"`
	RefreshCookieName          string                      `json:"refresh_cookie_name"`
	SessionTTL                 string                      `json:"session_ttl"`
	RefreshTTL                 string                      `json:"refresh_ttl"`
	NonceTTL                   string                      `json:"nonce_ttl"`
	AllowInsecureHTTP          bool                        `json:"allow_insecure_http"`
	SameSiteMode               string                      `json:"same_site_mode"`
	JWTIssuer                  string                      `json:"jwt_issuer"`
	JWTSigningKeyFingerprint   string                      `json:"jwt_signing_key_fingerprint"`
	OAuth                      oauthTenantPayload          `json:"oauth"`
}

type oauthTenantPayload struct {
	Enabled                      bool                   `json:"enabled"`
	AccessTokenTTL               string                 `json:"access_token_ttl,omitempty"`
	RefreshTokenTTL              string                 `json:"refresh_token_ttl,omitempty"`
	ConsentTTL                   string                 `json:"consent_ttl,omitempty"`
	AllowClientMetadataDocuments bool                   `json:"allow_client_metadata_documents"`
	Resources                    []oauthResourcePayload `json:"resources,omitempty"`
	Clients                      []oauthClientPayload   `json:"clients,omitempty"`
}

type oauthResourcePayload struct {
	Identifier string   `json:"identifier"`
	Scopes     []string `json:"scopes"`
}

type oauthClientPayload struct {
	ID              string   `json:"id"`
	ApplicationType string   `json:"application_type"`
	RedirectURIs    []string `json:"redirect_uris"`
}

type nativeGoogleClientPayload struct {
	Platform     string   `json:"platform"`
	ClientID     string   `json:"client_id"`
	RedirectURIs []string `json:"redirect_uris,omitempty"`
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
	if oauthErr := validateOAuth(config.OAuthServer(), tenantConfig); oauthErr != nil {
		return nil, fmt.Errorf("%w: %s: %w", errPreflight, errorCodeValidateOAuth, oauthErr)
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

func validateOAuth(serverConfig appconfig.OAuthServerConfig, tenantConfig tenants.Config) error {
	enabledTenants := 0
	for _, tenant := range tenantConfig.Tenants() {
		if tenant.OAuthAuthorization().Enabled() {
			enabledTenants++
		}
	}
	if serverConfig.Enabled() != (enabledTenants != 0) {
		return fmt.Errorf("issuer and tenant OAuth enablement must be configured together")
	}
	if !serverConfig.Enabled() {
		return nil
	}
	if _, registryErr := oauthserver.NewRegistry(tenantConfig); registryErr != nil {
		return registryErr
	}
	_, signerErr := oauthserver.NewSigner(serverConfig)
	return signerErr
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
	oauthPayload, oauthPayloadErr := buildOAuthServerPayload(reporter.config.OAuthServer())
	if oauthPayloadErr != nil {
		return nil, oauthPayloadErr
	}
	payload := effectiveConfigPayload{
		Server: serverPayload{
			EnableCORS:                  bool(reporter.config.Server.EnableCORS),
			CORSAllowedOrigins:          append([]string(nil), reporter.config.Server.CORSAllowedOrigins...),
			CORSAllowedOriginExceptions: append([]string(nil), reporter.config.Server.CORSAllowedOriginExceptions...),
			EnableTenantHeaderOverride:  bool(reporter.config.Server.EnableTenantHeaderOverride),
			OAuth:                       oauthPayload,
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
		origins := tenant.Origins()
		originHashes := make([]string, 0, len(origins))
		for _, origin := range origins {
			originHashes = append(originHashes, preflight.HashSHA256Hex([]byte(origin)))
		}
		sort.Strings(originHashes)

		payload := tenantPayload{
			TenantID:                   tenantID,
			DisplayName:                tenant.DisplayName(),
			TenantOriginsRedacted:      mode == preflight.RedactionModeRedacted,
			TenantOriginsCount:         len(origins),
			TenantOriginHashes:         originHashes,
			GoogleWebClientID:          tenant.GoogleWebClientID(),
			GoogleNativeClientID:       tenant.GoogleNativeClientID(),
			GoogleNativeClientIDs:      tenant.NativeGoogleClientIDs(),
			GoogleNativeClients:        buildNativeGoogleClientPayloads(tenant.NativeGoogleClients()),
			AppleOAuthEnabled:          tenant.AppleOAuth().Enabled(),
			AppleClientID:              tenant.AppleOAuth().ClientID(),
			AppleTeamID:                tenant.AppleOAuth().TeamID(),
			AppleKeyID:                 tenant.AppleOAuth().KeyID(),
			AppleRedirectURI:           tenant.AppleOAuth().RedirectURI(),
			AppleScopes:                tenant.AppleOAuth().Scopes(),
			AppleAuthorizationEndpoint: tenant.AppleOAuth().AuthorizationEndpoint(),
			AppleTokenEndpoint:         tenant.AppleOAuth().TokenEndpoint(),
			AppleJWKSURL:               tenant.AppleOAuth().JWKSURL(),
			PasswordAuthEnabled:        tenant.PasswordAuthEnabled(),
			PasswordUserCount:          len(tenant.PasswordUsers()),
			AccountManagementEnabled:   tenant.AccountManagement().Enabled(),
			PasswordSignupEnabled:      tenant.AccountManagement().PasswordSignupEnabled(),
			ReturnChallengeTokens:      tenant.AccountManagement().ReturnChallengeTokens(),
			EmailVerificationTTL:       tenant.AccountManagement().EmailVerificationTTL().String(),
			PasswordResetTTL:           tenant.AccountManagement().PasswordResetTTL().String(),
			CookieDomain:               tenant.CookieDomain(),
			SessionCookieName:          tenant.SessionCookieName(),
			RefreshCookieName:          tenant.RefreshCookieName(),
			SessionTTL:                 tenant.SessionTTL().String(),
			RefreshTTL:                 tenant.RefreshTTL().String(),
			NonceTTL:                   tenant.NonceTTL().String(),
			AllowInsecureHTTP:          tenant.AllowInsecureHTTP(),
			SameSiteMode:               formatSameSiteMode(serverConfig.SameSiteMode),
			JWTIssuer:                  serverConfig.AppJWTIssuer,
			JWTSigningKeyFingerprint:   preflight.HashSHA256Hex(tenant.SigningKey()),
			OAuth:                      buildOAuthTenantPayload(tenant.OAuthAuthorization()),
		}
		if tenant.AppleOAuth().Enabled() {
			payload.ApplePrivateKeyFingerprint = preflight.HashSHA256Hex([]byte(tenant.AppleOAuth().PrivateKey()))
		}

		if mode == preflight.RedactionModeFull {
			payload.TenantOrigins = append([]string(nil), origins...)
		}
		payloads = append(payloads, payload)
	}
	return payloads
}

func buildOAuthServerPayload(config appconfig.OAuthServerConfig) (oauthServerPayload, error) {
	payload := oauthServerPayload{Enabled: config.Enabled()}
	if !config.Enabled() {
		return payload, nil
	}
	policy := config.ClientMetadata()
	payload.Issuer = config.Issuer()
	payload.AuthorizationEndpoint = config.AuthorizationEndpoint()
	payload.TokenEndpoint = config.TokenEndpoint()
	payload.RevocationEndpoint = config.RevocationEndpoint()
	payload.JWKSURI = config.JWKSURI()
	payload.LoginEndpoint = config.LoginEndpoint()
	payload.ConsentEndpoint = config.ConsentEndpoint()
	payload.AuthorizationRequestTTL = config.AuthorizationRequestTTL().String()
	payload.AuthorizationCodeTTL = config.AuthorizationCodeTTL().String()
	payload.ActiveSigningKeyID = config.ActiveSigningKeyID()
	payload.ClientMetadata = oauthMetadataPayload{
		RequestTimeout: policy.RequestTimeout().String(), MaximumBytes: policy.MaximumBytes(),
		MinimumCacheTTL: policy.MinimumCacheTTL().String(), MaximumCacheTTL: policy.MaximumCacheTTL().String(),
	}
	for _, key := range config.SigningKeys() {
		publicKey := key.PublicKey()
		publicKeyBytes, encodeErr := publicKey.Bytes()
		if encodeErr != nil {
			return oauthServerPayload{}, encodeErr
		}
		payload.SigningKeys = append(payload.SigningKeys, oauthSigningKeyPayload{
			ID: key.ID(), Algorithm: key.Algorithm(), PublicKeyFingerprint: preflight.HashSHA256Hex(publicKeyBytes),
		})
	}
	return payload, nil
}

func buildOAuthTenantPayload(config tenants.OAuthAuthorization) oauthTenantPayload {
	payload := oauthTenantPayload{Enabled: config.Enabled()}
	if !config.Enabled() {
		return payload
	}
	payload.AccessTokenTTL = config.AccessTokenTTL().String()
	payload.RefreshTokenTTL = config.RefreshTokenTTL().String()
	payload.ConsentTTL = config.ConsentTTL().String()
	payload.AllowClientMetadataDocuments = config.AllowClientMetadataDocuments()
	for _, resource := range config.Resources() {
		scopes := make([]string, 0, len(resource.Scopes()))
		for _, scope := range resource.Scopes() {
			scopes = append(scopes, scope.Identifier())
		}
		payload.Resources = append(payload.Resources, oauthResourcePayload{Identifier: resource.Identifier(), Scopes: scopes})
	}
	for _, client := range config.Clients() {
		payload.Clients = append(payload.Clients, oauthClientPayload{
			ID: client.ID(), ApplicationType: client.ApplicationType(), RedirectURIs: client.RedirectURIs(),
		})
	}
	return payload
}

func buildNativeGoogleClientPayloads(clients []tenants.NativeGoogleClient) []nativeGoogleClientPayload {
	if len(clients) == 0 {
		return nil
	}
	payloads := make([]nativeGoogleClientPayload, 0, len(clients))
	for _, client := range clients {
		payloads = append(payloads, nativeGoogleClientPayload{
			Platform:     client.Platform(),
			ClientID:     client.ClientID(),
			RedirectURIs: client.RedirectURIs(),
		})
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

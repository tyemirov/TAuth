package tenants

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// Config captures the immutable tenant declarations loaded from disk.
type Config struct {
	tenants           []Tenant
	tenantIndex       map[TenantID]Tenant
	originToTenantIDs map[string][]TenantID
}

// Tenant represents one logical deployment tenant and its auth configuration.
type Tenant struct {
	id                   TenantID
	displayName          string
	origins              []string
	allowedUsers         []string
	googleWebClientID    string
	googleNativeClientID string
	nativeGoogleClients  []NativeGoogleClient
	appleOAuth           AppleOAuth
	passwordAuthEnabled  bool
	passwordUsers        []PasswordUser
	accountManagement    AccountManagement
	oauthAuthorization   OAuthAuthorization
	jwtSigningKey        []byte
	cookieDomain         string
	sessionCookieName    string
	refreshCookieName    string
	sessionTTL           time.Duration
	refreshTTL           time.Duration
	nonceTTL             time.Duration
	allowInsecureHTTP    bool
}

// TenantID identifies each tenant block.
type TenantID string

// NativeGoogleClient represents one accepted installed-app Google audience.
type NativeGoogleClient struct {
	platform     string
	clientID     string
	redirectURIs []string
}

// AppleOAuth represents tenant-level Sign in with Apple settings.
type AppleOAuth struct {
	enabled               bool
	clientID              string
	teamID                string
	keyID                 string
	privateKey            string
	redirectURI           string
	scopes                []string
	authorizationEndpoint string
	tokenEndpoint         string
	jwksURL               string
}

// PasswordUser represents one configured email/password user.
type PasswordUser struct {
	email        string
	displayName  string
	avatarURL    string
	passwordHash string
}

// AccountManagement represents tenant-level account lifecycle settings.
type AccountManagement struct {
	enabled               bool
	passwordSignupEnabled bool
	returnChallengeTokens bool
	emailVerificationTTL  time.Duration
	passwordResetTTL      time.Duration
}

type tenantCookieScope struct {
	tenantID          TenantID
	cookieDomain      string
	hostnames         []string
	sessionCookieName string
	refreshCookieName string
}

// ErrInvalidTenantConfig indicates the underlying configuration payload is invalid.
var ErrInvalidTenantConfig = errors.New("tenantconfig.invalid")

const (
	tenantIDPattern                      = "^[a-z0-9][a-z0-9_-]{1,63}$"
	nativeGooglePlatformPattern          = "^[a-z][a-z0-9_-]{1,31}$"
	defaultNonceTTL                      = 5 * time.Minute
	defaultEmailVerificationTTL          = 30 * time.Minute
	defaultPasswordResetTTL              = 15 * time.Minute
	defaultNativeGooglePlatform          = "desktop"
	errorCodeInvalidPath                 = "tenant.invalid_path"
	errorCodeDuplicateTenantID           = "tenant.duplicate_id"
	errorCodeInvalidID                   = "tenant.invalid_id"
	errorCodeMissingOrigins              = "tenant.missing_origins"
	errorCodeInvalidOrigin               = "tenant.invalid_origin"
	errorCodeDuplicateOrigin             = "tenant.duplicate_origin"
	errorCodeInvalidAllowedUser          = "tenant.invalid_allowed_user"
	errorCodeDuplicateAllowedUser        = "tenant.duplicate_allowed_user"
	errorCodeMissingAuthProvider         = "tenant.missing_auth_provider"
	errorCodeInvalidNativeGoogleID       = "tenant.invalid_native_google_client_id"
	errorCodeInvalidNativePlatform       = "tenant.invalid_native_google_platform"
	errorCodeInvalidNativeRedirectURI    = "tenant.invalid_native_redirect_uri"
	errorCodeDuplicateNativeGoogleID     = "tenant.duplicate_native_google_client_id"
	errorCodeAppleOAuthDisabled          = "tenant.apple_oauth_disabled"
	errorCodeInvalidAppleClientID        = "tenant.invalid_apple_client_id"
	errorCodeInvalidAppleTeamID          = "tenant.invalid_apple_team_id"
	errorCodeInvalidAppleKeyID           = "tenant.invalid_apple_key_id"
	errorCodeInvalidApplePrivateKey      = "tenant.invalid_apple_private_key"
	errorCodeInvalidAppleRedirectURI     = "tenant.invalid_apple_redirect_uri"
	errorCodeInvalidAppleScope           = "tenant.invalid_apple_scope"
	errorCodeInvalidAppleEndpoint        = "tenant.invalid_apple_endpoint"
	errorCodePasswordAuthDisabled        = "tenant.password_auth_disabled"
	errorCodeInvalidPasswordUser         = "tenant.invalid_password_user"
	errorCodeDuplicatePasswordUser       = "tenant.duplicate_password_user"
	errorCodeInvalidPasswordHash         = "tenant.invalid_password_hash"
	errorCodeAccountManagementDisabled   = "tenant.account_management_disabled"
	errorCodeInvalidEmailVerificationTTL = "tenant.invalid_email_verification_ttl"
	errorCodeInvalidPasswordResetTTL     = "tenant.invalid_password_reset_ttl"
	errorCodeInvalidSessionTTL           = "tenant.invalid_session_ttl"
	errorCodeInvalidRefreshTTL           = "tenant.invalid_refresh_ttl"
	errorCodeInvalidNonceTTL             = "tenant.invalid_nonce_ttl"
	errorCodeMissingSigningKey           = "tenant.missing_signing_key"
	errorCodeMissingSessionCookieName    = "tenant.missing_session_cookie_name"
	errorCodeMissingRefreshCookieName    = "tenant.missing_refresh_cookie_name"
	errorCodeDuplicateSessionCookieName  = "tenant.duplicate_session_cookie_name"
	errorCodeDuplicateRefreshCookieName  = "tenant.duplicate_refresh_cookie_name"
	errorCodeDuplicateCookieNameCross    = "tenant.duplicate_cookie_name_cross_type"
	errorCodeInvalidCookieScope          = "tenant.invalid_cookie_scope"
	originSchemeHTTP                     = "http"
	originSchemeHTTPS                    = "https"
	originExpectation                    = "expected schemeful origin (http/https) with host[:port] and no path/query/fragment"
	originReasonMissingScheme            = "missing scheme"
	originReasonUnsupportedScheme        = "unsupported scheme"
	originReasonMissingHost              = "missing host"
	originReasonUnexpectedPath           = "origin must not include path, query, or fragment"
	originReasonInvalidURL               = "invalid url"
	defaultAppleAuthorizationEndpoint    = "https://appleid.apple.com/auth/authorize"
	defaultAppleTokenEndpoint            = "https://appleid.apple.com/auth/token"
	defaultAppleJWKSURL                  = "https://appleid.apple.com/auth/keys"
)

var defaultAppleScopes = []string{"openid", "email", "name"}

const (
	cookieDomainSeparator          = "."
	cookieOverlapDomainFormat      = "domain=%s"
	cookieOverlapHostFormat        = "host=%s"
	cookieScopeErrorFormat         = "%w: %s tenant=%s"
	cookieScopeOriginErrorFormat   = "%w: %s tenant=%s origin=%s"
	duplicateCookieNameErrorFormat = "%w: %s cookie_name=%s tenant=%s other_tenant=%s overlap=%s"
	duplicateGoogleIDErrorFormat   = "%w: %s google_native_client_id=%s tenant=%s other_tenant=%s"
)

var tenantIDRegex = regexp.MustCompile(tenantIDPattern)
var nativeGooglePlatformRegex = regexp.MustCompile(nativeGooglePlatformPattern)

// LoadConfig reads and validates tenants from the provided YAML file path.
func LoadConfig(path string) (Config, error) {
	path = strings.TrimSpace(path)
	path = strings.Trim(path, `"'`)
	if path == "" {
		return Config{}, fmt.Errorf("%w: %s", ErrInvalidTenantConfig, errorCodeInvalidPath)
	}
	payload, readErr := os.ReadFile(path)
	if readErr != nil {
		return Config{}, fmt.Errorf("%w: %s read_file", ErrInvalidTenantConfig, errorCodeInvalidPath)
	}

	var document FileDocument
	decoder := yaml.NewDecoder(strings.NewReader(string(payload)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&document); err != nil {
		return Config{}, fmt.Errorf("%w: %s", ErrInvalidTenantConfig, err.Error())
	}
	return LoadConfigFromDocument(document)
}

// LoadConfigFromDocument constructs a Config from the parsed YAML document.
func LoadConfigFromDocument(document FileDocument) (Config, error) {
	document = expandFileDocumentEnv(document)
	tenantIndex := make(map[TenantID]Tenant)
	originToTenantIDs := make(map[string][]TenantID)
	nativeGoogleClientIDs := make(map[string]TenantID)
	oauthResourceIDs := make(map[string]TenantID)
	oauthClientIDs := make(map[string]TenantID)
	orderedTenants := make([]Tenant, 0, len(document.Tenants))
	cookieScopes := make([]tenantCookieScope, 0, len(document.Tenants))

	for _, entry := range document.Tenants {
		tenant, origins, err := buildTenant(entry)
		if err != nil {
			return Config{}, err
		}
		cookieScope, cookieScopeErr := buildTenantCookieScope(tenant, origins)
		if cookieScopeErr != nil {
			return Config{}, cookieScopeErr
		}
		if _, exists := tenantIndex[tenant.id]; exists {
			return Config{}, fmt.Errorf("%w: %s id=%s", ErrInvalidTenantConfig, errorCodeDuplicateTenantID, tenant.id)
		}
		for _, nativeGoogleClientID := range tenant.NativeGoogleClientIDs() {
			if otherTenantID, exists := nativeGoogleClientIDs[nativeGoogleClientID]; exists {
				return Config{}, fmt.Errorf(
					duplicateGoogleIDErrorFormat,
					ErrInvalidTenantConfig,
					errorCodeDuplicateNativeGoogleID,
					nativeGoogleClientID,
					tenant.id,
					otherTenantID,
				)
			}
			nativeGoogleClientIDs[nativeGoogleClientID] = tenant.id
		}
		for _, resource := range tenant.OAuthAuthorization().Resources() {
			if otherTenantID, exists := oauthResourceIDs[resource.Identifier()]; exists {
				return Config{}, fmt.Errorf("%w: tenant.oauth_duplicate_resource resource=%s tenant=%s other_tenant=%s", ErrInvalidTenantConfig, resource.Identifier(), tenant.id, otherTenantID)
			}
			oauthResourceIDs[resource.Identifier()] = tenant.id
		}
		for _, client := range tenant.OAuthAuthorization().Clients() {
			if otherTenantID, exists := oauthClientIDs[client.ID()]; exists {
				return Config{}, fmt.Errorf("%w: tenant.oauth_duplicate_client client_id=%s tenant=%s other_tenant=%s", ErrInvalidTenantConfig, client.ID(), tenant.id, otherTenantID)
			}
			oauthClientIDs[client.ID()] = tenant.id
		}
		for _, origin := range origins {
			originToTenantIDs[origin] = append(originToTenantIDs[origin], tenant.id)
		}
		tenantIndex[tenant.id] = tenant
		orderedTenants = append(orderedTenants, tenant)
		cookieScopes = append(cookieScopes, cookieScope)
	}

	sort.SliceStable(orderedTenants, func(i, j int) bool {
		return string(orderedTenants[i].id) < string(orderedTenants[j].id)
	})

	sort.SliceStable(cookieScopes, func(leftIndex, rightIndex int) bool {
		return string(cookieScopes[leftIndex].tenantID) < string(cookieScopes[rightIndex].tenantID)
	})
	if validationErr := validateCookieNameIsolation(cookieScopes); validationErr != nil {
		return Config{}, validationErr
	}

	return Config{
		tenants:           orderedTenants,
		tenantIndex:       tenantIndex,
		originToTenantIDs: originToTenantIDs,
	}, nil
}

// Tenants returns a copy of tenant slice for safe iteration.
func (config Config) Tenants() []Tenant {
	copyTenants := make([]Tenant, len(config.tenants))
	copy(copyTenants, config.tenants)
	return copyTenants
}

// TenantByID looks up a tenant.
func (config Config) TenantByID(id TenantID) (Tenant, bool) {
	tenant, exists := config.tenantIndex[id]
	return tenant, exists
}

// OriginOwner resolves an origin URL to a tenant.
func (config Config) OriginOwner(origin string) (TenantID, bool) {
	owners := config.originOwners(origin)
	if len(owners) == 0 {
		return "", false
	}
	return owners[0], true
}

// OriginIsAmbiguous indicates whether multiple tenants share an origin.
func (config Config) OriginIsAmbiguous(origin string) bool {
	return len(config.originOwners(origin)) > 1
}

func (config Config) originOwners(origin string) []TenantID {
	canonical, err := normalizeOrigin(origin)
	if err != nil {
		return nil
	}
	owners, exists := config.originToTenantIDs[canonical]
	if !exists {
		return nil
	}
	copyOwners := make([]TenantID, len(owners))
	copy(copyOwners, owners)
	return copyOwners
}

// ID returns the tenant identifier.
func (tenant Tenant) ID() TenantID {
	return tenant.id
}

// DisplayName returns the friendly display name.
func (tenant Tenant) DisplayName() string {
	return tenant.displayName
}

// Origins returns the allowed origins for the tenant.
func (tenant Tenant) Origins() []string {
	originsCopy := make([]string, len(tenant.origins))
	copy(originsCopy, tenant.origins)
	return originsCopy
}

// AllowedUsers returns the allowed user emails for the tenant.
func (tenant Tenant) AllowedUsers() []string {
	if tenant.allowedUsers == nil {
		return nil
	}
	allowedUsersCopy := make([]string, len(tenant.allowedUsers))
	copy(allowedUsersCopy, tenant.allowedUsers)
	return allowedUsersCopy
}

// GoogleWebClientID returns the OAuth client identifier.
func (tenant Tenant) GoogleWebClientID() string {
	return tenant.googleWebClientID
}

// GoogleNativeClientID returns the installed-app OAuth client identifier.
func (tenant Tenant) GoogleNativeClientID() string {
	return tenant.googleNativeClientID
}

// NativeGoogleClients returns the accepted installed-app Google clients.
func (tenant Tenant) NativeGoogleClients() []NativeGoogleClient {
	if len(tenant.nativeGoogleClients) == 0 {
		return nil
	}
	clients := make([]NativeGoogleClient, len(tenant.nativeGoogleClients))
	for index, client := range tenant.nativeGoogleClients {
		clients[index] = NativeGoogleClient{
			platform:     client.platform,
			clientID:     client.clientID,
			redirectURIs: append([]string(nil), client.redirectURIs...),
		}
	}
	return clients
}

// NativeGoogleClientIDs returns the accepted native Google audiences.
func (tenant Tenant) NativeGoogleClientIDs() []string {
	if len(tenant.nativeGoogleClients) == 0 {
		return nil
	}
	clientIDs := make([]string, 0, len(tenant.nativeGoogleClients))
	for _, client := range tenant.nativeGoogleClients {
		clientIDs = append(clientIDs, client.clientID)
	}
	return clientIDs
}

// AppleOAuth returns the Sign in with Apple settings for this tenant.
func (tenant Tenant) AppleOAuth() AppleOAuth {
	config := tenant.appleOAuth
	config.scopes = append([]string(nil), tenant.appleOAuth.scopes...)
	return config
}

// Enabled indicates whether Sign in with Apple is available.
func (settings AppleOAuth) Enabled() bool {
	return settings.enabled
}

// ClientID returns the Apple Services ID or app client identifier.
func (settings AppleOAuth) ClientID() string {
	return settings.clientID
}

// TeamID returns the Apple Developer Team ID.
func (settings AppleOAuth) TeamID() string {
	return settings.teamID
}

// KeyID returns the Apple private key identifier.
func (settings AppleOAuth) KeyID() string {
	return settings.keyID
}

// PrivateKey returns the PEM-encoded Apple private key.
func (settings AppleOAuth) PrivateKey() string {
	return settings.privateKey
}

// RedirectURI returns the configured Apple callback URI.
func (settings AppleOAuth) RedirectURI() string {
	return settings.redirectURI
}

// Scopes returns the configured Apple OAuth scopes.
func (settings AppleOAuth) Scopes() []string {
	return append([]string(nil), settings.scopes...)
}

// AuthorizationEndpoint returns the Sign in with Apple authorization endpoint.
func (settings AppleOAuth) AuthorizationEndpoint() string {
	return settings.authorizationEndpoint
}

// TokenEndpoint returns the Sign in with Apple token endpoint.
func (settings AppleOAuth) TokenEndpoint() string {
	return settings.tokenEndpoint
}

// JWKSURL returns the Apple JWKS endpoint.
func (settings AppleOAuth) JWKSURL() string {
	return settings.jwksURL
}

// PasswordAuthEnabled indicates whether password login is available for the tenant.
func (tenant Tenant) PasswordAuthEnabled() bool {
	return tenant.passwordAuthEnabled
}

// PasswordUsers returns configured password users for startup seeding.
func (tenant Tenant) PasswordUsers() []PasswordUser {
	if len(tenant.passwordUsers) == 0 {
		return nil
	}
	users := make([]PasswordUser, len(tenant.passwordUsers))
	copy(users, tenant.passwordUsers)
	return users
}

// AccountManagement returns the account lifecycle settings for the tenant.
func (tenant Tenant) AccountManagement() AccountManagement {
	return tenant.accountManagement
}

// OAuthAuthorization returns the tenant OAuth authorization policy.
func (tenant Tenant) OAuthAuthorization() OAuthAuthorization {
	return tenant.oauthAuthorization.clone()
}

// Enabled indicates whether full account management is available.
func (settings AccountManagement) Enabled() bool {
	return settings.enabled
}

// PasswordSignupEnabled indicates whether public password signup is available.
func (settings AccountManagement) PasswordSignupEnabled() bool {
	return settings.passwordSignupEnabled
}

// ReturnChallengeTokens indicates whether challenge tokens are returned in HTTP responses.
func (settings AccountManagement) ReturnChallengeTokens() bool {
	return settings.returnChallengeTokens
}

// EmailVerificationTTL returns the email-verification challenge lifetime.
func (settings AccountManagement) EmailVerificationTTL() time.Duration {
	return settings.emailVerificationTTL
}

// PasswordResetTTL returns the password-reset challenge lifetime.
func (settings AccountManagement) PasswordResetTTL() time.Duration {
	return settings.passwordResetTTL
}

// Platform returns the native platform label.
func (client NativeGoogleClient) Platform() string {
	return client.platform
}

// ClientID returns the accepted Google OAuth client ID.
func (client NativeGoogleClient) ClientID() string {
	return client.clientID
}

// RedirectURIs returns configured OAuth redirect URIs for the client.
func (client NativeGoogleClient) RedirectURIs() []string {
	return append([]string(nil), client.redirectURIs...)
}

// Email returns the normalized password user email.
func (user PasswordUser) Email() string {
	return user.email
}

// DisplayName returns the password user's display name.
func (user PasswordUser) DisplayName() string {
	return user.displayName
}

// AvatarURL returns the password user's configured avatar URL.
func (user PasswordUser) AvatarURL() string {
	return user.avatarURL
}

// PasswordHash returns the stored bcrypt password hash.
func (user PasswordUser) PasswordHash() string {
	return user.passwordHash
}

// SigningKey returns a copy of the tenant-specific signing key, if provided.
func (tenant Tenant) SigningKey() []byte {
	if len(tenant.jwtSigningKey) == 0 {
		return nil
	}
	copyKey := make([]byte, len(tenant.jwtSigningKey))
	copy(copyKey, tenant.jwtSigningKey)
	return copyKey
}

// CookieDomain returns the configured cookie domain; empty strings yield host-only cookies.
func (tenant Tenant) CookieDomain() string {
	return tenant.cookieDomain
}

// SessionCookieName returns the optional explicit session cookie name.
func (tenant Tenant) SessionCookieName() string {
	return tenant.sessionCookieName
}

// RefreshCookieName returns the optional explicit refresh cookie name.
func (tenant Tenant) RefreshCookieName() string {
	return tenant.refreshCookieName
}

// SessionTTL returns the duration of access tokens.
func (tenant Tenant) SessionTTL() time.Duration {
	return tenant.sessionTTL
}

// RefreshTTL returns the refresh token lifetime.
func (tenant Tenant) RefreshTTL() time.Duration {
	return tenant.refreshTTL
}

// NonceTTL returns the nonce expiration duration.
func (tenant Tenant) NonceTTL() time.Duration {
	return tenant.nonceTTL
}

// AllowInsecureHTTP indicates whether a tenant tolerates HTTP for development.
func (tenant Tenant) AllowInsecureHTTP() bool {
	return tenant.allowInsecureHTTP
}

func buildTenant(raw FileTenant) (Tenant, []string, error) {
	tenantID, idErr := parseTenantID(raw.ID)
	if idErr != nil {
		return Tenant{}, nil, idErr
	}
	origins, originErr := parseTenantOrigins(raw.TenantOrigins, tenantID)
	if originErr != nil {
		return Tenant{}, nil, originErr
	}
	allowedUsers, allowedUsersErr := parseAllowedUsers(raw.AllowedUsers, tenantID)
	if allowedUsersErr != nil {
		return Tenant{}, nil, allowedUsersErr
	}
	nativeGoogleClients, nativeGoogleClientErr := parseNativeGoogleClients(raw, tenantID)
	if nativeGoogleClientErr != nil {
		return Tenant{}, nil, nativeGoogleClientErr
	}
	googleNativeClientID := firstNativeGoogleClientID(nativeGoogleClients)
	allowInsecureHTTP := bool(raw.AllowInsecureHTTP)
	appleOAuth, appleOAuthErr := parseAppleOAuth(raw.AppleOAuth, tenantID, allowInsecureHTTP)
	if appleOAuthErr != nil {
		return Tenant{}, nil, appleOAuthErr
	}
	passwordAuthEnabled, passwordUsers, passwordAuthErr := parsePasswordAuth(raw.PasswordAuth, tenantID)
	if passwordAuthErr != nil {
		return Tenant{}, nil, passwordAuthErr
	}
	googleWebClientID := strings.TrimSpace(raw.GoogleWebClientID)
	if !tenantHasAuthProvider(googleWebClientID, nativeGoogleClients, appleOAuth, passwordAuthEnabled) {
		return Tenant{}, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeMissingAuthProvider, tenantID)
	}
	accountManagement, accountManagementErr := parseAccountManagement(raw.AccountManagement, tenantID)
	if accountManagementErr != nil {
		return Tenant{}, nil, accountManagementErr
	}
	oauthAuthorization, oauthAuthorizationErr := parseOAuthAuthorization(raw.OAuth, tenantID, allowInsecureHTTP)
	if oauthAuthorizationErr != nil {
		return Tenant{}, nil, oauthAuthorizationErr
	}
	if oauthAuthorization.Enabled() && !passwordAuthEnabled && googleWebClientID == "" {
		return Tenant{}, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeOAuthMissingBrowserAuth, tenantID)
	}
	cookieDomain := strings.TrimSpace(raw.CookieDomain)
	sessionTTL, sessionErr := parseDuration(raw.SessionTTL)
	if sessionErr != nil || sessionTTL <= 0 {
		return Tenant{}, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeInvalidSessionTTL, tenantID)
	}
	refreshTTL, refreshErr := parseDuration(raw.RefreshTTL)
	if refreshErr != nil || refreshTTL <= 0 {
		return Tenant{}, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeInvalidRefreshTTL, tenantID)
	}
	nonceTTL := defaultNonceTTL
	if strings.TrimSpace(raw.NonceTTL) != "" {
		nonceDuration, nonceErr := parseDuration(raw.NonceTTL)
		if nonceErr != nil || nonceDuration <= 0 {
			return Tenant{}, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeInvalidNonceTTL, tenantID)
		}
		nonceTTL = nonceDuration
	}

	displayName := strings.TrimSpace(raw.DisplayName)
	if displayName == "" {
		displayName = string(tenantID)
	}

	signingKeyValue := strings.TrimSpace(raw.JWTSigningKey)
	if signingKeyValue == "" {
		return Tenant{}, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeMissingSigningKey, tenantID)
	}
	signingKey := []byte(signingKeyValue)
	sessionCookieName := strings.TrimSpace(raw.SessionCookieName)
	refreshCookieName := strings.TrimSpace(raw.RefreshCookieName)
	if sessionCookieName == "" {
		return Tenant{}, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeMissingSessionCookieName, tenantID)
	}
	if refreshCookieName == "" {
		return Tenant{}, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeMissingRefreshCookieName, tenantID)
	}

	return Tenant{
		id:                   tenantID,
		displayName:          displayName,
		origins:              origins,
		allowedUsers:         allowedUsers,
		googleWebClientID:    googleWebClientID,
		googleNativeClientID: googleNativeClientID,
		nativeGoogleClients:  nativeGoogleClients,
		appleOAuth:           appleOAuth,
		passwordAuthEnabled:  passwordAuthEnabled,
		passwordUsers:        passwordUsers,
		accountManagement:    accountManagement,
		oauthAuthorization:   oauthAuthorization,
		jwtSigningKey:        signingKey,
		cookieDomain:         cookieDomain,
		sessionCookieName:    sessionCookieName,
		refreshCookieName:    refreshCookieName,
		sessionTTL:           sessionTTL,
		refreshTTL:           refreshTTL,
		nonceTTL:             nonceTTL,
		allowInsecureHTTP:    allowInsecureHTTP,
	}, origins, nil
}

func parseNativeGoogleClients(raw FileTenant, tenantID TenantID) ([]NativeGoogleClient, error) {
	clients := make([]NativeGoogleClient, 0, 1+len(raw.GoogleNativeClients))
	legacyClientID := strings.TrimSpace(raw.GoogleNativeClientID)
	if legacyClientID != "" {
		clients = append(clients, NativeGoogleClient{
			platform: defaultNativeGooglePlatform,
			clientID: legacyClientID,
		})
	}
	for _, rawClient := range raw.GoogleNativeClients {
		client, clientErr := parseNativeGoogleClient(rawClient, tenantID)
		if clientErr != nil {
			return nil, clientErr
		}
		clients = append(clients, client)
	}
	return clients, nil
}

func parseNativeGoogleClient(raw FileNativeGoogleClient, tenantID TenantID) (NativeGoogleClient, error) {
	platform := strings.ToLower(strings.TrimSpace(raw.Platform))
	if !nativeGooglePlatformRegex.MatchString(platform) {
		return NativeGoogleClient{}, fmt.Errorf("%w: %s tenant=%s platform=%s", ErrInvalidTenantConfig, errorCodeInvalidNativePlatform, tenantID, platform)
	}
	clientID := strings.TrimSpace(raw.ClientID)
	if clientID == "" {
		return NativeGoogleClient{}, fmt.Errorf("%w: %s tenant=%s platform=%s", ErrInvalidTenantConfig, errorCodeInvalidNativeGoogleID, tenantID, platform)
	}
	redirectURIs, redirectErr := parseNativeGoogleRedirectURIs(raw.RedirectURIs, tenantID, platform)
	if redirectErr != nil {
		return NativeGoogleClient{}, redirectErr
	}
	return NativeGoogleClient{
		platform:     platform,
		clientID:     clientID,
		redirectURIs: redirectURIs,
	}, nil
}

func parseNativeGoogleRedirectURIs(rawRedirectURIs []string, tenantID TenantID, platform string) ([]string, error) {
	if len(rawRedirectURIs) == 0 {
		return nil, nil
	}
	redirectURIs := make([]string, 0, len(rawRedirectURIs))
	seenRedirectURIs := make(map[string]struct{}, len(rawRedirectURIs))
	for _, rawRedirectURI := range rawRedirectURIs {
		redirectURI, redirectErr := normalizeNativeGoogleRedirectURI(rawRedirectURI)
		if redirectErr != nil {
			return nil, fmt.Errorf("%w: %s tenant=%s platform=%s redirect_uri=%s reason=%s", ErrInvalidTenantConfig, errorCodeInvalidNativeRedirectURI, tenantID, platform, rawRedirectURI, redirectErr)
		}
		duplicateKey := strings.ToLower(redirectURI)
		if _, exists := seenRedirectURIs[duplicateKey]; exists {
			return nil, fmt.Errorf("%w: %s tenant=%s platform=%s redirect_uri=%s", ErrInvalidTenantConfig, errorCodeInvalidNativeRedirectURI, tenantID, platform, redirectURI)
		}
		seenRedirectURIs[duplicateKey] = struct{}{}
		redirectURIs = append(redirectURIs, redirectURI)
	}
	return redirectURIs, nil
}

func normalizeNativeGoogleRedirectURI(rawRedirectURI string) (string, error) {
	trimmed := strings.TrimSpace(rawRedirectURI)
	parsedURI, parseErr := url.Parse(trimmed)
	if parseErr != nil {
		return "", parseErr
	}
	if parsedURI.Scheme == "" {
		return "", fmt.Errorf("missing scheme")
	}
	if parsedURI.Fragment != "" {
		return "", fmt.Errorf("fragment is not allowed")
	}
	scheme := strings.ToLower(parsedURI.Scheme)
	if scheme == originSchemeHTTP || scheme == originSchemeHTTPS {
		if parsedURI.Host == "" {
			return "", fmt.Errorf("missing host")
		}
		return trimmed, nil
	}
	if parsedURI.Host == "" && parsedURI.Path == "" && parsedURI.Opaque == "" {
		return "", fmt.Errorf("missing redirect target")
	}
	return trimmed, nil
}

func firstNativeGoogleClientID(clients []NativeGoogleClient) string {
	if len(clients) == 0 {
		return ""
	}
	return clients[0].clientID
}

func tenantHasAuthProvider(googleWebClientID string, nativeGoogleClients []NativeGoogleClient, appleOAuth AppleOAuth, passwordAuthEnabled bool) bool {
	return strings.TrimSpace(googleWebClientID) != "" ||
		len(nativeGoogleClients) > 0 ||
		appleOAuth.Enabled() ||
		passwordAuthEnabled
}

func parseAppleOAuth(raw FileAppleOAuth, tenantID TenantID, allowInsecureHTTP bool) (AppleOAuth, error) {
	enabled := bool(raw.Enabled)
	if !enabled {
		if appleOAuthBlockHasFields(raw) {
			return AppleOAuth{}, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeAppleOAuthDisabled, tenantID)
		}
		return AppleOAuth{}, nil
	}
	clientID := strings.TrimSpace(raw.ClientID)
	if clientID == "" {
		return AppleOAuth{}, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeInvalidAppleClientID, tenantID)
	}
	teamID := strings.TrimSpace(raw.TeamID)
	if teamID == "" {
		return AppleOAuth{}, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeInvalidAppleTeamID, tenantID)
	}
	keyID := strings.TrimSpace(raw.KeyID)
	if keyID == "" {
		return AppleOAuth{}, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeInvalidAppleKeyID, tenantID)
	}
	privateKey, privateKeyErr := parseApplePrivateKey(raw, tenantID)
	if privateKeyErr != nil {
		return AppleOAuth{}, privateKeyErr
	}
	redirectURI, redirectErr := normalizeAppleRedirectURI(raw.RedirectURI, allowInsecureHTTP)
	if redirectErr != nil {
		return AppleOAuth{}, fmt.Errorf("%w: %s tenant=%s redirect_uri=%s reason=%s", ErrInvalidTenantConfig, errorCodeInvalidAppleRedirectURI, tenantID, strings.TrimSpace(raw.RedirectURI), redirectErr)
	}
	scopes, scopeErr := parseAppleScopes(raw.Scopes, tenantID)
	if scopeErr != nil {
		return AppleOAuth{}, scopeErr
	}
	authorizationEndpoint, authorizationErr := parseAppleEndpoint(raw.AuthorizationEndpoint, defaultAppleAuthorizationEndpoint, allowInsecureHTTP)
	if authorizationErr != nil {
		return AppleOAuth{}, fmt.Errorf("%w: %s tenant=%s endpoint=authorization reason=%s", ErrInvalidTenantConfig, errorCodeInvalidAppleEndpoint, tenantID, authorizationErr)
	}
	tokenEndpoint, tokenErr := parseAppleEndpoint(raw.TokenEndpoint, defaultAppleTokenEndpoint, allowInsecureHTTP)
	if tokenErr != nil {
		return AppleOAuth{}, fmt.Errorf("%w: %s tenant=%s endpoint=token reason=%s", ErrInvalidTenantConfig, errorCodeInvalidAppleEndpoint, tenantID, tokenErr)
	}
	jwksURL, jwksErr := parseAppleEndpoint(raw.JWKSURL, defaultAppleJWKSURL, allowInsecureHTTP)
	if jwksErr != nil {
		return AppleOAuth{}, fmt.Errorf("%w: %s tenant=%s endpoint=jwks reason=%s", ErrInvalidTenantConfig, errorCodeInvalidAppleEndpoint, tenantID, jwksErr)
	}
	return AppleOAuth{
		enabled:               true,
		clientID:              clientID,
		teamID:                teamID,
		keyID:                 keyID,
		privateKey:            privateKey,
		redirectURI:           redirectURI,
		scopes:                scopes,
		authorizationEndpoint: authorizationEndpoint,
		tokenEndpoint:         tokenEndpoint,
		jwksURL:               jwksURL,
	}, nil
}

func parseApplePrivateKey(raw FileAppleOAuth, tenantID TenantID) (string, error) {
	privateKey := strings.TrimSpace(raw.PrivateKey)
	privateKeyBase64 := strings.Join(strings.Fields(strings.TrimSpace(raw.PrivateKeyBase64)), "")
	if privateKey != "" && privateKeyBase64 != "" {
		return "", fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeInvalidApplePrivateKey, tenantID)
	}
	if privateKeyBase64 != "" {
		decodedPrivateKey, decodeErr := base64.StdEncoding.DecodeString(privateKeyBase64)
		if decodeErr != nil {
			return "", fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeInvalidApplePrivateKey, tenantID)
		}
		privateKey = strings.TrimSpace(string(decodedPrivateKey))
	}
	if privateKey == "" || !applePrivateKeyPEMValid(privateKey) {
		return "", fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeInvalidApplePrivateKey, tenantID)
	}
	return privateKey, nil
}

func appleOAuthBlockHasFields(raw FileAppleOAuth) bool {
	return strings.TrimSpace(raw.ClientID) != "" ||
		strings.TrimSpace(raw.TeamID) != "" ||
		strings.TrimSpace(raw.KeyID) != "" ||
		strings.TrimSpace(raw.PrivateKey) != "" ||
		strings.TrimSpace(raw.PrivateKeyBase64) != "" ||
		strings.TrimSpace(raw.RedirectURI) != "" ||
		len(raw.Scopes) > 0 ||
		strings.TrimSpace(raw.AuthorizationEndpoint) != "" ||
		strings.TrimSpace(raw.TokenEndpoint) != "" ||
		strings.TrimSpace(raw.JWKSURL) != ""
}

func applePrivateKeyPEMValid(value string) bool {
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		return false
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return false
	}
	_, ok := key.(*ecdsa.PrivateKey)
	return ok
}

func normalizeAppleRedirectURI(rawRedirectURI string, allowInsecureHTTP bool) (string, error) {
	trimmed := strings.TrimSpace(rawRedirectURI)
	parsedURI, parseErr := url.Parse(trimmed)
	if parseErr != nil {
		return "", parseErr
	}
	if parsedURI.Scheme == "" {
		return "", fmt.Errorf("missing scheme")
	}
	if parsedURI.Host == "" {
		return "", fmt.Errorf("missing host")
	}
	if parsedURI.Fragment != "" {
		return "", fmt.Errorf("fragment is not allowed")
	}
	if parsedURI.Scheme != originSchemeHTTPS {
		if !allowInsecureHTTP || parsedURI.Scheme != originSchemeHTTP {
			return "", fmt.Errorf("https required")
		}
	}
	if !allowInsecureHTTP {
		host := parsedURI.Hostname()
		if strings.EqualFold(host, "localhost") || net.ParseIP(host) != nil {
			return "", fmt.Errorf("public domain required")
		}
	}
	return trimmed, nil
}

func parseAppleScopes(rawScopes []string, tenantID TenantID) ([]string, error) {
	if len(rawScopes) == 0 {
		return append([]string(nil), defaultAppleScopes...), nil
	}
	allowedScopes := map[string]struct{}{
		"openid": {},
		"email":  {},
		"name":   {},
	}
	scopes := make([]string, 0, len(rawScopes))
	seenScopes := make(map[string]struct{}, len(rawScopes))
	for _, rawScope := range rawScopes {
		scope := strings.ToLower(strings.TrimSpace(rawScope))
		if _, allowed := allowedScopes[scope]; !allowed {
			return nil, fmt.Errorf("%w: %s tenant=%s scope=%s", ErrInvalidTenantConfig, errorCodeInvalidAppleScope, tenantID, scope)
		}
		if _, exists := seenScopes[scope]; exists {
			continue
		}
		seenScopes[scope] = struct{}{}
		scopes = append(scopes, scope)
	}
	return scopes, nil
}

func parseAppleEndpoint(rawEndpoint string, fallback string, allowInsecureHTTP bool) (string, error) {
	endpoint := strings.TrimSpace(rawEndpoint)
	if endpoint == "" {
		endpoint = fallback
	}
	parsedEndpoint, parseErr := url.Parse(endpoint)
	if parseErr != nil {
		return "", parseErr
	}
	if parsedEndpoint.Scheme == "" || parsedEndpoint.Host == "" {
		return "", fmt.Errorf("absolute url required")
	}
	if parsedEndpoint.Scheme != originSchemeHTTPS {
		if !allowInsecureHTTP || parsedEndpoint.Scheme != originSchemeHTTP {
			return "", fmt.Errorf("https required")
		}
	}
	if parsedEndpoint.Fragment != "" {
		return "", fmt.Errorf("fragment is not allowed")
	}
	return endpoint, nil
}

func parseTenantID(raw string) (TenantID, error) {
	trimmed := strings.TrimSpace(raw)
	if !tenantIDRegex.MatchString(trimmed) {
		return "", fmt.Errorf("%w: %s id=%s", ErrInvalidTenantConfig, errorCodeInvalidID, trimmed)
	}
	return TenantID(trimmed), nil
}

func parseTenantOrigins(origins []string, tenantID TenantID) ([]string, error) {
	if len(origins) == 0 {
		return nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeMissingOrigins, tenantID)
	}
	normalizedOrigins := make([]string, 0, len(origins))
	seenOrigins := make(map[string]struct{})
	for _, origin := range origins {
		normalizedOrigin, err := normalizeOrigin(origin)
		if err != nil {
			return nil, fmt.Errorf("%w: %s tenant=%s origin=%s reason=%s", ErrInvalidTenantConfig, errorCodeInvalidOrigin, tenantID, origin, err)
		}
		if _, exists := seenOrigins[normalizedOrigin]; exists {
			return nil, fmt.Errorf("%w: %s tenant=%s origin=%s", ErrInvalidTenantConfig, errorCodeDuplicateOrigin, tenantID, origin)
		}
		seenOrigins[normalizedOrigin] = struct{}{}
		normalizedOrigins = append(normalizedOrigins, normalizedOrigin)
	}
	return normalizedOrigins, nil
}

func parseAllowedUsers(rawAllowedUsers []string, tenantID TenantID) ([]string, error) {
	if rawAllowedUsers == nil {
		return nil, nil
	}
	if len(rawAllowedUsers) == 0 {
		return []string{}, nil
	}
	normalizedUsers := make([]string, 0, len(rawAllowedUsers))
	seenUsers := make(map[string]struct{}, len(rawAllowedUsers))
	for _, rawUser := range rawAllowedUsers {
		normalizedUser, normalizeErr := normalizeEmailAddress(rawUser)
		if normalizeErr != nil {
			return nil, fmt.Errorf("%w: %s tenant=%s user=%s", ErrInvalidTenantConfig, errorCodeInvalidAllowedUser, tenantID, strings.TrimSpace(rawUser))
		}
		if _, exists := seenUsers[normalizedUser]; exists {
			return nil, fmt.Errorf("%w: %s tenant=%s user=%s", ErrInvalidTenantConfig, errorCodeDuplicateAllowedUser, tenantID, normalizedUser)
		}
		seenUsers[normalizedUser] = struct{}{}
		normalizedUsers = append(normalizedUsers, normalizedUser)
	}
	return normalizedUsers, nil
}

func parsePasswordAuth(raw FilePasswordAuth, tenantID TenantID) (bool, []PasswordUser, error) {
	enabled := bool(raw.Enabled)
	if !enabled {
		if len(raw.Users) > 0 {
			return false, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodePasswordAuthDisabled, tenantID)
		}
		return false, nil, nil
	}
	users := make([]PasswordUser, 0, len(raw.Users))
	seenUsers := make(map[string]struct{}, len(raw.Users))
	for _, rawUser := range raw.Users {
		user, userErr := parsePasswordUser(rawUser, tenantID)
		if userErr != nil {
			return false, nil, userErr
		}
		if _, exists := seenUsers[user.email]; exists {
			return false, nil, fmt.Errorf("%w: %s tenant=%s user=%s", ErrInvalidTenantConfig, errorCodeDuplicatePasswordUser, tenantID, user.email)
		}
		seenUsers[user.email] = struct{}{}
		users = append(users, user)
	}
	return true, users, nil
}

func parsePasswordUser(raw FilePasswordUser, tenantID TenantID) (PasswordUser, error) {
	normalizedEmail, emailErr := normalizeEmailAddress(raw.Email)
	if emailErr != nil {
		return PasswordUser{}, fmt.Errorf("%w: %s tenant=%s user=%s", ErrInvalidTenantConfig, errorCodeInvalidPasswordUser, tenantID, strings.TrimSpace(raw.Email))
	}
	passwordHash := strings.TrimSpace(raw.PasswordHash)
	if passwordHash == "" {
		return PasswordUser{}, fmt.Errorf("%w: %s tenant=%s user=%s", ErrInvalidTenantConfig, errorCodeInvalidPasswordHash, tenantID, normalizedEmail)
	}
	if _, hashErr := bcrypt.Cost([]byte(passwordHash)); hashErr != nil {
		return PasswordUser{}, fmt.Errorf("%w: %s tenant=%s user=%s", ErrInvalidTenantConfig, errorCodeInvalidPasswordHash, tenantID, normalizedEmail)
	}
	displayName := strings.TrimSpace(raw.DisplayName)
	if displayName == "" {
		displayName = normalizedEmail
	}
	return PasswordUser{
		email:        normalizedEmail,
		displayName:  displayName,
		avatarURL:    strings.TrimSpace(raw.AvatarURL),
		passwordHash: passwordHash,
	}, nil
}

func parseAccountManagement(raw FileAccountManagement, tenantID TenantID) (AccountManagement, error) {
	enabled := bool(raw.Enabled)
	passwordSignupEnabled := bool(raw.PasswordSignup.Enabled)
	if !enabled && passwordSignupEnabled {
		return AccountManagement{}, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeAccountManagementDisabled, tenantID)
	}
	emailVerificationTTL := defaultEmailVerificationTTL
	if strings.TrimSpace(raw.EmailVerificationTTL) != "" {
		parsedTTL, ttlErr := parseDuration(raw.EmailVerificationTTL)
		if ttlErr != nil || parsedTTL <= 0 {
			return AccountManagement{}, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeInvalidEmailVerificationTTL, tenantID)
		}
		emailVerificationTTL = parsedTTL
	}
	passwordResetTTL := defaultPasswordResetTTL
	if strings.TrimSpace(raw.PasswordResetTTL) != "" {
		parsedTTL, ttlErr := parseDuration(raw.PasswordResetTTL)
		if ttlErr != nil || parsedTTL <= 0 {
			return AccountManagement{}, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeInvalidPasswordResetTTL, tenantID)
		}
		passwordResetTTL = parsedTTL
	}
	return AccountManagement{
		enabled:               enabled,
		passwordSignupEnabled: passwordSignupEnabled,
		returnChallengeTokens: bool(raw.ReturnChallengeTokens),
		emailVerificationTTL:  emailVerificationTTL,
		passwordResetTTL:      passwordResetTTL,
	}, nil
}

func normalizeEmailAddress(rawEmail string) (string, error) {
	trimmedEmail := strings.TrimSpace(rawEmail)
	if trimmedEmail == "" {
		return "", fmt.Errorf("missing email")
	}
	normalizedEmail := strings.ToLower(trimmedEmail)
	parsedAddress, parseErr := mail.ParseAddress(normalizedEmail)
	if parseErr != nil {
		return "", parseErr
	}
	if parsedAddress.Address != normalizedEmail {
		return "", fmt.Errorf("email must not include display name")
	}
	return normalizedEmail, nil
}

func buildTenantCookieScope(tenant Tenant, origins []string) (tenantCookieScope, error) {
	hostnames, hostErr := extractTenantHostnames(tenant.id, origins)
	if hostErr != nil {
		return tenantCookieScope{}, hostErr
	}
	return tenantCookieScope{
		tenantID:          tenant.id,
		cookieDomain:      normalizeCookieDomain(tenant.cookieDomain),
		hostnames:         hostnames,
		sessionCookieName: tenant.sessionCookieName,
		refreshCookieName: tenant.refreshCookieName,
	}, nil
}

func extractTenantHostnames(tenantID TenantID, origins []string) ([]string, error) {
	hostSet := make(map[string]struct{})
	for _, origin := range origins {
		originHost, originErr := hostFromOrigin(origin)
		if originErr != nil {
			return nil, fmt.Errorf(cookieScopeOriginErrorFormat, ErrInvalidTenantConfig, errorCodeInvalidCookieScope, tenantID, origin)
		}
		hostSet[originHost] = struct{}{}
	}
	if len(hostSet) == 0 {
		return nil, fmt.Errorf(cookieScopeErrorFormat, ErrInvalidTenantConfig, errorCodeInvalidCookieScope, tenantID)
	}
	hostnames := make([]string, 0, len(hostSet))
	for hostname := range hostSet {
		hostnames = append(hostnames, hostname)
	}
	sort.Strings(hostnames)
	return hostnames, nil
}

func hostFromOrigin(origin string) (string, error) {
	hostValue, _, hostErr := hostPortFromOrigin(origin)
	if hostErr != nil {
		return "", hostErr
	}
	return hostValue, nil
}

func hostPortFromOrigin(origin string) (string, string, error) {
	normalizedOrigin, normalizeErr := normalizeOrigin(origin)
	if normalizeErr != nil {
		return "", "", normalizeErr
	}
	parsed, parseErr := url.Parse(normalizedOrigin)
	if parseErr != nil {
		return "", "", parseErr
	}
	if parsed.Host == "" {
		return "", "", fmt.Errorf("origin host missing")
	}
	hostValue, portValue, hostErr := normalizeHostPort(parsed.Host)
	if hostErr != nil {
		return "", "", hostErr
	}
	return hostValue, portValue, nil
}

func validateCookieNameIsolation(cookieScopes []tenantCookieScope) error {
	if len(cookieScopes) < 2 {
		return nil
	}
	for firstIndex := 0; firstIndex < len(cookieScopes); firstIndex++ {
		firstScope := cookieScopes[firstIndex]
		for secondIndex := firstIndex + 1; secondIndex < len(cookieScopes); secondIndex++ {
			secondScope := cookieScopes[secondIndex]
			overlapDescription, overlaps := cookieScopesOverlap(firstScope, secondScope)
			if !overlaps {
				continue
			}
			if firstScope.sessionCookieName == secondScope.sessionCookieName {
				return fmt.Errorf(duplicateCookieNameErrorFormat, ErrInvalidTenantConfig, errorCodeDuplicateSessionCookieName, firstScope.sessionCookieName, firstScope.tenantID, secondScope.tenantID, overlapDescription)
			}
			if firstScope.refreshCookieName == secondScope.refreshCookieName {
				return fmt.Errorf(duplicateCookieNameErrorFormat, ErrInvalidTenantConfig, errorCodeDuplicateRefreshCookieName, firstScope.refreshCookieName, firstScope.tenantID, secondScope.tenantID, overlapDescription)
			}
			if firstScope.sessionCookieName == secondScope.refreshCookieName {
				return fmt.Errorf(duplicateCookieNameErrorFormat, ErrInvalidTenantConfig, errorCodeDuplicateCookieNameCross, firstScope.sessionCookieName, firstScope.tenantID, secondScope.tenantID, overlapDescription)
			}
			if firstScope.refreshCookieName == secondScope.sessionCookieName {
				return fmt.Errorf(duplicateCookieNameErrorFormat, ErrInvalidTenantConfig, errorCodeDuplicateCookieNameCross, firstScope.refreshCookieName, firstScope.tenantID, secondScope.tenantID, overlapDescription)
			}
		}
	}
	return nil
}

func cookieScopesOverlap(firstScope tenantCookieScope, secondScope tenantCookieScope) (string, bool) {
	firstDomain := firstScope.cookieDomain
	secondDomain := secondScope.cookieDomain
	if firstDomain != "" && secondDomain != "" {
		if domainsOverlap(firstDomain, secondDomain) {
			return fmt.Sprintf(cookieOverlapDomainFormat, overlappingDomain(firstDomain, secondDomain)), true
		}
		return "", false
	}
	if firstDomain != "" {
		return domainHostOverlap(firstDomain, secondScope.hostnames)
	}
	if secondDomain != "" {
		return domainHostOverlap(secondDomain, firstScope.hostnames)
	}
	sharedHost := sharedHostName(firstScope.hostnames, secondScope.hostnames)
	if sharedHost == "" {
		return "", false
	}
	return fmt.Sprintf(cookieOverlapHostFormat, sharedHost), true
}

func domainHostOverlap(domain string, hostnames []string) (string, bool) {
	hostMatch := hostMatchingDomain(domain, hostnames)
	if hostMatch == "" {
		return "", false
	}
	return fmt.Sprintf(cookieOverlapHostFormat, hostMatch), true
}

func hostMatchingDomain(domain string, hostnames []string) string {
	for _, hostValue := range hostnames {
		if domainContainsHost(domain, hostValue) {
			return hostValue
		}
	}
	return ""
}

func sharedHostName(firstHostnames []string, secondHostnames []string) string {
	if len(firstHostnames) == 0 || len(secondHostnames) == 0 {
		return ""
	}
	hostSet := make(map[string]struct{}, len(firstHostnames))
	for _, hostValue := range firstHostnames {
		hostSet[hostValue] = struct{}{}
	}
	for _, hostValue := range secondHostnames {
		if _, exists := hostSet[hostValue]; exists {
			return hostValue
		}
	}
	return ""
}

func domainsOverlap(firstDomain string, secondDomain string) bool {
	if firstDomain == "" || secondDomain == "" {
		return false
	}
	if firstDomain == secondDomain {
		return true
	}
	if domainContainsHost(firstDomain, secondDomain) {
		return true
	}
	if domainContainsHost(secondDomain, firstDomain) {
		return true
	}
	return false
}

func overlappingDomain(firstDomain string, secondDomain string) string {
	if firstDomain == secondDomain {
		return firstDomain
	}
	if domainContainsHost(firstDomain, secondDomain) {
		return firstDomain
	}
	if domainContainsHost(secondDomain, firstDomain) {
		return secondDomain
	}
	return firstDomain
}

func domainContainsHost(domain string, host string) bool {
	normalizedDomain := normalizeCookieDomain(domain)
	normalizedHost := normalizeHost(host)
	if normalizedDomain == "" || normalizedHost == "" {
		return false
	}
	if normalizedDomain == normalizedHost {
		return true
	}
	return strings.HasSuffix(normalizedHost, cookieDomainSeparator+normalizedDomain)
}

func normalizeCookieDomain(domain string) string {
	trimmed := strings.TrimSpace(domain)
	if trimmed == "" {
		return ""
	}
	lowered := strings.ToLower(trimmed)
	return strings.TrimLeft(lowered, cookieDomainSeparator)
}

func normalizeHost(host string) string {
	normalized := strings.ToLower(strings.TrimSpace(host))
	if strings.HasPrefix(normalized, "[") && strings.HasSuffix(normalized, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(normalized, "["), "]")
	}
	return normalized
}

func normalizeHostPort(host string) (string, string, error) {
	trimmed := strings.TrimSpace(host)
	if trimmed == "" {
		return "", "", fmt.Errorf("missing host")
	}
	value := trimmed
	port := ""
	if strings.HasPrefix(trimmed, "[") {
		closing := strings.Index(trimmed, "]")
		if closing < 0 {
			return "", "", fmt.Errorf("invalid host")
		}
		rest := strings.TrimSpace(trimmed[closing+1:])
		value = trimmed[:closing+1]
		if strings.HasPrefix(rest, ":") {
			port = strings.TrimSpace(rest[1:])
		}
	} else {
		colon := strings.LastIndex(trimmed, ":")
		if colon > -1 && strings.Count(trimmed, ":") == 1 {
			value = trimmed[:colon]
			port = strings.TrimSpace(trimmed[colon+1:])
		}
	}
	normalizedHost := normalizeHost(value)
	if normalizedHost == "" {
		return "", "", fmt.Errorf("invalid host")
	}
	if port != "" {
		if _, err := strconv.Atoi(port); err != nil {
			return "", "", fmt.Errorf("invalid port")
		}
	}
	return normalizedHost, port, nil
}

func normalizeOrigin(origin string) (string, error) {
	trimmed := strings.TrimSpace(origin)
	parsedURL, err := url.Parse(trimmed)
	if err != nil {
		return "", originError(originReasonInvalidURL)
	}
	scheme := strings.ToLower(parsedURL.Scheme)
	if scheme == "" {
		return "", originError(originReasonMissingScheme)
	}
	if scheme != originSchemeHTTP && scheme != originSchemeHTTPS {
		return "", originError(fmt.Sprintf("%s: %s", originReasonUnsupportedScheme, scheme))
	}
	if parsedURL.Host == "" {
		return "", originError(originReasonMissingHost)
	}
	if parsedURL.Path != "" || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return "", originError(originReasonUnexpectedPath)
	}
	host := strings.ToLower(parsedURL.Host)
	return fmt.Sprintf("%s://%s", scheme, host), nil
}

func originError(reason string) error {
	return fmt.Errorf("%s (%s)", reason, originExpectation)
}

// NormalizeOrigin returns the canonical origin string or an error for invalid origins.
func NormalizeOrigin(origin string) (string, error) {
	return normalizeOrigin(origin)
}

func parseDuration(raw string) (time.Duration, error) {
	return time.ParseDuration(strings.TrimSpace(raw))
}

// FileDocument represents the raw tenants YAML schema.
type FileDocument struct {
	Tenants []FileTenant `json:"tenants" yaml:"tenants"`
}

func expandFileDocumentEnv(document FileDocument) FileDocument {
	for index := range document.Tenants {
		document.Tenants[index] = expandFileTenantEnv(document.Tenants[index])
	}
	return document
}

func expandFileTenantEnv(tenant FileTenant) FileTenant {
	tenant.ID = os.ExpandEnv(tenant.ID)
	tenant.DisplayName = os.ExpandEnv(tenant.DisplayName)
	tenant.TenantOrigins = expandEnvSlice(tenant.TenantOrigins)
	tenant.AllowedUsers = expandEnvSlice(tenant.AllowedUsers)
	tenant.GoogleWebClientID = os.ExpandEnv(tenant.GoogleWebClientID)
	tenant.GoogleNativeClientID = os.ExpandEnv(tenant.GoogleNativeClientID)
	for index := range tenant.GoogleNativeClients {
		tenant.GoogleNativeClients[index].Platform = os.ExpandEnv(tenant.GoogleNativeClients[index].Platform)
		tenant.GoogleNativeClients[index].ClientID = os.ExpandEnv(tenant.GoogleNativeClients[index].ClientID)
		tenant.GoogleNativeClients[index].RedirectURIs = expandEnvSlice(tenant.GoogleNativeClients[index].RedirectURIs)
	}
	tenant.AppleOAuth.ClientID = os.ExpandEnv(tenant.AppleOAuth.ClientID)
	tenant.AppleOAuth.TeamID = os.ExpandEnv(tenant.AppleOAuth.TeamID)
	tenant.AppleOAuth.KeyID = os.ExpandEnv(tenant.AppleOAuth.KeyID)
	tenant.AppleOAuth.PrivateKey = os.ExpandEnv(tenant.AppleOAuth.PrivateKey)
	tenant.AppleOAuth.PrivateKeyBase64 = os.ExpandEnv(tenant.AppleOAuth.PrivateKeyBase64)
	tenant.AppleOAuth.RedirectURI = os.ExpandEnv(tenant.AppleOAuth.RedirectURI)
	tenant.AppleOAuth.Scopes = expandEnvSlice(tenant.AppleOAuth.Scopes)
	tenant.AppleOAuth.AuthorizationEndpoint = os.ExpandEnv(tenant.AppleOAuth.AuthorizationEndpoint)
	tenant.AppleOAuth.TokenEndpoint = os.ExpandEnv(tenant.AppleOAuth.TokenEndpoint)
	tenant.AppleOAuth.JWKSURL = os.ExpandEnv(tenant.AppleOAuth.JWKSURL)
	for index := range tenant.PasswordAuth.Users {
		tenant.PasswordAuth.Users[index].Email = os.ExpandEnv(tenant.PasswordAuth.Users[index].Email)
		tenant.PasswordAuth.Users[index].DisplayName = os.ExpandEnv(tenant.PasswordAuth.Users[index].DisplayName)
		tenant.PasswordAuth.Users[index].AvatarURL = os.ExpandEnv(tenant.PasswordAuth.Users[index].AvatarURL)
		tenant.PasswordAuth.Users[index].PasswordHash = expandPasswordHashEnv(tenant.PasswordAuth.Users[index].PasswordHash)
	}
	tenant.AccountManagement.EmailVerificationTTL = os.ExpandEnv(tenant.AccountManagement.EmailVerificationTTL)
	tenant.AccountManagement.PasswordResetTTL = os.ExpandEnv(tenant.AccountManagement.PasswordResetTTL)
	tenant.OAuth = expandFileOAuthAuthorizationEnv(tenant.OAuth)
	tenant.JWTSigningKey = os.ExpandEnv(tenant.JWTSigningKey)
	tenant.CookieDomain = os.ExpandEnv(tenant.CookieDomain)
	tenant.SessionCookieName = os.ExpandEnv(tenant.SessionCookieName)
	tenant.RefreshCookieName = os.ExpandEnv(tenant.RefreshCookieName)
	tenant.SessionTTL = os.ExpandEnv(tenant.SessionTTL)
	tenant.RefreshTTL = os.ExpandEnv(tenant.RefreshTTL)
	tenant.NonceTTL = os.ExpandEnv(tenant.NonceTTL)
	return tenant
}

func expandPasswordHashEnv(value string) string {
	trimmedValue := strings.TrimSpace(value)
	if strings.HasPrefix(trimmedValue, "$2a$") || strings.HasPrefix(trimmedValue, "$2b$") || strings.HasPrefix(trimmedValue, "$2y$") {
		return value
	}
	return os.ExpandEnv(value)
}

func expandEnvSlice(values []string) []string {
	if len(values) == 0 {
		return values
	}
	expanded := make([]string, len(values))
	for index, value := range values {
		expanded[index] = os.ExpandEnv(value)
	}
	return expanded
}

// FileTenant represents a single tenant entry inside the YAML document.
type FileTenant struct {
	ID                   string                   `json:"id" yaml:"id"`
	DisplayName          string                   `json:"display_name" yaml:"display_name"`
	TenantOrigins        []string                 `json:"tenant_origins" yaml:"tenant_origins"`
	AllowedUsers         []string                 `json:"allowed_users" yaml:"allowed_users"`
	GoogleWebClientID    string                   `json:"google_web_client_id" yaml:"google_web_client_id"`
	GoogleNativeClientID string                   `json:"google_native_client_id" yaml:"google_native_client_id"`
	GoogleNativeClients  []FileNativeGoogleClient `json:"google_native_clients" yaml:"google_native_clients"`
	AppleOAuth           FileAppleOAuth           `json:"apple_oauth" yaml:"apple_oauth"`
	PasswordAuth         FilePasswordAuth         `json:"password_auth" yaml:"password_auth"`
	AccountManagement    FileAccountManagement    `json:"account_management" yaml:"account_management"`
	OAuth                FileOAuthAuthorization   `json:"oauth" yaml:"oauth"`
	JWTSigningKey        string                   `json:"jwt_signing_key" yaml:"jwt_signing_key"`
	CookieDomain         string                   `json:"cookie_domain" yaml:"cookie_domain"`
	SessionCookieName    string                   `json:"session_cookie_name" yaml:"session_cookie_name"`
	RefreshCookieName    string                   `json:"refresh_cookie_name" yaml:"refresh_cookie_name"`
	SessionTTL           string                   `json:"session_ttl" yaml:"session_ttl"`
	RefreshTTL           string                   `json:"refresh_ttl" yaml:"refresh_ttl"`
	NonceTTL             string                   `json:"nonce_ttl" yaml:"nonce_ttl"`
	AllowInsecureHTTP    yamlBool                 `json:"allow_insecure_http" yaml:"allow_insecure_http"`
}

// FileNativeGoogleClient represents one raw native Google client entry.
type FileNativeGoogleClient struct {
	Platform     string   `json:"platform" yaml:"platform"`
	ClientID     string   `json:"client_id" yaml:"client_id"`
	RedirectURIs []string `json:"redirect_uris" yaml:"redirect_uris"`
}

// FileAppleOAuth represents the raw Sign in with Apple tenant block.
type FileAppleOAuth struct {
	Enabled               yamlBool `json:"enabled" yaml:"enabled"`
	ClientID              string   `json:"client_id" yaml:"client_id"`
	TeamID                string   `json:"team_id" yaml:"team_id"`
	KeyID                 string   `json:"key_id" yaml:"key_id"`
	PrivateKey            string   `json:"private_key" yaml:"private_key"`
	PrivateKeyBase64      string   `json:"private_key_base64" yaml:"private_key_base64"`
	RedirectURI           string   `json:"redirect_uri" yaml:"redirect_uri"`
	Scopes                []string `json:"scopes" yaml:"scopes"`
	AuthorizationEndpoint string   `json:"authorization_endpoint" yaml:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint" yaml:"token_endpoint"`
	JWKSURL               string   `json:"jwks_url" yaml:"jwks_url"`
}

// FilePasswordAuth represents the raw password-auth tenant block.
type FilePasswordAuth struct {
	Enabled yamlBool           `json:"enabled" yaml:"enabled"`
	Users   []FilePasswordUser `json:"users" yaml:"users"`
}

// FilePasswordUser represents one raw password-auth user.
type FilePasswordUser struct {
	Email        string `json:"email" yaml:"email"`
	DisplayName  string `json:"display_name" yaml:"display_name"`
	AvatarURL    string `json:"avatar_url" yaml:"avatar_url"`
	PasswordHash string `json:"password_hash" yaml:"password_hash"`
}

// FileAccountManagement represents the raw account-management tenant block.
type FileAccountManagement struct {
	Enabled               yamlBool           `json:"enabled" yaml:"enabled"`
	PasswordSignup        FilePasswordSignup `json:"password_signup" yaml:"password_signup"`
	ReturnChallengeTokens yamlBool           `json:"return_challenge_tokens" yaml:"return_challenge_tokens"`
	EmailVerificationTTL  string             `json:"email_verification_ttl" yaml:"email_verification_ttl"`
	PasswordResetTTL      string             `json:"password_reset_ttl" yaml:"password_reset_ttl"`
}

// FilePasswordSignup represents the raw public signup toggle.
type FilePasswordSignup struct {
	Enabled yamlBool `json:"enabled" yaml:"enabled"`
}

type yamlBool bool

func (value *yamlBool) UnmarshalYAML(node *yaml.Node) error {
	switch node.Tag {
	case "!!bool":
		var parsed bool
		if err := node.Decode(&parsed); err != nil {
			return err
		}
		*value = yamlBool(parsed)
		return nil
	case "!!str":
		parsed, err := strconv.ParseBool(strings.TrimSpace(os.ExpandEnv(node.Value)))
		if err != nil {
			return err
		}
		*value = yamlBool(parsed)
		return nil
	case "!!int":
		var parsed int
		if err := node.Decode(&parsed); err != nil {
			return err
		}
		*value = yamlBool(parsed != 0)
		return nil
	default:
		var parsed bool
		if err := node.Decode(&parsed); err != nil {
			return err
		}
		*value = yamlBool(parsed)
		return nil
	}
}

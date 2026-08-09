package authkit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var (
	// ErrOAuthBrowserSessionMissing means the request has no valid tenant session.
	ErrOAuthBrowserSessionMissing = errors.New("oauth.browser_session_missing")
	// ErrOAuthBrowserLoginInvalid means the supplied browser login was not accepted.
	ErrOAuthBrowserLoginInvalid = errors.New("oauth.browser_login_invalid")
)

// OAuthBrowserSessions resolves and creates the normal TAuth browser session for OAuth pages.
type OAuthBrowserSessions struct {
	registry            TenantRegistry
	users               UserStore
	refreshTokens       RefreshTokenStore
	nonces              NonceStore
	passwordCredentials PasswordCredentialStore
	accountStore        AccountManagementStore
	clock               Clock
}

// NewOAuthBrowserSessions connects OAuth browser pages to the existing TAuth identity stores.
func NewOAuthBrowserSessions(
	registry TenantRegistry,
	users UserStore,
	refreshTokens RefreshTokenStore,
	nonces NonceStore,
	passwordCredentials PasswordCredentialStore,
) *OAuthBrowserSessions {
	clock := configuredClock
	if clock == nil {
		clock = NewSystemClock()
	}
	accountStore, _ := passwordCredentials.(AccountManagementStore)
	return &OAuthBrowserSessions{
		registry: registry, users: users, refreshTokens: refreshTokens,
		nonces: nonces, passwordCredentials: passwordCredentials, accountStore: accountStore, clock: clock,
	}
}

// LoginMethods returns the issuer-page authentication methods for one tenant.
func (sessions *OAuthBrowserSessions) LoginMethods(tenantID string) (bool, string, error) {
	config, exists := sessions.registry.ConfigByID(tenantID)
	if !exists {
		return false, "", ErrOAuthBrowserLoginInvalid
	}
	return config.PasswordAuthEnabled, strings.TrimSpace(config.GoogleWebClientID), nil
}

// IssueGoogleNonce creates the one-time nonce used by Google Identity Services.
func (sessions *OAuthBrowserSessions) IssueGoogleNonce(ctx context.Context, tenantID string) (string, error) {
	config, exists := sessions.registry.ConfigByID(tenantID)
	if !exists || strings.TrimSpace(config.GoogleWebClientID) == "" || sessions.nonces == nil {
		return "", ErrOAuthBrowserLoginInvalid
	}
	nonce, issueErr := sessions.nonces.Issue(ctx, tenantID)
	if issueErr != nil {
		return "", fmt.Errorf("oauth.browser_login_nonce: %w", issueErr)
	}
	return nonce, nil
}

// Resolve returns the authenticated application user for one exact tenant.
func (sessions *OAuthBrowserSessions) Resolve(request *http.Request, tenantID string) (string, error) {
	config, exists := sessions.registry.ConfigByID(tenantID)
	if !exists {
		return "", ErrOAuthBrowserSessionMissing
	}
	claims, validateErr := validateSessionRequest(request, config)
	if validateErr != nil || claims.GetTenantID() != tenantID || strings.TrimSpace(claims.GetUserID()) == "" {
		return "", ErrOAuthBrowserSessionMissing
	}
	return claims.GetUserID(), nil
}

// LoginPassword verifies credentials and writes the standard TAuth session cookies.
func (sessions *OAuthBrowserSessions) LoginPassword(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	tenantID string,
	email string,
	password string,
) (bool, error) {
	config, exists := sessions.registry.ConfigByID(tenantID)
	if !exists || !config.PasswordAuthEnabled || sessions.passwordCredentials == nil || sessions.users == nil || sessions.refreshTokens == nil {
		return false, nil
	}
	if !config.AllowInsecureHTTP && !isHTTPS(request) {
		return false, nil
	}
	normalizedEmail, emailErr := normalizePasswordEmail(email)
	if emailErr != nil || strings.TrimSpace(password) == "" || !isAllowedUser(normalizedEmail, config.AllowedUsers) {
		return false, nil
	}
	credential, authenticateErr := sessions.passwordCredentials.AuthenticatePassword(ctx, tenantID, normalizedEmail, password)
	if authenticateErr != nil {
		return false, nil
	}
	profile, profileErr := sessions.applicationProfile(ctx, config, tenantID, credential)
	if profileErr != nil {
		if errors.Is(profileErr, ErrOAuthBrowserLoginInvalid) {
			return false, nil
		}
		return false, profileErr
	}
	if sessionErr := sessions.writeBrowserSession(ctx, response, config, tenantID, profile); sessionErr != nil {
		return false, sessionErr
	}
	return true, nil
}

// LoginGoogle validates one Google ID token and writes the standard TAuth session cookies.
func (sessions *OAuthBrowserSessions) LoginGoogle(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	tenantID string,
	googleIDToken string,
	nonceToken string,
) (bool, error) {
	config, exists := sessions.registry.ConfigByID(tenantID)
	if !exists || strings.TrimSpace(config.GoogleWebClientID) == "" || sessions.nonces == nil || sessions.users == nil || sessions.refreshTokens == nil {
		return false, nil
	}
	if !config.AllowInsecureHTTP && !isHTTPS(request) {
		return false, nil
	}
	validator, validatorErr := resolveGoogleValidator(ctx)
	if validatorErr != nil {
		return false, fmt.Errorf("oauth.browser_login_google_validator: %w", validatorErr)
	}
	_, identity, identityErr := validateGoogleIdentityToken(ctx, validator, googleIDToken, config.GoogleWebClientID)
	if identityErr != nil {
		return false, nil
	}
	nonceClaim := strings.TrimSpace(identity.Nonce)
	if nonceClaim == "" || (nonceClaim != nonceToken && nonceClaim != hashOpaque(nonceToken)) {
		return false, nil
	}
	if consumeErr := sessions.nonces.Consume(ctx, tenantID, nonceToken); consumeErr != nil {
		if errors.Is(consumeErr, ErrNonceNotFound) || errors.Is(consumeErr, ErrNonceExpired) {
			return false, nil
		}
		return false, fmt.Errorf("oauth.browser_login_nonce: %w", consumeErr)
	}
	if identity.Sub == "" || identity.Email == "" || !identity.EmailVerified || !isAllowedUser(identity.Email, config.AllowedUsers) {
		return false, nil
	}
	profile, profileErr := sessions.googleApplicationProfile(ctx, config, tenantID, identity)
	if profileErr != nil {
		if errors.Is(profileErr, ErrOAuthBrowserLoginInvalid) {
			return false, nil
		}
		return false, profileErr
	}
	if sessionErr := sessions.writeBrowserSession(ctx, response, config, tenantID, profile); sessionErr != nil {
		return false, sessionErr
	}
	return true, nil
}

func (sessions *OAuthBrowserSessions) googleApplicationProfile(ctx context.Context, config ServerConfig, tenantID string, identity googleIdentity) (authenticatedSessionProfile, error) {
	if config.AccountManagementEnabled {
		if sessions.accountStore == nil {
			return authenticatedSessionProfile{}, fmt.Errorf("oauth.browser_login_account_store")
		}
		providerIdentity := AccountProviderIdentity{
			Provider: accountProviderGoogle, Subject: identity.Sub, UserEmail: identity.Email,
			DisplayName: identity.DisplayName, AvatarURL: identity.AvatarURL,
		}
		account, found, accountErr := sessions.accountStore.AuthenticateProviderAccount(ctx, tenantID, providerIdentity)
		if accountErr != nil {
			return authenticatedSessionProfile{}, fmt.Errorf("oauth.browser_login_account_store: %w", accountErr)
		}
		if !found {
			account, accountErr = sessions.accountStore.UpsertProviderAccount(ctx, tenantID, providerIdentity)
			if accountErr != nil {
				return authenticatedSessionProfile{}, fmt.Errorf("oauth.browser_login_account_store: %w", accountErr)
			}
		}
		if account.State != accountStateActive {
			return authenticatedSessionProfile{}, ErrOAuthBrowserLoginInvalid
		}
		applicationUserID, roles, upsertErr := sessions.users.UpsertAccountUser(ctx, tenantID, account.AccountID, account.UserEmail, account.DisplayName, account.AvatarURL)
		if upsertErr != nil || strings.TrimSpace(applicationUserID) == "" {
			return authenticatedSessionProfile{}, fmt.Errorf("oauth.browser_login_user_store")
		}
		return authenticatedSessionProfile{
			applicationUserID: applicationUserID, userEmail: account.UserEmail,
			userDisplayName: account.DisplayName, userAvatarURL: account.AvatarURL, userRoles: roles,
		}, nil
	}
	applicationUserID, roles, upsertErr := sessions.users.UpsertProviderUser(
		ctx, tenantID, accountProviderGoogle, identity.Sub, identity.Email, identity.DisplayName, identity.AvatarURL,
	)
	if upsertErr != nil || strings.TrimSpace(applicationUserID) == "" {
		return authenticatedSessionProfile{}, fmt.Errorf("oauth.browser_login_user_store")
	}
	return authenticatedSessionProfile{
		applicationUserID: applicationUserID, userEmail: identity.Email,
		userDisplayName: identity.DisplayName, userAvatarURL: identity.AvatarURL, userRoles: roles,
	}, nil
}

func (sessions *OAuthBrowserSessions) writeBrowserSession(ctx context.Context, response http.ResponseWriter, config ServerConfig, tenantID string, profile authenticatedSessionProfile) error {
	sessionToken, sessionExpiresAt, mintErr := MintAppJWT(
		sessions.clock,
		tenantID,
		profile.applicationUserID,
		profile.userEmail,
		profile.userDisplayName,
		profile.userAvatarURL,
		profile.userRoles,
		config.AppJWTIssuer,
		config.AppJWTSigningKey,
		config.SessionTTL,
	)
	if mintErr != nil {
		return fmt.Errorf("oauth.browser_login_session: %w", mintErr)
	}
	refreshExpiresAt := sessions.clock.Now().UTC().Add(config.RefreshTTL)
	_, refreshToken, refreshErr := sessions.refreshTokens.Issue(ctx, tenantID, profile.applicationUserID, refreshExpiresAt.Unix(), "")
	if refreshErr != nil || strings.TrimSpace(refreshToken) == "" {
		return fmt.Errorf("oauth.browser_login_refresh")
	}
	writeOAuthBrowserCookie(response, config, config.SessionCookieName, sessionToken, "/", sessionExpiresAt)
	writeOAuthBrowserCookie(response, config, config.RefreshCookieName, refreshToken, "/auth", refreshExpiresAt)
	return nil
}

func (sessions *OAuthBrowserSessions) applicationProfile(
	ctx context.Context,
	config ServerConfig,
	tenantID string,
	credential PasswordCredentialProfile,
) (authenticatedSessionProfile, error) {
	if config.AccountManagementEnabled {
		if sessions.accountStore == nil {
			return authenticatedSessionProfile{}, fmt.Errorf("oauth.browser_login_account_store")
		}
		account, accountErr := sessions.accountStore.EnsurePasswordAccount(ctx, tenantID, credential.UserEmail)
		if accountErr != nil || account.State != accountStateActive {
			return authenticatedSessionProfile{}, ErrOAuthBrowserLoginInvalid
		}
		applicationUserID, roles, upsertErr := sessions.users.UpsertAccountUser(ctx, tenantID, account.AccountID, account.UserEmail, account.DisplayName, account.AvatarURL)
		if upsertErr != nil || strings.TrimSpace(applicationUserID) == "" {
			return authenticatedSessionProfile{}, fmt.Errorf("oauth.browser_login_user_store")
		}
		return authenticatedSessionProfile{
			applicationUserID: applicationUserID, userEmail: account.UserEmail,
			userDisplayName: account.DisplayName, userAvatarURL: account.AvatarURL, userRoles: roles,
		}, nil
	}
	applicationUserID, roles, upsertErr := sessions.users.UpsertPasswordUser(ctx, tenantID, credential.UserEmail, credential.DisplayName, credential.AvatarURL)
	if upsertErr != nil || strings.TrimSpace(applicationUserID) == "" {
		return authenticatedSessionProfile{}, fmt.Errorf("oauth.browser_login_user_store")
	}
	return authenticatedSessionProfile{
		applicationUserID: applicationUserID, userEmail: credential.UserEmail,
		userDisplayName: credential.DisplayName, userAvatarURL: credential.AvatarURL, userRoles: roles,
	}, nil
}

func writeOAuthBrowserCookie(response http.ResponseWriter, config ServerConfig, name string, value string, path string, expiresAt time.Time) {
	http.SetCookie(response, &http.Cookie{
		Name: name, Value: value, Path: path, Domain: config.CookieDomain, Expires: expiresAt,
		Secure: !config.AllowInsecureHTTP, HttpOnly: true, SameSite: config.SameSiteMode,
	})
}

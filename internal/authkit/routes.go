package authkit

import (
	"context"
	"errors"
	"fmt"

	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/web"
	sessionvalidator "github.com/tyemirov/tauth/pkg/sessionvalidator"
	"go.uber.org/zap"
	"google.golang.org/api/idtoken"
)

type GoogleTokenValidator interface {
	Validate(ctx context.Context, idToken string, audience string) (*idtoken.Payload, error)
}

var newGoogleTokenValidator = func(ctx context.Context) (GoogleTokenValidator, error) {
	return idtoken.NewValidator(ctx)
}

// NewGoogleTokenValidator exposes the default validator constructor.
func NewGoogleTokenValidator(ctx context.Context) (GoogleTokenValidator, error) {
	return newGoogleTokenValidator(ctx)
}

var configuredGoogleValidator GoogleTokenValidator
var configuredClock Clock
var configuredLogger *zap.Logger
var configuredMetrics MetricsRecorder

var validatorCache struct {
	sync.RWMutex
	value GoogleTokenValidator
}

var errMissingTenantContext = errors.New("auth.tenant.missing_context")
var errInvalidGoogleIssuer = errors.New("auth.login.invalid_issuer")
var errGoogleLoginUserStore = errors.New("auth.login.user_store")
var errGoogleLoginMintJWT = errors.New("auth.login.mint_jwt")
var errGoogleLoginIssueRefresh = errors.New("auth.login.issue_refresh")

// ProvideGoogleTokenValidator injects a singleton validator for auth routes.
func ProvideGoogleTokenValidator(validator GoogleTokenValidator) {
	configuredGoogleValidator = validator
	validatorCache.Lock()
	validatorCache.value = nil
	validatorCache.Unlock()
}

// ProvideClock injects the clock used for minting tokens and expirations.
func ProvideClock(clock Clock) {
	configuredClock = clock
}

// ProvideLogger sets the logger used for auth route instrumentation.
func ProvideLogger(logger *zap.Logger) {
	configuredLogger = logger
}

// ProvideMetrics sets the metrics recorder used for auth route counters.
func ProvideMetrics(recorder MetricsRecorder) {
	configuredMetrics = recorder
}

func resolveGoogleValidator(ctx context.Context) (GoogleTokenValidator, error) {
	if configuredGoogleValidator != nil {
		return configuredGoogleValidator, nil
	}

	validatorCache.RLock()
	cached := validatorCache.value
	validatorCache.RUnlock()
	if cached != nil {
		return cached, nil
	}

	validatorCache.Lock()
	defer validatorCache.Unlock()
	if validatorCache.value != nil {
		return validatorCache.value, nil
	}

	validator, err := newGoogleTokenValidator(ctx)
	if err != nil {
		return nil, err
	}
	validatorCache.value = validator
	return validator, nil
}

const (
	metricAuthLoginSuccess                 = "auth.login.success"
	metricAuthLoginFailure                 = "auth.login.failure"
	metricAuthRefreshSuccess               = "auth.refresh.success"
	metricAuthRefreshFailure               = "auth.refresh.failure"
	metricAuthLogoutSuccess                = "auth.logout.success"
	errorUserNotAllowed                    = "user_not_allowed"
	errorNativeGoogleLoginNotConfigured    = "native_google_login_not_configured"
	errorNativeGooglePlatformNotConfigured = "native_google_platform_not_configured"
	errorNativeGoogleRedirectURIInvalid    = "invalid_redirect_uri"
	errorPasswordAuthNotConfigured         = "password_auth_not_configured"
	errorPasswordCredentialInvalid         = "invalid_credentials"
	errorAccountManagementNotConfigured    = "account_management_not_configured"
	errorPasswordSignupNotConfigured       = "password_signup_not_configured"
	errorAccountExists                     = "account_exists"
	errorAccountChallengeInvalid           = "invalid_challenge"
	errorAccountNotActive                  = "account_not_active"
	errorAccountDisabled                   = "account_disabled"
	errorAccountLastIdentity               = "last_identity"
	googleIssuerHTTPS                      = "https://accounts.google.com"
	googleIssuerLegacy                     = "accounts.google.com"
	googleAuthorizationEndpoint            = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenEndpoint                    = "https://oauth2.googleapis.com/token"
	googleOAuthResponseTypeCode            = "code"
	googleCodeChallengeMethodS256          = "S256"
	nativeGoogleDefaultPlatform            = "desktop"
)

var googleNativeScopes = []string{"openid", "email", "profile"}

type googleLoginInbound struct {
	GoogleIDToken string `json:"google_id_token"`
	NonceToken    string `json:"nonce_token"`
	Platform      string `json:"platform"`
	RedirectURI   string `json:"redirect_uri"`
}

type passwordLoginInbound struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type passwordSignupInbound struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
	AvatarURL   string `json:"avatar_url"`
}

type challengeTokenInbound struct {
	Token string `json:"token"`
}

type passwordResetStartInbound struct {
	Email string `json:"email"`
}

type passwordResetCompleteInbound struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

type passwordChangeInbound struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type accountUnlinkInbound struct {
	Provider   string `json:"provider"`
	ProviderID string `json:"provider_id"`
}

type authenticatedSessionProfile struct {
	applicationUserID string
	userEmail         string
	userDisplayName   string
	userAvatarURL     string
	userRoles         []string
}

type nativeGoogleConfigResponse struct {
	ClientID                      string                       `json:"client_id"`
	ClientIDs                     []string                     `json:"client_ids"`
	Platform                      string                       `json:"platform,omitempty"`
	RedirectURIs                  []string                     `json:"redirect_uris"`
	Clients                       []nativeGoogleClientResponse `json:"clients"`
	AuthorizationEndpoint         string                       `json:"authorization_endpoint"`
	TokenEndpoint                 string                       `json:"token_endpoint"`
	Scopes                        []string                     `json:"scopes"`
	ResponseType                  string                       `json:"response_type"`
	PKCERequired                  bool                         `json:"pkce_required"`
	CodeChallengeMethodsSupported []string                     `json:"code_challenge_methods_supported"`
}

type nativeGoogleClientResponse struct {
	Platform     string   `json:"platform"`
	ClientID     string   `json:"client_id"`
	RedirectURIs []string `json:"redirect_uris"`
}

type googleIdentity struct {
	Sub           string
	Email         string
	EmailVerified bool
	DisplayName   string
	AvatarURL     string
	Nonce         string
}

func recordMetric(event string) {
	if configuredMetrics == nil {
		return
	}
	configuredMetrics.Increment(event)
}

func logAuthWarning(code string, err error, fields ...zap.Field) {
	if configuredLogger == nil {
		return
	}
	logFields := append([]zap.Field{zap.String("code", code)}, fields...)
	if err != nil {
		logFields = append(logFields, zap.Error(err))
	}
	configuredLogger.Warn("auth", logFields...)
}

func logAuthError(code string, err error, fields ...zap.Field) {
	if configuredLogger == nil {
		return
	}
	logFields := append([]zap.Field{zap.String("code", code)}, fields...)
	if err != nil {
		logFields = append(logFields, zap.Error(err))
	}
	configuredLogger.Error("auth", logFields...)
}

// MountAuthRoutes registers /auth endpoints and session helpers.
func MountAuthRoutes(router gin.IRouter, registry TenantRegistry, users UserStore, refreshTokens RefreshTokenStore, nonces NonceStore) {
	MountAuthRoutesWithPassword(router, registry, users, refreshTokens, nonces, nil)
}

// MountAuthRoutesWithPassword registers /auth endpoints, including optional password login.
func MountAuthRoutesWithPassword(router gin.IRouter, registry TenantRegistry, users UserStore, refreshTokens RefreshTokenStore, nonces NonceStore, passwordCredentials PasswordCredentialStore) {
	clock := configuredClock
	if clock == nil {
		clock = NewSystemClock()
	}
	accountStore, _ := passwordCredentials.(AccountManagementStore)
	if nonces == nil {
		nonces = NewMemoryNonceStoreWithTTLResolver(func(tenantID string) time.Duration {
			return registry.Config(tenantID).NonceTTL
		})
	}

	router.POST("/auth/nonce", func(contextGin *gin.Context) {
		tenantID, resolved := resolveTenantIDRequired(contextGin, registry)
		if !resolved {
			logAuthError("auth.tenant.missing", errMissingTenantContext)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		token, issueErr := nonces.Issue(contextGin, tenantID)
		if issueErr != nil {
			logAuthError("auth.nonce.issue_failed", issueErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		contextGin.JSON(http.StatusOK, gin.H{"nonce": token})
	})

	router.GET("/auth/session", func(contextGin *gin.Context) {
		tenantID, resolved := resolveTenantIDRequired(contextGin, registry)
		if !resolved {
			logAuthError("auth.tenant.missing", errMissingTenantContext)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		config := registry.Config(tenantID)
		claims, validateSessionErr := validateSessionRequest(contextGin.Request, config)
		if validateSessionErr == nil {
			if strings.TrimSpace(claims.GetTenantID()) == tenantID {
				contextGin.JSON(http.StatusOK, sessionProfilePayload(
					claims.GetUserID(),
					claims.GetUserEmail(),
					claims.GetUserDisplayName(),
					claims.GetUserAvatarURL(),
					claims.GetUserRoles(),
					claims.GetExpiresAt(),
				))
				return
			}
			contextGin.Status(http.StatusNoContent)
			return
		}

		refreshCookieValues := refreshCookieCandidates(contextGin.Request, config.RefreshCookieName)
		if len(refreshCookieValues) == 0 {
			contextGin.Status(http.StatusNoContent)
			return
		}

		var applicationUserID string
		var currentTokenID string
		validationSucceeded := false
		for _, cookieValue := range refreshCookieValues {
			candidateUserID, candidateTokenID, _, validateErr := refreshTokens.Validate(contextGin, tenantID, cookieValue)
			if validateErr == nil {
				applicationUserID = candidateUserID
				currentTokenID = candidateTokenID
				validationSucceeded = true
				break
			}
			if errors.Is(validateErr, ErrRefreshTokenRevoked) || isUnauthorizedRefreshTokenError(validateErr) {
				continue
			}
			logAuthError("auth.session.refresh_validate", validateErr, zap.Int("cookie_candidates", len(refreshCookieValues)))
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if !validationSucceeded {
			contextGin.Status(http.StatusNoContent)
			return
		}

		userEmail, userDisplayName, userAvatarURL, userRoles, profileErr := users.GetUserProfile(contextGin, tenantID, applicationUserID)
		if profileErr != nil {
			logAuthError("auth.session.profile", profileErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		sessionToken, sessionExpiresAt, mintErr := MintAppJWT(clock, tenantID, applicationUserID, userEmail, userDisplayName, userAvatarURL, userRoles, config.AppJWTIssuer, config.AppJWTSigningKey, config.SessionTTL)
		if mintErr != nil {
			logAuthError("auth.session.mint_jwt", mintErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		refreshDeadline := clock.Now().UTC().Add(config.RefreshTTL)
		_, newOpaque, issueErr := refreshTokens.Issue(contextGin, tenantID, applicationUserID, refreshDeadline.Unix(), currentTokenID)
		if issueErr != nil || strings.TrimSpace(newOpaque) == "" {
			logAuthError("auth.session.issue_refresh", issueErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if revokeErr := refreshTokens.Revoke(contextGin, tenantID, currentTokenID); revokeErr != nil && !errors.Is(revokeErr, ErrRefreshTokenAlreadyRevoked) {
			logAuthError("auth.session.revoke_previous", revokeErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		writeSessionCookie(contextGin, config, sessionToken, sessionExpiresAt)
		writeRefreshCookie(contextGin, config, newOpaque, refreshDeadline)
		contextGin.JSON(http.StatusOK, sessionProfilePayload(
			applicationUserID,
			userEmail,
			userDisplayName,
			userAvatarURL,
			userRoles,
			sessionExpiresAt,
		))
	})

	router.GET("/auth/google/native/config", func(contextGin *gin.Context) {
		tenantID, resolved := resolveTenantIDRequired(contextGin, registry)
		if !resolved {
			logAuthError("auth.tenant.missing", errMissingTenantContext)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		config := registry.Config(tenantID)
		platform := strings.TrimSpace(contextGin.Query("platform"))
		nativeClients := nativeGoogleClientsForPlatform(config, platform)
		if len(nativeClients) == 0 {
			errorCode := errorNativeGoogleLoginNotConfigured
			if platform != "" {
				errorCode = errorNativeGooglePlatformNotConfigured
			}
			contextGin.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": errorCode})
			return
		}
		scopes := append([]string(nil), googleNativeScopes...)
		codeChallengeMethods := []string{googleCodeChallengeMethodS256}
		clientIDs := nativeGoogleClientIDs(nativeClients)
		redirectURIs := nativeGoogleRedirectURIs(nativeClients)
		contextGin.JSON(http.StatusOK, nativeGoogleConfigResponse{
			ClientID:                      clientIDs[0],
			ClientIDs:                     clientIDs,
			Platform:                      normalizeNativeGooglePlatform(platform),
			RedirectURIs:                  redirectURIs,
			Clients:                       nativeGoogleClientResponses(nativeClients),
			AuthorizationEndpoint:         googleAuthorizationEndpoint,
			TokenEndpoint:                 googleTokenEndpoint,
			Scopes:                        scopes,
			ResponseType:                  googleOAuthResponseTypeCode,
			PKCERequired:                  true,
			CodeChallengeMethodsSupported: codeChallengeMethods,
		})
	})

	router.POST("/auth/password/login", func(contextGin *gin.Context) {
		tenantID, resolved := resolveTenantIDRequired(contextGin, registry)
		if !resolved {
			recordMetric(metricAuthLoginFailure)
			logAuthError("auth.tenant.missing", errMissingTenantContext)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		config := registry.Config(tenantID)
		if !config.PasswordAuthEnabled {
			recordMetric(metricAuthLoginFailure)
			contextGin.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": errorPasswordAuthNotConfigured})
			return
		}
		if passwordCredentials == nil {
			recordMetric(metricAuthLoginFailure)
			logAuthError("auth.login.password.store_missing", nil)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		inbound, ok := bindPasswordLoginInbound(contextGin)
		if !ok {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.password.invalid_json", nil)
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
			return
		}
		normalizedEmail, emailErr := normalizePasswordEmail(inbound.Email)
		if emailErr != nil {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.password.invalid_email", nil)
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_email"})
			return
		}
		if inbound.Password == "" {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.password.missing_password", nil)
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing_password"})
			return
		}
		if !config.AllowInsecureHTTP && !isHTTPS(contextGin.Request) {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.password.insecure_http", nil)
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "https_required"})
			return
		}
		if !isAllowedUser(normalizedEmail, config.AllowedUsers) {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.password.user_not_allowed", nil)
			contextGin.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": errorUserNotAllowed})
			return
		}
		profile, authErr := passwordCredentials.AuthenticatePassword(contextGin, tenantID, normalizedEmail, inbound.Password)
		if authErr != nil {
			recordMetric(metricAuthLoginFailure)
			if errors.Is(authErr, ErrPasswordCredentialInvalid) {
				logAuthWarning("auth.login.password.invalid_credentials", nil)
				contextGin.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": errorPasswordCredentialInvalid})
				return
			}
			if errors.Is(authErr, ErrAccountNotActive) || errors.Is(authErr, ErrAccountDisabled) {
				writeAccountError(contextGin, authErr)
				return
			}
			logAuthError("auth.login.password.authenticate", authErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if config.AccountManagementEnabled {
			store, ok := requireAccountManagementStore(contextGin, config, accountStore)
			if !ok {
				recordMetric(metricAuthLoginFailure)
				return
			}
			accountProfile, ensureErr := store.EnsurePasswordAccount(contextGin, tenantID, profile.UserEmail)
			if ensureErr != nil {
				recordMetric(metricAuthLoginFailure)
				writeAccountError(contextGin, ensureErr)
				return
			}
			if finalizeErr := finalizeAccountLogin(contextGin, users, refreshTokens, clock, config, tenantID, accountProfile); finalizeErr != nil {
				recordMetric(metricAuthLoginFailure)
				logAuthError("auth.login.password.account_finalize", finalizeErr)
				contextGin.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			recordMetric(metricAuthLoginSuccess)
			return
		}
		if finalizeErr := finalizePasswordLogin(contextGin, users, refreshTokens, clock, config, tenantID, profile); finalizeErr != nil {
			recordMetric(metricAuthLoginFailure)
			logAuthError("auth.login.password.finalize", finalizeErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		recordMetric(metricAuthLoginSuccess)
	})

	router.POST("/auth/password/signup", func(contextGin *gin.Context) {
		tenantID, resolved := resolveTenantIDRequired(contextGin, registry)
		if !resolved {
			logAuthError("auth.tenant.missing", errMissingTenantContext)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		config := registry.Config(tenantID)
		store, ok := requireAccountManagementStore(contextGin, config, accountStore)
		if !ok {
			return
		}
		if !config.PasswordSignupEnabled {
			contextGin.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": errorPasswordSignupNotConfigured})
			return
		}
		inbound, ok := bindPasswordSignupInbound(contextGin)
		if !ok {
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
			return
		}
		normalizedEmail, emailErr := normalizePasswordEmail(inbound.Email)
		if emailErr != nil {
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_email"})
			return
		}
		if !config.AllowInsecureHTTP && !isHTTPS(contextGin.Request) {
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "https_required"})
			return
		}
		if !isAllowedUser(normalizedEmail, config.AllowedUsers) {
			contextGin.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": errorUserNotAllowed})
			return
		}
		challenge, signupErr := store.CreatePasswordSignup(contextGin, tenantID, AccountPasswordRequest{
			UserEmail:   normalizedEmail,
			Password:    inbound.Password,
			DisplayName: inbound.DisplayName,
			AvatarURL:   inbound.AvatarURL,
		}, clock.Now().UTC().Add(effectiveDuration(config.EmailVerificationTTL, 30*time.Minute)).Unix())
		if signupErr != nil {
			writeAccountError(contextGin, signupErr)
			return
		}
		contextGin.JSON(http.StatusAccepted, challengePayload(config, "verification_token", challenge))
	})

	router.POST("/auth/password/verify-email", func(contextGin *gin.Context) {
		tenantID, resolved := resolveTenantIDRequired(contextGin, registry)
		if !resolved {
			logAuthError("auth.tenant.missing", errMissingTenantContext)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		config := registry.Config(tenantID)
		store, ok := requireAccountManagementStore(contextGin, config, accountStore)
		if !ok {
			return
		}
		inbound, ok := bindChallengeTokenInbound(contextGin)
		if !ok {
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
			return
		}
		profile, verifyErr := store.VerifyEmailChallenge(contextGin, tenantID, inbound.Token)
		if verifyErr != nil {
			writeAccountError(contextGin, verifyErr)
			return
		}
		if finalizeErr := finalizeAccountLogin(contextGin, users, refreshTokens, clock, config, tenantID, profile); finalizeErr != nil {
			logAuthError("auth.account.verify.finalize", finalizeErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
		}
	})

	router.POST("/auth/password/reset/start", func(contextGin *gin.Context) {
		tenantID, resolved := resolveTenantIDRequired(contextGin, registry)
		if !resolved {
			logAuthError("auth.tenant.missing", errMissingTenantContext)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		config := registry.Config(tenantID)
		store, ok := requireAccountManagementStore(contextGin, config, accountStore)
		if !ok {
			return
		}
		inbound, ok := bindPasswordResetStartInbound(contextGin)
		if !ok {
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
			return
		}
		challenge, resetErr := store.StartPasswordReset(contextGin, tenantID, inbound.Email, clock.Now().UTC().Add(effectiveDuration(config.PasswordResetTTL, 15*time.Minute)).Unix())
		if resetErr != nil {
			if !errors.Is(resetErr, ErrAccountNotFound) && !errors.Is(resetErr, ErrPasswordCredentialInvalid) {
				logAuthError("auth.account.reset_start", resetErr)
				contextGin.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			challenge = fakeChallenge(clock.Now().UTC().Add(effectiveDuration(config.PasswordResetTTL, 15*time.Minute)).Unix())
		}
		contextGin.JSON(http.StatusAccepted, challengePayload(config, "reset_token", challenge))
	})

	router.POST("/auth/password/reset/complete", func(contextGin *gin.Context) {
		tenantID, resolved := resolveTenantIDRequired(contextGin, registry)
		if !resolved {
			logAuthError("auth.tenant.missing", errMissingTenantContext)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		config := registry.Config(tenantID)
		store, ok := requireAccountManagementStore(contextGin, config, accountStore)
		if !ok {
			return
		}
		inbound, ok := bindPasswordResetCompleteInbound(contextGin)
		if !ok {
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
			return
		}
		profile, resetErr := store.CompletePasswordReset(contextGin, tenantID, inbound.Token, inbound.Password)
		if resetErr != nil {
			writeAccountError(contextGin, resetErr)
			return
		}
		if revokeErr := refreshTokens.RevokeUser(contextGin, tenantID, profile.AccountID); revokeErr != nil {
			logAuthError("auth.account.reset_revoke", revokeErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if finalizeErr := finalizeAccountLogin(contextGin, users, refreshTokens, clock, config, tenantID, profile); finalizeErr != nil {
			logAuthError("auth.account.reset_finalize", finalizeErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
		}
	})

	router.POST("/auth/google", func(contextGin *gin.Context) {
		tenantID, resolved := resolveTenantIDRequired(contextGin, registry)
		if !resolved {
			recordMetric(metricAuthLoginFailure)
			logAuthError("auth.tenant.missing", errMissingTenantContext)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		config := registry.Config(tenantID)
		inbound, ok := bindGoogleLoginInbound(contextGin)
		if !ok {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.invalid_json", nil)
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
			return
		}
		if strings.TrimSpace(inbound.NonceToken) == "" {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.missing_nonce", nil)
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing_nonce"})
			return
		}

		if !config.AllowInsecureHTTP && !isHTTPS(contextGin.Request) {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.insecure_http", nil)
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "https_required"})
			return
		}

		validator, validatorErr := resolveGoogleValidator(context.Background())
		if validatorErr != nil {
			recordMetric(metricAuthLoginFailure)
			logAuthError("auth.login.validator_init", validatorErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		payload, identity, validateErr := validateGoogleIdentityToken(context.Background(), validator, inbound.GoogleIDToken, config.GoogleWebClientID)
		if validateErr != nil {
			recordMetric(metricAuthLoginFailure)
			if errors.Is(validateErr, errInvalidGoogleIssuer) {
				logAuthWarning("auth.login.invalid_issuer", validateErr)
				contextGin.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_issuer"})
				return
			}
			logAuthWarning("auth.login.invalid_google_token", validateErr)
			contextGin.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_google_token"})
			return
		}
		if consumeErr := consumeBrowserNonce(contextGin, nonces, tenantID, inbound.NonceToken, payload); consumeErr != nil {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.invalid_nonce_token", consumeErr)
			contextGin.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_nonce"})
			return
		}

		if identity.Sub == "" || identity.Email == "" || !identity.EmailVerified {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.unverified_identity", nil)
			contextGin.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unverified_identity"})
			return
		}
		if !isAllowedUser(identity.Email, config.AllowedUsers) {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.user_not_allowed", nil)
			contextGin.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": errorUserNotAllowed})
			return
		}

		if config.AccountManagementEnabled {
			if accountStore == nil {
				recordMetric(metricAuthLoginFailure)
				logAuthError("auth.login.account_store_missing", nil)
				contextGin.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			accountProfile, found, accountErr := accountStore.AuthenticateGoogleAccount(contextGin, tenantID, GoogleAccountIdentity{
				Subject:     identity.Sub,
				UserEmail:   identity.Email,
				DisplayName: identity.DisplayName,
				AvatarURL:   identity.AvatarURL,
			})
			if accountErr != nil {
				recordMetric(metricAuthLoginFailure)
				writeAccountError(contextGin, accountErr)
				return
			}
			if !found {
				accountProfile, accountErr = accountStore.UpsertGoogleAccount(contextGin, tenantID, GoogleAccountIdentity{
					Subject:     identity.Sub,
					UserEmail:   identity.Email,
					DisplayName: identity.DisplayName,
					AvatarURL:   identity.AvatarURL,
				})
				if accountErr != nil {
					recordMetric(metricAuthLoginFailure)
					writeAccountError(contextGin, accountErr)
					return
				}
			}
			if finalizeErr := finalizeAccountLogin(contextGin, users, refreshTokens, clock, config, tenantID, accountProfile); finalizeErr != nil {
				recordMetric(metricAuthLoginFailure)
				logAuthError("auth.login.account_finalize", finalizeErr)
				contextGin.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			recordMetric(metricAuthLoginSuccess)
			return
		}

		if finalizeErr := finalizeGoogleLogin(contextGin, users, refreshTokens, clock, config, tenantID, identity); finalizeErr != nil {
			recordMetric(metricAuthLoginFailure)
			switch {
			case errors.Is(finalizeErr, errGoogleLoginUserStore):
				logAuthError("auth.login.user_store", finalizeErr)
			case errors.Is(finalizeErr, errGoogleLoginMintJWT):
				logAuthError("auth.login.mint_jwt", finalizeErr)
			case errors.Is(finalizeErr, errGoogleLoginIssueRefresh):
				logAuthError("auth.login.issue_refresh", finalizeErr)
			default:
				logAuthError("auth.login.finalize", finalizeErr)
			}
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		recordMetric(metricAuthLoginSuccess)
	})

	router.POST("/auth/google/native", func(contextGin *gin.Context) {
		tenantID, resolved := resolveTenantIDRequired(contextGin, registry)
		if !resolved {
			recordMetric(metricAuthLoginFailure)
			logAuthError("auth.tenant.missing", errMissingTenantContext)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		config := registry.Config(tenantID)
		nativeClients := nativeGoogleClientsForPlatform(config, "")
		if len(nativeClients) == 0 {
			recordMetric(metricAuthLoginFailure)
			contextGin.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": errorNativeGoogleLoginNotConfigured})
			return
		}
		inbound, ok := bindGoogleLoginInbound(contextGin)
		if !ok {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.native.invalid_json", nil)
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
			return
		}
		if strings.TrimSpace(inbound.NonceToken) == "" {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.native.missing_nonce", nil)
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing_nonce"})
			return
		}
		nativeClients = nativeGoogleClientsForPlatform(config, inbound.Platform)
		if len(nativeClients) == 0 {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.native.platform_not_configured", nil, zap.String("platform", inbound.Platform))
			contextGin.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": errorNativeGooglePlatformNotConfigured})
			return
		}
		if redirectErr := validateNativeGoogleRedirectURI(nativeClients, inbound.RedirectURI); redirectErr != nil {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.native.invalid_redirect_uri", redirectErr)
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": errorNativeGoogleRedirectURIInvalid})
			return
		}
		if !config.AllowInsecureHTTP && !isHTTPS(contextGin.Request) {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.native.insecure_http", nil)
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "https_required"})
			return
		}
		validator, validatorErr := resolveGoogleValidator(context.Background())
		if validatorErr != nil {
			recordMetric(metricAuthLoginFailure)
			logAuthError("auth.login.native.validator_init", validatorErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		_, identity, validateErr := validateGoogleIdentityTokenForAudiences(context.Background(), validator, inbound.GoogleIDToken, nativeGoogleClientIDs(nativeClients))
		if validateErr != nil {
			recordMetric(metricAuthLoginFailure)
			if errors.Is(validateErr, errInvalidGoogleIssuer) {
				logAuthWarning("auth.login.native.invalid_issuer", validateErr)
				contextGin.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_issuer"})
				return
			}
			logAuthWarning("auth.login.native.invalid_google_token", validateErr)
			contextGin.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_google_token"})
			return
		}
		if strings.TrimSpace(identity.Nonce) == "" {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.native.missing_nonce_claim", nil)
			contextGin.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_nonce"})
			return
		}
		if identity.Nonce != strings.TrimSpace(inbound.NonceToken) {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning(
				"auth.login.native.nonce_mismatch",
				nil,
				zap.String("google_nonce", identity.Nonce),
			)
			contextGin.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_nonce"})
			return
		}
		if identity.Sub == "" || identity.Email == "" || !identity.EmailVerified {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.native.unverified_identity", nil)
			contextGin.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unverified_identity"})
			return
		}
		if !isAllowedUser(identity.Email, config.AllowedUsers) {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.native.user_not_allowed", nil)
			contextGin.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": errorUserNotAllowed})
			return
		}
		if config.AccountManagementEnabled {
			if accountStore == nil {
				recordMetric(metricAuthLoginFailure)
				logAuthError("auth.login.native.account_store_missing", nil)
				contextGin.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			accountProfile, found, accountErr := accountStore.AuthenticateGoogleAccount(contextGin, tenantID, GoogleAccountIdentity{
				Subject:     identity.Sub,
				UserEmail:   identity.Email,
				DisplayName: identity.DisplayName,
				AvatarURL:   identity.AvatarURL,
			})
			if accountErr != nil {
				recordMetric(metricAuthLoginFailure)
				writeAccountError(contextGin, accountErr)
				return
			}
			if !found {
				accountProfile, accountErr = accountStore.UpsertGoogleAccount(contextGin, tenantID, GoogleAccountIdentity{
					Subject:     identity.Sub,
					UserEmail:   identity.Email,
					DisplayName: identity.DisplayName,
					AvatarURL:   identity.AvatarURL,
				})
				if accountErr != nil {
					recordMetric(metricAuthLoginFailure)
					writeAccountError(contextGin, accountErr)
					return
				}
			}
			if finalizeErr := finalizeAccountLogin(contextGin, users, refreshTokens, clock, config, tenantID, accountProfile); finalizeErr != nil {
				recordMetric(metricAuthLoginFailure)
				logAuthError("auth.login.native.account_finalize", finalizeErr)
				contextGin.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			recordMetric(metricAuthLoginSuccess)
			return
		}
		if finalizeErr := finalizeGoogleLogin(contextGin, users, refreshTokens, clock, config, tenantID, identity); finalizeErr != nil {
			recordMetric(metricAuthLoginFailure)
			switch {
			case errors.Is(finalizeErr, errGoogleLoginUserStore):
				logAuthError("auth.login.native.user_store", finalizeErr)
			case errors.Is(finalizeErr, errGoogleLoginMintJWT):
				logAuthError("auth.login.native.mint_jwt", finalizeErr)
			case errors.Is(finalizeErr, errGoogleLoginIssueRefresh):
				logAuthError("auth.login.native.issue_refresh", finalizeErr)
			default:
				logAuthError("auth.login.native.finalize", finalizeErr)
			}
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		recordMetric(metricAuthLoginSuccess)
	})

	router.POST("/auth/refresh", func(contextGin *gin.Context) {
		tenantID, resolved := resolveTenantIDRequired(contextGin, registry)
		if !resolved {
			recordMetric(metricAuthRefreshFailure)
			logAuthError("auth.tenant.missing", errMissingTenantContext)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		config := registry.Config(tenantID)
		refreshCookieValues := refreshCookieCandidates(contextGin.Request, config.RefreshCookieName)
		if len(refreshCookieValues) == 0 {
			recordMetric(metricAuthRefreshFailure)
			logAuthWarning("auth.refresh.missing_cookie", nil)
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		var applicationUserID string
		var currentTokenID string
		validationSucceeded := false
		var lastUnauthorizedErr error
		for _, cookieValue := range refreshCookieValues {
			candidateUserID, candidateTokenID, _, validateErr := refreshTokens.Validate(contextGin, tenantID, cookieValue)
			if validateErr == nil {
				applicationUserID = candidateUserID
				currentTokenID = candidateTokenID
				validationSucceeded = true
				break
			}
			if errors.Is(validateErr, ErrRefreshTokenRevoked) || isUnauthorizedRefreshTokenError(validateErr) {
				lastUnauthorizedErr = validateErr
				continue
			}
			recordMetric(metricAuthRefreshFailure)
			logAuthError("auth.refresh.validate", validateErr, zap.Int("cookie_candidates", len(refreshCookieValues)))
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if !validationSucceeded {
			recordMetric(metricAuthRefreshFailure)
			logAuthWarning("auth.refresh.validate", lastUnauthorizedErr, zap.Int("cookie_candidates", len(refreshCookieValues)))
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		userEmail, userDisplayName, userAvatarURL, userRoles, profileErr := users.GetUserProfile(contextGin, tenantID, applicationUserID)
		if profileErr != nil {
			recordMetric(metricAuthRefreshFailure)
			logAuthError("auth.refresh.profile", profileErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		sessionToken, sessionExpiresAt, mintErr := MintAppJWT(clock, tenantID, applicationUserID, userEmail, userDisplayName, userAvatarURL, userRoles, config.AppJWTIssuer, config.AppJWTSigningKey, config.SessionTTL)
		if mintErr != nil {
			recordMetric(metricAuthRefreshFailure)
			logAuthError("auth.refresh.mint_jwt", mintErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		refreshDeadline := clock.Now().UTC().Add(config.RefreshTTL)
		_, newOpaque, issueErr := refreshTokens.Issue(contextGin, tenantID, applicationUserID, refreshDeadline.Unix(), currentTokenID)
		if issueErr != nil || strings.TrimSpace(newOpaque) == "" {
			recordMetric(metricAuthRefreshFailure)
			logAuthError("auth.refresh.issue_refresh", issueErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if revokeErr := refreshTokens.Revoke(contextGin, tenantID, currentTokenID); revokeErr != nil && !errors.Is(revokeErr, ErrRefreshTokenAlreadyRevoked) {
			recordMetric(metricAuthRefreshFailure)
			logAuthError("auth.refresh.revoke_previous", revokeErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		writeSessionCookie(contextGin, config, sessionToken, sessionExpiresAt)
		writeRefreshCookie(contextGin, config, newOpaque, refreshDeadline)

		contextGin.Status(http.StatusNoContent)
		recordMetric(metricAuthRefreshSuccess)
	})

	router.POST("/auth/logout", func(contextGin *gin.Context) {
		tenantID, resolved := resolveTenantIDRequired(contextGin, registry)
		if !resolved {
			logAuthError("auth.tenant.missing", errMissingTenantContext)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		config := registry.Config(tenantID)
		refreshCookie, cookieErr := contextGin.Request.Cookie(config.RefreshCookieName)
		if cookieErr == nil && refreshCookie != nil && strings.TrimSpace(refreshCookie.Value) != "" {
			_, tokenID, _, validateErr := refreshTokens.Validate(contextGin, tenantID, refreshCookie.Value)
			if validateErr == nil && tokenID != "" {
				if revokeErr := refreshTokens.Revoke(contextGin, tenantID, tokenID); revokeErr != nil && !errors.Is(revokeErr, ErrRefreshTokenAlreadyRevoked) {
					logAuthWarning("auth.logout.revoke", revokeErr)
				}
			}
		}
		clearCookie(contextGin, config, config.SessionCookieName, "/")
		clearCookie(contextGin, config, config.RefreshCookieName, "/auth")
		contextGin.Status(http.StatusNoContent)
		recordMetric(metricAuthLogoutSuccess)
	})

	accountRoutes := router.Group("/auth/account")
	accountRoutes.Use(RequireSession(registry))
	accountRoutes.POST("/password/change", func(contextGin *gin.Context) {
		tenantID, config, accountID, ok := currentAccountContext(contextGin, registry)
		if !ok {
			return
		}
		store, ok := requireAccountManagementStore(contextGin, config, accountStore)
		if !ok {
			return
		}
		inbound, ok := bindPasswordChangeInbound(contextGin)
		if !ok {
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
			return
		}
		profile, changeErr := store.ChangePassword(contextGin, tenantID, accountID, inbound.CurrentPassword, inbound.NewPassword)
		if changeErr != nil {
			writeAccountError(contextGin, changeErr)
			return
		}
		if revokeErr := refreshTokens.RevokeUser(contextGin, tenantID, profile.AccountID); revokeErr != nil {
			logAuthError("auth.account.change_password_revoke", revokeErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if finalizeErr := finalizeAccountLogin(contextGin, users, refreshTokens, clock, config, tenantID, profile); finalizeErr != nil {
			logAuthError("auth.account.change_password_finalize", finalizeErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
		}
	})

	accountRoutes.POST("/password/link/start", func(contextGin *gin.Context) {
		tenantID, config, accountID, ok := currentAccountContext(contextGin, registry)
		if !ok {
			return
		}
		store, ok := requireAccountManagementStore(contextGin, config, accountStore)
		if !ok {
			return
		}
		inbound, ok := bindPasswordSignupInbound(contextGin)
		if !ok {
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
			return
		}
		challenge, linkErr := store.CreatePasswordLink(contextGin, tenantID, accountID, AccountPasswordRequest{
			UserEmail:   inbound.Email,
			Password:    inbound.Password,
			DisplayName: inbound.DisplayName,
			AvatarURL:   inbound.AvatarURL,
		}, clock.Now().UTC().Add(effectiveDuration(config.EmailVerificationTTL, 30*time.Minute)).Unix())
		if linkErr != nil {
			writeAccountError(contextGin, linkErr)
			return
		}
		contextGin.JSON(http.StatusAccepted, challengePayload(config, "verification_token", challenge))
	})

	accountRoutes.POST("/password/link/verify", func(contextGin *gin.Context) {
		tenantID, config, accountID, ok := currentAccountContext(contextGin, registry)
		if !ok {
			return
		}
		store, ok := requireAccountManagementStore(contextGin, config, accountStore)
		if !ok {
			return
		}
		inbound, ok := bindChallengeTokenInbound(contextGin)
		if !ok {
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
			return
		}
		profile, linkErr := store.VerifyPasswordLink(contextGin, tenantID, accountID, inbound.Token)
		if linkErr != nil {
			writeAccountError(contextGin, linkErr)
			return
		}
		contextGin.JSON(http.StatusOK, accountProfilePayload(profile))
	})

	accountRoutes.POST("/google/link", func(contextGin *gin.Context) {
		tenantID, config, accountID, ok := currentAccountContext(contextGin, registry)
		if !ok {
			return
		}
		store, ok := requireAccountManagementStore(contextGin, config, accountStore)
		if !ok {
			return
		}
		inbound, ok := bindGoogleLoginInbound(contextGin)
		if !ok {
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
			return
		}
		if strings.TrimSpace(inbound.NonceToken) == "" {
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing_nonce"})
			return
		}
		validator, validatorErr := resolveGoogleValidator(context.Background())
		if validatorErr != nil {
			logAuthError("auth.account.link_google.validator_init", validatorErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		payload, identity, validateErr := validateGoogleIdentityToken(context.Background(), validator, inbound.GoogleIDToken, config.GoogleWebClientID)
		if validateErr != nil {
			contextGin.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_google_token"})
			return
		}
		if consumeErr := consumeBrowserNonce(contextGin, nonces, tenantID, inbound.NonceToken, payload); consumeErr != nil {
			contextGin.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_nonce"})
			return
		}
		if identity.Sub == "" || identity.Email == "" || !identity.EmailVerified {
			contextGin.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unverified_identity"})
			return
		}
		profile, linkErr := store.LinkGoogleIdentity(contextGin, tenantID, accountID, GoogleAccountIdentity{
			Subject:     identity.Sub,
			UserEmail:   identity.Email,
			DisplayName: identity.DisplayName,
			AvatarURL:   identity.AvatarURL,
		})
		if linkErr != nil {
			writeAccountError(contextGin, linkErr)
			return
		}
		contextGin.JSON(http.StatusOK, accountProfilePayload(profile))
	})

	accountRoutes.POST("/unlink", func(contextGin *gin.Context) {
		tenantID, config, accountID, ok := currentAccountContext(contextGin, registry)
		if !ok {
			return
		}
		store, ok := requireAccountManagementStore(contextGin, config, accountStore)
		if !ok {
			return
		}
		inbound, ok := bindAccountUnlinkInbound(contextGin)
		if !ok {
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
			return
		}
		profile, unlinkErr := store.UnlinkIdentity(contextGin, tenantID, accountID, inbound.Provider, inbound.ProviderID)
		if unlinkErr != nil {
			writeAccountError(contextGin, unlinkErr)
			return
		}
		if revokeErr := refreshTokens.RevokeUser(contextGin, tenantID, profile.AccountID); revokeErr != nil {
			logAuthError("auth.account.unlink_revoke", revokeErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if finalizeErr := finalizeAccountLogin(contextGin, users, refreshTokens, clock, config, tenantID, profile); finalizeErr != nil {
			logAuthError("auth.account.unlink_finalize", finalizeErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
		}
	})

	accountRoutes.POST("/disable", func(contextGin *gin.Context) {
		tenantID, config, accountID, ok := currentAccountContext(contextGin, registry)
		if !ok {
			return
		}
		store, ok := requireAccountManagementStore(contextGin, config, accountStore)
		if !ok {
			return
		}
		profile, disableErr := store.DisableAccount(contextGin, tenantID, accountID)
		if disableErr != nil {
			writeAccountError(contextGin, disableErr)
			return
		}
		if revokeErr := refreshTokens.RevokeUser(contextGin, tenantID, profile.AccountID); revokeErr != nil {
			logAuthError("auth.account.disable_revoke", revokeErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		clearCookie(contextGin, config, config.SessionCookieName, "/")
		clearCookie(contextGin, config, config.RefreshCookieName, "/auth")
		contextGin.Status(http.StatusNoContent)
	})

	whoAmI := router.Group("/")
	whoAmI.Use(RequireSession(registry))
	whoAmI.GET("/me", web.HandleWhoAmI(configuredLogger))
}

func bindGoogleLoginInbound(contextGin *gin.Context) (googleLoginInbound, bool) {
	var inbound googleLoginInbound
	if err := contextGin.BindJSON(&inbound); err != nil {
		return googleLoginInbound{}, false
	}
	if strings.TrimSpace(inbound.GoogleIDToken) == "" {
		return googleLoginInbound{}, false
	}
	return inbound, true
}

func bindPasswordLoginInbound(contextGin *gin.Context) (passwordLoginInbound, bool) {
	var inbound passwordLoginInbound
	if err := contextGin.BindJSON(&inbound); err != nil {
		return passwordLoginInbound{}, false
	}
	return inbound, true
}

func bindPasswordSignupInbound(contextGin *gin.Context) (passwordSignupInbound, bool) {
	var inbound passwordSignupInbound
	if err := contextGin.BindJSON(&inbound); err != nil {
		return passwordSignupInbound{}, false
	}
	if strings.TrimSpace(inbound.Email) == "" || strings.TrimSpace(inbound.Password) == "" {
		return passwordSignupInbound{}, false
	}
	return inbound, true
}

func bindChallengeTokenInbound(contextGin *gin.Context) (challengeTokenInbound, bool) {
	var inbound challengeTokenInbound
	if err := contextGin.BindJSON(&inbound); err != nil {
		return challengeTokenInbound{}, false
	}
	if strings.TrimSpace(inbound.Token) == "" {
		return challengeTokenInbound{}, false
	}
	return inbound, true
}

func bindPasswordResetStartInbound(contextGin *gin.Context) (passwordResetStartInbound, bool) {
	var inbound passwordResetStartInbound
	if err := contextGin.BindJSON(&inbound); err != nil {
		return passwordResetStartInbound{}, false
	}
	if strings.TrimSpace(inbound.Email) == "" {
		return passwordResetStartInbound{}, false
	}
	return inbound, true
}

func bindPasswordResetCompleteInbound(contextGin *gin.Context) (passwordResetCompleteInbound, bool) {
	var inbound passwordResetCompleteInbound
	if err := contextGin.BindJSON(&inbound); err != nil {
		return passwordResetCompleteInbound{}, false
	}
	if strings.TrimSpace(inbound.Token) == "" || strings.TrimSpace(inbound.Password) == "" {
		return passwordResetCompleteInbound{}, false
	}
	return inbound, true
}

func bindPasswordChangeInbound(contextGin *gin.Context) (passwordChangeInbound, bool) {
	var inbound passwordChangeInbound
	if err := contextGin.BindJSON(&inbound); err != nil {
		return passwordChangeInbound{}, false
	}
	if strings.TrimSpace(inbound.CurrentPassword) == "" || strings.TrimSpace(inbound.NewPassword) == "" {
		return passwordChangeInbound{}, false
	}
	return inbound, true
}

func bindAccountUnlinkInbound(contextGin *gin.Context) (accountUnlinkInbound, bool) {
	var inbound accountUnlinkInbound
	if err := contextGin.BindJSON(&inbound); err != nil {
		return accountUnlinkInbound{}, false
	}
	if strings.TrimSpace(inbound.Provider) == "" || strings.TrimSpace(inbound.ProviderID) == "" {
		return accountUnlinkInbound{}, false
	}
	return inbound, true
}

func validateGoogleIdentityToken(ctx context.Context, validator GoogleTokenValidator, idToken string, audience string) (*idtoken.Payload, googleIdentity, error) {
	payload, validateErr := validator.Validate(ctx, idToken, audience)
	if validateErr != nil {
		return nil, googleIdentity{}, validateErr
	}
	issuerValue, okIssuer := payload.Claims["iss"].(string)
	if !okIssuer || (issuerValue != googleIssuerHTTPS && issuerValue != googleIssuerLegacy) {
		return nil, googleIdentity{}, fmt.Errorf("%w issuer=%s", errInvalidGoogleIssuer, issuerValue)
	}
	return payload, googleIdentity{
		Sub:           readStringClaim(payload, "sub"),
		Email:         readStringClaim(payload, "email"),
		EmailVerified: readBoolClaim(payload, "email_verified"),
		DisplayName:   readStringClaim(payload, "name"),
		AvatarURL:     readStringClaim(payload, "picture"),
		Nonce:         readStringClaim(payload, "nonce"),
	}, nil
}

func validateGoogleIdentityTokenForAudiences(ctx context.Context, validator GoogleTokenValidator, idToken string, audiences []string) (*idtoken.Payload, googleIdentity, error) {
	acceptedAudiences := uniqueNonEmptyStrings(audiences)
	if len(acceptedAudiences) == 0 {
		return nil, googleIdentity{}, errors.New("auth.login.native.missing_audience")
	}
	var lastErr error
	for _, audience := range acceptedAudiences {
		payload, identity, validateErr := validateGoogleIdentityToken(ctx, validator, idToken, audience)
		if validateErr == nil {
			return payload, identity, nil
		}
		lastErr = validateErr
	}
	return nil, googleIdentity{}, lastErr
}

func nativeGoogleClientsForPlatform(config ServerConfig, platform string) []NativeGoogleClientConfig {
	clients := configuredNativeGoogleClients(config)
	normalizedPlatform := normalizeNativeGooglePlatform(platform)
	if normalizedPlatform == "" {
		return clients
	}
	filteredClients := make([]NativeGoogleClientConfig, 0, len(clients))
	for _, client := range clients {
		if normalizeNativeGooglePlatform(client.Platform) == normalizedPlatform {
			filteredClients = append(filteredClients, client)
		}
	}
	return filteredClients
}

func configuredNativeGoogleClients(config ServerConfig) []NativeGoogleClientConfig {
	clients := make([]NativeGoogleClientConfig, 0, len(config.NativeGoogleClients)+1)
	for _, client := range config.NativeGoogleClients {
		clientID := strings.TrimSpace(client.ClientID)
		if clientID == "" {
			continue
		}
		platform := normalizeNativeGooglePlatform(client.Platform)
		if platform == "" {
			platform = nativeGoogleDefaultPlatform
		}
		clients = append(clients, NativeGoogleClientConfig{
			Platform:     platform,
			ClientID:     clientID,
			RedirectURIs: append([]string(nil), client.RedirectURIs...),
		})
	}
	legacyClientID := strings.TrimSpace(config.GoogleNativeClientID)
	if legacyClientID != "" && !nativeGoogleClientIDExists(clients, legacyClientID) {
		clients = append(clients, NativeGoogleClientConfig{
			Platform: nativeGoogleDefaultPlatform,
			ClientID: legacyClientID,
		})
	}
	return clients
}

func nativeGoogleClientIDExists(clients []NativeGoogleClientConfig, clientID string) bool {
	for _, client := range clients {
		if client.ClientID == clientID {
			return true
		}
	}
	return false
}

func nativeGoogleClientIDs(clients []NativeGoogleClientConfig) []string {
	clientIDs := make([]string, 0, len(clients))
	seenClientIDs := make(map[string]struct{}, len(clients))
	for _, client := range clients {
		clientID := strings.TrimSpace(client.ClientID)
		if clientID == "" {
			continue
		}
		if _, exists := seenClientIDs[clientID]; exists {
			continue
		}
		seenClientIDs[clientID] = struct{}{}
		clientIDs = append(clientIDs, clientID)
	}
	return clientIDs
}

func nativeGoogleRedirectURIs(clients []NativeGoogleClientConfig) []string {
	redirectURIs := make([]string, 0)
	seenRedirectURIs := make(map[string]struct{})
	for _, client := range clients {
		for _, redirectURI := range client.RedirectURIs {
			trimmedRedirectURI := strings.TrimSpace(redirectURI)
			if trimmedRedirectURI == "" {
				continue
			}
			if _, exists := seenRedirectURIs[trimmedRedirectURI]; exists {
				continue
			}
			seenRedirectURIs[trimmedRedirectURI] = struct{}{}
			redirectURIs = append(redirectURIs, trimmedRedirectURI)
		}
	}
	return redirectURIs
}

func nativeGoogleClientResponses(clients []NativeGoogleClientConfig) []nativeGoogleClientResponse {
	responses := make([]nativeGoogleClientResponse, 0, len(clients))
	for _, client := range clients {
		responses = append(responses, nativeGoogleClientResponse{
			Platform:     normalizeNativeGooglePlatform(client.Platform),
			ClientID:     strings.TrimSpace(client.ClientID),
			RedirectURIs: append([]string(nil), client.RedirectURIs...),
		})
	}
	return responses
}

func validateNativeGoogleRedirectURI(clients []NativeGoogleClientConfig, redirectURI string) error {
	acceptedRedirectURIs := nativeGoogleRedirectURIs(clients)
	if len(acceptedRedirectURIs) == 0 {
		return nil
	}
	trimmedRedirectURI := strings.TrimSpace(redirectURI)
	if trimmedRedirectURI == "" {
		return errors.New("auth.login.native.redirect_uri_required")
	}
	for _, acceptedRedirectURI := range acceptedRedirectURIs {
		if acceptedRedirectURI == trimmedRedirectURI {
			return nil
		}
	}
	return errors.New("auth.login.native.redirect_uri_not_allowed")
}

func normalizeNativeGooglePlatform(platform string) string {
	return strings.ToLower(strings.TrimSpace(platform))
}

func uniqueNonEmptyStrings(values []string) []string {
	uniqueValues := make([]string, 0, len(values))
	seenValues := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmedValue := strings.TrimSpace(value)
		if trimmedValue == "" {
			continue
		}
		if _, exists := seenValues[trimmedValue]; exists {
			continue
		}
		seenValues[trimmedValue] = struct{}{}
		uniqueValues = append(uniqueValues, trimmedValue)
	}
	return uniqueValues
}

func readStringClaim(payload *idtoken.Payload, claim string) string {
	if payload == nil {
		return ""
	}
	value, _ := payload.Claims[claim].(string)
	return value
}

func readBoolClaim(payload *idtoken.Payload, claim string) bool {
	if payload == nil {
		return false
	}
	value, _ := payload.Claims[claim].(bool)
	return value
}

func validateSessionRequest(request *http.Request, config ServerConfig) (*sessionvalidator.Claims, error) {
	validator, validatorErr := sessionvalidator.New(sessionvalidator.Config{
		SigningKey: config.AppJWTSigningKey,
		Issuer:     config.AppJWTIssuer,
		CookieName: config.SessionCookieName,
	})
	if validatorErr != nil {
		return nil, validatorErr
	}
	return validator.ValidateRequest(request)
}

func sessionProfilePayload(userID string, userEmail string, userDisplayName string, userAvatarURL string, userRoles []string, expiresAt time.Time) gin.H {
	return gin.H{
		"user_id":    userID,
		"user_email": userEmail,
		"display":    userDisplayName,
		"avatar_url": userAvatarURL,
		"roles":      userRoles,
		"expires":    expiresAt,
	}
}

func accountProfilePayload(profile AccountProfile) gin.H {
	return gin.H{
		"user_id":    profile.AccountID,
		"user_email": profile.UserEmail,
		"display":    profile.DisplayName,
		"avatar_url": profile.AvatarURL,
		"roles":      profile.Roles,
		"state":      profile.State,
	}
}

func challengePayload(config ServerConfig, tokenField string, challenge AccountChallenge) gin.H {
	payload := gin.H{
		"status":       "accepted",
		"account_id":   challenge.AccountID,
		"expires_unix": challenge.ExpiresUnix,
	}
	if config.ReturnChallengeTokens {
		payload[tokenField] = challenge.Token
	}
	return payload
}

func fakeChallenge(expiresUnix int64) AccountChallenge {
	token, _, tokenErr := generateRefreshOpaque()
	if tokenErr != nil {
		token = "accepted"
	}
	return AccountChallenge{Token: token, ExpiresUnix: expiresUnix}
}

func effectiveDuration(value time.Duration, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}

func requireAccountManagementStore(contextGin *gin.Context, config ServerConfig, accountStore AccountManagementStore) (AccountManagementStore, bool) {
	if !config.AccountManagementEnabled {
		contextGin.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": errorAccountManagementNotConfigured})
		return nil, false
	}
	if accountStore == nil {
		logAuthError("auth.account.store_missing", nil)
		contextGin.AbortWithStatus(http.StatusInternalServerError)
		return nil, false
	}
	return accountStore, true
}

func currentAccountContext(contextGin *gin.Context, registry TenantRegistry) (string, ServerConfig, string, bool) {
	tenantID, resolved := resolveTenantIDRequired(contextGin, registry)
	if !resolved {
		contextGin.AbortWithStatus(http.StatusInternalServerError)
		return "", ServerConfig{}, "", false
	}
	claimsValue, exists := contextGin.Get("auth_claims")
	if !exists {
		contextGin.AbortWithStatus(http.StatusUnauthorized)
		return "", ServerConfig{}, "", false
	}
	claims, ok := claimsValue.(*JwtCustomClaims)
	if !ok {
		contextGin.AbortWithStatus(http.StatusUnauthorized)
		return "", ServerConfig{}, "", false
	}
	accountID := strings.TrimSpace(claims.GetUserID())
	if !strings.HasPrefix(accountID, accountIDPrefix) {
		contextGin.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": errorAccountNotActive})
		return "", ServerConfig{}, "", false
	}
	return tenantID, registry.Config(tenantID), accountID, true
}

func writeAccountError(contextGin *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrAccountExists):
		contextGin.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": errorAccountExists})
	case errors.Is(err, ErrAccountChallengeInvalid):
		contextGin.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": errorAccountChallengeInvalid})
	case errors.Is(err, ErrAccountLastIdentity):
		contextGin.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": errorAccountLastIdentity})
	case errors.Is(err, ErrAccountDisabled):
		contextGin.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": errorAccountDisabled})
	case errors.Is(err, ErrAccountNotActive):
		contextGin.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": errorAccountNotActive})
	case errors.Is(err, ErrPasswordCredentialInvalid):
		contextGin.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": errorPasswordCredentialInvalid})
	case errors.Is(err, ErrAccountNotFound):
		contextGin.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "account_not_found"})
	default:
		logAuthError("auth.account.error", err)
		contextGin.AbortWithStatus(http.StatusInternalServerError)
	}
}

func consumeBrowserNonce(contextGin *gin.Context, nonces NonceStore, tenantID string, nonceToken string, payload *idtoken.Payload) error {
	nonceClaim := strings.TrimSpace(readStringClaim(payload, "nonce"))
	issuedNonceToken := strings.TrimSpace(nonceToken)
	if nonceClaim == "" {
		return fmt.Errorf("%w: missing google nonce claim", ErrNonceNotFound)
	}
	expectedHashedNonce := hashOpaque(issuedNonceToken)
	nonceMatchesInbound := nonceClaim == issuedNonceToken
	nonceMatchesHashed := nonceClaim == expectedHashedNonce
	if !nonceMatchesInbound && !nonceMatchesHashed {
		return fmt.Errorf("%w: google nonce claim mismatch", ErrNonceNotFound)
	}
	return nonces.Consume(contextGin, tenantID, issuedNonceToken)
}

func finalizeGoogleLogin(
	contextGin *gin.Context,
	users UserStore,
	refreshTokens RefreshTokenStore,
	clock Clock,
	config ServerConfig,
	tenantID string,
	identity googleIdentity,
) error {
	applicationUserID, userRoles, upsertErr := users.UpsertGoogleUser(
		contextGin,
		tenantID,
		identity.Sub,
		identity.Email,
		identity.DisplayName,
		identity.AvatarURL,
	)
	if upsertErr != nil || applicationUserID == "" {
		if upsertErr != nil {
			return fmt.Errorf("%w: %w", errGoogleLoginUserStore, upsertErr)
		}
		return fmt.Errorf("%w: empty_user_id", errGoogleLoginUserStore)
	}
	return finalizeAuthenticatedSession(contextGin, refreshTokens, clock, config, tenantID, authenticatedSessionProfile{
		applicationUserID: applicationUserID,
		userEmail:         identity.Email,
		userDisplayName:   identity.DisplayName,
		userAvatarURL:     identity.AvatarURL,
		userRoles:         userRoles,
	})
}

func finalizePasswordLogin(
	contextGin *gin.Context,
	users UserStore,
	refreshTokens RefreshTokenStore,
	clock Clock,
	config ServerConfig,
	tenantID string,
	profile PasswordCredentialProfile,
) error {
	if strings.TrimSpace(profile.AccountID) != "" {
		return finalizeAccountLogin(contextGin, users, refreshTokens, clock, config, tenantID, AccountProfile{
			AccountID:   profile.AccountID,
			UserEmail:   profile.UserEmail,
			DisplayName: profile.DisplayName,
			AvatarURL:   profile.AvatarURL,
			Roles:       []string{defaultUserRole},
			State:       accountStateActive,
		})
	}
	applicationUserID, userRoles, upsertErr := users.UpsertPasswordUser(
		contextGin,
		tenantID,
		profile.UserEmail,
		profile.DisplayName,
		profile.AvatarURL,
	)
	if upsertErr != nil || applicationUserID == "" {
		if upsertErr != nil {
			return fmt.Errorf("auth.login.password.user_store: %w", upsertErr)
		}
		return fmt.Errorf("auth.login.password.user_store: empty_user_id")
	}
	return finalizeAuthenticatedSession(contextGin, refreshTokens, clock, config, tenantID, authenticatedSessionProfile{
		applicationUserID: applicationUserID,
		userEmail:         profile.UserEmail,
		userDisplayName:   profile.DisplayName,
		userAvatarURL:     profile.AvatarURL,
		userRoles:         userRoles,
	})
}

func finalizeAccountLogin(
	contextGin *gin.Context,
	users UserStore,
	refreshTokens RefreshTokenStore,
	clock Clock,
	config ServerConfig,
	tenantID string,
	profile AccountProfile,
) error {
	if profile.State == accountStateDisabled {
		return ErrAccountDisabled
	}
	if profile.State != accountStateActive {
		return ErrAccountNotActive
	}
	applicationUserID, userRoles, upsertErr := users.UpsertAccountUser(
		contextGin,
		tenantID,
		profile.AccountID,
		profile.UserEmail,
		profile.DisplayName,
		profile.AvatarURL,
	)
	if upsertErr != nil || applicationUserID == "" {
		if upsertErr != nil {
			return fmt.Errorf("auth.login.account.user_store: %w", upsertErr)
		}
		return fmt.Errorf("auth.login.account.user_store: empty_user_id")
	}
	return finalizeAuthenticatedSession(contextGin, refreshTokens, clock, config, tenantID, authenticatedSessionProfile{
		applicationUserID: applicationUserID,
		userEmail:         profile.UserEmail,
		userDisplayName:   profile.DisplayName,
		userAvatarURL:     profile.AvatarURL,
		userRoles:         userRoles,
	})
}

func finalizeAuthenticatedSession(
	contextGin *gin.Context,
	refreshTokens RefreshTokenStore,
	clock Clock,
	config ServerConfig,
	tenantID string,
	profile authenticatedSessionProfile,
) error {
	sessionToken, sessionExpiresAt, mintErr := MintAppJWT(
		clock,
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
		return fmt.Errorf("%w: %w", errGoogleLoginMintJWT, mintErr)
	}
	refreshDeadline := clock.Now().UTC().Add(config.RefreshTTL)
	_, refreshOpaque, issueErr := refreshTokens.Issue(contextGin, tenantID, profile.applicationUserID, refreshDeadline.Unix(), "")
	if issueErr != nil || strings.TrimSpace(refreshOpaque) == "" {
		if issueErr != nil {
			return fmt.Errorf("%w: %w", errGoogleLoginIssueRefresh, issueErr)
		}
		return fmt.Errorf("%w: empty_token", errGoogleLoginIssueRefresh)
	}
	writeSessionCookie(contextGin, config, sessionToken, sessionExpiresAt)
	writeRefreshCookie(contextGin, config, refreshOpaque, refreshDeadline)
	contextGin.JSON(http.StatusOK, gin.H{
		"user_id":    profile.applicationUserID,
		"user_email": profile.userEmail,
		"display":    profile.userDisplayName,
		"avatar_url": profile.userAvatarURL,
		"roles":      profile.userRoles,
	})
	return nil
}

func writeSessionCookie(contextGin *gin.Context, configuration ServerConfig, sessionToken string, expiresAt time.Time) {
	secure := !configuration.AllowInsecureHTTP
	http.SetCookie(contextGin.Writer, &http.Cookie{
		Name:     configuration.SessionCookieName,
		Value:    sessionToken,
		Path:     "/",
		Domain:   configuration.CookieDomain,
		Expires:  expiresAt,
		Secure:   secure,
		HttpOnly: true,
		SameSite: configuration.SameSiteMode,
	})
}

func writeRefreshCookie(contextGin *gin.Context, configuration ServerConfig, opaque string, expiresAt time.Time) {
	secure := !configuration.AllowInsecureHTTP
	http.SetCookie(contextGin.Writer, &http.Cookie{
		Name:     configuration.RefreshCookieName,
		Value:    opaque,
		Path:     "/auth",
		Domain:   configuration.CookieDomain,
		Expires:  expiresAt,
		Secure:   secure,
		HttpOnly: true,
		SameSite: configuration.SameSiteMode,
	})
}

func clearCookie(contextGin *gin.Context, configuration ServerConfig, name string, path string) {
	clearCookieVariants(contextGin, configuration, name, path)
}

func clearCookieVariants(contextGin *gin.Context, configuration ServerConfig, name string, path string) {
	secure := !configuration.AllowInsecureHTTP
	domains := []string{configuration.CookieDomain}
	if configuration.CookieDomain != "" {
		domains = append(domains, "")
	}
	for _, domain := range domains {
		http.SetCookie(contextGin.Writer, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     path,
			Domain:   domain,
			MaxAge:   -1,
			Secure:   secure,
			HttpOnly: true,
			SameSite: configuration.SameSiteMode,
		})
	}
}

func refreshCookieCandidates(request *http.Request, cookieName string) []string {
	if request == nil {
		return nil
	}
	trimmedName := strings.TrimSpace(cookieName)
	if trimmedName == "" {
		return nil
	}
	parsedCookies := request.Cookies()
	if len(parsedCookies) == 0 {
		return nil
	}
	candidates := make([]string, 0, len(parsedCookies))
	for _, cookie := range parsedCookies {
		if cookie == nil {
			continue
		}
		if cookie.Name != trimmedName {
			continue
		}
		trimmedValue := strings.TrimSpace(cookie.Value)
		if trimmedValue == "" {
			continue
		}
		candidates = append(candidates, trimmedValue)
	}
	return candidates
}

func isUnauthorizedRefreshTokenError(err error) bool {
	return errors.Is(err, ErrRefreshTokenEmptyOpaque) ||
		errors.Is(err, ErrRefreshTokenNotFound) ||
		errors.Is(err, ErrRefreshTokenExpired)
}

func isAllowedUser(userEmail string, allowedUsers map[string]struct{}) bool {
	if allowedUsers == nil {
		return true
	}
	normalizedEmail := normalizeUserEmail(userEmail)
	if normalizedEmail == "" {
		return false
	}
	_, allowed := allowedUsers[normalizedEmail]
	return allowed
}

func normalizeUserEmail(userEmail string) string {
	return strings.ToLower(strings.TrimSpace(userEmail))
}

func isHTTPS(request *http.Request) bool {
	if request.TLS != nil {
		return true
	}
	scheme := request.Header.Get("X-Forwarded-Proto")
	if strings.EqualFold(scheme, "https") {
		return true
	}
	forwarded := request.Header.Get("Forwarded")
	if forwarded != "" && strings.Contains(strings.ToLower(forwarded), "proto=https") {
		return true
	}
	host, _, splitErr := net.SplitHostPort(request.Host)
	if splitErr == nil && host == "localhost" {
		return true
	}
	return false
}

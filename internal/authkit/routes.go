package authkit

import (
	"context"
	"errors"

	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/web"
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
	metricAuthLoginSuccess   = "auth.login.success"
	metricAuthLoginFailure   = "auth.login.failure"
	metricAuthRefreshSuccess = "auth.refresh.success"
	metricAuthRefreshFailure = "auth.refresh.failure"
	metricAuthLogoutSuccess  = "auth.logout.success"
)

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
	clock := configuredClock
	if clock == nil {
		clock = NewSystemClock()
	}
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

	router.POST("/auth/google", func(contextGin *gin.Context) {
		tenantID, resolved := resolveTenantIDRequired(contextGin, registry)
		if !resolved {
			recordMetric(metricAuthLoginFailure)
			logAuthError("auth.tenant.missing", errMissingTenantContext)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		config := registry.Config(tenantID)
		var inbound struct {
			GoogleIDToken string `json:"google_id_token"`
			NonceToken    string `json:"nonce_token"`
		}
		if err := contextGin.BindJSON(&inbound); err != nil || strings.TrimSpace(inbound.GoogleIDToken) == "" {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.invalid_json", err)
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
		payload, validateErr := validator.Validate(context.Background(), inbound.GoogleIDToken, config.GoogleWebClientID)
		if validateErr != nil {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.invalid_google_token", validateErr)
			contextGin.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_google_token"})
			return
		}
		issuerValue, okIssuer := payload.Claims["iss"].(string)
		if !okIssuer || (issuerValue != "https://accounts.google.com" && issuerValue != "accounts.google.com") {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.invalid_issuer", nil, zap.String("issuer", issuerValue))
			contextGin.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_issuer"})
			return
		}
		googleSub, _ := payload.Claims["sub"].(string)
		userEmail, _ := payload.Claims["email"].(string)
		emailVerified, _ := payload.Claims["email_verified"].(bool)
		userDisplayName, _ := payload.Claims["name"].(string)
		userAvatarURL, _ := payload.Claims["picture"].(string)
		nonceClaim, _ := payload.Claims["nonce"].(string)
		if nonceClaim == "" {
			if consumeErr := nonces.Consume(contextGin, tenantID, inbound.NonceToken); consumeErr != nil {
				recordMetric(metricAuthLoginFailure)
				logAuthWarning("auth.login.invalid_nonce_token", consumeErr)
				contextGin.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_nonce"})
				return
			}
		} else {
			expectedHashedNonce := hashOpaque(inbound.NonceToken)
			nonceMatchesInbound := nonceClaim == inbound.NonceToken
			nonceMatchesHashed := nonceClaim == expectedHashedNonce
			tokenToConsume := inbound.NonceToken
			fallbackNonce := false
			if !nonceMatchesInbound && !nonceMatchesHashed {
				tokenToConsume = nonceClaim
				fallbackNonce = true
			}
			if consumeErr := nonces.Consume(contextGin, tenantID, tokenToConsume); consumeErr != nil {
				recordMetric(metricAuthLoginFailure)
				if fallbackNonce {
					logAuthWarning(
						"auth.login.nonce_mismatch",
						consumeErr,
						zap.String("google_nonce", nonceClaim),
						zap.String("expected_nonce_hashed", expectedHashedNonce),
					)
				} else {
					logAuthWarning("auth.login.invalid_nonce_token", consumeErr)
				}
				contextGin.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_nonce"})
				return
			}
		}

		if googleSub == "" || userEmail == "" || !emailVerified {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.unverified_identity", nil)
			contextGin.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unverified_identity"})
			return
		}

		applicationUserID, userRoles, upsertErr := users.UpsertGoogleUser(contextGin, tenantID, googleSub, userEmail, userDisplayName, userAvatarURL)
		if upsertErr != nil || applicationUserID == "" {
			recordMetric(metricAuthLoginFailure)
			logAuthError("auth.login.user_store", upsertErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		sessionToken, sessionExpiresAt, mintErr := MintAppJWT(clock, tenantID, applicationUserID, userEmail, userDisplayName, userAvatarURL, userRoles, config.AppJWTIssuer, config.AppJWTSigningKey, config.SessionTTL)
		if mintErr != nil {
			recordMetric(metricAuthLoginFailure)
			logAuthError("auth.login.mint_jwt", mintErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		refreshDeadline := clock.Now().UTC().Add(config.RefreshTTL)
		_, refreshOpaque, issueErr := refreshTokens.Issue(contextGin, tenantID, applicationUserID, refreshDeadline.Unix(), "")
		if issueErr != nil || strings.TrimSpace(refreshOpaque) == "" {
			recordMetric(metricAuthLoginFailure)
			logAuthError("auth.login.issue_refresh", issueErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		writeSessionCookie(contextGin, config, sessionToken, sessionExpiresAt)
		writeRefreshCookie(contextGin, config, refreshOpaque, refreshDeadline)

		contextGin.JSON(http.StatusOK, gin.H{
			"user_id":    applicationUserID,
			"user_email": userEmail,
			"display":    userDisplayName,
			"avatar_url": userAvatarURL,
			"roles":      userRoles,
		})
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
		refreshCookie, cookieErr := contextGin.Request.Cookie(config.RefreshCookieName)
		if cookieErr != nil || refreshCookie == nil || strings.TrimSpace(refreshCookie.Value) == "" {
			recordMetric(metricAuthRefreshFailure)
			logAuthWarning("auth.refresh.missing_cookie", cookieErr)
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		applicationUserID, currentTokenID, expiresUnix, validateErr := refreshTokens.Validate(contextGin, tenantID, refreshCookie.Value)
		if validateErr != nil {
			recordMetric(metricAuthRefreshFailure)
			if errors.Is(validateErr, ErrRefreshTokenRevoked) {
				logAuthWarning("auth.refresh.validate", validateErr)
				contextGin.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			if isClearableRefreshTokenError(validateErr) {
				logAuthWarning("auth.refresh.validate", validateErr)
				clearAuthCookies(contextGin, config)
				contextGin.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			logAuthError("auth.refresh.validate", validateErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if time.Unix(expiresUnix, 0).Before(clock.Now().UTC()) {
			recordMetric(metricAuthRefreshFailure)
			logAuthWarning("auth.refresh.expired", nil)
			clearAuthCookies(contextGin, config)
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		userEmail, userDisplayName, userAvatarURL, userRoles, profileErr := users.GetUserProfile(contextGin, tenantID, applicationUserID)
		if profileErr != nil {
			recordMetric(metricAuthRefreshFailure)
			logAuthWarning("auth.refresh.profile", profileErr)
			clearAuthCookies(contextGin, config)
			contextGin.AbortWithStatus(http.StatusUnauthorized)
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

	whoAmI := router.Group("/")
	whoAmI.Use(RequireSession(registry))
	whoAmI.GET("/me", web.HandleWhoAmI(users, configuredLogger))
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

func clearAuthCookies(contextGin *gin.Context, configuration ServerConfig) {
	clearCookie(contextGin, configuration, configuration.SessionCookieName, "/")
	clearCookie(contextGin, configuration, configuration.RefreshCookieName, "/auth")
}

func isClearableRefreshTokenError(err error) bool {
	return errors.Is(err, ErrRefreshTokenEmptyOpaque) ||
		errors.Is(err, ErrRefreshTokenNotFound) ||
		errors.Is(err, ErrRefreshTokenExpired)
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

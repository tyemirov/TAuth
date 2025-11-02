package authkit

import (
	"context"
	"errors"

	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/api/idtoken"
	"go.uber.org/zap"
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

// ProvideGoogleTokenValidator injects a singleton validator for auth routes.
func ProvideGoogleTokenValidator(validator GoogleTokenValidator) {
	configuredGoogleValidator = validator
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

// MountAuthRoutes registers /auth/google, /auth/refresh, /auth/logout, and /me.
func MountAuthRoutes(router gin.IRouter, configuration ServerConfig, users UserStore, refreshTokens RefreshTokenStore) {
	validator := configuredGoogleValidator
	var validatorInitErr error
	if validator == nil {
		validator, validatorInitErr = newGoogleTokenValidator(context.Background())
	}
	clock := configuredClock
	if clock == nil {
		clock = NewSystemClock()
	}

	router.POST("/auth/google", func(contextGin *gin.Context) {
		var inbound struct {
			GoogleIDToken string `json:"google_id_token"`
			Nonce         string `json:"nonce"`
		}
		if err := contextGin.BindJSON(&inbound); err != nil || strings.TrimSpace(inbound.GoogleIDToken) == "" {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.invalid_json", err)
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
			return
		}

		if !configuration.AllowInsecureHTTP && !isHTTPS(contextGin.Request) {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.insecure_http", nil)
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "https_required"})
			return
		}

		if validatorInitErr != nil {
			recordMetric(metricAuthLoginFailure)
			logAuthError("auth.login.validator_init", validatorInitErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		payload, validateErr := validator.Validate(context.Background(), inbound.GoogleIDToken, configuration.GoogleWebClientID)
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

		if googleSub == "" || userEmail == "" || !emailVerified {
			recordMetric(metricAuthLoginFailure)
			logAuthWarning("auth.login.unverified_identity", nil)
			contextGin.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unverified_identity"})
			return
		}

		applicationUserID, userRoles, upsertErr := users.UpsertGoogleUser(contextGin, googleSub, userEmail, userDisplayName)
		if upsertErr != nil || applicationUserID == "" {
			recordMetric(metricAuthLoginFailure)
			logAuthError("auth.login.user_store", upsertErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		sessionToken, sessionExpiresAt, mintErr := MintAppJWT(clock, applicationUserID, userEmail, userDisplayName, userRoles, configuration.AppJWTIssuer, configuration.AppJWTSigningKey, configuration.SessionTTL)
		if mintErr != nil {
			recordMetric(metricAuthLoginFailure)
			logAuthError("auth.login.mint_jwt", mintErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		refreshDeadline := clock.Now().UTC().Add(configuration.RefreshTTL)
		_, refreshOpaque, issueErr := refreshTokens.Issue(contextGin, applicationUserID, refreshDeadline.Unix(), "")
		if issueErr != nil || strings.TrimSpace(refreshOpaque) == "" {
			recordMetric(metricAuthLoginFailure)
			logAuthError("auth.login.issue_refresh", issueErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		writeSessionCookie(contextGin, configuration, sessionToken, sessionExpiresAt)
		writeRefreshCookie(contextGin, configuration, refreshOpaque, refreshDeadline)

		contextGin.JSON(http.StatusOK, gin.H{
			"user_id":    applicationUserID,
			"user_email": userEmail,
			"display":    userDisplayName,
			"roles":      userRoles,
		})
		recordMetric(metricAuthLoginSuccess)
	})

	router.POST("/auth/refresh", func(contextGin *gin.Context) {
		refreshCookie, cookieErr := contextGin.Request.Cookie(configuration.RefreshCookieName)
		if cookieErr != nil || refreshCookie == nil || strings.TrimSpace(refreshCookie.Value) == "" {
			recordMetric(metricAuthRefreshFailure)
			logAuthWarning("auth.refresh.missing_cookie", cookieErr)
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		applicationUserID, currentTokenID, expiresUnix, validateErr := refreshTokens.Validate(contextGin, refreshCookie.Value)
		if validateErr != nil {
			recordMetric(metricAuthRefreshFailure)
			logAuthWarning("auth.refresh.validate", validateErr)
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		if time.Unix(expiresUnix, 0).Before(clock.Now().UTC()) {
			recordMetric(metricAuthRefreshFailure)
			logAuthWarning("auth.refresh.expired", nil)
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		userEmail, userDisplayName, userRoles, profileErr := users.GetUserProfile(contextGin, applicationUserID)
		if profileErr != nil {
			recordMetric(metricAuthRefreshFailure)
			logAuthWarning("auth.refresh.profile", profileErr)
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		sessionToken, sessionExpiresAt, mintErr := MintAppJWT(clock, applicationUserID, userEmail, userDisplayName, userRoles, configuration.AppJWTIssuer, configuration.AppJWTSigningKey, configuration.SessionTTL)
		if mintErr != nil {
			recordMetric(metricAuthRefreshFailure)
			logAuthError("auth.refresh.mint_jwt", mintErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		refreshDeadline := clock.Now().UTC().Add(configuration.RefreshTTL)
		_, newOpaque, issueErr := refreshTokens.Issue(contextGin, applicationUserID, refreshDeadline.Unix(), currentTokenID)
		if issueErr != nil || strings.TrimSpace(newOpaque) == "" {
			recordMetric(metricAuthRefreshFailure)
			logAuthError("auth.refresh.issue_refresh", issueErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if revokeErr := refreshTokens.Revoke(contextGin, currentTokenID); revokeErr != nil && !errors.Is(revokeErr, ErrRefreshTokenAlreadyRevoked) {
			recordMetric(metricAuthRefreshFailure)
			logAuthError("auth.refresh.revoke_previous", revokeErr)
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		writeSessionCookie(contextGin, configuration, sessionToken, sessionExpiresAt)
		writeRefreshCookie(contextGin, configuration, newOpaque, refreshDeadline)

		contextGin.Status(http.StatusNoContent)
		recordMetric(metricAuthRefreshSuccess)
	})

	router.POST("/auth/logout", func(contextGin *gin.Context) {
		refreshCookie, cookieErr := contextGin.Request.Cookie(configuration.RefreshCookieName)
		if cookieErr == nil && refreshCookie != nil && strings.TrimSpace(refreshCookie.Value) != "" {
			_, tokenID, _, validateErr := refreshTokens.Validate(contextGin, refreshCookie.Value)
			if validateErr == nil && tokenID != "" {
				if revokeErr := refreshTokens.Revoke(contextGin, tokenID); revokeErr != nil && !errors.Is(revokeErr, ErrRefreshTokenAlreadyRevoked) {
					logAuthWarning("auth.logout.revoke", revokeErr)
				}
			}
		}
		clearCookie(contextGin, configuration.SessionCookieName, configuration.CookieDomain, configuration.SameSiteMode)
		clearCookie(contextGin, configuration.RefreshCookieName, configuration.CookieDomain, configuration.SameSiteMode)
		contextGin.Status(http.StatusNoContent)
		recordMetric(metricAuthLogoutSuccess)
	})

	router.GET("/me", func(contextGin *gin.Context) {
		sessionCookie, cookieErr := contextGin.Request.Cookie(configuration.SessionCookieName)
		if cookieErr != nil || sessionCookie == nil || strings.TrimSpace(sessionCookie.Value) == "" {
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		parsedToken, parseErr := jwt.ParseWithClaims(sessionCookie.Value, &JwtCustomClaims{}, func(parsed *jwt.Token) (interface{}, error) {
			return configuration.AppJWTSigningKey, nil
		}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
		if parseErr != nil || parsedToken == nil || !parsedToken.Valid {
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		claims, ok := parsedToken.Claims.(*JwtCustomClaims)
		if !ok || claims.Issuer != configuration.AppJWTIssuer {
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		contextGin.JSON(http.StatusOK, gin.H{
			"user_id":    claims.UserID,
			"user_email": claims.UserEmail,
			"display":    claims.UserDisplayName,
			"roles":      claims.UserRoles,
			"expires":    claims.ExpiresAt.Time,
		})
	})
}

func writeSessionCookie(contextGin *gin.Context, configuration ServerConfig, sessionToken string, expiresAt time.Time) {
	http.SetCookie(contextGin.Writer, &http.Cookie{
		Name:     configuration.SessionCookieName,
		Value:    sessionToken,
		Path:     "/",
		Domain:   configuration.CookieDomain,
		Expires:  expiresAt,
		Secure:   true,
		HttpOnly: true,
		SameSite: configuration.SameSiteMode,
	})
}

func writeRefreshCookie(contextGin *gin.Context, configuration ServerConfig, opaque string, expiresAt time.Time) {
	http.SetCookie(contextGin.Writer, &http.Cookie{
		Name:     configuration.RefreshCookieName,
		Value:    opaque,
		Path:     "/auth",
		Domain:   configuration.CookieDomain,
		Expires:  expiresAt,
		Secure:   true,
		HttpOnly: true,
		SameSite: configuration.SameSiteMode,
	})
}

func clearCookie(contextGin *gin.Context, name string, domain string, sameSite http.SameSite) {
	http.SetCookie(contextGin.Writer, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Domain:   domain,
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: sameSite,
	})
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

package authkit

import (
	"context"

	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/api/idtoken"
)

// MountAuthRoutes registers /auth/google, /auth/refresh, /auth/logout, and /me.
func MountAuthRoutes(router gin.IRouter, configuration ServerConfig, users UserStore, refreshTokens RefreshTokenStore) {
	router.POST("/auth/google", func(contextGin *gin.Context) {
		var inbound struct {
			GoogleIDToken string `json:"google_id_token"`
			Nonce         string `json:"nonce"`
		}
		if err := contextGin.BindJSON(&inbound); err != nil || strings.TrimSpace(inbound.GoogleIDToken) == "" {
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
			return
		}

		if !configuration.AllowInsecureHTTP && !isHTTPS(contextGin.Request) {
			contextGin.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "https_required"})
			return
		}

		validator, validatorErr := idtoken.NewValidator(context.Background())
		if validatorErr != nil {
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		payload, validateErr := validator.Validate(context.Background(), inbound.GoogleIDToken, configuration.GoogleWebClientID)
		if validateErr != nil {
			contextGin.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_google_token"})
			return
		}
		issuerValue, okIssuer := payload.Claims["iss"].(string)
		if !okIssuer || (issuerValue != "https://accounts.google.com" && issuerValue != "accounts.google.com") {
			contextGin.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_issuer"})
			return
		}
		googleSub, _ := payload.Claims["sub"].(string)
		userEmail, _ := payload.Claims["email"].(string)
		emailVerified, _ := payload.Claims["email_verified"].(bool)
		userDisplayName, _ := payload.Claims["name"].(string)

		if googleSub == "" || userEmail == "" || !emailVerified {
			contextGin.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unverified_identity"})
			return
		}

		applicationUserID, userRoles, upsertErr := users.UpsertGoogleUser(contextGin, googleSub, userEmail, userDisplayName)
		if upsertErr != nil || applicationUserID == "" {
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		sessionToken, sessionExpiresAt, mintErr := MintAppJWT(applicationUserID, userEmail, userDisplayName, userRoles, configuration.AppJWTIssuer, configuration.AppJWTSigningKey, configuration.SessionTTL)
		if mintErr != nil {
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		_, refreshOpaque, issueErr := refreshTokens.Issue(contextGin, applicationUserID, time.Now().UTC().Add(configuration.RefreshTTL).Unix(), "")
		if issueErr != nil || strings.TrimSpace(refreshOpaque) == "" {
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		writeSessionCookie(contextGin, configuration, sessionToken, sessionExpiresAt)
		writeRefreshCookie(contextGin, configuration, refreshOpaque, time.Now().UTC().Add(configuration.RefreshTTL))

		contextGin.JSON(http.StatusOK, gin.H{
			"user_id":    applicationUserID,
			"user_email": userEmail,
			"display":    userDisplayName,
			"roles":      userRoles,
		})
	})

	router.POST("/auth/refresh", func(contextGin *gin.Context) {
		refreshCookie, cookieErr := contextGin.Request.Cookie(configuration.RefreshCookieName)
		if cookieErr != nil || refreshCookie == nil || strings.TrimSpace(refreshCookie.Value) == "" {
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		applicationUserID, currentTokenID, expiresUnix, validateErr := refreshTokens.Validate(contextGin, refreshCookie.Value)
		if validateErr != nil {
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		if time.Unix(expiresUnix, 0).Before(time.Now().UTC()) {
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		userEmail, userDisplayName, userRoles, profileErr := users.GetUserProfile(contextGin, applicationUserID)
		if profileErr != nil {
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		sessionToken, sessionExpiresAt, mintErr := MintAppJWT(applicationUserID, userEmail, userDisplayName, userRoles, configuration.AppJWTIssuer, configuration.AppJWTSigningKey, configuration.SessionTTL)
		if mintErr != nil {
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		_, newOpaque, issueErr := refreshTokens.Issue(contextGin, applicationUserID, time.Now().UTC().Add(configuration.RefreshTTL).Unix(), currentTokenID)
		if issueErr != nil || strings.TrimSpace(newOpaque) == "" {
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if revokeErr := refreshTokens.Revoke(contextGin, currentTokenID); revokeErr != nil {
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		writeSessionCookie(contextGin, configuration, sessionToken, sessionExpiresAt)
		writeRefreshCookie(contextGin, configuration, newOpaque, time.Now().UTC().Add(configuration.RefreshTTL))

		contextGin.Status(http.StatusNoContent)
	})

	router.POST("/auth/logout", func(contextGin *gin.Context) {
		refreshCookie, cookieErr := contextGin.Request.Cookie(configuration.RefreshCookieName)
		if cookieErr == nil && refreshCookie != nil && strings.TrimSpace(refreshCookie.Value) != "" {
			_, tokenID, _, validateErr := refreshTokens.Validate(contextGin, refreshCookie.Value)
			if validateErr == nil && tokenID != "" {
				_ = refreshTokens.Revoke(contextGin, tokenID)
			}
		}
		clearCookie(contextGin, configuration.SessionCookieName, configuration.CookieDomain, configuration.SameSiteMode)
		clearCookie(contextGin, configuration.RefreshCookieName, configuration.CookieDomain, configuration.SameSiteMode)
		contextGin.Status(http.StatusNoContent)
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

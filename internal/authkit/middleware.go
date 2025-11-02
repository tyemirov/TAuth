package authkit

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// RequireSession validates the session cookie and injects claims.
func RequireSession(configuration ServerConfig) gin.HandlerFunc {
	return func(contextGin *gin.Context) {
		sessionCookie, cookieErr := contextGin.Request.Cookie(configuration.SessionCookieName)
		if cookieErr != nil || sessionCookie == nil || sessionCookie.Value == "" {
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
		contextGin.Set("auth_claims", claims)
		contextGin.Next()
	}
}

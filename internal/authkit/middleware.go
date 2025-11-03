package authkit

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	sessionvalidator "github.com/tyemirov/tauth/pkg/sessionvalidator"
)

// RequireSession validates the session cookie and injects claims.
func RequireSession(configuration ServerConfig) gin.HandlerFunc {
	validator, err := sessionvalidator.New(sessionvalidator.Config{
		SigningKey: configuration.AppJWTSigningKey,
		Issuer:     configuration.AppJWTIssuer,
		CookieName: configuration.SessionCookieName,
	})
	if err != nil {
		panic(fmt.Sprintf("authkit.RequireSession: %v", err))
	}
	return func(contextGin *gin.Context) {
		claims, validateErr := validator.ValidateRequest(contextGin.Request)
		if validateErr != nil {
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		contextGin.Set("auth_claims", claims)
		contextGin.Next()
	}
}

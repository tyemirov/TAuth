package authkit

import (
	"fmt"
	"net/http"
	"strings"

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
		expectedTenant := resolveTenantID(contextGin, configuration.TenantID)
		if claims.GetTenantID() == "" || strings.TrimSpace(claims.GetTenantID()) != expectedTenant {
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		contextGin.Set("auth_claims", claims)
		contextGin.Next()
	}
}

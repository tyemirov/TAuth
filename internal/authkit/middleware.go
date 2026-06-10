package authkit

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	sessionvalidator "github.com/tyemirov/tauth/pkg/sessionvalidator"
)

// RequireSession validates the session cookie and injects claims.
func RequireSession(registry TenantRegistry) gin.HandlerFunc {
	validators := make(map[string]*sessionvalidator.Validator, len(registry.configs))
	buildValidator := func(config ServerConfig) *sessionvalidator.Validator {
		instance, err := sessionvalidator.New(sessionvalidator.Config{
			SigningKey: config.AppJWTSigningKey,
			Issuer:     config.AppJWTIssuer,
			CookieName: config.SessionCookieName,
		})
		if err != nil {
			panic(fmt.Sprintf("authkit.RequireSession: %v", err))
		}
		return instance
	}
	for tenantID, config := range registry.configs {
		validators[tenantID] = buildValidator(config)
	}
	defaultValidator := validators[registry.defaultTenantID]
	return func(contextGin *gin.Context) {
		expectedTenant, resolved := resolveTenantIDRequired(contextGin, registry)
		if !resolved {
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		validator := validators[expectedTenant]
		if validator == nil {
			validator = defaultValidator
		}
		claims, validateErr := validator.ValidateRequest(contextGin.Request)
		if validateErr != nil {
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		tenantID := strings.TrimSpace(claims.GetTenantID())
		if tenantID == "" {
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if tenantID != expectedTenant {
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		contextGin.Set("auth_claims", claims)
		contextGin.Next()
	}
}

// RequireActiveAccountSession rejects disabled account sessions after JWT validation.
func RequireActiveAccountSession(registry TenantRegistry, accountStore AccountManagementStore) gin.HandlerFunc {
	return func(contextGin *gin.Context) {
		tenantID, resolved := resolveTenantIDRequired(contextGin, registry)
		if !resolved {
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		config := registry.Config(tenantID)
		claimsValue, exists := contextGin.Get("auth_claims")
		if !exists {
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		claims, ok := claimsValue.(*JwtCustomClaims)
		if !ok {
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		if !isAccountSessionID(claims.GetUserID()) {
			contextGin.Next()
			return
		}
		if _, activeErr := activeAccountProfileForSession(contextGin, config, accountStore, tenantID, claims.GetUserID()); activeErr != nil {
			if isInactiveAccountSessionError(activeErr) {
				clearCookie(contextGin, config, config.SessionCookieName, "/")
				clearCookie(contextGin, config, config.RefreshCookieName, "/auth")
			}
			writeAccountError(contextGin, activeErr)
			return
		}
		contextGin.Next()
	}
}

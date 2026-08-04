package web

import (
	"fmt"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// PermissiveCORS enables cross-origin requests. Only enable if needed.
func PermissiveCORS(allowedOrigins []string) (gin.HandlerFunc, error) {
	sanitized := make([]string, 0, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		trimmed := strings.TrimSpace(origin)
		if trimmed != "" {
			sanitized = append(sanitized, trimmed)
		}
	}
	if len(sanitized) == 0 {
		return nil, fmt.Errorf("web.cors.invalid_origins: at least one explicit origin is required when credentials are allowed")
	}

	return cors.New(cors.Config{
		AllowOrigins:     sanitized,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "X-Requested-With", "X-Client", "X-TAuth-Tenant"},
		ExposeHeaders:    []string{"Content-Type"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}), nil
}

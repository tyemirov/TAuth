package web

import (
	"embed"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// ServeEmbeddedStaticJS writes a single embedded JS file with cache headers.
func ServeEmbeddedStaticJS(contextGin *gin.Context, filesystem embed.FS, path string) {
	data, readErr := filesystem.ReadFile(path)
	if readErr != nil {
		contextGin.AbortWithStatus(http.StatusNotFound)
		return
	}
	contextGin.Header("Content-Type", "application/javascript; charset=utf-8")
	contextGin.Header("Cache-Control", "public, max-age=31536000, immutable")
	contextGin.Data(http.StatusOK, "application/javascript; charset=utf-8", data)
}

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
		AllowHeaders:     []string{"Content-Type", "X-Requested-With", "X-Client"},
		ExposeHeaders:    []string{"Content-Type"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}), nil
}

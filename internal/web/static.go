package web

import (
	"embed"
	"net/http"
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
func PermissiveCORS() gin.HandlerFunc {
	return cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "X-Requested-With", "X-Client"},
		ExposeHeaders:    []string{"Content-Type"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	})
}

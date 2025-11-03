package web

import (
	"embed"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

var (
	errWildcardOrigin      = errors.New("cors: wildcard origin not allowed when credentials are enabled")
	errEmptyAllowedOrigins = errors.New("cors: no explicit origins provided")
	errInvalidOrigin       = errors.New("cors: invalid origin format")
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

// ConfigureCORS enables cross-origin requests for supplied origins.
func ConfigureCORS(logger *zap.Logger, allowedOrigins []string) (gin.HandlerFunc, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	sanitized, err := sanitizeOrigins(logger, allowedOrigins)
	if err != nil {
		return nil, err
	}
	config := cors.Config{
		AllowOrigins:     sanitized,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "X-Requested-With", "X-Client"},
		ExposeHeaders:    []string{"Content-Type"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}
	return cors.New(config), nil
}

func sanitizeOrigins(logger *zap.Logger, allowed []string) ([]string, error) {
	if len(allowed) == 0 {
		return nil, errEmptyAllowedOrigins
	}

	cloned := make([]string, len(allowed))
	copy(cloned, allowed)
	sort.Strings(cloned)

	seen := make(map[string]struct{})
	sanitized := make([]string, 0, len(cloned))

	for _, origin := range cloned {
		trimmed := strings.TrimSpace(origin)
		if trimmed == "" {
			continue
		}
		if trimmed == "*" {
			return nil, errWildcardOrigin
		}
		parsed, parseErr := url.Parse(trimmed)
		if parseErr != nil || parsed.Scheme == "" || parsed.Host == "" {
			return nil, fmt.Errorf("%w: %s", errInvalidOrigin, trimmed)
		}
		if parsed.Path != "" && parsed.Path != "/" {
			return nil, fmt.Errorf("%w: %s contains path segment", errInvalidOrigin, trimmed)
		}
		if parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, fmt.Errorf("%w: %s contains query or fragment", errInvalidOrigin, trimmed)
		}
		scheme := strings.ToLower(parsed.Scheme)
		if scheme != "https" && scheme != "http" {
			return nil, fmt.Errorf("%w: %s uses unsupported scheme", errInvalidOrigin, trimmed)
		}

		normalized := fmt.Sprintf("%s://%s", scheme, parsed.Host)
		if _, exists := seen[normalized]; exists {
			continue
		}
		if scheme == "http" && !isDevelopmentHost(parsed.Hostname()) {
			logger.Warn("unsafe cors origin configured",
				zap.String("code", "cors.origin.unsafe"),
				zap.String("origin", normalized))
		}
		seen[normalized] = struct{}{}
		sanitized = append(sanitized, normalized)
	}

	if len(sanitized) == 0 {
		return nil, errEmptyAllowedOrigins
	}

	return sanitized, nil
}

func isDevelopmentHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1":
		return true
	default:
		return false
	}
}

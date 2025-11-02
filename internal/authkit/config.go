package authkit

import (
	"net/http"
	"time"
)

// ServerConfig configures issuers, cookies, and TTL.
type ServerConfig struct {
	GoogleWebClientID string
	AppJWTSigningKey  []byte
	AppJWTIssuer      string
	CookieDomain      string
	SessionCookieName string
	RefreshCookieName string
	SessionTTL        time.Duration
	RefreshTTL        time.Duration
	SameSiteMode      http.SameSite
	AllowInsecureHTTP bool
}

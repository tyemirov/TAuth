package authkit

import (
	"net/http"
	"time"
)

// ServerConfig configures issuers, cookies, and TTL.
type ServerConfig struct {
	GoogleWebClientID    string
	GoogleNativeClientID string
	AppJWTSigningKey     []byte
	AppJWTIssuer         string
	TenantID             string
	CookieDomain         string
	SessionCookieName    string
	RefreshCookieName    string
	AllowedUsers         map[string]struct{}
	SessionTTL           time.Duration
	RefreshTTL           time.Duration
	NonceTTL             time.Duration
	SameSiteMode         http.SameSite
	AllowInsecureHTTP    bool
}

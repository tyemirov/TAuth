package authkit

import (
	"net/http"
	"time"
)

// ServerConfig configures issuers, cookies, and TTL.
type ServerConfig struct {
	GoogleWebClientID        string
	GoogleNativeClientID     string
	NativeGoogleClients      []NativeGoogleClientConfig
	AppleOAuth               AppleOAuthConfig
	PasswordAuthEnabled      bool
	AccountManagementEnabled bool
	PasswordSignupEnabled    bool
	ReturnChallengeTokens    bool
	AppJWTSigningKey         []byte
	AppJWTIssuer             string
	TenantID                 string
	TenantOrigins            []string
	CookieDomain             string
	SessionCookieName        string
	RefreshCookieName        string
	AllowedUsers             map[string]struct{}
	SessionTTL               time.Duration
	RefreshTTL               time.Duration
	NonceTTL                 time.Duration
	EmailVerificationTTL     time.Duration
	PasswordResetTTL         time.Duration
	SameSiteMode             http.SameSite
	AllowInsecureHTTP        bool
}

// NativeGoogleClientConfig configures one accepted native Google OAuth client.
type NativeGoogleClientConfig struct {
	Platform     string
	ClientID     string
	RedirectURIs []string
}

// AppleOAuthConfig configures Sign in with Apple for one tenant.
type AppleOAuthConfig struct {
	Enabled               bool
	ClientID              string
	TeamID                string
	KeyID                 string
	PrivateKey            string
	RedirectURI           string
	Scopes                []string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURL               string
}

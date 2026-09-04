package authkit

import (
	"context"
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
	EmailVerificationURL     string
	PasswordResetTTL         time.Duration
	PasswordResetURL         string
	PasswordLinkURL          string
	SameSiteMode             http.SameSite
	AllowInsecureHTTP        bool
}

// EmailChallengeKind identifies one password-account email challenge.
type EmailChallengeKind string

const (
	// EmailChallengeKindVerification activates a new password account.
	EmailChallengeKindVerification EmailChallengeKind = "email_verification"
	// EmailChallengeKindPasswordReset authorizes a password reset.
	EmailChallengeKindPasswordReset EmailChallengeKind = "password_reset"
	// EmailChallengeKindPasswordLink authorizes a password identity link.
	EmailChallengeKindPasswordLink EmailChallengeKind = "password_link"
)

// EmailChallengeRequest contains one password-account email delivery request.
type EmailChallengeRequest struct {
	Kind      EmailChallengeKind
	TenantID  string
	Recipient string
	PublicURL string
	ExpiresAt time.Time
}

// EmailChallengeSender delivers password-account challenge emails.
type EmailChallengeSender interface {
	SendEmailChallenge(ctx context.Context, request EmailChallengeRequest) error
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
	NativeClientIDs       []string
	TeamID                string
	KeyID                 string
	PrivateKey            string
	RedirectURI           string
	Scopes                []string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURL               string
}

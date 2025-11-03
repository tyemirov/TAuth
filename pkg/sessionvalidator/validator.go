package sessionvalidator

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// Clock provides the current time.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

// Now returns the current UTC timestamp.
func (systemClock) Now() time.Time {
	return time.Now().UTC()
}

// Config configures the Validator.
type Config struct {
	SigningKey []byte
	Issuer     string
	CookieName string
	Clock      Clock
}

// DefaultContextKey is used by GinMiddleware when no explicit key is provided.
const DefaultContextKey = "auth_claims"

// DefaultCookieName is used when Config.CookieName is empty.
const DefaultCookieName = "app_session"

// Sentinel errors exposed by the validator.
var (
	ErrMissingSigningKey = errors.New("session.validator.missing_signing_key")
	ErrMissingIssuer     = errors.New("session.validator.missing_issuer")
	ErrMissingToken      = errors.New("session.validator.missing_token")
	ErrMissingCookie     = errors.New("session.validator.missing_cookie")
	ErrInvalidToken      = errors.New("session.validator.invalid_token")
	ErrInvalidIssuer     = errors.New("session.validator.invalid_issuer")
	ErrTokenExpired      = errors.New("session.validator.expired")
)

// Validator validates TAuth session cookies.
type Validator struct {
	signingKey []byte
	issuer     string
	cookieName string
	clock      Clock
}

// Claims represent the session payload embedded inside TAuth access tokens.
type Claims struct {
	UserID          string   `json:"user_id"`
	UserEmail       string   `json:"user_email"`
	UserDisplayName string   `json:"user_display_name"`
	UserAvatarURL   string   `json:"user_avatar_url"`
	UserRoles       []string `json:"user_roles"`
	jwt.RegisteredClaims
}

// GetUserID returns the user identifier from the session.
func (claims *Claims) GetUserID() string {
	if claims == nil {
		return ""
	}
	return claims.UserID
}

// GetUserEmail returns the email associated with the session.
func (claims *Claims) GetUserEmail() string {
	if claims == nil {
		return ""
	}
	return claims.UserEmail
}

// GetUserDisplayName returns the display name stored in the session.
func (claims *Claims) GetUserDisplayName() string {
	if claims == nil {
		return ""
	}
	return claims.UserDisplayName
}

// GetUserAvatarURL returns the avatar URL stored in the session.
func (claims *Claims) GetUserAvatarURL() string {
	if claims == nil {
		return ""
	}
	return claims.UserAvatarURL
}

// GetUserRoles returns the roles associated with the session.
func (claims *Claims) GetUserRoles() []string {
	if claims == nil {
		return nil
	}
	return claims.UserRoles
}

// GetExpiresAt returns the expiry timestamp.
func (claims *Claims) GetExpiresAt() time.Time {
	if claims == nil || claims.ExpiresAt == nil {
		return time.Time{}
	}
	return claims.ExpiresAt.Time
}

// New constructs a Validator after validating the supplied configuration.
func New(configuration Config) (*Validator, error) {
	if len(configuration.SigningKey) == 0 {
		return nil, fmt.Errorf("session.validator.new: %w", ErrMissingSigningKey)
	}
	if strings.TrimSpace(configuration.Issuer) == "" {
		return nil, fmt.Errorf("session.validator.new: %w", ErrMissingIssuer)
	}
	cookieName := configuration.CookieName
	if strings.TrimSpace(cookieName) == "" {
		cookieName = DefaultCookieName
	}
	clock := configuration.Clock
	if clock == nil {
		clock = systemClock{}
	}
	return &Validator{
		signingKey: configuration.SigningKey,
		issuer:     configuration.Issuer,
		cookieName: cookieName,
		clock:      clock,
	}, nil
}

// ValidateToken validates the provided JWT string and returns the parsed claims.
func (validator *Validator) ValidateToken(tokenString string) (*Claims, error) {
	if strings.TrimSpace(tokenString) == "" {
		return nil, fmt.Errorf("session.validator.validate_token: %w", ErrMissingToken)
	}
	parsedToken, parseErr := jwt.ParseWithClaims(tokenString, &Claims{}, func(parsed *jwt.Token) (interface{}, error) {
		return validator.signingKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithTimeFunc(func() time.Time {
		return validator.clock.Now()
	}))
	if parseErr != nil {
		if errors.Is(parseErr, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("session.validator.validate_token: %w", ErrTokenExpired)
		}
		return nil, fmt.Errorf("session.validator.validate_token: %w", ErrInvalidToken)
	}
	if parsedToken == nil || !parsedToken.Valid {
		return nil, fmt.Errorf("session.validator.validate_token: %w", ErrInvalidToken)
	}
	claims, ok := parsedToken.Claims.(*Claims)
	if !ok {
		return nil, fmt.Errorf("session.validator.validate_token: %w", ErrInvalidToken)
	}
	if claims.Issuer != validator.issuer {
		return nil, fmt.Errorf("session.validator.validate_token: %w", ErrInvalidIssuer)
	}
	current := validator.clock.Now()
	if claims.ExpiresAt != nil && current.After(claims.ExpiresAt.Time) {
		return nil, fmt.Errorf("session.validator.validate_token: %w", ErrTokenExpired)
	}
	if claims.NotBefore != nil && current.Before(claims.NotBefore.Time) {
		return nil, fmt.Errorf("session.validator.validate_token: %w", ErrInvalidToken)
	}
	if claims.IssuedAt != nil && current.Before(claims.IssuedAt.Time) {
		return nil, fmt.Errorf("session.validator.validate_token: %w", ErrInvalidToken)
	}
	return claims, nil
}

// ValidateRequest reads the configured cookie from the request and validates it.
func (validator *Validator) ValidateRequest(request *http.Request) (*Claims, error) {
	if request == nil {
		return nil, fmt.Errorf("session.validator.validate_request: %w", ErrMissingToken)
	}
	cookie, cookieErr := request.Cookie(validator.cookieName)
	if cookieErr != nil || cookie == nil || strings.TrimSpace(cookie.Value) == "" {
		return nil, fmt.Errorf("session.validator.validate_request: %w", ErrMissingCookie)
	}
	return validator.ValidateToken(cookie.Value)
}

// GinMiddleware returns a Gin middleware that validates the session cookie and injects claims.
func (validator *Validator) GinMiddleware(contextKey string) gin.HandlerFunc {
	if strings.TrimSpace(contextKey) == "" {
		contextKey = DefaultContextKey
	}
	return func(contextGin *gin.Context) {
		claims, err := validator.ValidateRequest(contextGin.Request)
		if err != nil {
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		contextGin.Set(contextKey, claims)
		contextGin.Next()
	}
}

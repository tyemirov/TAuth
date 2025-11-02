package authkit

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Clock provides the current time, enabling deterministic tests.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

// Now returns the current UTC time.
func (systemClock) Now() time.Time {
	return time.Now().UTC()
}

// NewSystemClock returns a production clock backed by time.Now.
func NewSystemClock() Clock {
	return systemClock{}
}

var errJWTMintFailure = errors.New("jwt.mint.failure")

// JwtCustomClaims are embedded in the session token.
type JwtCustomClaims struct {
	UserID          string   `json:"user_id"`
	UserEmail       string   `json:"user_email"`
	UserDisplayName string   `json:"user_display_name"`
	UserRoles       []string `json:"user_roles"`
	jwt.RegisteredClaims
}

// GetUserID returns the application user identifier.
func (claims *JwtCustomClaims) GetUserID() string {
	if claims == nil {
		return ""
	}
	return claims.UserID
}

// GetUserEmail returns the email stored in the claims.
func (claims *JwtCustomClaims) GetUserEmail() string {
	if claims == nil {
		return ""
	}
	return claims.UserEmail
}

// GetUserDisplayName returns the display name from the claims.
func (claims *JwtCustomClaims) GetUserDisplayName() string {
	if claims == nil {
		return ""
	}
	return claims.UserDisplayName
}

// GetUserRoles returns the role slice associated with the claims.
func (claims *JwtCustomClaims) GetUserRoles() []string {
	if claims == nil {
		return nil
	}
	return claims.UserRoles
}

// GetExpiresAt exposes the expiry timestamp for downstream consumers.
func (claims *JwtCustomClaims) GetExpiresAt() time.Time {
	if claims == nil || claims.ExpiresAt == nil {
		return time.Time{}
	}
	return claims.ExpiresAt.Time
}

// MintAppJWT creates a signed HS256 access token using the provided clock.
func MintAppJWT(clock Clock, applicationUserID string, userEmail string, userDisplayName string, userRoles []string, issuer string, signingKey []byte, ttl time.Duration) (string, time.Time, error) {
	if strings.TrimSpace(applicationUserID) == "" {
		return "", time.Time{}, fmt.Errorf("%w: subject must be non-empty", errJWTMintFailure)
	}

	current := clock.Now().UTC()
	expiresAt := current.Add(ttl)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, JwtCustomClaims{
		UserID:          applicationUserID,
		UserEmail:       userEmail,
		UserDisplayName: userDisplayName,
		UserRoles:       userRoles,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   applicationUserID,
			IssuedAt:  jwt.NewNumericDate(current),
			NotBefore: jwt.NewNumericDate(current.Add(-30 * time.Second)),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	})
	signed, signErr := token.SignedString(signingKey)
	if signErr != nil {
		return "", time.Time{}, fmt.Errorf("%w: sign", errJWTMintFailure)
	}
	return signed, expiresAt, nil
}

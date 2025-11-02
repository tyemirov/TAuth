package authkit

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JwtCustomClaims are embedded in the session token.
type JwtCustomClaims struct {
	UserID          string   `json:"user_id"`
	UserEmail       string   `json:"user_email"`
	UserDisplayName string   `json:"user_display_name"`
	UserRoles       []string `json:"user_roles"`
	jwt.RegisteredClaims
}

// MintAppJWT creates a signed HS256 access token.
func MintAppJWT(applicationUserID string, userEmail string, userDisplayName string, userRoles []string, issuer string, signingKey []byte, ttl time.Duration) (string, time.Time, error) {
	issuedAt := time.Now().UTC()
	expiresAt := issuedAt.Add(ttl)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, JwtCustomClaims{
		UserID:          applicationUserID,
		UserEmail:       userEmail,
		UserDisplayName: userDisplayName,
		UserRoles:       userRoles,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   applicationUserID,
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			NotBefore: jwt.NewNumericDate(issuedAt.Add(-30 * time.Second)),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	})
	signed, err := token.SignedString(signingKey)
	return signed, expiresAt, err
}

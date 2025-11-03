package web

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/authkit"
	"go.uber.org/zap"
)

// InMemoryUsers is a simple user store used for demo and local runs.
type InMemoryUsers struct {
	Users map[string]UserProfile
}

// UserProfile represents an application user.
type UserProfile struct {
	Email   string
	Display string
	Roles   []string
}

// ErrUserProfileNotFound is returned when a profile is missing in the store.
var ErrUserProfileNotFound = errors.New("user_profile_not_found")

// NewInMemoryUsers constructs a store with an empty map.
func NewInMemoryUsers() *InMemoryUsers {
	return &InMemoryUsers{Users: make(map[string]UserProfile)}
}

// UpsertGoogleUser inserts or updates a user based on Google sub.
func (store *InMemoryUsers) UpsertGoogleUser(ctx context.Context, googleSub string, userEmail string, userDisplayName string) (string, []string, error) {
	applicationUserID := "google:" + googleSub
	record := UserProfile{
		Email:   userEmail,
		Display: userDisplayName,
		Roles:   []string{"user"},
	}
	store.Users[applicationUserID] = record
	return applicationUserID, record.Roles, nil
}

// GetUserProfile returns a profile by application user id.
func (store *InMemoryUsers) GetUserProfile(ctx context.Context, applicationUserID string) (string, string, []string, error) {
	record, ok := store.Users[applicationUserID]
	if !ok {
		return "", "", nil, ErrUserProfileNotFound
	}
	return record.Email, record.Display, record.Roles, nil
}

// HandleWhoAmI resolves the authenticated user's profile payload.
func HandleWhoAmI(logger *zap.Logger, users authkit.UserStore) gin.HandlerFunc {
	if logger == nil {
		logger = zap.NewNop()
	}
	if users == nil {
		panic("user store is required")
	}

	return func(contextGin *gin.Context) {
		claimsValue, found := contextGin.Get("auth_claims")
		if !found {
			logger.Warn("missing auth claims on context",
				zap.String("code", "api.me.missing_claims"))
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		claims, ok := claimsValue.(*authkit.JwtCustomClaims)
		if !ok || claims == nil || claims.UserID == "" {
			logger.Warn("invalid auth claims on context",
				zap.String("code", "api.me.invalid_claims"))
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		email, display, roles, profileErr := users.GetUserProfile(contextGin, claims.UserID)
		if profileErr != nil {
			if errors.Is(profileErr, ErrUserProfileNotFound) {
				logger.Warn("user profile missing",
					zap.String("code", "api.me.profile_missing"),
					zap.String("user_id", claims.UserID))
				contextGin.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			logger.Error("user profile lookup error",
				zap.String("code", "api.me.profile_error"),
				zap.String("user_id", claims.UserID),
				zap.Error(profileErr))
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		expiresAt := time.Time{}
		if claims.ExpiresAt != nil {
			expiresAt = claims.ExpiresAt.Time
		}

		contextGin.JSON(http.StatusOK, gin.H{
			"user_id":    claims.UserID,
			"user_email": email,
			"display":    display,
			"roles":      roles,
			"expires":    expiresAt,
		})
	}
}

package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// ProfileStore exposes the ability to retrieve user profiles.
type ProfileStore interface {
	GetUserProfile(ctx context.Context, applicationUserID string) (string, string, string, []string, error)
}

// ClaimsProvider exposes identity fields extracted from a JWT.
type ClaimsProvider interface {
	GetUserID() string
	GetUserEmail() string
	GetUserDisplayName() string
	GetUserRoles() []string
	GetExpiresAt() time.Time
}

var ErrUserNotFound = errors.New("web.user.not_found")

// InMemoryUsers is a simple user store used for demo and local runs.
type InMemoryUsers struct {
	Users map[string]UserProfile
}

// UserProfile represents an application user.
type UserProfile struct {
	Email     string
	Display   string
	AvatarURL string
	Roles     []string
}

// NewInMemoryUsers constructs a store with an empty map.
func NewInMemoryUsers() *InMemoryUsers {
	return &InMemoryUsers{Users: make(map[string]UserProfile)}
}

// UpsertGoogleUser inserts or updates a user based on Google sub.
func (store *InMemoryUsers) UpsertGoogleUser(ctx context.Context, googleSub string, userEmail string, userDisplayName string, userAvatarURL string) (string, []string, error) {
	applicationUserID := "google:" + googleSub
	record := UserProfile{
		Email:     userEmail,
		Display:   userDisplayName,
		AvatarURL: userAvatarURL,
		Roles:     []string{"user"},
	}
	store.Users[applicationUserID] = record
	return applicationUserID, record.Roles, nil
}

// GetUserProfile returns a profile by application user id.
func (store *InMemoryUsers) GetUserProfile(ctx context.Context, applicationUserID string) (string, string, string, []string, error) {
	record, ok := store.Users[applicationUserID]
	if !ok {
		return "", "", "", nil, ErrUserNotFound
	}
	return record.Email, record.Display, record.AvatarURL, record.Roles, nil
}

// HandleWhoAmI returns the authenticated user's profile.
func HandleWhoAmI(store ProfileStore, logger *zap.Logger) gin.HandlerFunc {
	if logger == nil {
		logger = zap.NewNop()
	}
	return func(contextGin *gin.Context) {
		claimsValue, exists := contextGin.Get("auth_claims")
		if !exists {
			logger.Warn("whoami.missing_claims")
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		provider, ok := claimsValue.(ClaimsProvider)
		if !ok {
			logger.Warn("whoami.invalid_claims", zap.String("claims_type", getClaimsType(claimsValue)))
			contextGin.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		userEmail, display, avatarURL, roles, err := store.GetUserProfile(contextGin, provider.GetUserID())
		if err != nil {
			if errors.Is(err, ErrUserNotFound) {
				logger.Warn("whoami.user_not_found", zap.String("user_id", provider.GetUserID()))
				contextGin.AbortWithStatus(http.StatusNotFound)
				return
			}
			logger.Error("whoami.profile_error", zap.String("user_id", provider.GetUserID()), zap.Error(err))
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		contextGin.JSON(http.StatusOK, gin.H{
			"user_id":    provider.GetUserID(),
			"user_email": userEmail,
			"display":    display,
			"avatar_url": avatarURL,
			"roles":      roles,
			"expires":    provider.GetExpiresAt(),
		})
	}
}

func getClaimsType(claimsValue interface{}) string {
	if claimsValue == nil {
		return "nil"
	}
	return fmt.Sprintf("%T", claimsValue)
}

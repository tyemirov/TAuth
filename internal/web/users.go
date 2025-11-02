package web

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
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
		return "", "", nil, http.ErrNoCookie
	}
	return record.Email, record.Display, record.Roles, nil
}

// HandleWhoAmI returns a handler that echoes a simple payload.
func HandleWhoAmI() gin.HandlerFunc {
	return func(contextGin *gin.Context) {
		contextGin.JSON(http.StatusOK, gin.H{"message": "ok"})
	}
}

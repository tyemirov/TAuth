package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// ClaimsProvider exposes identity fields extracted from a JWT.
type ClaimsProvider interface {
	GetTenantID() string
	GetUserID() string
	GetUserEmail() string
	GetUserDisplayName() string
	GetUserAvatarURL() string
	GetUserRoles() []string
	GetExpiresAt() time.Time
}

var ErrUserNotFound = errors.New("web.user.not_found")

// InMemoryUsers is a simple user store used for demo and local runs.
type InMemoryUsers struct {
	tenants map[string]map[string]UserProfile
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
	return &InMemoryUsers{tenants: make(map[string]map[string]UserProfile)}
}

// UpsertGoogleUser inserts or updates a user based on Google sub.
func (store *InMemoryUsers) UpsertGoogleUser(ctx context.Context, tenantID string, googleSub string, userEmail string, userDisplayName string, userAvatarURL string) (string, []string, error) {
	return store.UpsertProviderUser(ctx, tenantID, "google", googleSub, userEmail, userDisplayName, userAvatarURL)
}

// UpsertProviderUser inserts or updates a user based on an external provider subject.
func (store *InMemoryUsers) UpsertProviderUser(ctx context.Context, tenantID string, provider string, providerID string, userEmail string, userDisplayName string, userAvatarURL string) (string, []string, error) {
	normalizedProvider := strings.ToLower(strings.TrimSpace(provider))
	normalizedProviderID := strings.TrimSpace(providerID)
	if normalizedProvider == "" || normalizedProviderID == "" {
		return "", nil, fmt.Errorf("web.user.invalid_provider_identity")
	}
	applicationUserID := normalizedProvider + ":" + normalizedProviderID
	return store.upsertUserProfile(tenantID, applicationUserID, userEmail, userDisplayName, userAvatarURL)
}

// UpsertPasswordUser inserts or updates a user based on normalized email.
func (store *InMemoryUsers) UpsertPasswordUser(ctx context.Context, tenantID string, userEmail string, userDisplayName string, userAvatarURL string) (string, []string, error) {
	applicationUserID := "email:" + strings.ToLower(strings.TrimSpace(userEmail))
	return store.upsertUserProfile(tenantID, applicationUserID, strings.ToLower(strings.TrimSpace(userEmail)), userDisplayName, userAvatarURL)
}

// UpsertAccountUser inserts or updates a canonical account profile.
func (store *InMemoryUsers) UpsertAccountUser(ctx context.Context, tenantID string, accountID string, userEmail string, userDisplayName string, userAvatarURL string) (string, []string, error) {
	return store.upsertUserProfile(tenantID, accountID, strings.ToLower(strings.TrimSpace(userEmail)), userDisplayName, userAvatarURL)
}

func (store *InMemoryUsers) upsertUserProfile(tenantID string, applicationUserID string, userEmail string, userDisplayName string, userAvatarURL string) (string, []string, error) {
	record := UserProfile{
		Email:     userEmail,
		Display:   userDisplayName,
		AvatarURL: userAvatarURL,
		Roles:     []string{"user"},
	}
	if _, exists := store.tenants[tenantID]; !exists {
		store.tenants[tenantID] = make(map[string]UserProfile)
	}
	store.tenants[tenantID][applicationUserID] = record
	return applicationUserID, record.Roles, nil
}

// GetUserProfile returns a profile by application user id.
func (store *InMemoryUsers) GetUserProfile(ctx context.Context, tenantID string, applicationUserID string) (string, string, string, []string, error) {
	records, exists := store.tenants[tenantID]
	if !exists {
		return "", "", "", nil, ErrUserNotFound
	}
	record, ok := records[applicationUserID]
	if !ok {
		return "", "", "", nil, ErrUserNotFound
	}
	return record.Email, record.Display, record.AvatarURL, record.Roles, nil
}

// HandleWhoAmI returns the authenticated user's profile.
func HandleWhoAmI(logger *zap.Logger) gin.HandlerFunc {
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

		tenantID := strings.TrimSpace(provider.GetTenantID())
		if tenantID == "" {
			logger.Warn("whoami.missing_tenant")
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		contextGin.JSON(http.StatusOK, gin.H{
			"user_id":    provider.GetUserID(),
			"user_email": provider.GetUserEmail(),
			"display":    provider.GetUserDisplayName(),
			"avatar_url": provider.GetUserAvatarURL(),
			"roles":      provider.GetUserRoles(),
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

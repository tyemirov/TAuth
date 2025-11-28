package authkit

import "context"

// UserStore persists and retrieves application users.
type UserStore interface {
	UpsertGoogleUser(ctx context.Context, tenantID string, googleSub string, userEmail string, userDisplayName string, userAvatarURL string) (applicationUserID string, userRoles []string, err error)
	GetUserProfile(ctx context.Context, tenantID string, applicationUserID string) (userEmail string, userDisplayName string, userAvatarURL string, userRoles []string, err error)
}

// RefreshTokenStore manages long-lived refresh tokens.
type RefreshTokenStore interface {
	Issue(ctx context.Context, tenantID string, applicationUserID string, expiresUnix int64, previousTokenID string) (tokenID string, tokenOpaque string, err error)
	Validate(ctx context.Context, tenantID string, tokenOpaque string) (applicationUserID string, tokenID string, expiresUnix int64, err error)
	Revoke(ctx context.Context, tenantID string, tokenID string) error
}

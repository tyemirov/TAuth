package authkit

import "context"

// UserStore persists and retrieves application users.
type UserStore interface {
	UpsertProviderUser(ctx context.Context, tenantID string, provider string, providerID string, userEmail string, userDisplayName string, userAvatarURL string) (applicationUserID string, userRoles []string, err error)
	UpsertGoogleUser(ctx context.Context, tenantID string, googleSub string, userEmail string, userDisplayName string, userAvatarURL string) (applicationUserID string, userRoles []string, err error)
	UpsertPasswordUser(ctx context.Context, tenantID string, userEmail string, userDisplayName string, userAvatarURL string) (applicationUserID string, userRoles []string, err error)
	UpsertAccountUser(ctx context.Context, tenantID string, accountID string, userEmail string, userDisplayName string, userAvatarURL string) (applicationUserID string, userRoles []string, err error)
	GetUserProfile(ctx context.Context, tenantID string, applicationUserID string) (userEmail string, userDisplayName string, userAvatarURL string, userRoles []string, err error)
}

// RefreshTokenStore manages long-lived refresh tokens.
type RefreshTokenStore interface {
	Issue(ctx context.Context, tenantID string, applicationUserID string, expiresUnix int64, previousTokenID string) (tokenID string, tokenOpaque string, err error)
	Validate(ctx context.Context, tenantID string, tokenOpaque string) (applicationUserID string, tokenID string, expiresUnix int64, err error)
	Revoke(ctx context.Context, tenantID string, tokenID string) error
	RevokeUser(ctx context.Context, tenantID string, applicationUserID string) error
}

// PasswordCredentialStore persists and verifies email/password credentials.
type PasswordCredentialStore interface {
	UpsertPasswordCredential(ctx context.Context, tenantID string, credential PasswordCredentialSeed) error
	ReconcilePasswordCredentials(ctx context.Context, tenantID string, configuredEmails []string) error
	AuthenticatePassword(ctx context.Context, tenantID string, userEmail string, password string) (PasswordCredentialProfile, error)
}

// AccountManagementStore manages first-party account lifecycle records.
type AccountManagementStore interface {
	CreatePasswordSignup(ctx context.Context, tenantID string, request AccountPasswordRequest, expiresUnix int64) (AccountChallenge, error)
	CancelPasswordSignup(ctx context.Context, tenantID string, accountID string) error
	CancelAccountChallenge(ctx context.Context, tenantID string, accountID string, token string) error
	VerifyEmailChallenge(ctx context.Context, tenantID string, token string) (AccountProfile, error)
	StartPasswordReset(ctx context.Context, tenantID string, userEmail string, expiresUnix int64) (AccountChallenge, error)
	CompletePasswordReset(ctx context.Context, tenantID string, token string, password string) (AccountProfile, error)
	ChangePassword(ctx context.Context, tenantID string, accountID string, currentPassword string, newPassword string) (AccountProfile, error)
	EnsurePasswordAccount(ctx context.Context, tenantID string, userEmail string) (AccountProfile, error)
	CreatePasswordLink(ctx context.Context, tenantID string, accountID string, request AccountPasswordRequest, expiresUnix int64) (AccountChallenge, error)
	VerifyPasswordLink(ctx context.Context, tenantID string, accountID string, token string) (AccountProfile, error)
	AuthenticateProviderAccount(ctx context.Context, tenantID string, identity AccountProviderIdentity) (AccountProfile, bool, error)
	UpsertProviderAccount(ctx context.Context, tenantID string, identity AccountProviderIdentity) (AccountProfile, error)
	LinkProviderIdentity(ctx context.Context, tenantID string, accountID string, identity AccountProviderIdentity) (AccountProfile, error)
	UnlinkIdentity(ctx context.Context, tenantID string, accountID string, provider string, providerID string) (AccountProfile, error)
	DisableAccount(ctx context.Context, tenantID string, accountID string) (AccountProfile, error)
	ReactivateAccount(ctx context.Context, tenantID string, accountID string) (AccountProfile, error)
	ResolveAccountProfile(ctx context.Context, tenantID string, accountID string) (AccountProfile, error)
}

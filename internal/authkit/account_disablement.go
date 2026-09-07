package authkit

import (
	"context"
	"fmt"
)

// AccountReference identifies an account within its tenant.
type AccountReference struct {
	TenantID  string
	AccountID string
}

// ResumeAccountDisablements completes persisted pending revocations before the server accepts traffic.
func ResumeAccountDisablements(ctx context.Context, accounts AccountManagementStore, refreshTokens RefreshTokenStore, oauthGrants OAuthGrantRevoker, nowUnix int64) error {
	pending, err := accounts.PendingAccountDisablements(ctx)
	if err != nil {
		return fmt.Errorf("auth.account.disable_pending: %w", err)
	}
	for _, account := range pending {
		if err := completeAccountDisablement(ctx, accounts, refreshTokens, oauthGrants, account, nowUnix); err != nil {
			return err
		}
	}
	return nil
}

func completeAccountDisablement(ctx context.Context, accounts AccountManagementStore, refreshTokens RefreshTokenStore, oauthGrants OAuthGrantRevoker, account AccountReference, nowUnix int64) error {
	if oauthGrants != nil {
		if err := oauthGrants.RevokeUser(ctx, account.TenantID, account.AccountID, nowUnix); err != nil {
			return fmt.Errorf("auth.account.disable_oauth_revoke tenant=%s account=%s: %w", account.TenantID, account.AccountID, err)
		}
	}
	if err := refreshTokens.RevokeUser(ctx, account.TenantID, account.AccountID); err != nil {
		return fmt.Errorf("auth.account.disable_refresh_revoke tenant=%s account=%s: %w", account.TenantID, account.AccountID, err)
	}
	if _, err := accounts.CompleteAccountDisable(ctx, account.TenantID, account.AccountID); err != nil {
		return fmt.Errorf("auth.account.disable_complete tenant=%s account=%s: %w", account.TenantID, account.AccountID, err)
	}
	return nil
}

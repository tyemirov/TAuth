package authkit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

type databaseAccountErasure struct {
	AccountState         string                    `gorm:"not null;default:retained"`
	NotificationAudience string                    `gorm:"-"`
	ProviderSnapshot     bool                      `gorm:"not null;default:false"`
	Providers            []databaseErasureProvider `gorm:"-"`
	UserID               *string
	OperationID          string  `gorm:"primaryKey"`
	TenantID             string  `gorm:"uniqueIndex:idx_erasure_account;uniqueIndex:idx_erasure_status"`
	AccountID            *string `gorm:"uniqueIndex:idx_erasure_account"`
	StatusHash           string  `gorm:"uniqueIndex:idx_erasure_status;not null"`
	State                string  `gorm:"index;not null"`
	Reason               string  `gorm:"not null"`
	Phase                string  `gorm:"not null"`
	LeaseToken           string  `gorm:"not null"`
	LeaseUntilUnix       int64   `gorm:"not null"`
	NextAttemptUnix      int64   `gorm:"index;not null"`
	AttemptCount         int     `gorm:"not null"`
	CreatedUnix          int64   `gorm:"not null"`
	UpdatedUnix          int64   `gorm:"not null"`
	ExpiresUnix          int64   `gorm:"index;not null"`
}

func (databaseAccountErasure) TableName() string { return "account_erasures" }

func (store *DatabaseUserStore) erasureByKey(ctx context.Context, tenantID, keyHash string) (databaseAccountErasure, error) {
	var job databaseAccountErasure
	now := store.now().UTC().Unix()
	err := store.db.WithContext(ctx).Where("tenant_id = ? AND status_hash = ? AND (expires_unix = 0 OR expires_unix > ?)", tenantID, keyHash, now).Take(&job).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return job, errErasureNotFound
	}
	if err != nil {
		return job, fmt.Errorf("account.erasure.status: %w", err)
	}
	if err := store.db.WithContext(ctx).Where("operation_id = ?", job.OperationID).Order("provider").Find(&job.Providers).Error; err != nil {
		return job, err
	}
	return job, nil
}

func (store *DatabaseUserStore) beginAccountErasure(ctx context.Context, tenantID, userID, keyHash, notificationAudience string) (databaseAccountErasure, error) {
	operationID, err := newOpaqueAccountID()
	if err != nil {
		return databaseAccountErasure{}, err
	}
	now := store.now().UTC().Unix()
	var job databaseAccountErasure
	err = store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// The first write obtains the database reservation before the account reads.
		changed := tx.Model(&databaseAccountRecord{}).Where("tenant_id = ? AND user_id = ? AND account_state IN ?", tenantID, userID, []string{accountStateActive, accountStateDisabled, accountStateDisabling}).Update("account_state", accountStateErasing)
		if changed.Error != nil {
			return changed.Error
		}
		if changed.RowsAffected != 1 {
			lookup := tx.Where("tenant_id = ? AND status_hash = ? AND (expires_unix = 0 OR expires_unix > ?)", tenantID, keyHash, now).Take(&job).Error
			if lookup == nil {
				return nil
			}
			if !errors.Is(lookup, gorm.ErrRecordNotFound) {
				return lookup
			}
			lookup = tx.Where("tenant_id = ? AND user_id = ? AND account_id IS NOT NULL", tenantID, userID).Take(&job).Error
			if lookup == nil {
				return errErasureKeyConflict
			}
			if !errors.Is(lookup, gorm.ErrRecordNotFound) {
				return lookup
			}
			return ErrAccountNotActive
		}
		profile, profileErr := store.accountProfileForUserWithTx(ctx, tx, tenantID, userID)
		if profileErr != nil {
			return profileErr
		}
		accountID := profile.AccountID
		lookup := tx.Where("tenant_id = ? AND account_id = ?", tenantID, accountID).Take(&job).Error
		if lookup == nil {
			if job.StatusHash != keyHash {
				return errErasureKeyConflict
			}
			return nil
		}
		if !errors.Is(lookup, gorm.ErrRecordNotFound) {
			return lookup
		}
		var configured int64
		if err := tx.Model(&passwordCredentialRecord{}).Where("tenant_id = ? AND managed_by_config = ? AND (account_id = ? OR user_email IN (SELECT provider_id FROM account_identities WHERE tenant_id = ? AND account_id = ? AND provider = ?))", tenantID, true, accountID, tenantID, accountID, accountProviderPassword).Count(&configured).Error; err != nil {
			return err
		}
		if configured != 0 {
			return errErasureConfigured
		}
		job = databaseAccountErasure{UserID: &userID, OperationID: operationID, TenantID: tenantID, AccountID: &accountID, StatusHash: keyHash, AccountState: erasureAccountRetained, NotificationAudience: notificationAudience, ProviderSnapshot: true, State: erasurePending, Phase: erasureProviderPhase, CreatedUnix: now, UpdatedUnix: now}
		if err := tx.Create(&job).Error; err != nil {
			return err
		}
		return store.captureErasureProviders(ctx, tx, job)
	})
	if err != nil {
		return databaseAccountErasure{}, fmt.Errorf("account.erasure.begin: %w", err)
	}
	return job, nil
}

func (store *DatabaseUserStore) claimErasure(ctx context.Context, operationID string) (databaseAccountErasure, bool, error) {
	token, err := newOpaqueAccountID()
	if err != nil {
		return databaseAccountErasure{}, false, err
	}
	now := store.now().UTC().Unix()
	changed := store.db.WithContext(ctx).Model(&databaseAccountErasure{}).Where("operation_id = ? AND state <> ? AND next_attempt_unix <= ? AND lease_until_unix <= ?", operationID, erasureCompleted, now, now).
		Updates(map[string]any{"state": erasureRunning, "reason": "", "lease_token": token, "lease_until_unix": now + int64(erasureLeaseTTL/time.Second), "updated_unix": now})
	if changed.Error != nil {
		return databaseAccountErasure{}, false, fmt.Errorf("account.erasure.claim: %w", changed.Error)
	}
	if changed.RowsAffected != 1 {
		return databaseAccountErasure{}, false, nil
	}
	var job databaseAccountErasure
	if err := store.db.WithContext(ctx).Where("operation_id = ? AND lease_token = ?", operationID, token).Take(&job).Error; err != nil {
		return job, false, fmt.Errorf("account.erasure.claim_read: %w", err)
	}
	return job, true, nil
}

func (store *DatabaseUserStore) advanceErasure(ctx context.Context, job databaseAccountErasure, next string) error {
	now := store.now().UTC().Unix()
	changed := store.db.WithContext(ctx).Model(&databaseAccountErasure{}).Where("operation_id = ? AND state = ? AND lease_token = ? AND lease_until_unix > ?", job.OperationID, erasureRunning, job.LeaseToken, now).
		Updates(map[string]any{"phase": next, "lease_until_unix": now + int64(erasureLeaseTTL/time.Second), "updated_unix": now})
	if changed.Error != nil {
		return fmt.Errorf("account.erasure.phase_advance: %w", changed.Error)
	}
	if changed.RowsAffected != 1 {
		return errErasureLeaseLost
	}
	return nil
}

func (store *DatabaseUserStore) blockErasure(ctx context.Context, job databaseAccountErasure, reason string) error {
	now := store.now().UTC().Unix()
	attempts := job.AttemptCount + 1
	exponent := attempts - 1
	if exponent > 7 {
		exponent = 7
	}
	backoff := int64(erasureScanInterval/time.Second) << exponent
	if backoff > 3600 {
		backoff = 3600
	}
	changed := store.db.WithContext(ctx).Model(&databaseAccountErasure{}).Where("operation_id = ? AND state = ? AND lease_token = ?", job.OperationID, erasureRunning, job.LeaseToken).
		Updates(map[string]any{"state": erasureBlocked, "reason": reason, "attempt_count": attempts, "lease_token": "", "lease_until_unix": 0, "next_attempt_unix": now + backoff, "updated_unix": now})
	if changed.Error != nil {
		return fmt.Errorf("account.erasure.block: %w", changed.Error)
	}
	if changed.RowsAffected != 1 {
		return errErasureLeaseLost
	}
	return nil
}

func (store *DatabaseUserStore) completeAccountErasure(ctx context.Context, job databaseAccountErasure) error {
	now := store.now().UTC().Unix()
	return store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		fenced := tx.Model(&databaseAccountErasure{}).Where("operation_id = ? AND state = ? AND phase = ? AND lease_token = ? AND lease_until_unix > ?", job.OperationID, erasureRunning, erasureUserPhase, job.LeaseToken, now).Update("updated_unix", now)
		if fenced.Error != nil {
			return fenced.Error
		}
		if fenced.RowsAffected != 1 {
			return errErasureLeaseLost
		}
		accountID := *job.AccountID
		profile, err := store.accountProfileWithTx(ctx, tx, job.TenantID, accountID)
		if err != nil {
			return err
		}
		models := []struct {
			model   any
			subject string
		}{
			{&databaseAppleGrant{}, "account_id"}, {&githubTransaction{}, "account_id"}, {&databaseAccountChallengeRecord{}, "account_id"}, {&passwordCredentialRecord{}, "account_id"}, {&databaseAccountIdentityRecord{}, "account_id"}, {&databaseGitHubCredential{}, "user_id"}, {&userProfileRecord{}, "user_id"}, {&databaseAccountRecord{}, "account_id"},
		}
		for _, model := range models {
			subject := accountID
			if model.subject == "user_id" {
				subject = profile.UserID
			}
			if err := tx.Where("tenant_id = ? AND "+model.subject+" = ?", job.TenantID, subject).Delete(model.model).Error; err != nil {
				return fmt.Errorf("account.erasure.user_purge: %w", err)
			}
		}
		return tx.Model(&databaseAccountErasure{}).Where("operation_id = ? AND lease_token = ?", job.OperationID, job.LeaseToken).
			Updates(map[string]any{"account_state": erasureAccountRemoved, "phase": erasureRevokePhase, "account_id": nil, "user_id": nil, "updated_unix": now}).Error
	})
}

func (store *DatabaseUserStore) cleanupErasureReceipts(ctx context.Context) error {
	now := store.now().UTC().Unix()
	if err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("operation_id IN (SELECT operation_id FROM account_erasures WHERE state = ? AND expires_unix > 0 AND expires_unix <= ?)", erasureCompleted, now).Delete(&databaseErasureProvider{}).Error; err != nil {
			return err
		}
		if err := tx.Where("operation_id IN (SELECT operation_id FROM account_erasures WHERE state = ? AND expires_unix > 0 AND expires_unix <= ?)", erasureCompleted, now).Delete(&databaseAppleErasureSubject{}).Error; err != nil {
			return err
		}
		return tx.Where("state = ? AND expires_unix > 0 AND expires_unix <= ?", erasureCompleted, now).Delete(&databaseAccountErasure{}).Error
	}); err != nil {
		return fmt.Errorf("account.erasure.receipt_cleanup: %w", err)
	}
	return nil
}

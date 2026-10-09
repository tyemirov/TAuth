package authkit

import (
	"context"
	"errors"
	"fmt"
	"gorm.io/gorm"
	"unicode/utf8"
)

// ErrTransientCapacity means the retained transient state reached its storage ceiling.
var ErrTransientCapacity = errors.New("auth.transient_capacity")

const transientTenantCapacity = 1000
const transientGlobalCapacity = 10000
const refreshTenantCapacity = 100000
const refreshGlobalCapacity = 1000000

type transientCapacityLock struct {
	Category string `gorm:"primaryKey"`
}

func (transientCapacityLock) TableName() string { return "auth_transient_capacity_locks" }
func lockTransientCapacity(tx *gorm.DB, category string) error {
	result := tx.Model(&transientCapacityLock{}).Where("category = ?", category).Update("category", category)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return fmt.Errorf("capacity lock missing: %s", category)
	}
	return nil
}
func checkTransientCapacity(tx *gorm.DB, model interface{}, tenantID string, tenantCap, globalCap int64) error {
	var total, tenant int64
	if err := tx.Model(model).Count(&total).Error; err != nil {
		return err
	}
	if err := tx.Model(model).Where("tenant_id = ?", tenantID).Count(&tenant).Error; err != nil {
		return err
	}
	if total >= globalCap || tenant >= tenantCap {
		return ErrTransientCapacity
	}
	return nil
}
func (store *memoryNonceStore) CleanupExpired(ctx context.Context, nowUnix int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.cleanupExpiredLocked(nowUnix)
	return nil
}
func (store *memoryNonceStore) cleanupExpiredLocked(nowUnix int64) {
	for tenant, entries := range store.entries {
		for token, expiry := range entries {
			if expiry.Unix() <= nowUnix {
				delete(entries, token)
			}
		}
		if len(entries) == 0 {
			delete(store.entries, tenant)
		}
	}
}

// CleanupExpired removes all expired nonce records.
func (store *DatabaseNonceStore) CleanupExpired(ctx context.Context, nowUnix int64) error {
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockTransientCapacity(tx, nonceStoreErrorPrefix); err != nil {
			return err
		}
		return tx.Where("expires_unix <= ?", nowUnix).Delete(&nonceRecord{}).Error
	})
	if err != nil {
		return fmt.Errorf("nonce_store.cleanup: %w", err)
	}
	return nil
}

func (store *MemoryPasswordCredentialStore) cleanupExpiredLocked(nowUnix int64) {
	for tenant, accounts := range store.accounts {
		for id, account := range accounts {
			if account.state != accountStatePendingVerification {
				continue
			}
			expired, live := false, false
			for _, challenge := range store.challenges[tenant] {
				if challenge.accountID == id && challenge.kind == accountChallengeEmailVerification {
					if challenge.expiresUnix <= nowUnix {
						expired = true
					}
					if challenge.expiresUnix > nowUnix && !challenge.consumed {
						live = true
					}
				}
			}
			if !expired || live {
				continue
			}
			removable := false
			protected := false
			for _, credential := range store.tenants[tenant] {
				if credential.accountID == id && (credential.verified || credential.managedByConfig) {
					protected = true
				}
				if credential.accountID == id && !credential.verified && !credential.managedByConfig {
					removable = true
				}
			}
			if removable && !protected {
				delete(accounts, id)
				for email, credential := range store.tenants[tenant] {
					if credential.accountID == id && !credential.verified && !credential.managedByConfig {
						delete(store.tenants[tenant], email)
					}
				}
			}
		}
	}
	for _, challenges := range store.challenges {
		for hash, challenge := range challenges {
			if challenge.expiresUnix <= nowUnix || challenge.consumed {
				delete(challenges, hash)
			}
		}
	}
	for key, record := range store.abuseBudgets {
		if record.ExpiresUnix <= nowUnix {
			delete(store.abuseBudgets, key)
		}
	}
	for key, record := range store.passwordFailures {
		if record.ExpiresUnixNano <= nowUnix*1000000000 {
			delete(store.passwordFailures, key)
		}
	}
}

// CleanupExpired removes expired account challenges, abandoned signups, and abuse state.
func (store *MemoryPasswordCredentialStore) CleanupExpired(ctx context.Context, nowUnix int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.cleanupExpiredLocked(nowUnix)
	return nil
}
func (store *MemoryPasswordCredentialStore) checkAccountCapacityLocked(tenantID string, signup bool) error {
	total, tenant, pendingTotal, pendingTenant := 0, 0, 0, 0
	for storedTenant, challenges := range store.challenges {
		total += len(challenges)
		if storedTenant == tenantID {
			tenant += len(challenges)
		}
	}
	if total >= transientGlobalCapacity || tenant >= transientTenantCapacity {
		return ErrTransientCapacity
	}
	if signup {
		for storedTenant, accounts := range store.accounts {
			for _, account := range accounts {
				if account.state == accountStatePendingVerification {
					pendingTotal++
					if storedTenant == tenantID {
						pendingTenant++
					}
				}
			}
		}
		if pendingTotal >= transientGlobalCapacity || pendingTenant >= transientTenantCapacity {
			return ErrTransientCapacity
		}
	}
	return nil
}
func lockAccountCapacity(tx *gorm.DB) error {
	return tx.Model(&abuseBudgetLock{}).Where("id = ?", 1).Update("id", 1).Error
}

const cleanupAccountBatchSize = 250
const abandonedSignupAccountSQL = `account_state = ? AND NOT EXISTS (SELECT 1 FROM password_credentials protected WHERE protected.tenant_id=accounts.tenant_id AND protected.account_id=accounts.account_id AND (protected.email_verified = true OR protected.managed_by_config = true)) AND EXISTS (SELECT 1 FROM password_credentials credential WHERE credential.tenant_id=accounts.tenant_id AND credential.account_id=accounts.account_id AND credential.email_verified = ? AND credential.managed_by_config = ?) AND EXISTS (SELECT 1 FROM account_challenges evidence WHERE evidence.tenant_id=accounts.tenant_id AND evidence.account_id=accounts.account_id AND evidence.challenge_kind = ? AND evidence.expires_unix <= ?) AND NOT EXISTS (SELECT 1 FROM account_challenges live WHERE live.tenant_id=accounts.tenant_id AND live.account_id=accounts.account_id AND live.challenge_kind = ? AND live.consumed_at_unix=0 AND live.expires_unix > ?)`

func cleanupDatabaseAccounts(tx *gorm.DB, nowUnix int64) error {
	eligibleAccounts := func() *gorm.DB {
		return tx.Model(&databaseAccountRecord{}).Where(abandonedSignupAccountSQL, accountStatePendingVerification, false, false, accountChallengeEmailVerification, nowUnix, accountChallengeEmailVerification, nowUnix)
	}
	for {
		var abandoned []databaseAccountRecord
		if err := eligibleAccounts().Select("tenant_id", "account_id").Order("tenant_id, account_id").Limit(cleanupAccountBatchSize).Find(&abandoned).Error; err != nil {
			return err
		}
		if len(abandoned) == 0 {
			break
		}
		keys := make([][]interface{}, len(abandoned))
		for index, account := range abandoned {
			keys[index] = []interface{}{account.TenantID, account.AccountID}
		}
		// Recheck eligibility in the deletion statement. Concurrent durable account changes remain authoritative.
		if err := eligibleAccounts().Where("(tenant_id, account_id) IN ?", keys).Delete(&databaseAccountRecord{}).Error; err != nil {
			return err
		}
		// A credential belongs to this sweep only after its pending account was removed.
		if err := tx.Where("(tenant_id, account_id) IN ? AND email_verified = ? AND managed_by_config = ? AND NOT EXISTS (SELECT 1 FROM accounts retained WHERE retained.tenant_id=password_credentials.tenant_id AND retained.account_id=password_credentials.account_id)", keys, false, false).Delete(&passwordCredentialRecord{}).Error; err != nil {
			return err
		}
	}

	if err := tx.Where("expires_unix <= ? OR consumed_at_unix <> 0", nowUnix).Delete(&databaseAccountChallengeRecord{}).Error; err != nil {
		return err
	}
	if err := tx.Where("expires_unix <= ?", nowUnix).Delete(&abuseBudgetRecord{}).Error; err != nil {
		return err
	}
	return tx.Where("expires_unix_nano <= ?", nowUnix*1000000000).Delete(&passwordFailureRecord{}).Error
}

// CleanupExpired removes expired account challenges, abandoned signups, and abuse state.
func (store *DatabaseUserStore) CleanupExpired(ctx context.Context, nowUnix int64) error {
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockAccountCapacity(tx); err != nil {
			return err
		}
		return cleanupDatabaseAccounts(tx, nowUnix)
	})
	if err != nil {
		return fmt.Errorf("account.cleanup: %w", err)
	}
	return nil
}
func checkDatabaseAccountCapacity(tx *gorm.DB, tenantID string, signup bool) error {
	if err := checkTransientCapacity(tx, &databaseAccountChallengeRecord{}, tenantID, transientTenantCapacity, transientGlobalCapacity); err != nil {
		return err
	}
	if signup {
		var total, tenant int64
		query := tx.Model(&databaseAccountRecord{}).Where("account_state = ?", accountStatePendingVerification)
		if err := query.Count(&total).Error; err != nil {
			return err
		}
		if err := query.Where("tenant_id = ?", tenantID).Count(&tenant).Error; err != nil {
			return err
		}
		if total >= transientGlobalCapacity || tenant >= transientTenantCapacity {
			return ErrTransientCapacity
		}
	}
	return nil
}
func validateSignupRequest(request AccountPasswordRequest) (string, error) {
	email, err := normalizePasswordEmail(request.UserEmail)
	if err != nil {
		return "", ErrPasswordCredentialInvalid
	}
	if err := validatePlainPassword(request.Password); err != nil {
		return "", ErrPasswordCredentialInvalid
	}
	if !utf8.ValidString(request.Password) || utf8.RuneCountInString(request.Password) < passwordMinCodePoints {
		return "", ErrPasswordCredentialInvalid
	}
	return email, nil
}

func isAccountAdmissionError(err error) bool {
	return errors.Is(err, ErrAccountNotActive) || errors.Is(err, ErrAccountDisabled) || errors.Is(err, ErrAccountNotFound) || errors.Is(err, ErrAccountExists)
}

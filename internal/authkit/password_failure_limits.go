package authkit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const passwordFailureExpiry = 15 * time.Minute
const maximumPasswordFailureRecords = 10000

type passwordFailureRecord struct {
	Key                 string `gorm:"primaryKey"`
	Failures            int    `gorm:"not null"`
	Ticket              string `gorm:"not null"`
	NextAllowedUnixNano int64  `gorm:"not null"`
	ExpiresUnixNano     int64  `gorm:"index;not null"`
}

func (passwordFailureRecord) TableName() string { return "auth_password_failures" }

type authenticationDelayError struct{ seconds int }

func (err authenticationDelayError) Error() string { return ErrAuthenticationRateLimited.Error() }
func (err authenticationDelayError) Unwrap() error { return ErrAuthenticationRateLimited }

// AuthenticationRetryAfter returns the remaining authentication delay in seconds.
func AuthenticationRetryAfter(err error) int {
	var delay authenticationDelayError
	if errors.As(err, &delay) {
		return delay.seconds
	}
	return 60
}
func passwordFailureKey(tenantID, email string) string { return hashOpaque(tenantID + "\x00" + email) }
func reservePasswordFailure(record passwordFailureRecord, key, ticket string, now time.Time) (passwordFailureRecord, error) {
	if record.NextAllowedUnixNano > now.UnixNano() {
		remaining := time.Duration(record.NextAllowedUnixNano - now.UnixNano())
		return record, authenticationDelayError{seconds: int((remaining + time.Second - 1) / time.Second)}
	}
	record.Key, record.Ticket = key, ticket
	if record.Failures < 7 {
		record.Failures++
	}
	delay := time.Second * time.Duration(1<<(record.Failures-1))
	if delay > time.Minute {
		delay = time.Minute
	}
	record.NextAllowedUnixNano = now.Add(delay).UnixNano()
	record.ExpiresUnixNano = now.Add(passwordFailureExpiry).UnixNano()
	return record, nil
}
func (store *MemoryPasswordCredentialStore) reservePasswordAttempt(ctx context.Context, tenantID, email string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	ticket, _, err := generateRefreshOpaque()
	if err != nil {
		return "", fmt.Errorf("password_auth.reserve_attempt: %w", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	now := store.now()
	for key, record := range store.passwordFailures {
		if record.ExpiresUnixNano <= now.UnixNano() {
			delete(store.passwordFailures, key)
		}
	}
	key := passwordFailureKey(tenantID, email)
	record, exists := store.passwordFailures[key]
	if !exists && len(store.passwordFailures) >= maximumPasswordFailureRecords {
		return "", ErrAuthenticationRateLimited
	}
	record, err = reservePasswordFailure(record, key, ticket, now)
	if err != nil {
		return "", err
	}
	store.passwordFailures[key] = record
	return ticket, nil
}
func (store *MemoryPasswordCredentialStore) clearPasswordAttempt(ctx context.Context, tenantID, email, ticket string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := passwordFailureKey(tenantID, email)
	if store.passwordFailures[key].Ticket == ticket {
		delete(store.passwordFailures, key)
	}
	return nil
}
func (store *DatabaseUserStore) reservePasswordAttempt(ctx context.Context, tenantID, email string) (string, error) {
	ticket, _, err := generateRefreshOpaque()
	if err != nil {
		return "", fmt.Errorf("password_auth.reserve_attempt: %w", err)
	}
	var admissionErr error
	err = store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&abuseBudgetLock{}).Where("id = ?", 1).Update("id", 1).Error; err != nil {
			return err
		}
		now := store.now()
		if err := tx.Where("expires_unix_nano <= ?", now.UnixNano()).Delete(&passwordFailureRecord{}).Error; err != nil {
			return err
		}
		key := passwordFailureKey(tenantID, email)
		var record passwordFailureRecord
		err := tx.Where("key = ?", key).Take(&record).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			var count int64
			if err := tx.Model(&passwordFailureRecord{}).Count(&count).Error; err != nil {
				return err
			}
			if count >= maximumPasswordFailureRecords {
				admissionErr = ErrAuthenticationRateLimited
				return nil
			}
		} else if err != nil {
			return err
		}
		record, admissionErr = reservePasswordFailure(record, key, ticket, now)
		if admissionErr != nil {
			return nil
		}
		return tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "key"}}, DoUpdates: clause.AssignmentColumns([]string{"failures", "ticket", "next_allowed_unix_nano", "expires_unix_nano"})}).Create(&record).Error
	})
	if err != nil {
		return "", fmt.Errorf("password_auth.reserve_attempt: %w", err)
	}
	return ticket, admissionErr
}
func (store *DatabaseUserStore) clearPasswordAttempt(ctx context.Context, tenantID, email, ticket string) error {
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&abuseBudgetLock{}).Where("id = ?", 1).Update("id", 1).Error; err != nil {
			return err
		}
		return tx.Where("key = ? AND ticket = ?", passwordFailureKey(tenantID, email), ticket).Delete(&passwordFailureRecord{}).Error
	})
	if err != nil {
		return fmt.Errorf("password_auth.clear_attempt: %w", err)
	}
	return nil
}

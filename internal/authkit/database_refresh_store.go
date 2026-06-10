package authkit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

const refreshTokenTableName = "refresh_tokens"

// DatabaseRefreshTokenStore persists rotating refresh tokens using GORM.
type DatabaseRefreshTokenStore struct {
	db          *gorm.DB
	driverLabel string
}

// Driver exposes the selected database driver label.
func (store *DatabaseRefreshTokenStore) Driver() string {
	return store.driverLabel
}

type refreshTokenRecord struct {
	TokenID         string `gorm:"column:token_id;primaryKey"`
	TenantID        string `gorm:"column:tenant_id;index;not null"`
	UserID          string `gorm:"column:user_id;index;not null"`
	TokenHash       string `gorm:"column:token_hash;uniqueIndex;not null"`
	ExpiresUnix     int64  `gorm:"column:expires_unix;not null"`
	RevokedAtUnix   int64  `gorm:"column:revoked_at_unix;not null;default:0"`
	PreviousTokenID string `gorm:"column:previous_token_id;not null;default:''"`
	IssuedAtUnix    int64  `gorm:"column:issued_at_unix;not null"`
}

func (refreshTokenRecord) TableName() string {
	return refreshTokenTableName
}

// NewDatabaseRefreshTokenStore constructs a GORM-backed store.
func NewDatabaseRefreshTokenStore(ctx context.Context, databaseURL string) (*DatabaseRefreshTokenStore, error) {
	databaseHandle, driverLabel, openErr := openDatabase(ctx, databaseURL, refreshStoreErrorPrefix, &refreshTokenRecord{})
	if openErr != nil {
		return nil, openErr
	}
	return &DatabaseRefreshTokenStore{
		db:          databaseHandle,
		driverLabel: driverLabel,
	}, nil
}

// Issue inserts a new refresh token record and returns its identifiers.
func (store *DatabaseRefreshTokenStore) Issue(ctx context.Context, tenantID string, applicationUserID string, expiresUnix int64, previousTokenID string) (string, string, error) {
	now := time.Now().UTC()
	tokenID := newRefreshTokenID(now)
	opaqueToken, hashValue, randomErr := generateRefreshOpaque()
	if randomErr != nil {
		return "", "", fmt.Errorf("refresh_store.issue.%s: %w", store.driverLabel, randomErr)
	}
	record := refreshTokenRecord{
		TenantID:        tenantID,
		TokenID:         tokenID,
		UserID:          applicationUserID,
		TokenHash:       hashValue,
		ExpiresUnix:     expiresUnix,
		RevokedAtUnix:   0,
		PreviousTokenID: previousTokenID,
		IssuedAtUnix:    now.Unix(),
	}
	if err := store.db.WithContext(ctx).Create(&record).Error; err != nil {
		return "", "", fmt.Errorf("refresh_store.issue.%s: %w", store.driverLabel, err)
	}
	return tokenID, opaqueToken, nil
}

// Validate locates a refresh token by its opaque value.
func (store *DatabaseRefreshTokenStore) Validate(ctx context.Context, tenantID string, tokenOpaque string) (string, string, int64, error) {
	if strings.TrimSpace(tokenOpaque) == "" {
		return "", "", 0, fmt.Errorf("refresh_store.validate.%s: %w", store.driverLabel, ErrRefreshTokenEmptyOpaque)
	}
	hashValue := hashOpaque(tokenOpaque)
	var record refreshTokenRecord
	err := store.db.WithContext(ctx).Where("tenant_id = ? AND token_hash = ?", tenantID, hashValue).Take(&record).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", "", 0, fmt.Errorf("refresh_store.validate.%s: %w", store.driverLabel, ErrRefreshTokenNotFound)
		}
		return "", "", 0, fmt.Errorf("refresh_store.validate.%s: %w", store.driverLabel, err)
	}
	now := time.Now().UTC()
	if record.RevokedAtUnix != 0 {
		return "", "", 0, fmt.Errorf("refresh_store.validate.%s: %w", store.driverLabel, ErrRefreshTokenRevoked)
	}
	if time.Unix(record.ExpiresUnix, 0).Before(now) {
		return "", "", 0, fmt.Errorf("refresh_store.validate.%s: %w", store.driverLabel, ErrRefreshTokenExpired)
	}
	return record.UserID, record.TokenID, record.ExpiresUnix, nil
}

// Revoke marks a refresh token as revoked.
func (store *DatabaseRefreshTokenStore) Revoke(ctx context.Context, tenantID string, tokenID string) error {
	now := time.Now().UTC()
	result := store.db.WithContext(ctx).Model(&refreshTokenRecord{}).
		Where("tenant_id = ? AND token_id = ? AND revoked_at_unix = 0", tenantID, tokenID).
		Update("revoked_at_unix", now.Unix())
	if result.Error != nil {
		return fmt.Errorf("refresh_store.revoke.%s: %w", store.driverLabel, result.Error)
	}
	if result.RowsAffected == 0 {
		var record refreshTokenRecord
		findErr := store.db.WithContext(ctx).Where("tenant_id = ? AND token_id = ?", tenantID, tokenID).Take(&record).Error
		if errors.Is(findErr, gorm.ErrRecordNotFound) {
			return fmt.Errorf("refresh_store.revoke.%s: %w", store.driverLabel, ErrRefreshTokenNotFound)
		}
		if findErr != nil {
			return fmt.Errorf("refresh_store.revoke.%s: %w", store.driverLabel, findErr)
		}
		if record.RevokedAtUnix != 0 {
			return fmt.Errorf("refresh_store.revoke.%s: %w", store.driverLabel, ErrRefreshTokenAlreadyRevoked)
		}
		return nil
	}
	return nil
}

// RevokeUser marks all active refresh tokens for an application user as revoked.
func (store *DatabaseRefreshTokenStore) RevokeUser(ctx context.Context, tenantID string, applicationUserID string) error {
	now := time.Now().UTC()
	result := store.db.WithContext(ctx).Model(&refreshTokenRecord{}).
		Where("tenant_id = ? AND user_id = ? AND revoked_at_unix = 0", tenantID, applicationUserID).
		Update("revoked_at_unix", now.Unix())
	if result.Error != nil {
		return fmt.Errorf("refresh_store.revoke_user.%s: %w", store.driverLabel, result.Error)
	}
	return nil
}

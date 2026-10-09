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
	db               *gorm.DB
	driverLabel      string
	databaseIdentity string
	now              func() time.Time
}

// Driver exposes the selected database driver label.
func (store *DatabaseRefreshTokenStore) Driver() string {
	return store.driverLabel
}

type refreshTokenRecord struct {
	TokenID         string `gorm:"column:token_id;primaryKey"`
	TenantID        string `gorm:"column:tenant_id;index;index:idx_refresh_family_children,priority:1;not null"`
	UserID          string `gorm:"column:user_id;index;not null"`
	TokenHash       string `gorm:"column:token_hash;uniqueIndex;not null"`
	ExpiresUnix     int64  `gorm:"column:expires_unix;index;index:idx_refresh_root_expiry,priority:2;not null"`
	RevokedAtUnix   int64  `gorm:"column:revoked_at_unix;not null;default:0"`
	PreviousTokenID string `gorm:"column:previous_token_id;index;index:idx_refresh_root_expiry,priority:1;index:idx_refresh_family_children,priority:2;not null;default:''"`
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
		db:               databaseHandle,
		driverLabel:      driverLabel,
		databaseIdentity: hashOpaque(databaseURL),
		now:              time.Now,
	}, nil
}

// Issue inserts a new refresh token record and returns its identifiers.
func (store *DatabaseRefreshTokenStore) Issue(ctx context.Context, tenantID string, applicationUserID string, expiresUnix int64, previousTokenID string) (string, string, error) {
	now := store.now().UTC()
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
	var rotationErr error
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockTransientCapacity(tx, refreshStoreErrorPrefix); err != nil {
			return err
		}
		if err := cleanupDatabaseRefresh(tx, now.Unix()); err != nil {
			return err
		}
		rotationErr = checkTransientCapacity(tx, &refreshTokenRecord{}, tenantID, refreshTenantCapacity, refreshGlobalCapacity)
		if errors.Is(rotationErr, ErrTransientCapacity) {
			return nil
		}
		if rotationErr != nil {
			return rotationErr
		}
		if err := RequireActiveAccountWrite(ctx, tx, tenantID, applicationUserID); err != nil {
			return err
		}
		if previousTokenID != "" {
			if err := lockRefreshFamily(tx, tenantID, previousTokenID); err != nil {
				return err
			}
			result := tx.Model(&refreshTokenRecord{}).Where("tenant_id = ? AND token_id = ? AND user_id = ? AND revoked_at_unix = 0 AND expires_unix > ?", tenantID, previousTokenID, applicationUserID, now.Unix()).Update("revoked_at_unix", now.Unix())
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected != 1 {
				rotationErr = ErrRefreshTokenRevoked
				return revokeRefreshFamily(tx, tenantID, previousTokenID, now.Unix())
			}
		}
		return tx.Create(&record).Error
	})
	if err != nil {
		return "", "", fmt.Errorf("refresh_store.issue.%s: %w", store.driverLabel, err)
	}
	if rotationErr != nil {
		return "", "", rotationErr
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
			if cleanupErr := store.CleanupExpired(ctx, store.now().Unix()); cleanupErr != nil {
				return "", "", 0, cleanupErr
			}
			return "", "", 0, fmt.Errorf("refresh_store.validate.%s: %w", store.driverLabel, ErrRefreshTokenNotFound)
		}
		return "", "", 0, fmt.Errorf("refresh_store.validate.%s: %w", store.driverLabel, err)
	}
	if cleanupErr := store.CleanupExpired(ctx, store.now().Unix()); cleanupErr != nil {
		return "", "", 0, cleanupErr
	}
	now := store.now().UTC()
	if record.RevokedAtUnix != 0 {
		if err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			if err := lockRefreshFamily(tx, tenantID, record.TokenID); err != nil {
				return err
			}
			return revokeRefreshFamily(tx, tenantID, record.TokenID, now.Unix())
		}); err != nil {
			return "", "", 0, fmt.Errorf("refresh_store.reuse.%s: %w", store.driverLabel, err)
		}
		return "", "", 0, fmt.Errorf("refresh_store.validate.%s: %w", store.driverLabel, ErrRefreshTokenRevoked)
	}
	if record.ExpiresUnix <= now.Unix() {
		return "", "", 0, fmt.Errorf("refresh_store.validate.%s: %w", store.driverLabel, ErrRefreshTokenExpired)
	}
	return record.UserID, record.TokenID, record.ExpiresUnix, nil
}

// lockRefreshFamily serializes rotations and reuse revocation on the immutable root.
func lockRefreshFamily(tx *gorm.DB, tenantID, tokenID string) error {
	// One write statement acquires the root lock before later reads on both SQLite and Postgres.
	result := tx.Exec(`WITH RECURSIVE ancestors AS (
		SELECT token_id, previous_token_id FROM refresh_tokens WHERE tenant_id = ? AND token_id = ?
		UNION SELECT parent.token_id, parent.previous_token_id FROM refresh_tokens parent JOIN ancestors child ON parent.token_id = child.previous_token_id WHERE parent.tenant_id = ?
	) UPDATE refresh_tokens SET issued_at_unix = issued_at_unix WHERE tenant_id = ? AND token_id IN (SELECT token_id FROM ancestors WHERE previous_token_id = '')`, tenantID, tokenID, tenantID, tenantID)
	return result.Error
}

func revokeRefreshFamily(tx *gorm.DB, tenantID, tokenID string, nowUnix int64) error {
	return tx.Exec(`WITH RECURSIVE ancestors AS (
		SELECT token_id, previous_token_id FROM refresh_tokens WHERE tenant_id = ? AND token_id = ?
		UNION SELECT parent.token_id, parent.previous_token_id FROM refresh_tokens parent JOIN ancestors child ON parent.token_id = child.previous_token_id WHERE parent.tenant_id = ?
	), family AS (
		SELECT token_id FROM ancestors WHERE previous_token_id = ''
		UNION SELECT child.token_id FROM refresh_tokens child JOIN family parent ON child.previous_token_id = parent.token_id WHERE child.tenant_id = ?
	) UPDATE refresh_tokens SET revoked_at_unix = ? WHERE tenant_id = ? AND token_id IN (SELECT token_id FROM family)`, tenantID, tokenID, tenantID, tenantID, nowUnix, tenantID).Error
}

// Revoke marks a refresh token as revoked.
func (store *DatabaseRefreshTokenStore) Revoke(ctx context.Context, tenantID string, tokenID string) error {
	now := store.now().UTC()
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
	now := store.now().UTC()
	result := store.db.WithContext(ctx).Model(&refreshTokenRecord{}).
		Where("tenant_id = ? AND user_id = ? AND revoked_at_unix = 0", tenantID, applicationUserID).
		Update("revoked_at_unix", now.Unix())
	if result.Error != nil {
		return fmt.Errorf("refresh_store.revoke_user.%s: %w", store.driverLabel, result.Error)
	}
	return nil
}

// RevokeTenantSessions participates in the tenant suspension transaction.
func RevokeTenantSessions(ctx context.Context, db *gorm.DB, tenantID string) error {
	if err := db.WithContext(ctx).Model(&refreshTokenRecord{}).Where("tenant_id = ? AND revoked_at_unix = 0", tenantID).Update("revoked_at_unix", time.Now().UTC().Unix()).Error; err != nil {
		return fmt.Errorf("refresh_store.suspend tenant=%s: %w", tenantID, err)
	}
	return nil
}

// PurgeUser removes all application refresh-token rows for one tenant and user.
func (store *DatabaseRefreshTokenStore) PurgeUser(ctx context.Context, tenantID, userID string) error {
	if err := store.db.WithContext(ctx).Where("tenant_id = ? AND user_id = ?", tenantID, userID).Delete(&refreshTokenRecord{}).Error; err != nil {
		return fmt.Errorf("refresh_store.user_purge: %w", err)
	}
	return nil
}

// ErasureDatabaseIdentity identifies the selected database without disclosing its URL.
func (store *DatabaseRefreshTokenStore) ErasureDatabaseIdentity() string {
	return store.databaseIdentity
}

// CleanupExpired removes whole refresh families after every retained member expires.
func (store *DatabaseRefreshTokenStore) CleanupExpired(ctx context.Context, nowUnix int64) error {
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockTransientCapacity(tx, refreshStoreErrorPrefix); err != nil {
			return err
		}
		return cleanupDatabaseRefresh(tx, nowUnix)
	})
	if err != nil {
		return fmt.Errorf("refresh_store.cleanup: %w", err)
	}
	return nil
}

const cleanupRefreshFamiliesSQL = `WITH RECURSIVE family AS (
 SELECT tenant_id,token_id,token_id AS root_id,expires_unix FROM refresh_tokens WHERE previous_token_id = '' AND expires_unix <= ?
 UNION ALL SELECT child.tenant_id,child.token_id,parent.root_id,child.expires_unix FROM refresh_tokens child JOIN family parent ON child.tenant_id=parent.tenant_id AND child.previous_token_id=parent.token_id
 ),expired_families AS (
 SELECT tenant_id,root_id FROM family GROUP BY tenant_id,root_id HAVING MAX(expires_unix) <= ?
 ) DELETE FROM refresh_tokens WHERE (tenant_id,token_id) IN (SELECT family.tenant_id,family.token_id FROM family JOIN expired_families ON expired_families.tenant_id=family.tenant_id AND expired_families.root_id=family.root_id)`

func cleanupDatabaseRefresh(tx *gorm.DB, nowUnix int64) error {
	var expiredRoots []refreshTokenRecord
	if err := tx.Select("token_id").Where("previous_token_id = '' AND expires_unix <= ?", nowUnix).Limit(1).Find(&expiredRoots).Error; err != nil {
		return err
	}
	if len(expiredRoots) == 0 {
		return nil
	}
	return tx.Exec(cleanupRefreshFamiliesSQL, nowUnix, nowUnix).Error
}

package authkit

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"gorm.io/gorm"
)

const nonceTokenTableName = "nonce_tokens"

var errNonceStoreTTLResolverMissing = errors.New("nonce_store.ttl_resolver_missing")

// DatabaseNonceStore persists nonces using GORM.
type DatabaseNonceStore struct {
	db          *gorm.DB
	driverLabel string
	ttlResolver func(string) time.Duration
	now         func() time.Time
	randReader  io.Reader
	tokenSize   int
}

// Driver returns the active database driver label.
func (store *DatabaseNonceStore) Driver() string {
	return store.driverLabel
}

type nonceRecord struct {
	TenantID     string `gorm:"column:tenant_id;primaryKey"`
	TokenHash    string `gorm:"column:token_hash;primaryKey"`
	ExpiresUnix  int64  `gorm:"column:expires_unix;not null"`
	IssuedAtUnix int64  `gorm:"column:issued_at_unix;not null"`
}

func (nonceRecord) TableName() string {
	return nonceTokenTableName
}

// NewDatabaseNonceStore constructs a DatabaseNonceStore with a fixed TTL.
func NewDatabaseNonceStore(ctx context.Context, databaseURL string, ttl time.Duration) (*DatabaseNonceStore, error) {
	return NewDatabaseNonceStoreWithTTLResolver(ctx, databaseURL, func(string) time.Duration {
		return ttl
	})
}

// NewDatabaseNonceStoreWithTTLResolver constructs a DatabaseNonceStore with a per-tenant TTL resolver.
func NewDatabaseNonceStoreWithTTLResolver(ctx context.Context, databaseURL string, ttlResolver func(string) time.Duration) (*DatabaseNonceStore, error) {
	if ttlResolver == nil {
		return nil, fmt.Errorf("%s.init: %w", nonceStoreErrorPrefix, errNonceStoreTTLResolverMissing)
	}
	databaseHandle, driverLabel, openErr := openDatabase(ctx, databaseURL, nonceStoreErrorPrefix, &nonceRecord{})
	if openErr != nil {
		return nil, openErr
	}
	return &DatabaseNonceStore{
		db:          databaseHandle,
		driverLabel: driverLabel,
		ttlResolver: ttlResolver,
		now:         time.Now,
		randReader:  rand.Reader,
		tokenSize:   nonceTokenByteLength,
	}, nil
}

// Issue creates and stores a nonce token for the provided tenant.
func (store *DatabaseNonceStore) Issue(ctx context.Context, tenantID string) (string, error) {
	if purgeErr := store.purgeExpired(ctx, tenantID); purgeErr != nil {
		return "", purgeErr
	}
	opaqueToken, hashValue, randomErr := generateOpaqueToken(store.randReader, store.tokenSize, nonceStoreErrorPrefix)
	if randomErr != nil {
		return "", fmt.Errorf("%s.issue.%s: %w", nonceStoreErrorPrefix, store.driverLabel, randomErr)
	}
	now := store.now().UTC()
	record := nonceRecord{
		TenantID:     tenantID,
		TokenHash:    hashValue,
		ExpiresUnix:  now.Add(store.ttlResolver(tenantID)).Unix(),
		IssuedAtUnix: now.Unix(),
	}
	if createErr := store.db.WithContext(ctx).Create(&record).Error; createErr != nil {
		return "", fmt.Errorf("%s.issue.%s: %w", nonceStoreErrorPrefix, store.driverLabel, createErr)
	}
	return opaqueToken, nil
}

// Consume validates and invalidates a previously issued nonce token.
func (store *DatabaseNonceStore) Consume(ctx context.Context, tenantID string, token string) error {
	hashValue := hashOpaque(token)
	var record nonceRecord
	queryErr := store.db.WithContext(ctx).
		Where("tenant_id = ? AND token_hash IN (?, ?)", tenantID, hashValue, token).
		Take(&record).Error
	if queryErr != nil {
		if errors.Is(queryErr, gorm.ErrRecordNotFound) {
			if purgeErr := store.purgeExpired(ctx, tenantID); purgeErr != nil {
				return purgeErr
			}
			return ErrNonceNotFound
		}
		return fmt.Errorf("%s.consume.%s: %w", nonceStoreErrorPrefix, store.driverLabel, queryErr)
	}
	now := store.now().UTC()
	if now.After(time.Unix(record.ExpiresUnix, 0)) {
		if deleteErr := store.deleteRecord(ctx, tenantID, record.TokenHash); deleteErr != nil {
			return deleteErr
		}
		if purgeErr := store.purgeExpired(ctx, tenantID); purgeErr != nil {
			return purgeErr
		}
		return ErrNonceExpired
	}
	if deleteErr := store.deleteRecord(ctx, tenantID, record.TokenHash); deleteErr != nil {
		return deleteErr
	}
	if purgeErr := store.purgeExpired(ctx, tenantID); purgeErr != nil {
		return purgeErr
	}
	return nil
}

func (store *DatabaseNonceStore) deleteRecord(ctx context.Context, tenantID string, tokenHash string) error {
	deleteErr := store.db.WithContext(ctx).
		Where("tenant_id = ? AND token_hash = ?", tenantID, tokenHash).
		Delete(&nonceRecord{}).Error
	if deleteErr != nil {
		return fmt.Errorf("%s.delete.%s: %w", nonceStoreErrorPrefix, store.driverLabel, deleteErr)
	}
	return nil
}

func (store *DatabaseNonceStore) purgeExpired(ctx context.Context, tenantID string) error {
	nowUnix := store.now().UTC().Unix()
	purgeErr := store.db.WithContext(ctx).
		Where("tenant_id = ? AND expires_unix < ?", tenantID, nowUnix).
		Delete(&nonceRecord{}).Error
	if purgeErr != nil {
		return fmt.Errorf("%s.purge.%s: %w", nonceStoreErrorPrefix, store.driverLabel, purgeErr)
	}
	return nil
}

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
	var capacityErr error
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockTransientCapacity(tx, nonceStoreErrorPrefix); err != nil {
			return err
		}
		if err := tx.Where("expires_unix <= ?", now.Unix()).Delete(&nonceRecord{}).Error; err != nil {
			return err
		}
		capacityErr = checkTransientCapacity(tx, &nonceRecord{}, tenantID, transientTenantCapacity, transientGlobalCapacity)
		if errors.Is(capacityErr, ErrTransientCapacity) {
			return nil
		}
		if capacityErr != nil {
			return capacityErr
		}
		return tx.Create(&record).Error
	})
	if err != nil {
		return "", fmt.Errorf("nonce_store.issue: %w", err)
	}
	if capacityErr != nil {
		return "", capacityErr
	}
	return opaqueToken, nil
}

// Consume validates and invalidates a previously issued nonce token.
func (store *DatabaseNonceStore) Consume(ctx context.Context, tenantID string, token string) error {
	hashValue := hashOpaque(token)
	nowUnix := store.now().UTC().Unix()
	result := store.db.WithContext(ctx).
		Where("tenant_id = ? AND token_hash = ? AND expires_unix > ?", tenantID, hashValue, nowUnix).
		Delete(&nonceRecord{})
	if result.Error != nil {
		return fmt.Errorf("%s.consume.%s: %w", nonceStoreErrorPrefix, store.driverLabel, result.Error)
	}
	if result.RowsAffected != 1 {
		// A failed admission cannot authorize a credential operation. This read
		// only distinguishes an expired token from an absent or consumed token.
		var record nonceRecord
		queryErr := store.db.WithContext(ctx).Where("tenant_id = ? AND token_hash = ?", tenantID, hashValue).Take(&record).Error
		if queryErr != nil && !errors.Is(queryErr, gorm.ErrRecordNotFound) {
			return fmt.Errorf("%s.consume.%s: %w", nonceStoreErrorPrefix, store.driverLabel, queryErr)
		}
		if purgeErr := store.purgeExpired(ctx, tenantID); purgeErr != nil {
			return purgeErr
		}
		if queryErr == nil && record.ExpiresUnix <= nowUnix {
			return ErrNonceExpired
		}
		return ErrNonceNotFound
	}
	return store.purgeExpired(ctx, tenantID)
}

func (store *DatabaseNonceStore) purgeExpired(ctx context.Context, tenantID string) error {
	nowUnix := store.now().UTC().Unix()
	purgeErr := store.db.WithContext(ctx).
		Where("tenant_id = ? AND expires_unix <= ?", tenantID, nowUnix).
		Delete(&nonceRecord{}).Error
	if purgeErr != nil {
		return fmt.Errorf("%s.purge.%s: %w", nonceStoreErrorPrefix, store.driverLabel, purgeErr)
	}
	return nil
}

// WithTTLResolver retains the database and binds nonce policy to one runtime snapshot.
func (store *DatabaseNonceStore) WithTTLResolver(resolve func(string) time.Duration) *DatabaseNonceStore {
	copy := *store
	copy.ttlResolver = resolve
	return &copy
}

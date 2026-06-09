package authkit

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// MemoryRefreshTokenStore is an in-memory store intended for tests and dev.
type MemoryRefreshTokenStore struct {
	mutex      sync.Mutex
	byID       map[string]*memoryRecord
	byHash     map[string]string
	sequenceID uint64
}

type memoryRecord struct {
	TenantID        string
	TokenID         string
	UserID          string
	Hash            string
	ExpiresUnix     int64
	RevokedAtUnix   int64
	PreviousTokenID string
	IssuedAtUnix    int64
}

// NewMemoryRefreshTokenStore creates a new in-memory token store.
func NewMemoryRefreshTokenStore() *MemoryRefreshTokenStore {
	return &MemoryRefreshTokenStore{
		byID:   make(map[string]*memoryRecord),
		byHash: make(map[string]string),
	}
}

// Issue creates a new token, optionally linked to a previous token.
func (store *MemoryRefreshTokenStore) Issue(ctx context.Context, tenantID string, applicationUserID string, expiresUnix int64, previousTokenID string) (string, string, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	tokenID := store.nextID()
	opaque, hashValue, err := store.randomOpaque()
	if err != nil {
		return "", "", fmt.Errorf("refresh_store.issue.memory: %w", err)
	}
	nowUnix := time.Now().UTC().Unix()

	record := &memoryRecord{
		TenantID:        tenantID,
		TokenID:         tokenID,
		UserID:          applicationUserID,
		Hash:            hashValue,
		ExpiresUnix:     expiresUnix,
		RevokedAtUnix:   0,
		PreviousTokenID: previousTokenID,
		IssuedAtUnix:    nowUnix,
	}
	store.byID[tokenID] = record
	store.byHash[store.hashKey(tenantID, hashValue)] = tokenID
	return tokenID, opaque, nil
}

// Validate checks the opaque token and returns user, token id, and expiry.
func (store *MemoryRefreshTokenStore) Validate(ctx context.Context, tenantID string, tokenOpaque string) (string, string, int64, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	hashValue := store.hash(tokenOpaque)
	tokenID, ok := store.byHash[store.hashKey(tenantID, hashValue)]
	if !ok {
		return "", "", 0, fmt.Errorf("refresh_store.validate.memory: %w", ErrRefreshTokenNotFound)
	}
	rec := store.byID[tokenID]
	if rec == nil {
		return "", "", 0, fmt.Errorf("refresh_store.validate.memory: %w", ErrRefreshTokenNotFound)
	}
	if rec.TenantID != tenantID {
		return "", "", 0, fmt.Errorf("refresh_store.validate.memory: %w", ErrRefreshTokenNotFound)
	}
	if rec.RevokedAtUnix != 0 {
		return "", "", 0, fmt.Errorf("refresh_store.validate.memory: %w", ErrRefreshTokenRevoked)
	}
	if time.Unix(rec.ExpiresUnix, 0).Before(time.Now().UTC()) {
		return "", "", 0, fmt.Errorf("refresh_store.validate.memory: %w", ErrRefreshTokenExpired)
	}
	return rec.UserID, rec.TokenID, rec.ExpiresUnix, nil
}

// Revoke marks a token as revoked.
func (store *MemoryRefreshTokenStore) Revoke(ctx context.Context, tenantID string, tokenID string) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	rec := store.byID[tokenID]
	if rec == nil {
		return fmt.Errorf("refresh_store.revoke.memory: %w", ErrRefreshTokenNotFound)
	}
	if rec.TenantID != tenantID {
		return fmt.Errorf("refresh_store.revoke.memory: %w", ErrRefreshTokenNotFound)
	}
	if rec.RevokedAtUnix != 0 {
		return fmt.Errorf("refresh_store.revoke.memory: %w", ErrRefreshTokenAlreadyRevoked)
	}
	rec.RevokedAtUnix = time.Now().UTC().Unix()
	return nil
}

// RevokeUser marks all refresh tokens for an application user as revoked.
func (store *MemoryRefreshTokenStore) RevokeUser(ctx context.Context, tenantID string, applicationUserID string) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	nowUnix := time.Now().UTC().Unix()
	for _, record := range store.byID {
		if record == nil || record.TenantID != tenantID || record.UserID != applicationUserID || record.RevokedAtUnix != 0 {
			continue
		}
		record.RevokedAtUnix = nowUnix
	}
	return nil
}

func (store *MemoryRefreshTokenStore) nextID() string {
	store.sequenceID++
	timestampID := newRefreshTokenID(time.Now().UTC())
	sequenceFragment := base64.RawURLEncoding.EncodeToString([]byte{byte(store.sequenceID % 255)})
	return timestampID + "-" + sequenceFragment
}

func (store *MemoryRefreshTokenStore) randomOpaque() (string, string, error) {
	return generateRefreshOpaque()
}

func (store *MemoryRefreshTokenStore) hash(opaque string) string {
	return hashOpaque(opaque)
}

func (store *MemoryRefreshTokenStore) hashKey(tenantID string, hashValue string) string {
	return tenantID + "::" + hashValue
}

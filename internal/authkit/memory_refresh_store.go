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
	now        func() time.Time
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
		now:    time.Now,
	}
}

// Issue creates a new token, optionally linked to a previous token.
func (store *MemoryRefreshTokenStore) Issue(ctx context.Context, tenantID string, applicationUserID string, expiresUnix int64, previousTokenID string) (string, string, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	store.cleanupExpiredLocked(store.now().Unix())
	total := len(store.byID)
	tenantCount := 0
	for _, record := range store.byID {
		if record.TenantID == tenantID {
			tenantCount++
		}
	}
	if total >= refreshGlobalCapacity || tenantCount >= refreshTenantCapacity {
		return "", "", ErrTransientCapacity
	}
	tokenID := store.nextID()
	opaque, hashValue, err := store.randomOpaque()
	if err != nil {
		return "", "", fmt.Errorf("refresh_store.issue.memory: %w", err)
	}
	nowUnix := store.now().UTC().Unix()
	if previousTokenID != "" {
		parent := store.byID[previousTokenID]
		if parent == nil || parent.TenantID != tenantID || parent.UserID != applicationUserID {
			return "", "", ErrRefreshTokenNotFound
		}
		if parent.RevokedAtUnix != 0 || parent.ExpiresUnix <= nowUnix {
			store.revokeFamily(parent, nowUnix)
			return "", "", ErrRefreshTokenRevoked
		}
		parent.RevokedAtUnix = nowUnix
	}

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
	rec := store.byID[tokenID]
	store.cleanupExpiredLocked(store.now().Unix())
	if !ok {
		return "", "", 0, fmt.Errorf("refresh_store.validate.memory: %w", ErrRefreshTokenNotFound)
	}
	if rec == nil {
		return "", "", 0, fmt.Errorf("refresh_store.validate.memory: %w", ErrRefreshTokenNotFound)
	}
	if rec.TenantID != tenantID {
		return "", "", 0, fmt.Errorf("refresh_store.validate.memory: %w", ErrRefreshTokenNotFound)
	}
	if rec.RevokedAtUnix != 0 {
		if store.byID[rec.TokenID] != nil {
			store.revokeFamily(rec, store.now().UTC().Unix())
		}
		return "", "", 0, fmt.Errorf("refresh_store.validate.memory: %w", ErrRefreshTokenRevoked)
	}
	if rec.ExpiresUnix <= store.now().Unix() {
		return "", "", 0, fmt.Errorf("refresh_store.validate.memory: %w", ErrRefreshTokenExpired)
	}
	return rec.UserID, rec.TokenID, rec.ExpiresUnix, nil
}

func (store *MemoryRefreshTokenStore) revokeFamily(record *memoryRecord, nowUnix int64) {
	root := record
	for root.PreviousTokenID != "" {
		root = store.byID[root.PreviousTokenID]
	}
	family := map[string]bool{root.TokenID: true}
	for changed := true; changed; {
		changed = false
		for _, candidate := range store.byID {
			if candidate.TenantID == root.TenantID && family[candidate.PreviousTokenID] && !family[candidate.TokenID] {
				family[candidate.TokenID] = true
				changed = true
			}
		}
	}
	for id := range family {
		store.byID[id].RevokedAtUnix = nowUnix
	}
}

// Revoke marks a token as revoked.
func (store *MemoryRefreshTokenStore) Revoke(ctx context.Context, tenantID string, tokenID string) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	rec := store.byID[tokenID]
	store.cleanupExpiredLocked(store.now().Unix())
	if rec == nil {
		return fmt.Errorf("refresh_store.revoke.memory: %w", ErrRefreshTokenNotFound)
	}
	if rec.TenantID != tenantID {
		return fmt.Errorf("refresh_store.revoke.memory: %w", ErrRefreshTokenNotFound)
	}
	if rec.RevokedAtUnix != 0 {
		return fmt.Errorf("refresh_store.revoke.memory: %w", ErrRefreshTokenAlreadyRevoked)
	}
	rec.RevokedAtUnix = store.now().UTC().Unix()
	return nil
}

// RevokeUser marks all refresh tokens for an application user as revoked.
func (store *MemoryRefreshTokenStore) RevokeUser(ctx context.Context, tenantID string, applicationUserID string) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	nowUnix := store.now().UTC().Unix()
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
	timestampID := newRefreshTokenID(store.now().UTC())
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

// PurgeUser removes all application refresh tokens for one tenant and user.
func (store *MemoryRefreshTokenStore) PurgeUser(ctx context.Context, tenantID, userID string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("refresh_store.user_purge: %w", err)
	}
	store.mutex.Lock()
	defer store.mutex.Unlock()
	for id, record := range store.byID {
		if record.TenantID == tenantID && record.UserID == userID {
			delete(store.byHash, store.hashKey(tenantID, record.Hash))
			delete(store.byID, id)
		}
	}
	return nil
}

// CleanupExpired removes whole refresh families after every retained member expires.
func (store *MemoryRefreshTokenStore) CleanupExpired(ctx context.Context, nowUnix int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.cleanupExpiredLocked(nowUnix)
	return nil
}
func (store *MemoryRefreshTokenStore) cleanupExpiredLocked(nowUnix int64) {
	roots := make(map[string]string, len(store.byID))
	live := map[string]bool{}
	for _, record := range store.byID {
		var rootID string
		path := make([]string, 0)
		current := record
		for {
			if cached, exists := roots[current.TokenID]; exists {
				rootID = cached
				break
			}
			path = append(path, current.TokenID)
			if current.PreviousTokenID == "" {
				rootID = current.TokenID
				break
			}
			current = store.byID[current.PreviousTokenID]
		}
		for _, id := range path {
			roots[id] = rootID
		}
		if record.ExpiresUnix > nowUnix {
			live[rootID] = true
		}
	}

	for id, root := range roots {
		if !live[root] {
			record := store.byID[id]
			delete(store.byHash, store.hashKey(record.TenantID, record.Hash))
			delete(store.byID, id)
		}
	}
}

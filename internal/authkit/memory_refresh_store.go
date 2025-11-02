package authkit

import (
	"context"
	"encoding/base64"
	"errors"
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
func (store *MemoryRefreshTokenStore) Issue(ctx context.Context, applicationUserID string, expiresUnix int64, previousTokenID string) (string, string, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	tokenID := store.nextID()
	opaque, hashValue, err := store.randomOpaque()
	if err != nil {
		return "", "", err
	}
	nowUnix := time.Now().UTC().Unix()

	record := &memoryRecord{
		TokenID:         tokenID,
		UserID:          applicationUserID,
		Hash:            hashValue,
		ExpiresUnix:     expiresUnix,
		RevokedAtUnix:   0,
		PreviousTokenID: previousTokenID,
		IssuedAtUnix:    nowUnix,
	}
	store.byID[tokenID] = record
	store.byHash[hashValue] = tokenID
	return tokenID, opaque, nil
}

// Validate checks the opaque token and returns user, token id, and expiry.
func (store *MemoryRefreshTokenStore) Validate(ctx context.Context, tokenOpaque string) (string, string, int64, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	hashValue := store.hash(tokenOpaque)
	tokenID, ok := store.byHash[hashValue]
	if !ok {
		return "", "", 0, errors.New("not_found")
	}
	rec := store.byID[tokenID]
	if rec == nil {
		return "", "", 0, errors.New("not_found")
	}
	if rec.RevokedAtUnix != 0 {
		return "", "", 0, errors.New("revoked")
	}
	if time.Unix(rec.ExpiresUnix, 0).Before(time.Now().UTC()) {
		return "", "", 0, errors.New("expired")
	}
	return rec.UserID, rec.TokenID, rec.ExpiresUnix, nil
}

// Revoke marks a token as revoked.
func (store *MemoryRefreshTokenStore) Revoke(ctx context.Context, tokenID string) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	rec := store.byID[tokenID]
	if rec == nil {
		return errors.New("not_found")
	}
	if rec.RevokedAtUnix != 0 {
		return nil
	}
	rec.RevokedAtUnix = time.Now().UTC().Unix()
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

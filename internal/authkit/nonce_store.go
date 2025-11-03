package authkit

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

var (
	// ErrNonceNotFound indicates the supplied nonce token was not issued or already consumed.
	ErrNonceNotFound = errors.New("nonce not found")
	// ErrNonceExpired indicates the nonce token expired before consumption.
	ErrNonceExpired = errors.New("nonce expired")
)

// NonceStore issues one-time nonce tokens to bind Google ID token requests.
type NonceStore interface {
	// Issue creates a new nonce token with the configured TTL.
	Issue(ctx context.Context) (string, error)
	// Consume validates and invalidates an issued nonce token.
	Consume(ctx context.Context, token string) error
}

type memoryNonceStore struct {
	mutex     sync.Mutex
	entries   map[string]time.Time
	ttl       time.Duration
	now       func() time.Time
	tokenSize int
}

// NewMemoryNonceStore constructs an in-memory NonceStore with the provided TTL.
func NewMemoryNonceStore(ttl time.Duration) NonceStore {
	return &memoryNonceStore{
		entries:   make(map[string]time.Time),
		ttl:       ttl,
		now:       time.Now,
		tokenSize: 32,
	}
}

func (store *memoryNonceStore) Issue(ctx context.Context) (string, error) {
	token, err := store.randomToken()
	if err != nil {
		return "", err
	}
	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.purgeExpiredLocked()
	store.entries[token] = store.now().Add(store.ttl)
	return token, nil
}

func (store *memoryNonceStore) Consume(ctx context.Context, token string) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	expiry, ok := store.entries[token]
	if !ok {
		store.purgeExpiredLocked()
		return ErrNonceNotFound
	}
	delete(store.entries, token)
	if store.now().After(expiry) {
		store.purgeExpiredLocked()
		return ErrNonceExpired
	}
	store.purgeExpiredLocked()
	return nil
}

func (store *memoryNonceStore) purgeExpiredLocked() {
	if len(store.entries) == 0 {
		return
	}
	now := store.now()
	for token, expiry := range store.entries {
		if now.After(expiry) {
			delete(store.entries, token)
		}
	}
}

func (store *memoryNonceStore) randomToken() (string, error) {
	buffer := make([]byte, store.tokenSize)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

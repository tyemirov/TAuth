package authkit

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"time"
)

const nonceTokenByteLength = 32

var (
	// ErrNonceNotFound indicates the supplied nonce token was not issued or already consumed.
	ErrNonceNotFound = errors.New("nonce not found")
	// ErrNonceExpired indicates the nonce token expired before consumption.
	ErrNonceExpired = errors.New("nonce expired")
)

// NonceStore issues one-time nonce tokens to bind Google ID token requests.
type NonceStore interface {
	// Issue creates a new nonce token with the configured TTL for the provided tenant.
	Issue(ctx context.Context, tenantID string) (string, error)
	// Consume validates and invalidates the opaque token returned by Issue.
	Consume(ctx context.Context, tenantID string, token string) error
}

type memoryNonceStore struct {
	mutex       sync.Mutex
	entries     map[string]map[string]time.Time
	ttlResolver func(string) time.Duration
	now         func() time.Time
	tokenSize   int
	randReader  io.Reader
}

// NewMemoryNonceStore constructs an in-memory NonceStore with a fixed TTL for all tenants.
func NewMemoryNonceStore(ttl time.Duration) NonceStore {
	return NewMemoryNonceStoreWithTTLResolver(func(string) time.Duration {
		return ttl
	})
}

// NewMemoryNonceStoreWithTTLResolver constructs an in-memory NonceStore that derives TTL per tenant.
func NewMemoryNonceStoreWithTTLResolver(ttlResolver func(string) time.Duration) NonceStore {
	if ttlResolver == nil {
		panic("nonce_store: ttlResolver is required")
	}
	return &memoryNonceStore{
		entries:     make(map[string]map[string]time.Time),
		ttlResolver: ttlResolver,
		now:         time.Now,
		tokenSize:   nonceTokenByteLength,
		randReader:  rand.Reader,
	}
}

func (store *memoryNonceStore) Issue(ctx context.Context, tenantID string) (string, error) {
	token, err := store.randomToken()
	if err != nil {
		return "", err
	}
	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.cleanupExpiredLocked(store.now().Unix())
	total := 0
	for _, entries := range store.entries {
		total += len(entries)
	}
	if total >= transientGlobalCapacity || len(store.entries[tenantID]) >= transientTenantCapacity {
		return "", ErrTransientCapacity
	}
	store.ensureTenant(tenantID)
	store.entries[tenantID][token] = store.now().Add(store.ttlResolver(tenantID))
	return token, nil
}

func (store *memoryNonceStore) Consume(ctx context.Context, tenantID string, token string) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	expiry, ok := store.entries[tenantID][token]
	if !ok {
		store.cleanupExpiredLocked(store.now().Unix())
		return ErrNonceNotFound
	}
	delete(store.entries[tenantID], token)
	if !store.now().Before(expiry) {
		store.cleanupExpiredLocked(store.now().Unix())
		return ErrNonceExpired
	}
	store.cleanupExpiredLocked(store.now().Unix())
	return nil
}

func (store *memoryNonceStore) ensureTenant(tenantID string) {
	if tenantID == "" {
		panic("nonce_store: tenant id must be provided")
	}
	if _, exists := store.entries[tenantID]; !exists {
		store.entries[tenantID] = make(map[string]time.Time)
	}
}

func (store *memoryNonceStore) randomToken() (string, error) {
	buffer := make([]byte, store.tokenSize)
	if _, err := io.ReadFull(store.randReader, buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

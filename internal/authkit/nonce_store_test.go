package authkit

import (
	"context"
	"testing"
	"time"
)

func TestMemoryNonceStoreIssueAndConsume(t *testing.T) {
	t.Parallel()
	store := NewMemoryNonceStore(2 * time.Minute).(*memoryNonceStore)
	store.now = func() time.Time { return time.Unix(1000, 0) }

	token, err := store.Issue(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("issue nonce: %v", err)
	}
	if token == "" {
		t.Fatalf("expected token")
	}

	if err := store.Consume(context.Background(), "tenant-a", token); err != nil {
		t.Fatalf("consume nonce: %v", err)
	}

	if err := store.Consume(context.Background(), "tenant-a", token); err != ErrNonceNotFound {
		t.Fatalf("expected ErrNonceNotFound, got %v", err)
	}

	if err := store.Consume(context.Background(), "tenant-b", token); err != ErrNonceNotFound {
		t.Fatalf("expected ErrNonceNotFound, got %v", err)
	}
}

func TestMemoryNonceStoreExpiry(t *testing.T) {
	t.Parallel()
	store := NewMemoryNonceStore(time.Minute).(*memoryNonceStore)
	current := time.Unix(1000, 0)
	store.now = func() time.Time { return current }

	token, err := store.Issue(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("issue nonce: %v", err)
	}

	current = current.Add(2 * time.Minute)

	err = store.Consume(context.Background(), "tenant-a", token)
	if err != ErrNonceExpired {
		t.Fatalf("expected ErrNonceExpired, got %v", err)
	}
}

func TestMemoryNonceStoreSupportsTenantTTL(t *testing.T) {
	t.Parallel()
	current := time.Unix(1000, 0)
	store := NewMemoryNonceStoreWithTTLResolver(func(tenantID string) time.Duration {
		switch tenantID {
		case "tenant-a":
			return time.Minute
		case "tenant-b":
			return 2 * time.Second
		default:
			return time.Hour
		}
	}).(*memoryNonceStore)
	store.now = func() time.Time { return current }

	tokenA, err := store.Issue(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("issue nonce for tenant-a: %v", err)
	}
	tokenB, err := store.Issue(context.Background(), "tenant-b")
	if err != nil {
		t.Fatalf("issue nonce for tenant-b: %v", err)
	}

	current = current.Add(30 * time.Second)
	if err := store.Consume(context.Background(), "tenant-a", tokenA); err != nil {
		t.Fatalf("tenant-a nonce should be valid: %v", err)
	}

	current = current.Add(2 * time.Second)
	if err := store.Consume(context.Background(), "tenant-b", tokenB); err != ErrNonceExpired {
		t.Fatalf("tenant-b nonce should be expired, got %v", err)
	}
}

func TestMemoryNonceStorePanicsWithoutTenant(t *testing.T) {
	t.Parallel()
	store := NewMemoryNonceStore(time.Minute).(*memoryNonceStore)
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic when issuing without tenant id")
		}
	}()
	_, _ = store.Issue(context.Background(), "")
}

func TestNewMemoryNonceStoreWithNilResolverPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic when ttl resolver nil")
		}
	}()
	NewMemoryNonceStoreWithTTLResolver(nil)
}

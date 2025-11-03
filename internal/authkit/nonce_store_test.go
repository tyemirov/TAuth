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

	token, err := store.Issue(context.Background())
	if err != nil {
		t.Fatalf("issue nonce: %v", err)
	}
	if token == "" {
		t.Fatalf("expected token")
	}

	if err := store.Consume(context.Background(), token); err != nil {
		t.Fatalf("consume nonce: %v", err)
	}

	if err := store.Consume(context.Background(), token); err != ErrNonceNotFound {
		t.Fatalf("expected ErrNonceNotFound, got %v", err)
	}
}

func TestMemoryNonceStoreExpiry(t *testing.T) {
	t.Parallel()
	store := NewMemoryNonceStore(time.Minute).(*memoryNonceStore)
	current := time.Unix(1000, 0)
	store.now = func() time.Time { return current }

	token, err := store.Issue(context.Background())
	if err != nil {
		t.Fatalf("issue nonce: %v", err)
	}

	current = current.Add(2 * time.Minute)

	err = store.Consume(context.Background(), token)
	if err != ErrNonceExpired {
		t.Fatalf("expected ErrNonceExpired, got %v", err)
	}
}

package authkit

import (
	"context"
	"testing"
	"time"
)

func TestMemoryRefreshTokenStoreErrors(t *testing.T) {
	store := NewMemoryRefreshTokenStore()
	if _, _, _, err := store.Validate(context.Background(), "tenant-a", "missing"); err == nil {
		t.Fatalf("expected error for missing refresh token")
	}
	if err := store.Revoke(context.Background(), "tenant-a", "missing"); err == nil {
		t.Fatalf("expected error when revoking unknown token")
	}

	tokenID, opaque, err := store.Issue(context.Background(), "tenant-a", "user", time.Now().Add(time.Minute).Unix(), "")
	if err != nil {
		t.Fatalf("issue error: %v", err)
	}
	store.mutex.Lock()
	delete(store.byID, tokenID)
	store.mutex.Unlock()
	if _, _, _, err := store.Validate(context.Background(), "tenant-a", opaque); err == nil {
		t.Fatalf("expected error when backing record missing")
	}

	if _, _, _, err := store.Validate(context.Background(), "tenant-b", opaque); err == nil {
		t.Fatalf("expected tenant mismatch to fail validation")
	}
}

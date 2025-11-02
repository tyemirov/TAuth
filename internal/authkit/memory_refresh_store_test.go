package authkit

import (
	"context"
	"testing"
	"time"
)

func TestMemoryRefreshTokenStoreErrors(t *testing.T) {
	store := NewMemoryRefreshTokenStore()
	if _, _, _, err := store.Validate(context.Background(), "missing"); err == nil {
		t.Fatalf("expected error for missing refresh token")
	}
	if err := store.Revoke(context.Background(), "missing"); err == nil {
		t.Fatalf("expected error when revoking unknown token")
	}

	tokenID, opaque, err := store.Issue(context.Background(), "user", time.Now().Add(time.Minute).Unix(), "")
	if err != nil {
		t.Fatalf("issue error: %v", err)
	}
	store.mutex.Lock()
	delete(store.byID, tokenID)
	store.mutex.Unlock()
	if _, _, _, err := store.Validate(context.Background(), opaque); err == nil {
		t.Fatalf("expected error when backing record missing")
	}
}

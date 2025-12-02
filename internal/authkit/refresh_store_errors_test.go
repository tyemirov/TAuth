package authkit

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRefreshTokenStoresShareSentinelErrors(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		store func(t *testing.T) RefreshTokenStore
	}{
		{
			name: "memory",
			store: func(t *testing.T) RefreshTokenStore {
				t.Helper()
				return NewMemoryRefreshTokenStore()
			},
		},
		{
			name: "sqlite",
			store: func(t *testing.T) RefreshTokenStore {
				t.Helper()
				store, err := NewDatabaseRefreshTokenStore(context.Background(), "sqlite://file::memory:?cache=shared")
				if err != nil {
					t.Fatalf("failed to create sqlite store: %v", err)
				}
				return store
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			store := testCase.store(t)

			_, _, _, err := store.Validate(context.Background(), "tenant-a", "missing")
			if !errors.Is(err, ErrRefreshTokenNotFound) {
				t.Fatalf("expected ErrRefreshTokenNotFound, got %v", err)
			}

			tokenID, opaque, issueErr := store.Issue(context.Background(), "tenant-a", "user", time.Now().Add(time.Minute).Unix(), "")
			if issueErr != nil {
				t.Fatalf("issue failed: %v", issueErr)
			}

			if err := store.Revoke(context.Background(), "tenant-a", tokenID); err != nil {
				t.Fatalf("revoke failed: %v", err)
			}
			if err := store.Revoke(context.Background(), "tenant-a", tokenID); !errors.Is(err, ErrRefreshTokenAlreadyRevoked) {
				t.Fatalf("expected ErrRefreshTokenAlreadyRevoked, got %v", err)
			}

			_, _, _, err = store.Validate(context.Background(), "tenant-a", opaque)
			if !errors.Is(err, ErrRefreshTokenRevoked) {
				t.Fatalf("expected ErrRefreshTokenRevoked, got %v", err)
			}

			expiredID, expiredOpaque, issueExpiredErr := store.Issue(context.Background(), "tenant-a", "user", time.Now().Add(-time.Minute).Unix(), "")
			if issueExpiredErr != nil {
				t.Fatalf("issue expired failed: %v", issueExpiredErr)
			}

			_, _, _, err = store.Validate(context.Background(), "tenant-a", expiredOpaque)
			if !errors.Is(err, ErrRefreshTokenExpired) {
				t.Fatalf("expected ErrRefreshTokenExpired, got %v", err)
			}

			if err := store.Revoke(context.Background(), "tenant-a", "missing-token"); !errors.Is(err, ErrRefreshTokenNotFound) {
				t.Fatalf("expected ErrRefreshTokenNotFound when revoking missing token, got %v", err)
			}

			if _, _, _, tenantMismatchErr := store.Validate(context.Background(), "tenant-b", opaque); tenantMismatchErr == nil {
				t.Fatalf("expected tenant mismatch validation error")
			}

			// cleanup to avoid unused variable compile warning.
			_ = expiredID
		})
	}
}

package authkit

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDatabaseNonceStoreIssueAndConsume(testContext *testing.T) {
	testContext.Parallel()
	databaseURL := sqliteDatabaseURL(testContext)
	store, err := NewDatabaseNonceStore(context.Background(), databaseURL, 2*time.Minute)
	if err != nil {
		testContext.Fatalf("failed to create store: %v", err)
	}

	if store.Driver() != "sqlite" {
		testContext.Fatalf("expected sqlite driver label, got %s", store.Driver())
	}

	token, issueErr := store.Issue(context.Background(), "tenant-a")
	if issueErr != nil {
		testContext.Fatalf("issue error: %v", issueErr)
	}
	if token == "" {
		testContext.Fatalf("expected non-empty token")
	}

	if consumeErr := store.Consume(context.Background(), "tenant-a", token); consumeErr != nil {
		testContext.Fatalf("consume error: %v", consumeErr)
	}

	if consumeErr := store.Consume(context.Background(), "tenant-a", token); !errors.Is(consumeErr, ErrNonceNotFound) {
		testContext.Fatalf("expected ErrNonceNotFound, got %v", consumeErr)
	}
}

func TestDatabaseNonceStoreRejectHashedToken(testContext *testing.T) {
	testContext.Parallel()
	databaseURL := sqliteDatabaseURL(testContext)
	store, err := NewDatabaseNonceStore(context.Background(), databaseURL, 2*time.Minute)
	if err != nil {
		testContext.Fatalf("failed to create store: %v", err)
	}

	token, issueErr := store.Issue(context.Background(), "tenant-a")
	if issueErr != nil {
		testContext.Fatalf("issue error: %v", issueErr)
	}
	hashedToken := hashOpaque(token)
	if consumeErr := store.Consume(context.Background(), "tenant-a", hashedToken); !errors.Is(consumeErr, ErrNonceNotFound) {
		testContext.Fatalf("expected hashed input rejection, got %v", consumeErr)
	}
	if consumeErr := store.Consume(context.Background(), "tenant-a", token); consumeErr != nil {
		testContext.Fatalf("raw issued token rejected: %v", consumeErr)
	}
}

func TestDatabaseNonceStoreExpiry(testContext *testing.T) {
	testContext.Parallel()
	databaseURL := sqliteDatabaseURL(testContext)
	nonceStore, err := NewDatabaseNonceStore(context.Background(), databaseURL, 1*time.Minute)
	if err != nil {
		testContext.Fatalf("failed to create store: %v", err)
	}
	baseTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	nonceStore.now = func() time.Time {
		return baseTime
	}
	token, issueErr := nonceStore.Issue(context.Background(), "tenant-a")
	if issueErr != nil {
		testContext.Fatalf("issue error: %v", issueErr)
	}
	nonceStore.now = func() time.Time {
		return baseTime.Add(2 * time.Minute)
	}
	if consumeErr := nonceStore.Consume(context.Background(), "tenant-a", token); !errors.Is(consumeErr, ErrNonceExpired) {
		testContext.Fatalf("expected ErrNonceExpired, got %v", consumeErr)
	}
}

func TestDatabaseNonceStoreNilResolver(testContext *testing.T) {
	testContext.Parallel()
	databaseURL := sqliteDatabaseURL(testContext)
	if _, err := NewDatabaseNonceStoreWithTTLResolver(context.Background(), databaseURL, nil); err == nil {
		testContext.Fatalf("expected error for nil ttl resolver")
	}
}

func TestNonceStoresOpaqueTokenAndExactExpiry(t *testing.T) {
	for _, backend := range []string{"memory", "database"} {
		t.Run(backend, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			var store NonceStore
			if backend == "memory" {
				memory := NewMemoryNonceStore(time.Minute).(*memoryNonceStore)
				memory.now = func() time.Time { return now }
				store = memory
			} else {
				database, err := NewDatabaseNonceStore(context.Background(), sqliteDatabaseURL(t), time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				database.now = func() time.Time { return now }
				store = database
			}
			token, err := store.Issue(context.Background(), "tenant-a")
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Consume(context.Background(), "tenant-b", token); !errors.Is(err, ErrNonceNotFound) {
				t.Fatalf("wrong tenant result: %v", err)
			}
			if err := store.Consume(context.Background(), "tenant-a", hashOpaque(token)); !errors.Is(err, ErrNonceNotFound) {
				t.Fatalf("hashed token result: %v", err)
			}
			if err := store.Consume(context.Background(), "tenant-a", token); err != nil {
				t.Fatalf("invalid request burned valid nonce: %v", err)
			}
			token, err = store.Issue(context.Background(), "tenant-a")
			if err != nil {
				t.Fatal(err)
			}
			now = now.Add(time.Minute)
			if err := store.Consume(context.Background(), "tenant-a", token); !errors.Is(err, ErrNonceExpired) {
				t.Fatalf("exact expiry result: %v", err)
			}
			if err := store.Consume(context.Background(), "tenant-a", token); !errors.Is(err, ErrNonceNotFound) {
				t.Fatalf("expired replay result: %v", err)
			}
		})
	}
}

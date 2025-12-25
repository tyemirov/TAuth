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

func TestDatabaseNonceStoreConsumeHashedToken(testContext *testing.T) {
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
	if consumeErr := store.Consume(context.Background(), "tenant-a", hashedToken); consumeErr != nil {
		testContext.Fatalf("consume hashed error: %v", consumeErr)
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

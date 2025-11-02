package authkit

import (
	"context"
	"errors"
	"testing"
	"time"

	sqliteDialector "gorm.io/driver/sqlite"
)

func TestResolveDialectorUnsupportedScheme(t *testing.T) {
	_, _, err := resolveDialector("mysql://user:pass@localhost/db")
	if err == nil {
		t.Fatalf("expected error for unsupported scheme")
	}
	if !errors.Is(err, ErrUnsupportedDialect) {
		t.Fatalf("expected ErrUnsupportedDialect, got %v", err)
	}
}

func TestResolveDialectorSQLite(t *testing.T) {
	dialector, driverLabel, err := resolveDialector("sqlite://file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if driverLabel != "sqlite" {
		t.Fatalf("expected driver label sqlite, got %s", driverLabel)
	}
	if _, ok := dialector.(*sqliteDialector.Dialector); !ok {
		t.Fatalf("expected sqlite dialector, got %T", dialector)
	}
}

func TestNewDatabaseRefreshTokenStoreLifecycle(t *testing.T) {
	store, err := NewDatabaseRefreshTokenStore(context.Background(), "sqlite://file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	expiry := time.Now().Add(10 * time.Minute).Unix()
	tokenID, opaqueToken, issueErr := store.Issue(context.Background(), "user-123", expiry, "")
	if issueErr != nil {
		t.Fatalf("issue error: %v", issueErr)
	}
	if tokenID == "" || opaqueToken == "" {
		t.Fatalf("expected non-empty token id and opaque token")
	}

	applicationUserID, storedTokenID, expiresUnix, validateErr := store.Validate(context.Background(), opaqueToken)
	if validateErr != nil {
		t.Fatalf("validate error: %v", validateErr)
	}
	if applicationUserID != "user-123" {
		t.Fatalf("expected user-123, got %s", applicationUserID)
	}
	if storedTokenID != tokenID {
		t.Fatalf("expected token id %s, got %s", tokenID, storedTokenID)
	}
	if expiresUnix != expiry {
		t.Fatalf("expected expiry %d, got %d", expiry, expiresUnix)
	}

	revokeErr := store.Revoke(context.Background(), tokenID)
	if revokeErr != nil {
		t.Fatalf("revoke error: %v", revokeErr)
	}

	_, _, _, postRevokeErr := store.Validate(context.Background(), opaqueToken)
	if postRevokeErr == nil {
		t.Fatalf("expected error after revocation")
	}
}

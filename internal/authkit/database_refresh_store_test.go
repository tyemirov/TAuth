package authkit

import (
	"context"
	"errors"
	"testing"
	"time"

	sqliteDialector "github.com/glebarez/sqlite"
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

func TestResolveDialectorMissingScheme(t *testing.T) {
	_, _, err := resolveDialector("localhost/db")
	if err == nil {
		t.Fatalf("expected error for missing scheme")
	}
	if !errors.Is(err, errUnsupportedNoScheme) {
		t.Fatalf("expected errUnsupportedNoScheme, got %v", err)
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

	if store.Driver() != "sqlite" {
		t.Fatalf("expected sqlite driver label, got %s", store.Driver())
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

	secondRevokeErr := store.Revoke(context.Background(), tokenID)
	if !errors.Is(secondRevokeErr, ErrRefreshTokenAlreadyRevoked) {
		t.Fatalf("expected ErrRefreshTokenAlreadyRevoked, got %v", secondRevokeErr)
	}

	missingRevokeErr := store.Revoke(context.Background(), "missing-token")
	if !errors.Is(missingRevokeErr, ErrRefreshTokenNotFound) {
		t.Fatalf("expected ErrRefreshTokenNotFound, got %v", missingRevokeErr)
	}
}

func TestBuildSQLiteDSNVariants(t *testing.T) {
	_, _, err := resolveDialector("sqlite://localhost/tmp/test.db?mode=ro")
	if err != nil {
		t.Fatalf("unexpected error resolving host-based sqlite DSN: %v", err)
	}

	_, _, err = resolveDialector("sqlite://")
	if !errors.Is(err, errSQLiteEmptyPath) {
		t.Fatalf("expected errSQLiteEmptyPath, got %v", err)
	}
}

func TestNewDatabaseRefreshTokenStoreEmptyURL(t *testing.T) {
	_, err := NewDatabaseRefreshTokenStore(context.Background(), "  ")
	if err == nil {
		t.Fatalf("expected error for empty database URL")
	}
	if !errors.Is(err, errEmptyDatabaseURL) {
		t.Fatalf("expected errEmptyDatabaseURL, got %v", err)
	}
}

func TestDatabaseRefreshTokenStoreValidateNotFound(t *testing.T) {
	store, err := NewDatabaseRefreshTokenStore(context.Background(), "sqlite://file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("unexpected error creating store: %v", err)
	}
	_, _, _, validateErr := store.Validate(context.Background(), "unknown")
	if validateErr == nil {
		t.Fatalf("expected error for unknown refresh token")
	}
	if !errors.Is(validateErr, ErrRefreshTokenNotFound) {
		t.Fatalf("expected ErrRefreshTokenNotFound, got %v", validateErr)
	}
}

func TestNewDatabaseRefreshTokenStoreUnsupportedScheme(t *testing.T) {
	_, err := NewDatabaseRefreshTokenStore(context.Background(), "mysql://user:pass@localhost/db")
	if err == nil {
		t.Fatalf("expected unsupported dialect error")
	}
	if !errors.Is(err, ErrUnsupportedDialect) {
		t.Fatalf("expected ErrUnsupportedDialect, got %v", err)
	}
}

func TestNewDatabaseRefreshTokenStoreOpenError(t *testing.T) {
	_, err := NewDatabaseRefreshTokenStore(context.Background(), "postgres://invalid:invalid@localhost:1/testdb?sslmode=disable")
	if err == nil {
		t.Fatalf("expected connection error for postgres dialector")
	}
}

func TestDatabaseRefreshTokenStoreIssueRandomFailure(t *testing.T) {
	store, err := NewDatabaseRefreshTokenStore(context.Background(), "sqlite://file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("unexpected error creating store: %v", err)
	}
	original := refreshTokenRandomSource
	refreshTokenRandomSource = failingRandomSource{}
	defer func() { refreshTokenRandomSource = original }()

	_, _, issueErr := store.Issue(context.Background(), "user", time.Now().Add(time.Minute).Unix(), "")
	if issueErr == nil {
		t.Fatalf("expected random source failure to bubble up")
	}
}

func TestDatabaseRefreshTokenStoreValidateEmptyToken(t *testing.T) {
	store, err := NewDatabaseRefreshTokenStore(context.Background(), "sqlite://file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("unexpected error creating store: %v", err)
	}
	_, _, _, validateErr := store.Validate(context.Background(), "   ")
	if !errors.Is(validateErr, ErrRefreshTokenEmptyOpaque) {
		t.Fatalf("expected ErrRefreshTokenEmptyOpaque, got %v", validateErr)
	}
}

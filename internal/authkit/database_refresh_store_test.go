package authkit

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	sqliteDialector "github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	refreshTokenTenantIDColumn = "tenant_id"
	refreshTokenIssuedAtColumn = "issued_at_unix"
)

func TestResolveDialectorUnsupportedScheme(t *testing.T) {
	_, _, err := resolveDialector("mysql://user:pass@localhost/db", refreshStoreErrorPrefix)
	if err == nil {
		t.Fatalf("expected error for unsupported scheme")
	}
	if !errors.Is(err, ErrUnsupportedDialect) {
		t.Fatalf("expected ErrUnsupportedDialect, got %v", err)
	}
}

func TestResolveDialectorMissingScheme(t *testing.T) {
	_, _, err := resolveDialector("localhost/db", refreshStoreErrorPrefix)
	if err == nil {
		t.Fatalf("expected error for missing scheme")
	}
	if !errors.Is(err, errUnsupportedNoScheme) {
		t.Fatalf("expected errUnsupportedNoScheme, got %v", err)
	}
}

func TestResolveDialectorSQLite(t *testing.T) {
	dialector, driverLabel, err := resolveDialector("sqlite://file::memory:?cache=shared", refreshStoreErrorPrefix)
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
	tokenID, opaqueToken, issueErr := store.Issue(context.Background(), "tenant-a", "user-123", expiry, "")
	if issueErr != nil {
		t.Fatalf("issue error: %v", issueErr)
	}
	if tokenID == "" || opaqueToken == "" {
		t.Fatalf("expected non-empty token id and opaque token")
	}

	applicationUserID, storedTokenID, expiresUnix, validateErr := store.Validate(context.Background(), "tenant-a", opaqueToken)
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

	if _, _, _, mismatchedValidateErr := store.Validate(context.Background(), "tenant-b", opaqueToken); mismatchedValidateErr == nil {
		t.Fatalf("expected tenant mismatch validation error")
	}

	revokeErr := store.Revoke(context.Background(), "tenant-a", tokenID)
	if revokeErr != nil {
		t.Fatalf("revoke error: %v", revokeErr)
	}

	_, _, _, postRevokeErr := store.Validate(context.Background(), "tenant-a", opaqueToken)
	if postRevokeErr == nil {
		t.Fatalf("expected error after revocation")
	}

	secondRevokeErr := store.Revoke(context.Background(), "tenant-a", tokenID)
	if !errors.Is(secondRevokeErr, ErrRefreshTokenAlreadyRevoked) {
		t.Fatalf("expected ErrRefreshTokenAlreadyRevoked, got %v", secondRevokeErr)
	}

	if wrongTenantRevokeErr := store.Revoke(context.Background(), "tenant-b", tokenID); !errors.Is(wrongTenantRevokeErr, ErrRefreshTokenNotFound) {
		t.Fatalf("expected tenant mismatch revoke to report not found, got %v", wrongTenantRevokeErr)
	}

	missingRevokeErr := store.Revoke(context.Background(), "tenant-a", "missing-token")
	if !errors.Is(missingRevokeErr, ErrRefreshTokenNotFound) {
		t.Fatalf("expected ErrRefreshTokenNotFound, got %v", missingRevokeErr)
	}
}

func TestRefreshTokenStoreResetsSQLiteSchemaOnLegacyTable(testContext *testing.T) {
	databasePath := filepath.Join(testContext.TempDir(), "tauth.db")
	databaseURL := fmt.Sprintf("sqlite:///%s", filepath.ToSlash(databasePath))
	legacyDatabaseHandle, openErr := gorm.Open(sqliteDialector.Open(filepath.ToSlash(databasePath)), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if openErr != nil {
		testContext.Fatalf("failed to open legacy database: %v", openErr)
	}
	createStatement := fmt.Sprintf(
		"CREATE TABLE %s (token_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, expires_unix BIGINT NOT NULL, revoked_at_unix BIGINT NOT NULL DEFAULT 0)",
		refreshTokenTableName,
	)
	if createErr := legacyDatabaseHandle.Exec(createStatement).Error; createErr != nil {
		testContext.Fatalf("failed to create legacy refresh token table: %v", createErr)
	}
	insertStatement := fmt.Sprintf(
		"INSERT INTO %s (token_id, user_id, token_hash, expires_unix, revoked_at_unix) VALUES (?, ?, ?, ?, ?)",
		refreshTokenTableName,
	)
	if insertErr := legacyDatabaseHandle.Exec(insertStatement, "legacy-token", "legacy-user", "legacy-hash", int64(1700000000), int64(0)).Error; insertErr != nil {
		testContext.Fatalf("failed to insert legacy refresh token: %v", insertErr)
	}
	rawDatabaseHandle, rawErr := legacyDatabaseHandle.DB()
	if rawErr != nil {
		testContext.Fatalf("failed to access legacy sql handle: %v", rawErr)
	}
	if closeErr := rawDatabaseHandle.Close(); closeErr != nil {
		testContext.Fatalf("failed to close legacy database: %v", closeErr)
	}

	store, storeErr := NewDatabaseRefreshTokenStore(context.Background(), databaseURL)
	if storeErr != nil {
		testContext.Fatalf("failed to open refresh token store: %v", storeErr)
	}
	if !store.db.Migrator().HasColumn(&refreshTokenRecord{}, refreshTokenTenantIDColumn) {
		testContext.Fatalf("expected tenant_id column after reset migration")
	}
	if !store.db.Migrator().HasColumn(&refreshTokenRecord{}, refreshTokenIssuedAtColumn) {
		testContext.Fatalf("expected issued_at_unix column after reset migration")
	}
	var tokenCount int64
	if countErr := store.db.Model(&refreshTokenRecord{}).Count(&tokenCount).Error; countErr != nil {
		testContext.Fatalf("failed to count refresh tokens after reset: %v", countErr)
	}
	if tokenCount != 0 {
		testContext.Fatalf("expected legacy refresh tokens to be dropped, got %d", tokenCount)
	}

	expiryUnix := time.Now().Add(10 * time.Minute).Unix()
	_, _, issueErr := store.Issue(context.Background(), "tenant-a", "user-123", expiryUnix, "")
	if issueErr != nil {
		testContext.Fatalf("failed to issue refresh token after reset: %v", issueErr)
	}
	var issuedCount int64
	if countErr := store.db.Model(&refreshTokenRecord{}).Count(&issuedCount).Error; countErr != nil {
		testContext.Fatalf("failed to count issued refresh tokens: %v", countErr)
	}
	if issuedCount == 0 {
		testContext.Fatalf("expected issued refresh token to persist")
	}
	rawStoreHandle, rawStoreErr := store.db.DB()
	if rawStoreErr != nil {
		testContext.Fatalf("failed to access store sql handle: %v", rawStoreErr)
	}
	if closeErr := rawStoreHandle.Close(); closeErr != nil {
		testContext.Fatalf("failed to close store database: %v", closeErr)
	}

	secondStore, secondStoreErr := NewDatabaseRefreshTokenStore(context.Background(), databaseURL)
	if secondStoreErr != nil {
		testContext.Fatalf("failed to reopen refresh token store: %v", secondStoreErr)
	}
	var secondCount int64
	if countErr := secondStore.db.Model(&refreshTokenRecord{}).Count(&secondCount).Error; countErr != nil {
		testContext.Fatalf("failed to count refresh tokens after reopen: %v", countErr)
	}
	if secondCount != issuedCount {
		testContext.Fatalf("expected refresh token count to persist, got %d", secondCount)
	}
}

func TestBuildSQLiteDSNVariants(t *testing.T) {
	_, _, err := resolveDialector("sqlite://localhost/tmp/test.db?mode=ro", refreshStoreErrorPrefix)
	if err != nil {
		t.Fatalf("unexpected error resolving host-based sqlite DSN: %v", err)
	}

	_, _, err = resolveDialector("sqlite://", refreshStoreErrorPrefix)
	if !errors.Is(err, errSQLiteEmptyPath) {
		t.Fatalf("expected errSQLiteEmptyPath, got %v", err)
	}
}

func TestBuildSQLiteDSNRejectsFileHost(t *testing.T) {
	parsed, err := url.Parse("sqlite://file:/data/tauth.db")
	if err != nil {
		t.Fatalf("failed to parse url: %v", err)
	}
	_, buildErr := buildSQLiteDSN(parsed)
	if buildErr == nil {
		t.Fatalf("expected error for file host")
	}
	if !errors.Is(buildErr, errSQLiteUnsupportedHost) {
		t.Fatalf("expected errSQLiteUnsupportedHost, got %v", buildErr)
	}

	parsed, err = url.Parse("sqlite:///data/alt.db")
	if err != nil {
		t.Fatalf("failed to parse triple slash url: %v", err)
	}
	dsn, buildErr := buildSQLiteDSN(parsed)
	if buildErr != nil {
		t.Fatalf("unexpected error for triple slash absolute path: %v", buildErr)
	}
	if dsn != "/data/alt.db" {
		t.Fatalf("expected /data/alt.db, got %s", dsn)
	}
}

func TestBuildSQLiteDSNCoversOpaqueAndHostPathVariants(t *testing.T) {
	opaqueParsed, err := url.Parse("sqlite:file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("failed to parse opaque sqlite url: %v", err)
	}
	opaqueDSN, opaqueErr := buildSQLiteDSN(opaqueParsed)
	if opaqueErr != nil {
		t.Fatalf("unexpected error building opaque dsn: %v", opaqueErr)
	}
	if opaqueDSN != "file::memory:?cache=shared" {
		t.Fatalf("unexpected opaque dsn: %s", opaqueDSN)
	}

	hostParsed := &url.URL{
		Scheme: "sqlite",
		Host:   "localhost",
		Path:   "tmp/test.db",
	}
	hostDSN, hostErr := buildSQLiteDSN(hostParsed)
	if hostErr != nil {
		t.Fatalf("unexpected error building host dsn: %v", hostErr)
	}
	if hostDSN != "localhost/tmp/test.db" {
		t.Fatalf("unexpected host dsn: %s", hostDSN)
	}

	if _, nilErr := buildSQLiteDSN(nil); nilErr == nil {
		t.Fatalf("expected error for nil url")
	}
}

func TestResolveDialectorRejectsFileHost(t *testing.T) {
	_, _, err := resolveDialector("sqlite://file:/data/tauth.db", refreshStoreErrorPrefix)
	if err == nil {
		t.Fatalf("expected error for file host DSN")
	}
	if !errors.Is(err, errSQLiteUnsupportedHost) {
		t.Fatalf("expected errSQLiteUnsupportedHost, got %v", err)
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
	_, _, _, validateErr := store.Validate(context.Background(), "tenant-a", "unknown")
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

	_, _, issueErr := store.Issue(context.Background(), "tenant-a", "user", time.Now().Add(time.Minute).Unix(), "")
	if issueErr == nil {
		t.Fatalf("expected random source failure to bubble up")
	}
}

func TestDatabaseRefreshTokenStoreValidateEmptyToken(t *testing.T) {
	store, err := NewDatabaseRefreshTokenStore(context.Background(), "sqlite://file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("unexpected error creating store: %v", err)
	}
	_, _, _, validateErr := store.Validate(context.Background(), "tenant-a", "   ")
	if !errors.Is(validateErr, ErrRefreshTokenEmptyOpaque) {
		t.Fatalf("expected ErrRefreshTokenEmptyOpaque, got %v", validateErr)
	}
}

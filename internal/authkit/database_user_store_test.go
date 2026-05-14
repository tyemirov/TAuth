package authkit

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	sqliteDialector "github.com/glebarez/sqlite"
	"github.com/tyemirov/tauth/internal/web"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestDatabaseUserStoreLifecycle(testContext *testing.T) {
	testContext.Parallel()
	databaseURL := sqliteDatabaseURL(testContext)
	store, err := NewDatabaseUserStore(context.Background(), databaseURL)
	if err != nil {
		testContext.Fatalf("failed to create store: %v", err)
	}

	if store.Driver() != "sqlite" {
		testContext.Fatalf("expected sqlite driver label, got %s", store.Driver())
	}

	applicationUserID, roles, upsertErr := store.UpsertGoogleUser(context.Background(), "tenant-a", "sub-123", "user@example.com", "Demo User", "https://example.com/avatar.png")
	if upsertErr != nil {
		testContext.Fatalf("upsert error: %v", upsertErr)
	}
	if applicationUserID == "" {
		testContext.Fatalf("expected application user id")
	}
	if len(roles) != 1 || roles[0] != defaultUserRole {
		testContext.Fatalf("expected default role assignment")
	}

	email, display, avatarURL, storedRoles, fetchErr := store.GetUserProfile(context.Background(), "tenant-a", applicationUserID)
	if fetchErr != nil {
		testContext.Fatalf("fetch error: %v", fetchErr)
	}
	if email != "user@example.com" || display != "Demo User" || avatarURL != "https://example.com/avatar.png" {
		testContext.Fatalf("unexpected profile data")
	}
	if len(storedRoles) != 1 || storedRoles[0] != defaultUserRole {
		testContext.Fatalf("unexpected stored roles")
	}

	_, _, updateErr := store.UpsertGoogleUser(context.Background(), "tenant-a", "sub-123", "user2@example.com", "Updated User", "https://example.com/next.png")
	if updateErr != nil {
		testContext.Fatalf("update error: %v", updateErr)
	}
	email, display, avatarURL, storedRoles, fetchErr = store.GetUserProfile(context.Background(), "tenant-a", applicationUserID)
	if fetchErr != nil {
		testContext.Fatalf("fetch error after update: %v", fetchErr)
	}
	if email != "user2@example.com" || display != "Updated User" || avatarURL != "https://example.com/next.png" {
		testContext.Fatalf("unexpected profile data after update")
	}
	if len(storedRoles) != 1 || storedRoles[0] != defaultUserRole {
		testContext.Fatalf("unexpected stored roles after update")
	}

	if _, _, _, _, missingErr := store.GetUserProfile(context.Background(), "tenant-a", "missing-user"); !errors.Is(missingErr, web.ErrUserNotFound) {
		testContext.Fatalf("expected ErrUserNotFound for missing user, got %v", missingErr)
	}
}

func TestDatabaseUserStorePasswordCredentialLifecycle(testContext *testing.T) {
	testContext.Parallel()
	databaseURL := sqliteDatabaseURL(testContext)
	store, err := NewDatabaseUserStore(context.Background(), databaseURL)
	if err != nil {
		testContext.Fatalf("failed to create store: %v", err)
	}

	passwordHash, hashErr := HashPassword("correct horse battery staple")
	if hashErr != nil {
		testContext.Fatalf("failed to hash password: %v", hashErr)
	}
	profileID, roles, profileErr := store.UpsertPasswordUser(context.Background(), "tenant-a", "User@Example.com", "Password User", "https://example.com/password.png")
	if profileErr != nil {
		testContext.Fatalf("failed to upsert password profile: %v", profileErr)
	}
	if profileID != "email:user@example.com" {
		testContext.Fatalf("unexpected password user id: %s", profileID)
	}
	if len(roles) != 1 || roles[0] != defaultUserRole {
		testContext.Fatalf("unexpected roles: %#v", roles)
	}
	credentialErr := store.UpsertPasswordCredential(context.Background(), "tenant-a", PasswordCredentialSeed{
		UserEmail:    "User@Example.com",
		DisplayName:  "Password User",
		AvatarURL:    "https://example.com/password.png",
		PasswordHash: passwordHash,
	})
	if credentialErr != nil {
		testContext.Fatalf("failed to upsert password credential: %v", credentialErr)
	}

	profile, authErr := store.AuthenticatePassword(context.Background(), "tenant-a", "user@example.com", "correct horse battery staple")
	if authErr != nil {
		testContext.Fatalf("expected password auth to pass: %v", authErr)
	}
	if profile.UserEmail != "user@example.com" || profile.DisplayName != "Password User" || profile.AvatarURL != "https://example.com/password.png" {
		testContext.Fatalf("unexpected password profile: %#v", profile)
	}
	email, display, avatarURL, storedRoles, fetchErr := store.GetUserProfile(context.Background(), "tenant-a", profileID)
	if fetchErr != nil {
		testContext.Fatalf("failed to fetch password profile: %v", fetchErr)
	}
	if email != "user@example.com" || display != "Password User" || avatarURL != "https://example.com/password.png" {
		testContext.Fatalf("unexpected stored password profile")
	}
	if len(storedRoles) != 1 || storedRoles[0] != defaultUserRole {
		testContext.Fatalf("unexpected stored roles")
	}
	_, wrongPasswordErr := store.AuthenticatePassword(context.Background(), "tenant-a", "user@example.com", "wrong-password")
	if !errors.Is(wrongPasswordErr, ErrPasswordCredentialInvalid) {
		testContext.Fatalf("expected invalid credential error, got %v", wrongPasswordErr)
	}
}

func TestDatabaseUserStoreReconcilesPasswordCredentials(testContext *testing.T) {
	testContext.Parallel()
	databaseURL := sqliteDatabaseURL(testContext)
	store, err := NewDatabaseUserStore(context.Background(), databaseURL)
	if err != nil {
		testContext.Fatalf("failed to create store: %v", err)
	}
	passwordHash, hashErr := HashPassword("correct horse battery staple")
	if hashErr != nil {
		testContext.Fatalf("failed to hash password: %v", hashErr)
	}
	for _, userEmail := range []string{"kept@example.com", "removed@example.com"} {
		credentialErr := store.UpsertPasswordCredential(context.Background(), "tenant-a", PasswordCredentialSeed{
			UserEmail:    userEmail,
			DisplayName:  userEmail,
			PasswordHash: passwordHash,
		})
		if credentialErr != nil {
			testContext.Fatalf("failed to upsert password credential: %v", credentialErr)
		}
	}
	if reconcileErr := store.ReconcilePasswordCredentials(context.Background(), "tenant-a", []string{"kept@example.com"}); reconcileErr != nil {
		testContext.Fatalf("failed to reconcile password credentials: %v", reconcileErr)
	}
	if _, authErr := store.AuthenticatePassword(context.Background(), "tenant-a", "kept@example.com", "correct horse battery staple"); authErr != nil {
		testContext.Fatalf("expected kept credential to authenticate: %v", authErr)
	}
	if _, removedErr := store.AuthenticatePassword(context.Background(), "tenant-a", "removed@example.com", "correct horse battery staple"); !errors.Is(removedErr, ErrPasswordCredentialInvalid) {
		testContext.Fatalf("expected removed credential to be rejected, got %v", removedErr)
	}
	if reconcileErr := store.ReconcilePasswordCredentials(context.Background(), "tenant-a", nil); reconcileErr != nil {
		testContext.Fatalf("failed to reconcile empty password credentials: %v", reconcileErr)
	}
	if _, removedErr := store.AuthenticatePassword(context.Background(), "tenant-a", "kept@example.com", "correct horse battery staple"); !errors.Is(removedErr, ErrPasswordCredentialInvalid) {
		testContext.Fatalf("expected empty config to remove kept credential, got %v", removedErr)
	}
}

func TestUserStorePreservesLegacySchemaWhenMigrationRecordMissing(testContext *testing.T) {
	databasePath := filepath.Join(testContext.TempDir(), "tauth.db")
	databaseURL := fmt.Sprintf("sqlite:///%s", filepath.ToSlash(databasePath))
	legacyDatabaseHandle, openErr := gorm.Open(sqliteDialector.Open(filepath.ToSlash(databasePath)), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if openErr != nil {
		testContext.Fatalf("failed to open legacy database: %v", openErr)
	}
	createStatement := fmt.Sprintf(
		"CREATE TABLE %s (tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, user_email TEXT NOT NULL, user_display_name TEXT NOT NULL, user_avatar_url TEXT NOT NULL, user_roles TEXT NOT NULL, created_at_unix BIGINT NOT NULL, last_updated_unix BIGINT NOT NULL, PRIMARY KEY (tenant_id, user_id))",
		userProfileTableName,
	)
	if createErr := legacyDatabaseHandle.Exec(createStatement).Error; createErr != nil {
		testContext.Fatalf("failed to create legacy user table: %v", createErr)
	}
	rolePayload := fmt.Sprintf("[\"%s\"]", defaultUserRole)
	legacyTenantID := "tenant-legacy"
	legacyUserID := "google:legacy-user"
	legacyUserEmail := "legacy@example.com"
	legacyDisplayName := "Legacy User"
	legacyAvatarURL := "https://example.com/avatar.png"
	nowUnix := time.Now().UTC().Unix()
	insertStatement := fmt.Sprintf(
		"INSERT INTO %s (tenant_id, user_id, user_email, user_display_name, user_avatar_url, user_roles, created_at_unix, last_updated_unix) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		userProfileTableName,
	)
	if insertErr := legacyDatabaseHandle.Exec(insertStatement, legacyTenantID, legacyUserID, legacyUserEmail, legacyDisplayName, legacyAvatarURL, rolePayload, nowUnix, nowUnix).Error; insertErr != nil {
		testContext.Fatalf("failed to insert legacy user: %v", insertErr)
	}
	rawDatabaseHandle, rawErr := legacyDatabaseHandle.DB()
	if rawErr != nil {
		testContext.Fatalf("failed to access legacy sql handle: %v", rawErr)
	}
	if closeErr := rawDatabaseHandle.Close(); closeErr != nil {
		testContext.Fatalf("failed to close legacy database: %v", closeErr)
	}

	store, storeErr := NewDatabaseUserStore(context.Background(), databaseURL)
	if storeErr != nil {
		testContext.Fatalf("failed to open user store: %v", storeErr)
	}
	var userCount int64
	if countErr := store.db.Model(&userProfileRecord{}).Count(&userCount).Error; countErr != nil {
		testContext.Fatalf("failed to count user profiles: %v", countErr)
	}
	if userCount != 1 {
		testContext.Fatalf("expected legacy user profiles to remain, got %d", userCount)
	}
	email, display, avatarURL, roles, fetchErr := store.GetUserProfile(context.Background(), legacyTenantID, legacyUserID)
	if fetchErr != nil {
		testContext.Fatalf("failed to fetch legacy profile: %v", fetchErr)
	}
	if email != legacyUserEmail || display != legacyDisplayName || avatarURL != legacyAvatarURL {
		testContext.Fatalf("unexpected legacy profile data")
	}
	if len(roles) != 1 || roles[0] != defaultUserRole {
		testContext.Fatalf("unexpected legacy roles")
	}
	var migrationRecord schemaMigrationRecord
	migrationErr := store.db.WithContext(context.Background()).
		Where(schemaMigrationLookupByName, userStoreErrorPrefix).
		Take(&migrationRecord).Error
	if migrationErr != nil {
		testContext.Fatalf("failed to load migration record: %v", migrationErr)
	}
	if migrationRecord.Version != userStoreSchemaVersion {
		testContext.Fatalf("expected user store schema version %d, got %d", userStoreSchemaVersion, migrationRecord.Version)
	}
	rawStoreHandle, rawStoreErr := store.db.DB()
	if rawStoreErr != nil {
		testContext.Fatalf("failed to access store sql handle: %v", rawStoreErr)
	}
	if closeErr := rawStoreHandle.Close(); closeErr != nil {
		testContext.Fatalf("failed to close store database: %v", closeErr)
	}
}

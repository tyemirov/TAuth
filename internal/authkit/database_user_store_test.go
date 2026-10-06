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

	account, upsertErr := store.UpsertProviderAccount(context.Background(), "tenant-a", AccountProviderIdentity{Provider: "google", Subject: "sub-123", UserEmail: "user@example.com", DisplayName: "Demo User", AvatarURL: "https://example.com/avatar.png"})
	if upsertErr != nil {
		testContext.Fatal(upsertErr)
	}
	applicationUserID, roles, upsertErr := store.UpsertAccountUser(context.Background(), "tenant-a", account.AccountID, account.UserEmail, account.DisplayName, account.AvatarURL)
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

	account, updateErr := store.UpsertProviderAccount(context.Background(), "tenant-a", AccountProviderIdentity{Provider: "google", Subject: "sub-123", UserEmail: "user2@example.com", DisplayName: "Updated User", AvatarURL: "https://example.com/next.png"})
	if updateErr == nil {
		_, _, updateErr = store.UpsertAccountUser(context.Background(), "tenant-a", account.AccountID, account.UserEmail, account.DisplayName, account.AvatarURL)
	}
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

	credentialErr := store.UpsertPasswordCredential(context.Background(), "tenant-a", PasswordCredentialSeed{
		UserEmail:    "User@Example.com",
		DisplayName:  "Password User",
		AvatarURL:    "https://example.com/password.png",
		PasswordHash: passwordHash,
	})
	if credentialErr != nil {
		testContext.Fatalf("failed to upsert password credential: %v", credentialErr)
	}

	account, profileErr := store.EnsurePasswordAccount(context.Background(), "tenant-a", "user@example.com")
	if profileErr != nil {
		testContext.Fatal(profileErr)
	}
	profileID, roles, profileErr := store.UpsertAccountUser(context.Background(), "tenant-a", account.AccountID, account.UserEmail, account.DisplayName, account.AvatarURL)
	if profileErr != nil {
		testContext.Fatalf("failed to upsert password profile: %v", profileErr)
	}
	if validateOpaqueAccountID(profileID) != nil {
		testContext.Fatalf("unexpected password user id: %s", profileID)
	}
	if len(roles) != 1 || roles[0] != defaultUserRole {
		testContext.Fatalf("unexpected roles: %#v", roles)
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

func TestDatabaseUserStoreAccountManagementLifecycle(testContext *testing.T) {
	testContext.Parallel()
	ctx := context.Background()
	databaseURL := sqliteDatabaseURL(testContext)
	store, err := NewDatabaseUserStore(ctx, databaseURL)
	if err != nil {
		testContext.Fatalf("failed to create store: %v", err)
	}

	expiresUnix := time.Now().UTC().Add(time.Hour).Unix()
	challenge, signupErr := store.CreatePasswordSignup(ctx, "tenant-a", AccountPasswordRequest{
		UserEmail:   "Account@Example.com",
		DisplayName: "Account User",
		AvatarURL:   "https://example.com/account.png",
		Password:    "correct horse battery staple",
	}, expiresUnix)
	if signupErr != nil {
		testContext.Fatalf("failed to start signup: %v", signupErr)
	}
	expectedAccountID := assertOpaqueAccountID(testContext, challenge.AccountID)
	if challenge.Token == "" || challenge.ExpiresUnix != expiresUnix {
		testContext.Fatalf("unexpected signup challenge: %#v", challenge)
	}

	if _, authErr := store.AuthenticatePassword(ctx, "tenant-a", "account@example.com", "correct horse battery staple"); !errors.Is(authErr, ErrAccountNotActive) {
		testContext.Fatalf("expected unverified account to reject login, got %v", authErr)
	}

	profile, verifyErr := store.VerifyEmailChallenge(ctx, "tenant-a", challenge.Token)
	if verifyErr != nil {
		testContext.Fatalf("failed to verify email: %v", verifyErr)
	}
	if profile.AccountID != expectedAccountID || profile.UserEmail != "account@example.com" || profile.State != accountStateActive {
		testContext.Fatalf("unexpected verified profile: %#v", profile)
	}
	if _, reuseErr := store.VerifyEmailChallenge(ctx, "tenant-a", challenge.Token); !errors.Is(reuseErr, ErrAccountChallengeInvalid) {
		testContext.Fatalf("expected consumed challenge to be rejected, got %v", reuseErr)
	}

	passwordProfile, passwordErr := store.AuthenticatePassword(ctx, "tenant-a", "account@example.com", "correct horse battery staple")
	if passwordErr != nil {
		testContext.Fatalf("expected verified password login: %v", passwordErr)
	}
	if passwordProfile.AccountID != expectedAccountID {
		testContext.Fatalf("unexpected password account id: %#v", passwordProfile)
	}

	resetChallenge, resetStartErr := store.StartPasswordReset(ctx, "tenant-a", "account@example.com", expiresUnix)
	if resetStartErr != nil {
		testContext.Fatalf("failed to start reset: %v", resetStartErr)
	}
	resetProfile, resetCompleteErr := store.CompletePasswordReset(ctx, "tenant-a", resetChallenge.Token, "new correct horse battery staple")
	if resetCompleteErr != nil {
		testContext.Fatalf("failed to complete reset: %v", resetCompleteErr)
	}
	if resetProfile.AccountID != expectedAccountID {
		testContext.Fatalf("unexpected reset profile: %#v", resetProfile)
	}
	if _, oldPasswordErr := store.AuthenticatePassword(ctx, "tenant-a", "account@example.com", "correct horse battery staple"); !errors.Is(oldPasswordErr, ErrPasswordCredentialInvalid) {
		testContext.Fatalf("expected old password to be rejected, got %v", oldPasswordErr)
	}

	changeProfile, changeErr := store.ChangePassword(ctx, "tenant-a", expectedAccountID, "new correct horse battery staple", "changed correct horse battery staple")
	if changeErr != nil {
		testContext.Fatalf("failed to change password: %v", changeErr)
	}
	if changeProfile.AccountID != expectedAccountID {
		testContext.Fatalf("unexpected change profile: %#v", changeProfile)
	}
	if _, newPasswordErr := store.AuthenticatePassword(ctx, "tenant-a", "account@example.com", "changed correct horse battery staple"); newPasswordErr != nil {
		testContext.Fatalf("expected changed password to authenticate: %v", newPasswordErr)
	}

	googleProfile, linkErr := store.LinkGoogleIdentity(ctx, "tenant-a", expectedAccountID, GoogleAccountIdentity{
		Subject:     "google-subject",
		UserEmail:   "google@example.com",
		DisplayName: "Google User",
		AvatarURL:   "https://example.com/google.png",
	})
	if linkErr != nil {
		testContext.Fatalf("failed to link google identity: %v", linkErr)
	}
	if googleProfile.AccountID != expectedAccountID {
		testContext.Fatalf("unexpected linked google profile: %#v", googleProfile)
	}
	googleAuthProfile, found, googleAuthErr := store.AuthenticateGoogleAccount(ctx, "tenant-a", GoogleAccountIdentity{
		Subject:   "google-subject",
		UserEmail: "google@example.com",
	})
	if googleAuthErr != nil || !found {
		testContext.Fatalf("expected linked google auth, found=%t err=%v", found, googleAuthErr)
	}
	if googleAuthProfile.AccountID != expectedAccountID {
		testContext.Fatalf("unexpected google auth profile: %#v", googleAuthProfile)
	}

	unlinkedProfile, unlinkErr := store.UnlinkIdentity(ctx, "tenant-a", expectedAccountID, accountProviderPassword, "account@example.com")
	if unlinkErr != nil {
		testContext.Fatalf("failed to unlink password identity: %v", unlinkErr)
	}
	if unlinkedProfile.AccountID != expectedAccountID {
		testContext.Fatalf("unexpected unlinked profile: %#v", unlinkedProfile)
	}
	if _, unlinkedPasswordErr := store.AuthenticatePassword(ctx, "tenant-a", "account@example.com", "changed correct horse battery staple"); !errors.Is(unlinkedPasswordErr, ErrPasswordCredentialInvalid) {
		testContext.Fatalf("expected unlinked password to be rejected, got %v", unlinkedPasswordErr)
	}

	if _, err := store.BeginAccountDisable(ctx, "tenant-a", expectedAccountID); err != nil {
		testContext.Fatal(err)
	}
	disabledProfile, disableErr := store.CompleteAccountDisable(ctx, "tenant-a", expectedAccountID)
	if disableErr != nil {
		testContext.Fatalf("failed to disable account: %v", disableErr)
	}
	if disabledProfile.State != accountStateDisabled {
		testContext.Fatalf("expected disabled state, got %#v", disabledProfile)
	}
	if _, _, disabledAuthErr := store.AuthenticateGoogleAccount(ctx, "tenant-a", GoogleAccountIdentity{Subject: "google-subject", UserEmail: "google@example.com"}); !errors.Is(disabledAuthErr, ErrAccountDisabled) {
		testContext.Fatalf("expected disabled google auth error, got %v", disabledAuthErr)
	}
	reactivatedProfile, reactivateErr := store.ReactivateAccount(ctx, "tenant-a", expectedAccountID)
	if reactivateErr != nil {
		testContext.Fatalf("failed to reactivate account: %v", reactivateErr)
	}
	if reactivatedProfile.State != accountStateActive {
		testContext.Fatalf("expected active state after reactivation, got %#v", reactivatedProfile)
	}
}

func TestDatabaseUserStoreEnsuresSeededPasswordAccount(testContext *testing.T) {
	testContext.Parallel()
	ctx := context.Background()
	databaseURL := sqliteDatabaseURL(testContext)
	store, err := NewDatabaseUserStore(ctx, databaseURL)
	if err != nil {
		testContext.Fatalf("failed to create store: %v", err)
	}
	passwordHash, hashErr := HashPassword("correct horse battery staple")
	if hashErr != nil {
		testContext.Fatalf("failed to hash password: %v", hashErr)
	}
	if credentialErr := store.UpsertPasswordCredential(ctx, "tenant-a", PasswordCredentialSeed{
		UserEmail:    "Seeded@Example.com",
		DisplayName:  "Seeded User",
		AvatarURL:    "https://example.com/seeded.png",
		PasswordHash: passwordHash,
	}); credentialErr != nil {
		testContext.Fatalf("failed to seed credential: %v", credentialErr)
	}

	legacyProfile, legacyAuthErr := store.AuthenticatePassword(ctx, "tenant-a", "seeded@example.com", "correct horse battery staple")
	if legacyAuthErr != nil {
		testContext.Fatalf("expected seeded credential to authenticate: %v", legacyAuthErr)
	}
	assertOpaqueAccountID(testContext, legacyProfile.AccountID)

	accountProfile, ensureErr := store.EnsurePasswordAccount(ctx, "tenant-a", "seeded@example.com")
	if ensureErr != nil {
		testContext.Fatalf("failed to ensure account: %v", ensureErr)
	}
	expectedAccountID := assertOpaqueAccountID(testContext, accountProfile.AccountID)
	if accountProfile.AccountID != expectedAccountID || accountProfile.AccountID != legacyProfile.AccountID || accountProfile.State != accountStateActive {
		testContext.Fatalf("unexpected ensured account profile: %#v", accountProfile)
	}
	accountPasswordProfile, accountPasswordErr := store.AuthenticatePassword(ctx, "tenant-a", "seeded@example.com", "correct horse battery staple")
	if accountPasswordErr != nil {
		testContext.Fatalf("expected account credential to authenticate: %v", accountPasswordErr)
	}
	if accountPasswordProfile.AccountID != expectedAccountID {
		testContext.Fatalf("unexpected account credential profile: %#v", accountPasswordProfile)
	}
	reopenedStore, reopenErr := NewDatabaseUserStore(ctx, databaseURL)
	if reopenErr != nil {
		testContext.Fatalf("failed to reopen user store: %v", reopenErr)
	}
	reopenedPasswordProfile, reopenedPasswordErr := reopenedStore.AuthenticatePassword(ctx, "tenant-a", "seeded@example.com", "correct horse battery staple")
	if reopenedPasswordErr != nil {
		testContext.Fatalf("expected reopened account credential to authenticate: %v", reopenedPasswordErr)
	}
	if reopenedPasswordProfile.AccountID != expectedAccountID {
		testContext.Fatalf("expected reopened account id %s, got %#v", expectedAccountID, reopenedPasswordProfile)
	}

	if _, disableErr := store.BeginAccountDisable(ctx, "tenant-a", expectedAccountID); disableErr != nil {
		testContext.Fatalf("failed to disable account: %v", disableErr)
	}
	if _, err := store.CompleteAccountDisable(ctx, "tenant-a", expectedAccountID); err != nil {
		testContext.Fatal(err)
	}
	if _, disabledChangeErr := store.ChangePassword(ctx, "tenant-a", expectedAccountID, "correct horse battery staple", "disabled account password"); !errors.Is(disabledChangeErr, ErrAccountDisabled) {
		testContext.Fatalf("expected disabled account password change rejection, got %v", disabledChangeErr)
	}
	if _, disabledErr := store.AuthenticatePassword(ctx, "tenant-a", "seeded@example.com", "correct horse battery staple"); !errors.Is(disabledErr, ErrAccountDisabled) {
		testContext.Fatalf("expected disabled account password rejection, got %v", disabledErr)
	}
}

func TestDatabaseUserStoreProviderAccountUsesPersistedOpaqueID(testContext *testing.T) {
	testContext.Parallel()
	ctx := context.Background()
	databaseURL := sqliteDatabaseURL(testContext)
	store, err := NewDatabaseUserStore(ctx, databaseURL)
	if err != nil {
		testContext.Fatalf("failed to create store: %v", err)
	}

	profile, upsertErr := store.UpsertProviderAccount(ctx, "tenant-a", AccountProviderIdentity{
		Provider:    accountProviderGoogle,
		Subject:     "google-subject",
		UserEmail:   "google@example.com",
		DisplayName: "Google User",
		AvatarURL:   "https://example.com/google.png",
	})
	if upsertErr != nil {
		testContext.Fatalf("failed to create provider account: %v", upsertErr)
	}
	expectedAccountID := assertOpaqueAccountID(testContext, profile.AccountID)

	secondProfile, secondUpsertErr := store.UpsertProviderAccount(ctx, "tenant-a", AccountProviderIdentity{
		Provider:    accountProviderGoogle,
		Subject:     "google-subject",
		UserEmail:   "updated@example.com",
		DisplayName: "Updated User",
		AvatarURL:   "https://example.com/updated.png",
	})
	if secondUpsertErr != nil {
		testContext.Fatalf("failed to update provider account: %v", secondUpsertErr)
	}
	if secondProfile.AccountID != expectedAccountID || secondProfile.UserEmail != "updated@example.com" {
		testContext.Fatalf("expected provider account id reuse, got %#v", secondProfile)
	}

	reopenedStore, reopenErr := NewDatabaseUserStore(ctx, databaseURL)
	if reopenErr != nil {
		testContext.Fatalf("failed to reopen store: %v", reopenErr)
	}
	reopenedProfile, found, authErr := reopenedStore.AuthenticateProviderAccount(ctx, "tenant-a", AccountProviderIdentity{
		Provider:  accountProviderGoogle,
		Subject:   "google-subject",
		UserEmail: "updated@example.com",
	})
	if authErr != nil || !found {
		testContext.Fatalf("expected reopened provider account, found=%t err=%v", found, authErr)
	}
	if reopenedProfile.AccountID != expectedAccountID {
		testContext.Fatalf("expected reopened provider account id %s, got %#v", expectedAccountID, reopenedProfile)
	}
}

func TestDatabaseUserStoreMasksUnknownPasswordCredentialLookup(testContext *testing.T) {
	testContext.Parallel()
	databaseURL := sqliteDatabaseURL(testContext)
	store, err := NewDatabaseUserStore(context.Background(), databaseURL)
	if err != nil {
		testContext.Fatalf("failed to create store: %v", err)
	}
	compareCalls := 0
	var comparedHash string
	store.passwordHashComparer = func(hashedPassword []byte, password []byte) error {
		compareCalls++
		comparedHash = string(hashedPassword)
		return errors.New("password mismatch")
	}

	_, authErr := store.AuthenticatePassword(context.Background(), "tenant-a", "missing@example.com", "correct horse battery staple")
	if !errors.Is(authErr, ErrPasswordCredentialInvalid) {
		testContext.Fatalf("expected invalid credential error, got %v", authErr)
	}
	if compareCalls != 1 {
		testContext.Fatalf("expected one dummy compare, got %d", compareCalls)
	}
	if comparedHash != passwordCredentialTimingHash {
		testContext.Fatalf("expected dummy timing hash, got %s", comparedHash)
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

func TestDatabaseUserStoreReconcilePreservesSignupCredentials(testContext *testing.T) {
	testContext.Parallel()
	ctx := context.Background()
	databaseURL := sqliteDatabaseURL(testContext)
	store, err := NewDatabaseUserStore(ctx, databaseURL)
	if err != nil {
		testContext.Fatalf("failed to create store: %v", err)
	}
	expiresUnix := time.Now().UTC().Add(time.Hour).Unix()
	challenge, signupErr := store.CreatePasswordSignup(ctx, "tenant-a", AccountPasswordRequest{
		UserEmail:   "Signup@Example.com",
		DisplayName: "Signup User",
		Password:    "correct horse battery staple",
	}, expiresUnix)
	if signupErr != nil {
		testContext.Fatalf("failed to create signup: %v", signupErr)
	}
	if _, verifyErr := store.VerifyEmailChallenge(ctx, "tenant-a", challenge.Token); verifyErr != nil {
		testContext.Fatalf("failed to verify signup: %v", verifyErr)
	}
	passwordHash, hashErr := HashPassword("configured password value")
	if hashErr != nil {
		testContext.Fatalf("failed to hash configured password: %v", hashErr)
	}
	if seedErr := store.UpsertPasswordCredential(ctx, "tenant-a", PasswordCredentialSeed{
		UserEmail:    "configured@example.com",
		DisplayName:  "Configured User",
		PasswordHash: passwordHash,
	}); seedErr != nil {
		testContext.Fatalf("failed to seed configured credential: %v", seedErr)
	}

	if reconcileErr := store.ReconcilePasswordCredentials(ctx, "tenant-a", []string{"configured@example.com"}); reconcileErr != nil {
		testContext.Fatalf("failed to reconcile configured credentials: %v", reconcileErr)
	}
	if _, authErr := store.AuthenticatePassword(ctx, "tenant-a", "signup@example.com", "correct horse battery staple"); authErr != nil {
		testContext.Fatalf("expected signup credential to survive reconcile: %v", authErr)
	}
	if reconcileErr := store.ReconcilePasswordCredentials(ctx, "tenant-a", nil); reconcileErr != nil {
		testContext.Fatalf("failed to reconcile empty configured credentials: %v", reconcileErr)
	}
	if _, authErr := store.AuthenticatePassword(ctx, "tenant-a", "signup@example.com", "correct horse battery staple"); authErr != nil {
		testContext.Fatalf("expected signup credential to survive empty reconcile: %v", authErr)
	}
	if _, configErr := store.AuthenticatePassword(ctx, "tenant-a", "configured@example.com", "configured password value"); !errors.Is(configErr, ErrPasswordCredentialInvalid) {
		testContext.Fatalf("expected configured credential to be removed, got %v", configErr)
	}
}

func TestDatabaseUserStoreRejectsObsoleteAccountSchema(testContext *testing.T) {
	databasePath := filepath.Join(testContext.TempDir(), "tauth.db")
	databaseURL := fmt.Sprintf("sqlite:///%s", filepath.ToSlash(databasePath))
	legacyDatabaseHandle, openErr := gorm.Open(sqliteDialector.Open(filepath.ToSlash(databasePath)), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if openErr != nil {
		testContext.Fatalf("failed to open legacy database: %v", openErr)
	}
	if migrateErr := legacyDatabaseHandle.AutoMigrate(&schemaMigrationRecord{}, &userProfileRecord{}, &passwordCredentialRecord{}, &databaseAccountRecord{}, &databaseAccountIdentityRecord{}, &databaseAccountChallengeRecord{}, &refreshTokenRecord{}); migrateErr != nil {
		testContext.Fatalf("failed to migrate legacy database: %v", migrateErr)
	}
	oldAccountID := "account:AAAAAAAAAAAAAAAAAAAAAA"
	nowUnix := time.Now().UTC().Unix()
	if createErr := legacyDatabaseHandle.Create(&databaseAccountRecord{
		TenantID:        "tenant-a",
		AccountID:       oldAccountID,
		UserEmail:       "legacy@example.com",
		UserDisplayName: "Legacy User",
		UserAvatarURL:   "https://example.com/legacy.png",
		AccountState:    accountStateActive,
		UserRoles:       roleList([]string{defaultUserRole}),
		CreatedAtUnix:   nowUnix,
		LastUpdatedUnix: nowUnix,
	}).Error; createErr != nil {
		testContext.Fatalf("failed to create legacy account: %v", createErr)
	}
	if createErr := legacyDatabaseHandle.Create(&databaseAccountIdentityRecord{
		TenantID:        "tenant-a",
		Provider:        accountProviderPassword,
		ProviderID:      "legacy@example.com",
		AccountID:       oldAccountID,
		CreatedAtUnix:   nowUnix,
		LastUpdatedUnix: nowUnix,
	}).Error; createErr != nil {
		testContext.Fatalf("failed to create legacy identity: %v", createErr)
	}
	if createErr := legacyDatabaseHandle.Create(&passwordCredentialRecord{
		TenantID:        "tenant-a",
		UserEmail:       "legacy@example.com",
		UserID:          "email:legacy@example.com",
		AccountID:       oldAccountID,
		UserDisplayName: "Legacy User",
		UserAvatarURL:   "https://example.com/legacy.png",
		PasswordHash:    passwordCredentialTimingHash,
		EmailVerified:   true,
		ManagedByConfig: false,
		CreatedAtUnix:   nowUnix,
		LastUpdatedUnix: nowUnix,
	}).Error; createErr != nil {
		testContext.Fatalf("failed to create legacy credential: %v", createErr)
	}
	if createErr := legacyDatabaseHandle.Create(&databaseAccountChallengeRecord{
		TenantID:        "tenant-a",
		TokenHash:       hashOpaque("legacy-token"),
		AccountID:       oldAccountID,
		ChallengeKind:   accountChallengePasswordReset,
		UserEmail:       "legacy@example.com",
		UserDisplayName: "Legacy User",
		UserAvatarURL:   "https://example.com/legacy.png",
		PasswordHash:    passwordCredentialTimingHash,
		ExpiresUnix:     nowUnix + 3600,
		CreatedAtUnix:   nowUnix,
	}).Error; createErr != nil {
		testContext.Fatalf("failed to create legacy challenge: %v", createErr)
	}
	if createErr := legacyDatabaseHandle.Create(&userProfileRecord{
		TenantID:        "tenant-a",
		UserID:          oldAccountID,
		UserEmail:       "legacy@example.com",
		UserDisplayName: "Legacy User",
		UserAvatarURL:   "https://example.com/legacy.png",
		UserRoles:       roleList([]string{defaultUserRole}),
		CreatedAtUnix:   nowUnix,
		LastUpdatedUnix: nowUnix,
	}).Error; createErr != nil {
		testContext.Fatalf("failed to create legacy user profile: %v", createErr)
	}
	if createErr := legacyDatabaseHandle.Create(&refreshTokenRecord{
		TokenID:         "legacy-refresh-token",
		TenantID:        "tenant-a",
		UserID:          oldAccountID,
		TokenHash:       hashOpaque("legacy-refresh"),
		ExpiresUnix:     nowUnix + 3600,
		PreviousTokenID: "",
		IssuedAtUnix:    nowUnix,
	}).Error; createErr != nil {
		testContext.Fatalf("failed to create legacy refresh token: %v", createErr)
	}
	rawDatabaseHandle, rawErr := legacyDatabaseHandle.DB()
	if rawErr != nil {
		testContext.Fatalf("failed to access legacy sql handle: %v", rawErr)
	}
	if closeErr := rawDatabaseHandle.Close(); closeErr != nil {
		testContext.Fatalf("failed to close legacy database: %v", closeErr)
	}

	if _, err := NewDatabaseUserStore(context.Background(), databaseURL); err == nil {
		testContext.Fatal("startup accepted obsolete internal account ID")
	}
	db, err := OpenControlDatabase(context.Background(), databaseURL)
	if err != nil {
		testContext.Fatal(err)
	}
	defer func() { raw, _ := db.DB(); raw.Close() }()
	var account databaseAccountRecord
	if err = db.Where("tenant_id = ?", "tenant-a").Take(&account).Error; err != nil || account.AccountID != oldAccountID {
		testContext.Fatalf("startup changed persisted internal ID: %+v %v", account, err)
	}
	var profile userProfileRecord
	if err = db.Where("tenant_id = ? AND user_id = ?", "tenant-a", oldAccountID).Take(&profile).Error; err != nil {
		testContext.Fatal(err)
	}
	var refresh refreshTokenRecord
	if err = db.Where("token_id = ?", "legacy-refresh-token").Take(&refresh).Error; err != nil || refresh.UserID != oldAccountID || refresh.RevokedAtUnix != 0 {
		testContext.Fatalf("startup changed refresh data: %+v %v", refresh, err)
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

	if _, err := NewDatabaseUserStore(context.Background(), databaseURL); err == nil {
		testContext.Fatal("startup accepted unmigrated provider subjects")
	}
	db, err := OpenControlDatabase(context.Background(), databaseURL)
	if err != nil {
		testContext.Fatal(err)
	}
	defer func() { raw, _ := db.DB(); raw.Close() }()
	var profile userProfileRecord
	if err = db.Where("tenant_id = ? AND user_id = ?", legacyTenantID, legacyUserID).Take(&profile).Error; err != nil || profile.UserEmail != legacyUserEmail || profile.UserDisplayName != legacyDisplayName {
		testContext.Fatalf("startup changed persisted profile: %+v %v", profile, err)
	}
}

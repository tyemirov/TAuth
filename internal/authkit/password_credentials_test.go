package authkit

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryPasswordCredentialStoreAuthenticates(testingHandle *testing.T) {
	store := NewMemoryPasswordCredentialStore()
	passwordHash, hashErr := HashPassword("correct horse battery staple")
	if hashErr != nil {
		testingHandle.Fatalf("failed to hash password: %v", hashErr)
	}
	upsertErr := store.UpsertPasswordCredential(context.Background(), "tenant-a", PasswordCredentialSeed{
		UserEmail:    "User@Example.com",
		DisplayName:  "Password User",
		AvatarURL:    "https://example.com/avatar.png",
		PasswordHash: passwordHash,
	})
	if upsertErr != nil {
		testingHandle.Fatalf("failed to upsert password credential: %v", upsertErr)
	}

	profile, authErr := store.AuthenticatePassword(context.Background(), "tenant-a", "user@example.com", "correct horse battery staple")
	if authErr != nil {
		testingHandle.Fatalf("expected password auth to pass: %v", authErr)
	}
	if profile.UserEmail != "user@example.com" || profile.DisplayName != "Password User" || profile.AvatarURL != "https://example.com/avatar.png" {
		testingHandle.Fatalf("unexpected password profile: %#v", profile)
	}

	_, wrongPasswordErr := store.AuthenticatePassword(context.Background(), "tenant-a", "user@example.com", "wrong-password")
	if !errors.Is(wrongPasswordErr, ErrPasswordCredentialInvalid) {
		testingHandle.Fatalf("expected invalid credential error, got %v", wrongPasswordErr)
	}
}

func TestMemoryPasswordCredentialStoreMasksUnknownEmailLookup(testingHandle *testing.T) {
	store := NewMemoryPasswordCredentialStore()
	compareCalls := 0
	var comparedHash string
	store.passwordHashComparer = func(hashedPassword []byte, password []byte) error {
		compareCalls++
		comparedHash = string(hashedPassword)
		return errors.New("password mismatch")
	}

	_, authErr := store.AuthenticatePassword(context.Background(), "tenant-a", "missing@example.com", "correct horse battery staple")
	if !errors.Is(authErr, ErrPasswordCredentialInvalid) {
		testingHandle.Fatalf("expected invalid credential error, got %v", authErr)
	}
	if compareCalls != 1 {
		testingHandle.Fatalf("expected one dummy compare, got %d", compareCalls)
	}
	if comparedHash != passwordCredentialTimingHash {
		testingHandle.Fatalf("expected dummy timing hash, got %s", comparedHash)
	}
}

func TestMemoryPasswordCredentialStoreReconcilesCredentials(testingHandle *testing.T) {
	store := NewMemoryPasswordCredentialStore()
	passwordHash, hashErr := HashPassword("correct horse battery staple")
	if hashErr != nil {
		testingHandle.Fatalf("failed to hash password: %v", hashErr)
	}
	for _, email := range []string{"kept@example.com", "removed@example.com"} {
		if upsertErr := store.UpsertPasswordCredential(context.Background(), "tenant-a", PasswordCredentialSeed{
			UserEmail:    email,
			DisplayName:  email,
			PasswordHash: passwordHash,
		}); upsertErr != nil {
			testingHandle.Fatalf("failed to upsert password credential: %v", upsertErr)
		}
	}

	if reconcileErr := store.ReconcilePasswordCredentials(context.Background(), "tenant-a", []string{"kept@example.com"}); reconcileErr != nil {
		testingHandle.Fatalf("failed to reconcile password credentials: %v", reconcileErr)
	}
	if _, authErr := store.AuthenticatePassword(context.Background(), "tenant-a", "kept@example.com", "correct horse battery staple"); authErr != nil {
		testingHandle.Fatalf("expected kept credential to authenticate: %v", authErr)
	}
	if _, removedErr := store.AuthenticatePassword(context.Background(), "tenant-a", "removed@example.com", "correct horse battery staple"); !errors.Is(removedErr, ErrPasswordCredentialInvalid) {
		testingHandle.Fatalf("expected removed credential to be rejected, got %v", removedErr)
	}

	if reconcileErr := store.ReconcilePasswordCredentials(context.Background(), "tenant-a", nil); reconcileErr != nil {
		testingHandle.Fatalf("failed to reconcile empty password credentials: %v", reconcileErr)
	}
	if _, removedErr := store.AuthenticatePassword(context.Background(), "tenant-a", "kept@example.com", "correct horse battery staple"); !errors.Is(removedErr, ErrPasswordCredentialInvalid) {
		testingHandle.Fatalf("expected empty config to remove kept credential, got %v", removedErr)
	}
}

func TestMemoryPasswordCredentialStoreReconcilePreservesSignupCredentials(testingHandle *testing.T) {
	store := NewMemoryPasswordCredentialStore()
	expiresUnix := time.Now().UTC().Add(time.Hour).Unix()
	challenge, signupErr := store.CreatePasswordSignup(context.Background(), "tenant-a", AccountPasswordRequest{
		UserEmail:   "Signup@Example.com",
		DisplayName: "Signup User",
		Password:    "correct horse battery staple",
	}, expiresUnix)
	if signupErr != nil {
		testingHandle.Fatalf("failed to create signup: %v", signupErr)
	}
	if _, verifyErr := store.VerifyEmailChallenge(context.Background(), "tenant-a", challenge.Token); verifyErr != nil {
		testingHandle.Fatalf("failed to verify signup: %v", verifyErr)
	}
	passwordHash, hashErr := HashPassword("configured password value")
	if hashErr != nil {
		testingHandle.Fatalf("failed to hash configured password: %v", hashErr)
	}
	if seedErr := store.UpsertPasswordCredential(context.Background(), "tenant-a", PasswordCredentialSeed{
		UserEmail:    "configured@example.com",
		DisplayName:  "Configured User",
		PasswordHash: passwordHash,
	}); seedErr != nil {
		testingHandle.Fatalf("failed to seed configured credential: %v", seedErr)
	}

	if reconcileErr := store.ReconcilePasswordCredentials(context.Background(), "tenant-a", []string{"configured@example.com"}); reconcileErr != nil {
		testingHandle.Fatalf("failed to reconcile configured credentials: %v", reconcileErr)
	}
	if _, authErr := store.AuthenticatePassword(context.Background(), "tenant-a", "signup@example.com", "correct horse battery staple"); authErr != nil {
		testingHandle.Fatalf("expected signup credential to survive reconcile: %v", authErr)
	}
	if reconcileErr := store.ReconcilePasswordCredentials(context.Background(), "tenant-a", nil); reconcileErr != nil {
		testingHandle.Fatalf("failed to reconcile empty configured credentials: %v", reconcileErr)
	}
	if _, authErr := store.AuthenticatePassword(context.Background(), "tenant-a", "signup@example.com", "correct horse battery staple"); authErr != nil {
		testingHandle.Fatalf("expected signup credential to survive empty reconcile: %v", authErr)
	}
	if _, configErr := store.AuthenticatePassword(context.Background(), "tenant-a", "configured@example.com", "configured password value"); !errors.Is(configErr, ErrPasswordCredentialInvalid) {
		testingHandle.Fatalf("expected configured credential to be removed, got %v", configErr)
	}
}

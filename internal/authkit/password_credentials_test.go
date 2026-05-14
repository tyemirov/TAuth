package authkit

import (
	"context"
	"errors"
	"testing"
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

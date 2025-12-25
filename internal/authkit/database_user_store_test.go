package authkit

import (
	"context"
	"errors"
	"testing"

	"github.com/tyemirov/tauth/internal/web"
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

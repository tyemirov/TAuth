package oauthserver

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSecurityAuthorizationCapacity(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			fixture := newGitHubOAuthFixture(t, backend, false)
			now := time.Now().UTC()
			fixture.server.now = func() time.Time { return now }
			target := authorizationURL(fixture.issuer, strings.Repeat("A", 43), "capacity", testOAuthRedirect, testOAuthResource, testOAuthScope, testOAuthClient)
			// Seed through the public store boundary, then test the HTTP rejection and recovery.
			for index := 0; index < 1000; index++ {
				_, err := fixture.server.store.CreateAuthorizationRequest(context.Background(), AuthorizationRequest{TenantID: "demo", CreatedAtUnix: now.Unix(), ExpiresAtUnix: now.Add(time.Minute).Unix()})
				if err != nil {
					t.Fatal(err)
				}
			}
			response := doRequest(t, fixture.client, http.MethodGet, target, nil)
			response.Body.Close()
			if response.StatusCode != http.StatusTooManyRequests {
				t.Fatalf("capacity: want 429, got %d", response.StatusCode)
			}
			now = now.Add(2 * time.Minute)
			response = doRequest(t, fixture.client, http.MethodGet, target, nil)
			response.Body.Close()
			if response.StatusCode != http.StatusSeeOther {
				t.Fatalf("after expiry: want 303, got %d", response.StatusCode)
			}
			switch store := fixture.server.store.(type) {
			case *MemoryStore:
				if len(store.requests) != 1 {
					t.Fatalf("retained %d requests", len(store.requests))
				}
			case *DatabaseStore:
				var count int64
				if err := store.db.Model(&databaseAuthorizationRequest{}).Count(&count).Error; err != nil {
					t.Fatal(err)
				}
				if count != 1 {
					t.Fatalf("retained %d requests", count)
				}
			}
		})
	}
}

func TestSecurityCapacitySchemaUpgrade(t *testing.T) {
	databaseURL := "sqlite://" + t.TempDir() + "/oauth.db"
	store, err := NewDatabaseStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	request, err := store.CreateAuthorizationRequest(context.Background(), AuthorizationRequest{TenantID: "demo", CreatedAtUnix: time.Now().Unix(), ExpiresAtUnix: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.db.Migrator().DropTable(&databaseCapacityLock{}); err != nil {
		t.Fatal(err)
	}
	if err := store.db.Exec("UPDATE schema_migrations SET version = 2 WHERE store_name = 'oauth_store'").Error; err != nil {
		t.Fatal(err)
	}
	reopened, err := NewDatabaseStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.GetAuthorizationRequest(context.Background(), request, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
}

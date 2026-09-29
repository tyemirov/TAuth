package authkit

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestSecurityPasswordAbuse(t *testing.T) {
	for _, backend := range []string{"memory", "database"} {
		t.Run(backend, func(t *testing.T) {
			config := newTestServerConfig()
			config.PasswordAuthEnabled = true
			config.AccountManagementEnabled = true
			sender := enableTestChallengeDelivery(&config)
			now := time.Now()
			var accounts AccountManagementStore
			var credentials PasswordCredentialStore
			if backend == "memory" {
				store := NewMemoryPasswordCredentialStore()
				store.now = func() time.Time { return now }
				accounts, credentials = store, store
			} else {
				store, err := NewDatabaseUserStore(context.Background(), sqliteDatabaseURL(t))
				if err != nil {
					t.Fatal(err)
				}
				store.now = func() time.Time { return now }
				accounts, credentials = store, store
			}
			signup, err := accounts.CreatePasswordSignup(context.Background(), config.TenantID, AccountPasswordRequest{UserEmail: "known@example.com", Password: "correct horse battery staple"}, time.Now().Add(time.Hour).Unix())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := accounts.VerifyEmailChallenge(context.Background(), config.TenantID, signup.Token); err != nil {
				t.Fatal(err)
			}
			router := gin.New()
			MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), nil, credentials, sender, nil)
			server := httptest.NewTLSServer(router)
			defer server.Close()
			post := func(path, email, password string) (int, string) {
				t.Helper()
				response, err := server.Client().Post(server.URL+path, "application/json", strings.NewReader(`{"email":"`+email+`","password":"`+password+`"}`))
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				return response.StatusCode, string(body)
			}
			t.Run("guesses", func(t *testing.T) {
				for attempt := 0; attempt < 5; attempt++ {
					status, _ := post("/auth/password/login", "known@example.com", "wrong")
					if status != http.StatusUnauthorized {
						t.Fatalf("attempt %d: %d", attempt, status)
					}
				}
				status, _ := post("/auth/password/login", "known@example.com", "correct horse battery staple")
				if status != http.StatusTooManyRequests {
					t.Fatalf("guess budget bypassed: %d", status)
				}
			})
			t.Run("reset", func(t *testing.T) {
				knownStatus, known := post("/auth/password/reset/start", "known@example.com", "")
				unknownStatus, unknown := post("/auth/password/reset/start", "unknown@example.com", "")
				if knownStatus != http.StatusAccepted || unknownStatus != knownStatus || known != unknown || known != `{"status":"accepted"}` {
					t.Errorf("reset responses disclose account state: known=%s unknown=%s", known, unknown)
				}
				for attempt := 0; attempt < 3; attempt++ {
					status, body := post("/auth/password/reset/start", "known@example.com", "")
					if status != knownStatus || body != known {
						t.Errorf("throttled response changed: %d %s", status, body)
					}
				}
				if len(sender.requests) != 1 {
					t.Fatalf("reset email flood: %d deliveries", len(sender.requests))
				}
				now = now.Add(time.Minute + time.Second)
				status, body := post("/auth/password/reset/start", "known@example.com", "")
				if status != knownStatus || body != known || len(sender.requests) != 2 {
					t.Fatal("reset did not recover after cooldown")
				}
				oldToken := challengeTokenFromDeliveryURL(t, sender.requests[0], EmailChallengeKindPasswordReset)
				if _, err := accounts.CompletePasswordReset(context.Background(), config.TenantID, oldToken, "replacement correct horse battery staple"); err == nil {
					t.Fatal("replaced reset challenge remains usable")
				}
				newToken := challengeTokenFromDeliveryURL(t, sender.requests[1], EmailChallengeKindPasswordReset)
				if _, err := accounts.CompletePasswordReset(context.Background(), config.TenantID, newToken, "replacement correct horse battery staple"); err != nil {
					t.Fatal(err)
				}

			})
		})
	}
}

func TestSecurityBudgetSchemaUpgrade(t *testing.T) {
	databaseURL := sqliteDatabaseURL(t)
	store, err := NewDatabaseUserStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	userID, _, err := store.UpsertGoogleUser(context.Background(), "tenant", "subject", "user@example.com", "User", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.db.Migrator().DropTable(&abuseBudgetRecord{}, &abuseBudgetLock{}); err != nil {
		t.Fatal(err)
	}
	if err := store.db.Model(&schemaMigrationRecord{}).Where("store_name = ?", userStoreErrorPrefix).Update("version", 5).Error; err != nil {
		t.Fatal(err)
	}
	reopened, err := NewDatabaseUserStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := reopened.GetUserProfile(context.Background(), "tenant", userID); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.AuthenticatePassword(context.Background(), "tenant", "missing@example.com", "wrong"); err != ErrPasswordCredentialInvalid {
		t.Fatalf("upgraded authentication: %v", err)
	}
}

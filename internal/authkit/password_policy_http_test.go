package authkit

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPPasswordPolicyAndDelay(t *testing.T) {
	for _, backend := range []string{"memory", "database"} {
		t.Run(backend, func(t *testing.T) {
			config := newTestServerConfig()
			config.PasswordAuthEnabled, config.AccountManagementEnabled = true, true
			config.PasswordSignupEnabled = true
			sender := enableTestChallengeDelivery(&config)
			now := time.Now()
			var credentials PasswordCredentialStore
			if backend == "memory" {
				store := NewMemoryPasswordCredentialStore()
				store.now = func() time.Time { return now }
				credentials = store
			} else {
				store, err := NewDatabaseUserStore(context.Background(), sqliteDatabaseURL(t))
				if err != nil {
					t.Fatal(err)
				}
				store.now = func() time.Time { return now }
				credentials = store
			}
			router := gin.New()
			MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), nil, credentials, newTestPasswordResetDispatcher(t), sender, nil)
			server := httptest.NewTLSServer(router)
			defer server.Close()
			t.Run("strength", func(t *testing.T) {
				for _, password := range []string{"x", "12345678901234"} {
					response := oneTimePost(t, server, "/auth/password/signup", `{"email":"weak@example.com","password":"`+password+`"}`)
					if response.StatusCode != http.StatusUnauthorized {
						t.Fatalf("weak password accepted: %d", response.StatusCode)
					}
				}
			})
			t.Run("delay", func(t *testing.T) {
				response := oneTimePost(t, server, "/auth/password/login", `{"email":"missing@example.com","password":"wrong"}`)
				if response.StatusCode != http.StatusUnauthorized {
					t.Fatalf("first guess: %d", response.StatusCode)
				}
				response = oneTimePost(t, server, "/auth/password/login", `{"email":"missing@example.com","password":"wrong"}`)
				if response.StatusCode != http.StatusTooManyRequests || response.Header.Get("Retry-After") != "1" {
					t.Fatalf("delay response: %d %s", response.StatusCode, response.Header.Get("Retry-After"))
				}
			})
		})
	}
}

func advancePasswordTestClock(credentials PasswordCredentialStore, elapsed time.Duration) {
	switch store := credentials.(type) {
	case *MemoryPasswordCredentialStore:
		now := store.now().Add(elapsed)
		store.now = func() time.Time { return now }
	case *DatabaseUserStore:
		now := store.now().Add(elapsed)
		store.now = func() time.Time { return now }
	}
}

func TestHTTPPasswordCreationBoundaries(t *testing.T) {
	for _, backend := range []string{"memory", "database"} {
		t.Run(backend, func(t *testing.T) {
			config := newTestServerConfig()
			config.PasswordAuthEnabled, config.AccountManagementEnabled, config.PasswordSignupEnabled = true, true, true
			sender := enableTestChallengeDelivery(&config)
			var credentials PasswordCredentialStore
			if backend == "memory" {
				credentials = NewMemoryPasswordCredentialStore()
			} else {
				store, err := NewDatabaseUserStore(context.Background(), sqliteDatabaseURL(t))
				if err != nil {
					t.Fatal(err)
				}
				credentials = store
			}
			accounts := credentials.(AccountManagementStore)
			challenge, err := accounts.CreatePasswordSignup(context.Background(), config.TenantID, AccountPasswordRequest{UserEmail: "owner@example.com", Password: "correct horse battery staple"}, time.Now().Add(time.Hour).Unix())
			if err != nil {
				t.Fatal(err)
			}
			profile, err := accounts.VerifyEmailChallenge(context.Background(), config.TenantID, challenge.Token)
			if err != nil {
				t.Fatal(err)
			}
			reset, err := accounts.StartPasswordReset(context.Background(), config.TenantID, "owner@example.com", time.Now().Add(time.Hour).Unix())
			if err != nil {
				t.Fatal(err)
			}
			session, _, err := MintAppJWT(NewSystemClock(), config.TenantID, profile.UserID, profile.UserEmail, profile.DisplayName, "", profile.Roles, config.AppJWTIssuer, config.AppJWTSigningKey, config.SessionTTL)
			if err != nil {
				t.Fatal(err)
			}
			router := gin.New()
			MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), nil, credentials, newTestPasswordResetDispatcher(t), sender, nil)
			server := httptest.NewTLSServer(router)
			defer server.Close()
			post := func(path, body string) *http.Response {
				t.Helper()
				request, err := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("Content-Type", "application/json")
				request.AddCookie(&http.Cookie{Name: config.SessionCookieName, Value: session})
				response, err := server.Client().Do(request)
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, response.Body)
				response.Body.Close()
				return response
			}
			for _, password := range []string{"x", strings.Repeat("界", 14)} {
				for _, request := range []struct{ path, body string }{
					{"/auth/password/signup", fmt.Sprintf(`{"email":"new@example.com","password":%q}`, password)},
					{"/auth/password/reset/complete", fmt.Sprintf(`{"token":%q,"password":%q}`, reset.Token, password)},
					{"/auth/account/password/change", fmt.Sprintf(`{"current_password":"correct horse battery staple","new_password":%q}`, password)},
					{"/auth/account/password/link/start", fmt.Sprintf(`{"email":"link@example.com","password":%q}`, password)},
				} {
					response := post(request.path, request.body)
					if response.StatusCode != http.StatusUnauthorized {
						t.Fatalf("%s invalid password status=%d", request.path, response.StatusCode)
					}
				}
			}
			for index, password := range []string{strings.Repeat("界", 15), strings.Repeat("a", 72)} {
				response := post("/auth/password/signup", fmt.Sprintf(`{"email":"new%d@example.com","password":%q}`, index, password))
				if response.StatusCode != http.StatusAccepted {
					t.Fatalf("valid password status=%d", response.StatusCode)
				}
			}
			response := post("/auth/password/reset/complete", fmt.Sprintf(`{"token":%q,"password":%q}`, reset.Token, strings.Repeat("界", 15)))
			if response.StatusCode != http.StatusOK {
				t.Fatalf("valid reset status=%d", response.StatusCode)
			}
			response = post("/auth/account/password/change", fmt.Sprintf(`{"current_password":%q,"new_password":%q}`, strings.Repeat("界", 15), strings.Repeat("a", 72)))
			if response.StatusCode != http.StatusOK {
				t.Fatalf("valid change status=%d", response.StatusCode)
			}
			response = post("/auth/account/password/link/start", fmt.Sprintf(`{"email":"link@example.com","password":%q}`, strings.Repeat("界", 15)))
			if response.StatusCode != http.StatusAccepted {
				t.Fatalf("valid link status=%d", response.StatusCode)
			}
		})
	}
}

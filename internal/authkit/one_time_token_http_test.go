package authkit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"google.golang.org/api/idtoken"
	"gorm.io/gorm"
)

type oneTimeHTTPResult struct {
	response *http.Response
	err      error
	index    int
}

func oneTimeRequest(server *httptest.Server, path, body string) oneTimeHTTPResult {
	response, err := server.Client().Post(server.URL+path, "application/json", strings.NewReader(body))
	if err != nil {
		return oneTimeHTTPResult{err: err}
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	if readErr != nil {
		return oneTimeHTTPResult{err: readErr}
	}
	return oneTimeHTTPResult{response: response, err: closeErr}
}

func oneTimePost(t *testing.T, server *httptest.Server, path, body string) *http.Response {
	t.Helper()
	result := oneTimeRequest(server, path, body)
	if result.err != nil {
		t.Fatal(result.err)
	}
	return result.response
}

func oneTimeRace(t *testing.T, server *httptest.Server, path string, bodies [2]string) int {
	t.Helper()
	results := make(chan oneTimeHTTPResult, 2)
	for index, body := range bodies {
		go func(index int, body string) {
			result := oneTimeRequest(server, path, body)
			result.index = index
			results <- result
		}(index, body)
	}
	successes := 0
	winner := -1
	for index := 0; index < 2; index++ {
		select {
		case result := <-results:
			if result.err != nil {
				t.Fatal(result.err)
			}
			if result.response.StatusCode == http.StatusOK {
				if len(result.response.Cookies()) != 2 {
					t.Fatalf("winner did not issue session and refresh cookies: %v", result.response.Cookies())
				}
				successes++
				winner = result.index
			} else {
				if result.response.StatusCode != http.StatusUnauthorized && result.response.StatusCode != http.StatusBadRequest {
					t.Fatalf("loser status=%d", result.response.StatusCode)
				}
				if len(result.response.Cookies()) != 0 {
					t.Fatalf("loser issued cookies: %v", result.response.Cookies())
				}
			}
		case <-time.After(10 * time.Second):
			t.Fatal("token requests did not complete")
		}
	}
	if successes != 1 {
		t.Fatalf("token completed %d operations, want exactly one", successes)
	}
	return winner
}

func oneTimeBarrier(t *testing.T, db *gorm.DB, mutation, table string) {
	t.Helper()
	var attempts atomic.Int32
	ready := make(chan struct{})
	callback := func(tx *gorm.DB) {
		if tx.Statement.Table != table {
			return
		}
		attempt := attempts.Add(1)
		if attempt == 2 {
			close(ready)
		}
		if attempt <= 2 {
			select {
			case <-ready:
			case <-time.After(10 * time.Second):
				tx.AddError(fmt.Errorf("token mutation barrier timed out"))
			}
		}
	}
	var err error
	if mutation == "delete" {
		err = db.Callback().Delete().Before("gorm:begin_transaction").Register("test:token_race", callback)
	} else {
		err = db.Callback().Update().Before("gorm:update").Register("test:token_race", callback)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestOneTimeDatabaseNonceConcurrentHTTP(t *testing.T) {
	config := newTestServerConfig()
	nonces, err := NewDatabaseNonceStore(context.Background(), sqliteDatabaseURL(t), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	token, err := nonces.Issue(context.Background(), config.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	validator := &fakeGoogleValidator{results: map[string]validatorResult{"one-time-google": {payload: &idtoken.Payload{Claims: map[string]interface{}{"iss": "https://accounts.google.com", "sub": "one-time-subject", "email": "once@example.com", "email_verified": true, "nonce": token}}}}}
	ProvideGoogleTokenValidator(validator)
	t.Cleanup(func() { ProvideGoogleTokenValidator(nil) })
	users, err := NewDatabaseUserStore(context.Background(), sqliteDatabaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	MountAuthRoutes(router, NewSingleTenantRegistry(config), users, NewMemoryRefreshTokenStore(), nonces, users, newTestPasswordResetDispatcher(t))
	server := httptest.NewTLSServer(router)
	defer server.Close()
	// Admit both deletion attempts before executing either mutation. The old
	// consumer has already read the same record at this point.
	oneTimeBarrier(t, nonces.db, "delete", nonceTokenTableName)
	body := fmt.Sprintf(`{"google_id_token":"one-time-google","nonce_token":%q}`, token)
	oneTimeRace(t, server, "/auth/google", [2]string{body, body})
	var identities int64
	if err := users.db.Model(&databaseAccountIdentityRecord{}).Where("tenant_id = ?", config.TenantID).Count(&identities).Error; err != nil {
		t.Fatal(err)
	}
	if identities != 1 {
		t.Fatalf("created %d identities, want one", identities)
	}
}

func TestOneTimeChallengeExactExpiryHTTP(t *testing.T) {
	for _, backend := range []string{"memory", "database"} {
		t.Run(backend, func(t *testing.T) {
			config := newTestServerConfig()
			config.PasswordAuthEnabled = true
			config.AccountManagementEnabled = true
			now := time.Now().UTC().Truncate(time.Second)
			var store AccountManagementStore
			var credentials PasswordCredentialStore
			if backend == "memory" {
				memory := NewMemoryPasswordCredentialStore()
				memory.now = func() time.Time { return now }
				store, credentials = memory, memory
			} else {
				database, err := NewDatabaseUserStore(context.Background(), sqliteDatabaseURL(t))
				if err != nil {
					t.Fatal(err)
				}
				database.now = func() time.Time { return now }
				store, credentials = database, database
			}
			challenge, err := store.CreatePasswordSignup(context.Background(), config.TenantID, AccountPasswordRequest{UserEmail: "expiry@example.com", Password: "correct horse battery staple"}, now.Add(time.Minute).Unix())
			if err != nil {
				t.Fatal(err)
			}
			now = now.Add(time.Minute)
			router := gin.New()
			MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), nil, credentials, newTestPasswordResetDispatcher(t), nil, nil)
			server := httptest.NewTLSServer(router)
			defer server.Close()
			response := oneTimePost(t, server, "/auth/password/verify-email", fmt.Sprintf(`{"token":%q}`, challenge.Token))
			if response.StatusCode == http.StatusOK || len(response.Cookies()) != 0 {
				t.Fatalf("expired challenge issued a session: status=%d cookies=%v", response.StatusCode, response.Cookies())
			}
			if _, err := store.ResolveAccountProfile(context.Background(), config.TenantID, challenge.AccountID); !errors.Is(err, ErrAccountNotFound) {
				t.Fatalf("expired pending account remains: %v", err)
			}
		})
	}
}

func TestOneTimeDatabaseChallengesConcurrentHTTP(t *testing.T) {
	for _, kind := range []string{accountChallengeEmailVerification, accountChallengePasswordReset} {
		t.Run(kind, func(t *testing.T) {
			config := newTestServerConfig()
			config.PasswordAuthEnabled = true
			config.AccountManagementEnabled = true
			store, err := NewDatabaseUserStore(context.Background(), sqliteDatabaseURL(t))
			if err != nil {
				t.Fatal(err)
			}
			challenge, err := store.CreatePasswordSignup(context.Background(), config.TenantID, AccountPasswordRequest{UserEmail: "race@example.com", Password: "initial correct horse battery staple"}, time.Now().Add(time.Hour).Unix())
			if err != nil {
				t.Fatal(err)
			}
			path := "/auth/password/verify-email"
			bodies := [2]string{fmt.Sprintf(`{"token":%q}`, challenge.Token), fmt.Sprintf(`{"token":%q}`, challenge.Token)}
			passwords := [2]string{"first correct horse battery staple", "second correct horse battery staple"}
			if kind == accountChallengePasswordReset {
				if _, err := store.VerifyEmailChallenge(context.Background(), config.TenantID, challenge.Token); err != nil {
					t.Fatal(err)
				}
				challenge, err = store.StartPasswordReset(context.Background(), config.TenantID, "race@example.com", time.Now().Add(time.Hour).Unix())
				if err != nil {
					t.Fatal(err)
				}
				path = "/auth/password/reset/complete"
				for index, password := range passwords {
					bodies[index] = fmt.Sprintf(`{"token":%q,"password":%q}`, challenge.Token, password)
				}
			}
			oneTimeBarrier(t, store.db, "update", (abuseBudgetLock{}).TableName())
			router := gin.New()
			MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(config), store, NewMemoryRefreshTokenStore(), nil, store, newTestPasswordResetDispatcher(t), nil, nil)
			server := httptest.NewTLSServer(router)
			defer server.Close()
			winner := oneTimeRace(t, server, path, bodies)
			var consumed int64
			if err := store.db.Model(&databaseAccountChallengeRecord{}).Where("tenant_id = ? AND token_hash = ? AND consumed_at_unix > 0", config.TenantID, hashOpaque(challenge.Token)).Count(&consumed).Error; err != nil {
				t.Fatal(err)
			}
			if consumed > 1 {
				t.Fatalf("consumed %d challenges", consumed)
			}
			if kind == accountChallengePasswordReset {
				if _, err := store.AuthenticatePassword(context.Background(), config.TenantID, "race@example.com", passwords[winner]); err != nil {
					t.Fatalf("winner password rejected: %v", err)
				}
				if _, err := store.AuthenticatePassword(context.Background(), config.TenantID, "race@example.com", passwords[1-winner]); err == nil {
					t.Fatal("loser changed credential")
				}
			} else {
				profile, err := store.ResolveAccountProfile(context.Background(), config.TenantID, challenge.AccountID)
				if err != nil {
					t.Fatal(err)
				}
				if profile.State != accountStateActive {
					t.Fatalf("verification state=%s", profile.State)
				}
				var identities int64
				if err := store.db.Model(&databaseAccountIdentityRecord{}).Where("tenant_id = ? AND account_id = ?", config.TenantID, challenge.AccountID).Count(&identities).Error; err != nil {
					t.Fatal(err)
				}
				if identities != 1 {
					t.Fatalf("verification created %d identities", identities)
				}
			}
		})
	}
}

func TestOneTimeChallengeIsolationAndLinkRollbackHTTP(t *testing.T) {
	for _, backend := range []string{"memory", "database"} {
		t.Run(backend, func(t *testing.T) {
			config := newTestServerConfig()
			config.PasswordAuthEnabled = true
			config.AccountManagementEnabled = true
			var store AccountManagementStore
			var credentials PasswordCredentialStore
			if backend == "memory" {
				memory := NewMemoryPasswordCredentialStore()
				store, credentials = memory, memory
			} else {
				database, err := NewDatabaseUserStore(context.Background(), sqliteDatabaseURL(t))
				if err != nil {
					t.Fatal(err)
				}
				store, credentials = database, database
			}
			owner, err := store.UpsertProviderAccount(context.Background(), config.TenantID, AccountProviderIdentity{Provider: "google", Subject: "owner", UserEmail: "owner@example.com"})
			if err != nil {
				t.Fatal(err)
			}
			other, err := store.UpsertProviderAccount(context.Background(), config.TenantID, AccountProviderIdentity{Provider: "google", Subject: "other", UserEmail: "other@example.com"})
			if err != nil {
				t.Fatal(err)
			}
			challenge, err := store.CreatePasswordLink(context.Background(), config.TenantID, owner.AccountID, AccountPasswordRequest{UserEmail: "linked@example.com", Password: "linked correct horse battery staple"}, time.Now().Add(time.Hour).Unix())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.VerifyPasswordLink(context.Background(), "other-tenant", owner.AccountID, challenge.Token); err == nil {
				t.Fatal("wrong tenant consumed link")
			}
			router := gin.New()
			MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), nil, credentials, newTestPasswordResetDispatcher(t), nil, nil)
			server := httptest.NewTLSServer(router)
			defer server.Close()
			wrongKind := oneTimePost(t, server, "/auth/password/reset/complete", fmt.Sprintf(`{"token":%q,"password":"wrong correct horse battery staple"}`, challenge.Token))
			if wrongKind.StatusCode == http.StatusOK || len(wrongKind.Cookies()) != 0 {
				t.Fatal("wrong challenge type accepted")
			}
			verify := func(profile AccountProfile) *http.Response {
				t.Helper()
				session, _, err := MintAppJWT(NewSystemClock(), config.TenantID, profile.AccountID, profile.UserEmail, profile.DisplayName, "", profile.Roles, config.AppJWTIssuer, config.AppJWTSigningKey, config.SessionTTL)
				if err != nil {
					t.Fatal(err)
				}
				request, err := http.NewRequest(http.MethodPost, server.URL+"/auth/account/password/link/verify", strings.NewReader(fmt.Sprintf(`{"token":%q}`, challenge.Token)))
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
			wrongAccount := verify(other)
			if wrongAccount.StatusCode == http.StatusOK || len(wrongAccount.Cookies()) != 0 {
				t.Fatal("wrong account linked password")
			}
			if _, err := credentials.AuthenticatePassword(context.Background(), config.TenantID, "linked@example.com", "linked correct horse battery staple"); err == nil {
				t.Fatal("failed request created credential")
			}
			if response := verify(owner); response.StatusCode != http.StatusOK {
				t.Fatalf("failed request burned link challenge: %d", response.StatusCode)
			}
			advancePasswordTestClock(credentials, time.Second)
			if _, err := credentials.AuthenticatePassword(context.Background(), config.TenantID, "linked@example.com", "linked correct horse battery staple"); err != nil {
				t.Fatal(err)
			}
			if response := verify(owner); response.StatusCode == http.StatusOK {
				t.Fatal("link replay accepted")
			}
		})
	}
}

func TestOneTimeDatabaseResetRollbackHTTP(t *testing.T) {
	config := newTestServerConfig()
	config.PasswordAuthEnabled = true
	config.AccountManagementEnabled = true
	store, err := NewDatabaseUserStore(context.Background(), sqliteDatabaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	signup, err := store.CreatePasswordSignup(context.Background(), config.TenantID, AccountPasswordRequest{UserEmail: "rollback@example.com", Password: "original correct horse battery staple"}, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyEmailChallenge(context.Background(), config.TenantID, signup.Token); err != nil {
		t.Fatal(err)
	}
	challenge, err := store.StartPasswordReset(context.Background(), config.TenantID, "rollback@example.com", time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.db.Callback().Update().Before("gorm:update").Register("test:credential_failure", func(tx *gorm.DB) {
		if tx.Statement.Table == passwordCredentialTableName {
			tx.AddError(fmt.Errorf("test credential write failed"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(config), store, NewMemoryRefreshTokenStore(), nil, store, newTestPasswordResetDispatcher(t), nil, nil)
	server := httptest.NewTLSServer(router)
	defer server.Close()
	body := fmt.Sprintf(`{"token":%q,"password":"replacement correct horse battery staple"}`, challenge.Token)
	response := oneTimePost(t, server, "/auth/password/reset/complete", body)
	if response.StatusCode != http.StatusInternalServerError || len(response.Cookies()) != 0 {
		t.Fatalf("failed reset status=%d cookies=%v", response.StatusCode, response.Cookies())
	}
	var persisted databaseAccountChallengeRecord
	if err := store.db.Where("tenant_id = ? AND token_hash = ?", config.TenantID, hashOpaque(challenge.Token)).Take(&persisted).Error; err != nil {
		t.Fatal(err)
	}
	if persisted.ConsumedAtUnix != 0 {
		t.Fatal("credential failure committed challenge consumption")
	}
	if _, err := store.AuthenticatePassword(context.Background(), config.TenantID, "rollback@example.com", "original correct horse battery staple"); err != nil {
		t.Fatalf("failure changed original credential: %v", err)
	}
	if err := store.db.Callback().Update().Remove("test:credential_failure"); err != nil {
		t.Fatal(err)
	}
	response = oneTimePost(t, server, "/auth/password/reset/complete", body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("rolled back challenge rejected: %d", response.StatusCode)
	}
	if _, err := store.AuthenticatePassword(context.Background(), config.TenantID, "rollback@example.com", "replacement correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
}

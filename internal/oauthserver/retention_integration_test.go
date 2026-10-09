package oauthserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOAuthRetentionExpiredRequestAccess(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			fixture := newGitHubOAuthFixture(t, backend, false)
			verifier := strings.Repeat("r", 43)
			callback, _ := fixture.begin(t, "expired", verifier, testOAuthClient, testOAuthRedirect)
			consentURL := fixture.callbackDestination(t, callback)
			token := queryValue(t, consentURL, "request")
			pending, err := fixture.server.store.GetAuthorizationRequest(context.Background(), token, time.Now().Unix())
			if err != nil {
				t.Fatal(err)
			}
			fixture.server.now = func() time.Time { return time.Unix(pending.ExpiresAtUnix, 0) }
			response := doRequest(t, fixture.client, http.MethodGet, consentURL, nil)
			assertOAuthError(t, response, "invalid_request")
			switch store := fixture.server.store.(type) {
			case *MemoryStore:
				if _, exists := store.requests[digestToken(token)]; exists {
					t.Fatal("expired request physically retained")
				}
			case *DatabaseStore:
				var count int64
				if err := store.db.Model(&databaseAuthorizationRequest{}).Where("request_hash = ?", digestToken(token)).Count(&count).Error; err != nil {
					t.Fatal(err)
				}
				if count != 0 {
					t.Fatal("expired request physically retained")
				}
			}
		})
	}
}

func TestOAuthRetentionCodeCapacityPreservesConsentRequest(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			fixture := newGitHubOAuthFixture(t, backend, false)
			verifier := strings.Repeat("c", 43)
			callback, _ := fixture.begin(t, "capacity", verifier, testOAuthClient, testOAuthRedirect)
			consentURL := fixture.callbackDestination(t, callback)
			token := queryValue(t, consentURL, "request")
			now := time.Now().Unix()
			seedOAuthCodes(t, fixture.server.store, maximumPendingPerTenant, now+3600)
			form := url.Values{"request": {token}, "decision": {"approve"}}
			response := doRequest(t, fixture.client, http.MethodPost, consentURL, strings.NewReader(form.Encode()))
			assertStatus(t, response, http.StatusTooManyRequests)
			if body := readBody(t, response); body != "{\"error\":\"temporarily_unavailable\"}\n" {
				t.Fatalf("unexpected capacity response: %s", body)
			}
			if _, err := fixture.server.store.GetAuthorizationRequest(context.Background(), token, now); err != nil {
				t.Fatalf("quota consumed request: %v", err)
			}
			switch store := fixture.server.store.(type) {
			case *MemoryStore:
				if len(store.codes) != maximumPendingPerTenant || len(store.consents) != 0 {
					t.Fatal("quota mutated codes/consents")
				}
				delete(store.codes, "seed-0")
			case *DatabaseStore:
				var count int64
				store.db.Model(&databaseConsent{}).Count(&count)
				if count != 0 {
					t.Fatal("quota committed consent")
				}
				if err := store.db.Where("code_hash = ?", "seed-0").Delete(&databaseAuthorizationCode{}).Error; err != nil {
					t.Fatal(err)
				}
			}
			destination := fixture.approve(t, consentURL)
			response = doRequest(t, fixture.client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(codeTokenForm(queryValue(t, destination, "code"), verifier).Encode()))
			assertStatus(t, response, http.StatusOK)
			response.Body.Close()
		})
	}
}

func seedOAuthCodes(t *testing.T, store Store, count int, expiry int64) {
	t.Helper()
	switch concrete := store.(type) {
	case *MemoryStore:
		for index := 0; index < count; index++ {
			concrete.codes[fmt.Sprintf("seed-%d", index)] = memoryAuthorizationCode{grant: AuthorizationGrant{TenantID: "demo", ExpiresAtUnix: expiry}}
		}
	case *DatabaseStore:
		rows := make([]databaseAuthorizationCode, count)
		for index := range rows {
			rows[index] = databaseAuthorizationCode{CodeHash: fmt.Sprintf("seed-%d", index), TenantID: "demo", ExpiresAtUnix: expiry}
		}
		if err := concrete.db.CreateInBatches(rows, 200).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func TestOAuthRetentionRefreshCapacityPreservesCodeAndRotation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			fixture := newGitHubOAuthFixture(t, backend, false)
			verifier := strings.Repeat("f", 43)
			callback, _ := fixture.begin(t, "refresh-capacity", verifier, testOAuthClient, testOAuthRedirect)
			destination := fixture.approve(t, fixture.callbackDestination(t, callback))
			code := queryValue(t, destination, "code")
			now := time.Now().Unix()
			seedOAuthRefresh(t, fixture.server.store, maximumRefreshPerTenant, now+3600)
			response := doRequest(t, fixture.client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(codeTokenForm(code, verifier).Encode()))
			assertStatus(t, response, http.StatusTooManyRequests)
			if body := readBody(t, response); body != "{\"error\":\"temporarily_unavailable\"}\n" {
				t.Fatalf("unexpected capacity response: %s", body)
			}
			removeOAuthSeedRefresh(t, fixture.server.store, "seed-0")
			response = doRequest(t, fixture.client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(codeTokenForm(code, verifier).Encode()))
			assertStatus(t, response, http.StatusOK)
			tokens := decodeTokenResponse(t, response)
			form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}, "client_id": {testOAuthClient}, "resource": {testOAuthResource}}
			response = doRequest(t, fixture.client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(form.Encode()))
			assertStatus(t, response, http.StatusTooManyRequests)
			if body := readBody(t, response); body != "{\"error\":\"temporarily_unavailable\"}\n" {
				t.Fatalf("unexpected capacity response: %s", body)
			}
			removeOAuthSeedRefresh(t, fixture.server.store, "seed-1")
			response = doRequest(t, fixture.client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(form.Encode()))
			assertStatus(t, response, http.StatusOK)
			decodeTokenResponse(t, response)
		})
	}
}

func seedOAuthRefresh(t *testing.T, store Store, count int, expiry int64) {
	t.Helper()
	switch concrete := store.(type) {
	case *MemoryStore:
		for index := 0; index < count; index++ {
			concrete.refreshTokens[fmt.Sprintf("seed-%d", index)] = memoryRefreshToken{grant: RefreshGrant{TenantID: "demo", ExpiresAtUnix: expiry}, status: refreshTokenStatusRotated}
		}
	case *DatabaseStore:
		rows := make([]databaseOAuthRefreshToken, count)
		for index := range rows {
			rows[index] = databaseOAuthRefreshToken{TokenHash: fmt.Sprintf("seed-%d", index), TenantID: "demo", ExpiresAtUnix: expiry, Status: refreshTokenStatusRotated}
		}
		if err := concrete.db.CreateInBatches(rows, 200).Error; err != nil {
			t.Fatal(err)
		}
	}
}
func removeOAuthSeedRefresh(t *testing.T, store Store, key string) {
	t.Helper()
	switch concrete := store.(type) {
	case *MemoryStore:
		delete(concrete.refreshTokens, key)
	case *DatabaseStore:
		if err := concrete.db.Where("token_hash = ?", key).Delete(&databaseOAuthRefreshToken{}).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func TestOAuthRetentionCleanupPreservesReferencedConsentAndReplay(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			fixture := newGitHubOAuthFixture(t, backend, false)
			verifier := strings.Repeat("p", 43)
			callback, _ := fixture.begin(t, "retention", verifier, testOAuthClient, testOAuthRedirect)
			destination := fixture.approve(t, fixture.callbackDestination(t, callback))
			response := doRequest(t, fixture.client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(codeTokenForm(queryValue(t, destination, "code"), verifier).Encode()))
			tokens := decodeTokenResponse(t, response)
			form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}, "client_id": {testOAuthClient}, "resource": {testOAuthResource}}
			response = doRequest(t, fixture.client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(form.Encode()))
			rotated := decodeTokenResponse(t, response)
			now := time.Now().Unix()
			switch store := fixture.server.store.(type) {
			case *MemoryStore:
				store.refreshTokens["expired-family-member"] = memoryRefreshToken{grant: RefreshGrant{FamilyID: store.refreshTokens[digestToken(tokens.RefreshToken)].grant.FamilyID, ExpiresAtUnix: now}, status: refreshTokenStatusRotated}
				store.consents["expired-unreferenced"] = Consent{ID: "expired-unreferenced", ExpiresAtUnix: now}
			case *DatabaseStore:
				var original databaseOAuthRefreshToken
				if err := store.db.Where("token_hash = ?", digestToken(tokens.RefreshToken)).Take(&original).Error; err != nil {
					t.Fatal(err)
				}
				if err := store.db.Create(&databaseOAuthRefreshToken{TokenHash: "expired-family-member", FamilyID: original.FamilyID, ExpiresAtUnix: now, Status: refreshTokenStatusRotated}).Error; err != nil {
					t.Fatal(err)
				}
				if err := store.db.Create(&databaseConsent{ID: "expired-unreferenced", ExpiresAtUnix: now}).Error; err != nil {
					t.Fatal(err)
				}
			}
			if err := fixture.server.store.CleanupExpired(context.Background(), now); err != nil {
				t.Fatal(err)
			}
			switch store := fixture.server.store.(type) {
			case *MemoryStore:
				if len(store.refreshTokens) != 2 || len(store.consents) != 1 || len(store.codes) != 0 {
					t.Fatal("cleanup did not preserve exactly live/replay rows")
				}
			case *DatabaseStore:
				for model, expected := range map[string]int64{oauthRefreshTokensTable: 2, oauthConsentsTable: 1, oauthAuthorizationCodesTable: 0} {
					var count int64
					if err := store.db.Table(model).Count(&count).Error; err != nil {
						t.Fatal(err)
					}
					if count != expected {
						t.Fatalf("%s retained %d expected %d", model, count, expected)
					}
				}
			}
			response = doRequest(t, fixture.client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(form.Encode()))
			assertOAuthError(t, response, "invalid_grant")
			form.Set("refresh_token", rotated.RefreshToken)
			assertOAuthError(t, doRequest(t, fixture.client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(form.Encode())), "invalid_grant")
		})
	}
}

func TestOAuthRetentionCodeAdmissionAcrossConnections(t *testing.T) {
	fixture := newGitHubOAuthFixture(t, "sqlite", false)
	first := fixture.server.store.(*DatabaseStore)
	// Open an independent GORM connection to the same database file.
	var databaseFiles []struct {
		Name string
		File string
	}
	if err := first.db.Raw("PRAGMA database_list").Scan(&databaseFiles).Error; err != nil {
		t.Fatal(err)
	}
	second, err := NewDatabaseStore(context.Background(), "sqlite://"+databaseFiles[0].File)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	seedOAuthCodes(t, first, maximumPendingPerTenant-1, now+3600)
	verifier := strings.Repeat("q", 43)
	callback, _ := fixture.begin(t, "connections", verifier, testOAuthClient, testOAuthRedirect)
	destination := fixture.approve(t, fixture.callbackDestination(t, callback))
	var grantRecord databaseAuthorizationCode
	if err := first.db.Where("code_hash = ?", digestToken(queryValue(t, destination, "code"))).Take(&grantRecord).Error; err != nil {
		t.Fatal(err)
	}
	// Free one slot, then race two independent admissions for that final slot.
	if err := first.db.Where("code_hash = ?", "seed-0").Delete(&databaseAuthorizationCode{}).Error; err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	for _, store := range []*DatabaseStore{first, second} {
		go func(selected *DatabaseStore) {
			_, err := selected.IssueAuthorizationCode(context.Background(), authorizationGrantFromDatabase(grantRecord), now)
			results <- err
		}(store)
	}
	successes, rejected := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			successes++
		} else if errors.Is(err, ErrAuthorizationCapacity) {
			rejected++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || rejected != 1 {
		t.Fatalf("admissions success=%d rejected=%d", successes, rejected)
	}
	var count int64
	if err := first.db.Model(&databaseAuthorizationCode{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != maximumPendingPerTenant {
		t.Fatalf("capacity retained %d", count)
	}
}

func TestOAuthRetentionInactiveConsentReference(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			fixture := newGitHubOAuthFixture(t, backend, false)
			now := time.Now().Unix()
			switch store := fixture.server.store.(type) {
			case *MemoryStore:
				store.consents["referenced"] = Consent{ID: "referenced", ExpiresAtUnix: now, RevokedAtUnix: now}
				store.codes["reference"] = memoryAuthorizationCode{grant: AuthorizationGrant{ConsentID: "referenced", ExpiresAtUnix: now + 1}}
			case *DatabaseStore:
				if err := store.db.Create(&databaseConsent{ID: "referenced", ExpiresAtUnix: now, RevokedAtUnix: now}).Error; err != nil {
					t.Fatal(err)
				}
				if err := store.db.Create(&databaseAuthorizationCode{CodeHash: "reference", ConsentID: "referenced", ExpiresAtUnix: now + 1}).Error; err != nil {
					t.Fatal(err)
				}
			}
			for _, instant := range []int64{now, now + 1} {
				if err := fixture.server.store.CleanupExpired(context.Background(), instant); err != nil {
					t.Fatal(err)
				}
				expected := int64(1)
				if instant == now+1 {
					expected = 0
				}
				switch store := fixture.server.store.(type) {
				case *MemoryStore:
					if int64(len(store.consents)) != expected {
						t.Fatal("inactive consent reference retention violated")
					}
				case *DatabaseStore:
					var count int64
					if err := store.db.Model(&databaseConsent{}).Count(&count).Error; err != nil {
						t.Fatal(err)
					}
					if count != expected {
						t.Fatal("inactive consent reference retention violated")
					}
				}
			}
		})
	}
}

func TestOAuthRetentionGlobalCodeCapacity(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			fixture := newGitHubOAuthFixture(t, backend, false)
			now := time.Now().Unix()
			seedOAuthCodes(t, fixture.server.store, maximumPendingGlobal, now+3600)
			// Move retained rows to other tenants so only the global ceiling rejects demo.
			switch store := fixture.server.store.(type) {
			case *MemoryStore:
				for digest, record := range store.codes {
					record.grant.TenantID = "other-tenant"
					store.codes[digest] = record
				}
			case *DatabaseStore:
				if err := store.db.Model(&databaseAuthorizationCode{}).Where("tenant_id = ?", "demo").Update("tenant_id", "other-tenant").Error; err != nil {
					t.Fatal(err)
				}
			}
			verifier := strings.Repeat("g", 43)
			callback, _ := fixture.begin(t, "global-code-capacity", verifier, testOAuthClient, testOAuthRedirect)
			consentURL := fixture.callbackDestination(t, callback)
			form := url.Values{"request": {queryValue(t, consentURL, "request")}, "decision": {"approve"}}
			response := doRequest(t, fixture.client, http.MethodPost, consentURL, strings.NewReader(form.Encode()))
			assertStatus(t, response, http.StatusTooManyRequests)
			if body := readBody(t, response); body != "{\"error\":\"temporarily_unavailable\"}\n" {
				t.Fatalf("unexpected capacity response: %s", body)
			}
		})
	}
}

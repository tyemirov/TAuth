package authkit

import (
	"context"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func patchAccountProfile(t *testing.T, fixture *githubHTTPFixture, body string) (int, string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPatch, fixture.server.URL+"/auth/account", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := fixture.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode == http.StatusOK && response.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("missing no-store: %v", response.Header)
	}
	return response.StatusCode, string(payload)
}

func TestAccountProfileCorrectionHTTP(t *testing.T) {
	for _, database := range []bool{false, true} {
		label := "memory"
		if database {
			label = "database"
		}
		t.Run(label, func(t *testing.T) {
			fixture := newGitHubHTTPFixture(t, database, true)
			if status, _ := githubHTTPResponse(t, fixture.client, fixture.callbackURL(t, "")); status != http.StatusSeeOther {
				t.Fatalf("login: %d", status)
			}
			original := fixture.profile(t)
			accountID := original["user_id"].(string)
			other, err := fixture.accounts.UpsertProviderAccount(context.Background(), "other", AccountProviderIdentity{Provider: "github", Subject: "9007199254740993", UserEmail: "private@example.com", DisplayName: "Other Parent"})
			if err != nil {
				t.Fatal(err)
			}
			var persistent *DatabaseUserStore
			if database {
				persistent = fixture.accounts.(*DatabaseUserStore)
				if err := persistent.db.Exec("CREATE TABLE owner_accounts (id TEXT PRIMARY KEY, display_name TEXT, email TEXT)").Error; err != nil {
					t.Fatal(err)
				}
				if err := persistent.db.Exec("INSERT INTO owner_accounts VALUES (?, ?, ?)", accountID, "Console Owner", "private@example.com").Error; err != nil {
					t.Fatal(err)
				}
			}
			status, body := patchAccountProfile(t, fixture, `{"display_name":"  Corrected Parent  "}`)
			if status != http.StatusOK {
				t.Fatalf("patch status=%d body=%s", status, body)
			}
			var corrected map[string]any
			if err := json.Unmarshal([]byte(body), &corrected); err != nil {
				t.Fatal(err)
			}
			if corrected["display"] != "Corrected Parent" || corrected["user_id"] != accountID || corrected["user_email"] != original["user_email"] {
				t.Fatalf("correction response: %v", corrected)
			}
			if status, body := patchAccountProfile(t, fixture, `{"display_name":"Corrected Parent"}`); status != http.StatusOK {
				t.Fatalf("idempotent retry: %d %s", status, body)
			}
			if profile := fixture.profile(t); profile["display"] != "Corrected Parent" {
				t.Fatalf("stale session: %v", profile)
			}
			response, err := fixture.client.Post(fixture.server.URL+"/auth/refresh", "application/json", strings.NewReader(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusNoContent {
				t.Fatalf("refresh: %d", response.StatusCode)
			}
			if profile := fixture.profile(t); profile["display"] != "Corrected Parent" {
				t.Fatalf("stale refreshed session: %v", profile)
			}
			fixture.provider.UserJSON = `{"id":9007199254740993,"login":"new-login","name":"Provider Changed Name"}`
			if status, _ := githubHTTPResponse(t, fixture.client, fixture.callbackURL(t, "")); status != http.StatusSeeOther {
				t.Fatalf("repeat login: %d", status)
			}
			if profile := fixture.profile(t); profile["display"] != "Corrected Parent" {
				t.Fatalf("provider replaced correction: %v", profile)
			}
			otherProfile, err := fixture.accounts.ResolveAccountProfile(context.Background(), "other", other.AccountID)
			if err != nil || otherProfile.DisplayName != "Other Parent" {
				t.Fatalf("tenant isolation: %+v %v", otherProfile, err)
			}
			for _, invalid := range []struct {
				body   string
				status int
			}{
				{`{"email":"new@example.com"}`, http.StatusBadRequest},
				{`{"display_name":"Changed","email":"new@example.com"}`, http.StatusBadRequest},
				{`{"display_name":""}`, http.StatusUnprocessableEntity},
				{`{}`, http.StatusUnprocessableEntity},
				{`{"display_name":null}`, http.StatusUnprocessableEntity},
				{`{"display_name":"Parent\nName"}`, http.StatusUnprocessableEntity},
				{`{"display_name":"` + strings.Repeat("a", 201) + `"}`, http.StatusUnprocessableEntity},
				{`{"display_name":"OK"} {}`, http.StatusBadRequest},
			} {
				if status, body := patchAccountProfile(t, fixture, invalid.body); status != invalid.status {
					t.Errorf("invalid %s: %d %s", invalid.body, status, body)
				}
			}
			if profile := fixture.profile(t); profile["display"] != "Corrected Parent" || profile["user_email"] != original["user_email"] {
				t.Fatalf("invalid request mutated profile: %v", profile)
			}
			if database {
				databaseHandle, err := persistent.db.DB()
				if err != nil {
					t.Fatal(err)
				}
				if err := databaseHandle.Close(); err != nil {
					t.Fatal(err)
				}
				reopened, err := NewDatabaseUserStore(context.Background(), fixture.databaseURL)
				if err != nil {
					t.Fatal(err)
				}
				profile, err := reopened.ResolveAccountProfile(context.Background(), "github", accountID)
				if err != nil || profile.DisplayName != "Corrected Parent" {
					t.Fatalf("durability: %+v %v", profile, err)
				}
				_, name, _, _, err := reopened.GetUserProfile(context.Background(), "github", accountID)
				if err != nil || name != "Corrected Parent" {
					t.Fatalf("stored user profile: %s %v", name, err)
				}
				var ownerName string
				if err := reopened.db.Raw("SELECT display_name FROM owner_accounts WHERE id = ?", accountID).Scan(&ownerName).Error; err != nil || ownerName != "Console Owner" {
					t.Fatalf("owner mutation: %s %v", ownerName, err)
				}
			}
		})
	}
}

func TestAccountProfileCorrectionAuthorizationHTTP(t *testing.T) {
	fixture := newGitHubHTTPFixture(t, true, true)
	if status, _ := patchAccountProfile(t, fixture, `{"display_name":"Parent"}`); status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", status)
	}
	disabled := newGitHubHTTPFixture(t, true, false)
	if status, _ := githubHTTPResponse(t, disabled.client, disabled.callbackURL(t, "")); status != http.StatusSeeOther {
		t.Fatalf("login: %d", status)
	}
	if status, _ := patchAccountProfile(t, disabled, `{"display_name":"Parent"}`); status != http.StatusNotFound {
		t.Fatalf("policy disabled: %d", status)
	}
	active := newGitHubHTTPFixture(t, true, true)
	if status, _ := githubHTTPResponse(t, active.client, active.callbackURL(t, "")); status != http.StatusSeeOther {
		t.Fatalf("login: %d", status)
	}
	profile := active.profile(t)
	if _, err := active.accounts.BeginAccountDisable(context.Background(), "github", profile["user_id"].(string)); err != nil {
		t.Fatal(err)
	}
	if status, _ := patchAccountProfile(t, active, `{"display_name":"Blocked Parent"}`); status != http.StatusForbidden {
		t.Fatalf("inactive account: %d", status)
	}

}

func TestAccountProfileCorrectionDatabaseFailureHTTP(t *testing.T) {
	fixture := newGitHubHTTPFixture(t, true, true)
	if status, _ := githubHTTPResponse(t, fixture.client, fixture.callbackURL(t, "")); status != http.StatusSeeOther {
		t.Fatalf("login: %d", status)
	}
	before := fixture.profile(t)
	store := fixture.accounts.(*DatabaseUserStore)
	if err := store.db.Exec("CREATE TRIGGER reject_profile_update BEFORE UPDATE ON user_profiles BEGIN SELECT RAISE(ABORT, 'test profile write failure'); END;").Error; err != nil {
		t.Fatal(err)
	}
	if status, _ := patchAccountProfile(t, fixture, `{"display_name":"Failed Correction"}`); status != http.StatusInternalServerError {
		t.Fatalf("write failure: %d", status)
	}
	if after := fixture.profile(t); after["display"] != before["display"] {
		t.Fatalf("partial account write: %v", after)
	}
	var override *string
	if err := store.db.Raw("SELECT display_name_override FROM accounts WHERE tenant_id = ? AND account_id = ?", "github", before["user_id"]).Scan(&override).Error; err != nil {
		t.Fatal(err)
	}
	if override != nil {
		t.Fatalf("failed correction persisted override: %v", *override)
	}
}

func TestAccountProfileCorrectionTenantBoundaryHTTP(t *testing.T) {
	store, err := NewDatabaseUserStore(context.Background(), sqliteDatabaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	identity := AccountProviderIdentity{Provider: "github", Subject: "123", UserEmail: "same@example.com", DisplayName: "Original"}
	first, err := store.UpsertProviderAccount(context.Background(), "tenant-a", identity)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.UpsertProviderAccount(context.Background(), "tenant-b", identity)
	if err != nil {
		t.Fatal(err)
	}
	serve := func(tenantID, accountID, name string) (int, string) {
		t.Helper()
		config := newTestServerConfig()
		config.TenantID = tenantID
		config.AccountManagementEnabled = true
		router := gin.New()
		MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(config), store, NewMemoryRefreshTokenStore(), nil, store, nil, nil)
		server := httptest.NewTLSServer(router)
		defer server.Close()
		token, _, err := MintAppJWT(NewSystemClock(), tenantID, accountID, "same@example.com", "Original", "", []string{"user"}, config.AppJWTIssuer, config.AppJWTSigningKey, config.SessionTTL)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequest(http.MethodPatch, server.URL+"/auth/account", strings.NewReader(`{"display_name":"`+name+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.AddCookie(&http.Cookie{Name: config.SessionCookieName, Value: token})
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		payload, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, string(payload)
	}
	if status, body := serve("tenant-a", first.AccountID, "First Parent"); status != http.StatusOK {
		t.Fatalf("tenant A: %d %s", status, body)
	}
	if status, body := serve("tenant-b", first.AccountID, "Cross Tenant"); status != http.StatusNotFound {
		t.Fatalf("cross tenant ID: %d %s", status, body)
	}
	if status, body := serve("tenant-b", second.AccountID, "Second Parent"); status != http.StatusOK {
		t.Fatalf("tenant B: %d %s", status, body)
	}
	_, secondName, _, _, err := store.GetUserProfile(context.Background(), "tenant-b", second.AccountID)
	if err != nil || secondName != "Second Parent" {
		t.Fatalf("missing tenant B profile: %s %v", secondName, err)
	}
	firstProfile, err := store.ResolveAccountProfile(context.Background(), "tenant-a", first.AccountID)
	if err != nil || firstProfile.DisplayName != "First Parent" {
		t.Fatalf("tenant A changed: %+v %v", firstProfile, err)
	}
}

func TestAccountProfileCorrectionSchemaUpgradeHTTP(t *testing.T) {
	fixture := newGitHubHTTPFixture(t, true, true)
	if status, _ := githubHTTPResponse(t, fixture.client, fixture.callbackURL(t, "")); status != http.StatusSeeOther {
		t.Fatalf("login: %d", status)
	}
	before := fixture.profile(t)
	oldStore := fixture.accounts.(*DatabaseUserStore)
	if err := oldStore.db.Migrator().DropColumn(&databaseAccountRecord{}, "DisplayNameOverride"); err != nil {
		t.Fatal(err)
	}
	if err := oldStore.db.Model(&schemaMigrationRecord{}).Where("store_name = ?", userStoreErrorPrefix).Update("version", 6).Error; err != nil {
		t.Fatal(err)
	}
	databaseHandle, err := oldStore.db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := databaseHandle.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewDatabaseUserStore(context.Background(), fixture.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := reopened.ResolveAccountProfile(context.Background(), "github", before["user_id"].(string))
	if err != nil || profile.DisplayName != before["display"] || profile.UserEmail != before["user_email"] {
		t.Fatalf("upgrade lost account: %+v %v", profile, err)
	}
	var migration schemaMigrationRecord
	if err := reopened.db.Where("store_name = ?", userStoreErrorPrefix).Take(&migration).Error; err != nil || migration.Version != userStoreSchemaVersion {
		t.Fatalf("schema upgrade: %+v %v", migration, err)
	}
	config := newTestServerConfig()
	config.TenantID = "github"
	config.AccountManagementEnabled = true
	config.PasswordAuthEnabled = true
	router := gin.New()
	MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(config), reopened, NewMemoryRefreshTokenStore(), nil, reopened, nil, nil)
	server := httptest.NewTLSServer(router)
	defer server.Close()
	token, _, err := MintAppJWT(NewSystemClock(), config.TenantID, profile.AccountID, profile.UserEmail, profile.DisplayName, "", profile.Roles, config.AppJWTIssuer, config.AppJWTSigningKey, config.SessionTTL)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPatch, server.URL+"/auth/account", strings.NewReader(`{"display_name":"Upgraded Parent"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: config.SessionCookieName, Value: token})
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("upgraded patch: %d", response.StatusCode)
	}
	challenge, err := reopened.CreatePasswordLink(context.Background(), config.TenantID, profile.AccountID, AccountPasswordRequest{UserEmail: "linked@example.com", DisplayName: "Password Name", Password: "correct horse battery staple"}, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.VerifyPasswordLink(context.Background(), config.TenantID, profile.AccountID, challenge.Token); err != nil {
		t.Fatal(err)
	}
	response, err = server.Client().Post(server.URL+"/auth/password/login", "application/json", strings.NewReader(`{"email":"linked@example.com","password":"correct horse battery staple"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(string(payload), `"display":"Upgraded Parent"`) {
		t.Fatalf("password login replaced correction: %d %s", response.StatusCode, payload)
	}
}

func TestAccountProfileCorrectionSplitStoreFailureHTTP(t *testing.T) {
	for _, database := range []bool{false, true} {
		label := "memory"
		if database {
			label = "database"
		}
		t.Run(label, func(t *testing.T) {
			config := newTestServerConfig()
			config.AccountManagementEnabled = true
			var credentials PasswordCredentialStore = NewMemoryPasswordCredentialStore()
			if database {
				store, err := NewDatabaseUserStore(context.Background(), sqliteDatabaseURL(t))
				if err != nil {
					t.Fatal(err)
				}
				credentials = store
			}
			accounts := credentials.(AccountManagementStore)
			profile, err := accounts.UpsertProviderAccount(context.Background(), config.TenantID, AccountProviderIdentity{Provider: "github", Subject: "123", UserEmail: "parent@example.com", DisplayName: "Original Parent"})
			if err != nil {
				t.Fatal(err)
			}
			router := gin.New()
			users := githubFailingUsers{UserStore: newTestUserStore()}
			MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(config), users, NewMemoryRefreshTokenStore(), nil, credentials, nil, nil)
			server := httptest.NewTLSServer(router)
			defer server.Close()
			token, _, err := MintAppJWT(NewSystemClock(), config.TenantID, profile.AccountID, profile.UserEmail, profile.DisplayName, "", profile.Roles, config.AppJWTIssuer, config.AppJWTSigningKey, config.SessionTTL)
			if err != nil {
				t.Fatal(err)
			}
			request, err := http.NewRequest(http.MethodPatch, server.URL+"/auth/account", strings.NewReader(`{"display_name":"Failed Parent"}`))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/json")
			request.AddCookie(&http.Cookie{Name: config.SessionCookieName, Value: token})
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusInternalServerError {
				t.Errorf("split profile error: %d", response.StatusCode)
			}
			after, err := accounts.ResolveAccountProfile(context.Background(), config.TenantID, profile.AccountID)
			if err != nil || after.DisplayName != "Original Parent" {
				t.Fatalf("failed profile write changed account: %+v %v", after, err)
			}
		})
	}
}

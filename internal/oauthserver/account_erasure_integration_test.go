package oauthserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/authkit"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAccountErasureHTTPOAuthActualPurge(t *testing.T) {
	for _, migrated := range []bool{false, true} {
		name := "new-account"
		if migrated {
			name = "retained-public-subject"
		}
		t.Run(name, func(t *testing.T) { testAccountErasureHTTPOAuthActualPurge(t, migrated) })
	}
}

func testAccountErasureHTTPOAuthActualPurge(t *testing.T, migrated bool) {
	ctx := context.Background()
	databaseURL := "sqlite://" + filepath.Join(t.TempDir(), "erasure.db")
	accounts, err := authkit.NewDatabaseUserStore(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := authkit.NewDatabaseRefreshTokenStore(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	oauth, err := NewDatabaseStore(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	_, tenantConfig := loadOAuthTestConfig(t, "https://auth.example.com")
	registry, err := authkit.BuildTenantRegistry(authkit.ServerConfig{AppJWTIssuer: "tauth"}, tenantConfig, authkit.NewSameSiteResolver(false))
	if err != nil {
		t.Fatal(err)
	}
	config := registry.DefaultConfig()
	config.AccountManagementEnabled = true
	config.PasswordAuthEnabled = true
	config.CookieDomain = ""
	registry = authkit.NewSingleTenantRegistry(config)
	challenge, err := accounts.CreatePasswordSignup(ctx, config.TenantID, authkit.AccountPasswordRequest{UserEmail: "parent@example.com", DisplayName: "Parent", Password: testOAuthPassword}, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	profile, err := accounts.VerifyEmailChallenge(ctx, config.TenantID, challenge.Token)
	if err != nil {
		t.Fatal(err)
	}
	if migrated {
		// The canonical fixture represents an account with a retained, previously issued application subject.
		db, err := authkit.OpenControlDatabase(ctx, databaseURL)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := db.DB()
		if err != nil {
			t.Fatal(err)
		}
		publicID := "email:parent@example.com"
		if err = db.Table("accounts").Where("tenant_id = ? AND account_id = ?", config.TenantID, profile.AccountID).Update("user_id", publicID).Error; err != nil {
			t.Fatal(err)
		}
		if err = db.Table("password_credentials").Where("tenant_id = ? AND account_id = ?", config.TenantID, profile.AccountID).Update("user_id", publicID).Error; err != nil {
			t.Fatal(err)
		}
		if err = raw.Close(); err != nil {
			t.Fatal(err)
		}
		profile, err = accounts.ResolveAccountProfile(ctx, config.TenantID, profile.AccountID)
		if err != nil {
			t.Fatal(err)
		}
		if profile.UserID != publicID || profile.UserID == profile.AccountID {
			t.Fatal("public and internal identities were not separated", profile)
		}
	}
	other, err := accounts.UpsertProviderAccount(ctx, config.TenantID, authkit.AccountProviderIdentity{Provider: "google", Subject: "other-parent", UserEmail: "other@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{profile.UserID, other.UserID} {
		consent, err := oauth.SaveConsent(ctx, Consent{ConsentKey: ConsentKey{TenantID: config.TenantID, UserID: user, ClientID: testOAuthClient, Resource: testOAuthResource, Scope: testOAuthScope}, ExpiresAtUnix: time.Now().Add(time.Hour).Unix()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := oauth.IssueAuthorizationCode(ctx, AuthorizationGrant{TenantID: config.TenantID, UserID: user, ConsentID: consent.ID, ClientID: testOAuthClient, Resource: testOAuthResource, ExpiresAtUnix: time.Now().Add(time.Hour).Unix()}, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := oauth.IssueRefreshToken(ctx, RefreshGrant{TenantID: config.TenantID, UserID: user, ConsentID: consent.ID, ClientID: testOAuthClient, Resource: testOAuthResource, ExpiresAtUnix: time.Now().Add(time.Hour).Unix()}, 0); err != nil {
			t.Fatal(err)
		}
	}
	router := gin.New()
	authkit.MountAuthRoutesWithPassword(router, registry, accounts, refresh, nil, accounts, newTestPasswordResetDispatcher(t), nil, oauth)
	server := httptest.NewTLSServer(router)
	defer server.Close()
	client := server.Client()
	client.Jar, _ = cookiejar.New(nil)
	response, err := client.Post(server.URL+"/auth/password/login", "application/json", strings.NewReader(`{"email":"parent@example.com","password":"`+testOAuthPassword+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("login: %d", response.StatusCode)
	}
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		t.Fatal(err)
	}
	key := base64.RawURLEncoding.EncodeToString(bytes)
	request, _ := http.NewRequest(http.MethodDelete, server.URL+"/auth/account", strings.NewReader(`{"status_key":"`+key+`"}`))
	request.Header.Set("Content-Type", "application/json")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 202 || body["state"] != "completed" {
		t.Fatalf("erasure: %d %+v", response.StatusCode, body)
	}
	for _, record := range []any{&databaseConsent{}, &databaseAuthorizationCode{}, &databaseOAuthRefreshToken{}} {
		var count int64
		if err := oauth.db.Model(record).Where("tenant_id = ? AND user_id = ?", config.TenantID, profile.UserID).Count(&count).Error; err != nil || count != 0 {
			t.Fatalf("owned OAuth data retained: %d %v", count, err)
		}
		if err := oauth.db.Model(record).Where("tenant_id = ? AND user_id = ?", config.TenantID, other.UserID).Count(&count).Error; err != nil || count != 1 {
			t.Fatalf("unrelated OAuth data changed: %d %v", count, err)
		}
	}
	if _, err := oauth.SaveConsent(ctx, Consent{ConsentKey: ConsentKey{TenantID: config.TenantID, UserID: profile.UserID}}); err == nil {
		t.Fatal("erased account consent recreated")
	}
}

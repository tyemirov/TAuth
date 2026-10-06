package authkit

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestApplicationSubjectAppleHTTP(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(response).Encode(mockAppleJWKS(key, "apple-subject-key")); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(provider.Close)
	ProvideAppleOAuthHTTPClient(provider.Client())
	t.Cleanup(func() { ProvideAppleOAuthHTTPClient(nil) })
	config := newTestServerConfig()
	config.AppleOAuth = AppleOAuthConfig{Enabled: true, ClientID: "com.example.web", NativeClientIDs: []string{"com.example.ios"}, JWKSURL: provider.URL + "/auth/keys"}
	databaseURL := sqliteDatabaseURL(t)
	users, err := NewDatabaseUserStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := NewDatabaseRefreshTokenStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	registry := NewSingleTenantRegistry(config)
	fixtureRouter := newApplicationSubjectRouter(registry, users, refresh)
	server := httptest.NewTLSServer(fixtureRouter)
	t.Cleanup(server.Close)
	client := server.Client()
	client.Jar, _ = cookiejar.New(nil)
	login := func(email string, includeName bool) string {
		nonce := issueNonceViaClient(t, client, server.URL)
		token := mintMockAppleIDToken(t, key, "apple-subject-key", "com.example.ios", "stable-apple", email, "", nonce)
		body := map[string]any{"apple_id_token": token, "nonce_token": nonce}
		if includeName {
			body["full_name"] = map[string]string{"given_name": "Apple", "family_name": "Parent"}
		}
		payload, _ := json.Marshal(body)
		response, err := client.Post(server.URL+"/auth/apple/native", "application/json", strings.NewReader(string(payload)))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var result map[string]any
		if err = json.NewDecoder(response.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK {
			t.Fatalf("Apple login=%d %v", response.StatusCode, result)
		}
		if result["display"] != "Apple Parent" {
			t.Fatalf("provider omitted name replaced accepted profile: %v", result)
		}
		return result["user_id"].(string)
	}
	original := login("original@example.com", true)
	assertOpaqueAccountID(t, original)
	for _, enabled := range []bool{true, false, true} {
		next := registry.configs[config.TenantID]
		next.AccountManagementEnabled = enabled
		registry.configs[config.TenantID] = next
		if id := login("changed@example.com", false); id != original {
			t.Fatalf("Apple flag/email changed subject: %s", id)
		}
	}
	raw, _ := users.db.DB()
	if err = raw.Close(); err != nil {
		t.Fatal(err)
	}
	users, err = NewDatabaseUserStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = newApplicationSubjectRouter(registry, users, refresh)
	if id := login("changed@example.com", false); id != original {
		t.Fatal("Apple restart changed public subject")
	}
	account, err := users.ResolveAccountForUser(context.Background(), config.TenantID, original)
	if err != nil || account.UserEmail != "changed@example.com" {
		t.Fatalf("Apple account=%+v %v", account, err)
	}
}

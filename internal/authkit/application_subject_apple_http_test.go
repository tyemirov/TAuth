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
		if request.URL.Path == "/auth/token" {
			_ = request.ParseForm()
			_ = json.NewEncoder(response).Encode(map[string]any{"id_token": request.PostForm.Get("code"), "refresh_token": "stable-refresh"})
			return
		}
		response.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(response).Encode(mockAppleJWKS(key, "apple-subject-key")); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(provider.Close)
	ProvideAppleOAuthHTTPClient(provider.Client())
	t.Cleanup(func() { ProvideAppleOAuthHTTPClient(nil) })
	config := newTestServerConfig()
	config.AppleOAuth = AppleOAuthConfig{Enabled: true, ClientID: "com.example.web", NativeClientIDs: []string{"com.example.ios"}, JWKSURL: provider.URL + "/auth/keys", TokenEndpoint: provider.URL + "/auth/token", PrivateKey: generateTestAppleClientPrivateKeyPEM(t), TeamID: "TEAM", KeyID: "KEY"}
	databaseURL := sqliteDatabaseURL(t)
	users, err := NewDatabaseUserStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := NewDatabaseRefreshTokenStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	users.SetProviderGrantCipher(newTestProviderGrantCipher(t))
	registry := NewSingleTenantRegistry(config)
	fixtureRouter := newApplicationSubjectRouter(t, registry, users, refresh)
	server := httptest.NewTLSServer(fixtureRouter)
	t.Cleanup(server.Close)
	client := server.Client()
	client.Jar, _ = cookiejar.New(nil)
	login := func(email string, includeName bool) string {
		nonce := issueNonceViaClient(t, client, server.URL)
		token := mintMockAppleIDToken(t, key, "apple-subject-key", "com.example.ios", "stable-apple", email, "", nonce)
		body := map[string]any{"apple_id_token": token, "authorization_code": token, "nonce_token": nonce}
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
	users.SetProviderGrantCipher(newTestProviderGrantCipher(t))
	server.Config.Handler = newApplicationSubjectRouter(t, registry, users, refresh)
	if id := login("changed@example.com", false); id != original {
		t.Fatal("Apple restart changed public subject")
	}
	account, err := users.ResolveAccountForUser(context.Background(), config.TenantID, original)
	if err != nil || account.UserEmail != "changed@example.com" {
		t.Fatalf("Apple account=%+v %v", account, err)
	}
}

func TestApplicationSubjectAppleNativeRequiresAuthorizationCodeHTTP(t *testing.T) {
	config := newTestServerConfig()
	config.AppleOAuth = AppleOAuthConfig{Enabled: true, ClientID: "com.example.web", NativeClientIDs: []string{"com.example.ios"}}
	users, err := NewDatabaseUserStore(context.Background(), sqliteDatabaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(newApplicationSubjectRouter(t, NewSingleTenantRegistry(config), users, NewMemoryRefreshTokenStore()))
	defer server.Close()
	client := server.Client()
	nonce := issueNonceViaClient(t, client, server.URL)
	response, err := client.Post(server.URL+"/auth/apple/native", "application/json", strings.NewReader(`{"apple_id_token":"token","nonce_token":"`+nonce+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result map[string]any
	_ = json.NewDecoder(response.Body).Decode(&result)
	if response.StatusCode != http.StatusBadRequest || result["error"] != "missing_authorization_code" {
		t.Fatalf("native Apple missing code = %d %v", response.StatusCode, result)
	}
}

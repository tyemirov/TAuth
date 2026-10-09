package authkit

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testProviderGrantCipher struct{ cipher cipher.AEAD }

func newTestProviderGrantCipher(t *testing.T) testProviderGrantCipher {
	t.Helper()
	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return testProviderGrantCipher{aead}
}
func (box testProviderGrantCipher) SealProviderGrant(binding string, value []byte) ([]byte, error) {
	nonce := make([]byte, box.cipher.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return box.cipher.Seal(nonce, nonce, value, []byte(binding)), nil
}
func (box testProviderGrantCipher) OpenProviderGrant(binding string, value []byte) ([]byte, error) {
	if len(value) < box.cipher.NonceSize() {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	return box.cipher.Open(nil, value[:box.cipher.NonceSize()], value[box.cipher.NonceSize():], []byte(binding))
}
func newAppleHTTPUserStore(t *testing.T) *DatabaseUserStore {
	t.Helper()
	store, err := NewDatabaseUserStore(context.Background(), sqliteDatabaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	store.SetProviderGrantCipher(newTestProviderGrantCipher(t))
	return store
}

// The local protocol fixture uses the supplied signed ID token as its one-time code.
func mountAppleTestCodeExchange(router *http.ServeMux) {
	router.HandleFunc("/auth/token", func(response http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil {
			http.Error(response, "invalid form", 400)
			return
		}
		if request.PostForm.Get("redirect_uri") != "" {
			http.Error(response, "native redirect URI supplied", 400)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"id_token": request.PostForm.Get("code"), "refresh_token": "fixture-refresh"})
	})
}

func TestAppleErasureMissingGrantRemovesLocalAccountHTTP(t *testing.T) {
	fixture := newErasureHTTPFixture(t)
	fixture.accounts.SetProviderGrantCipher(newTestProviderGrantCipher(t))
	if _, err := fixture.accounts.LinkProviderIdentity(context.Background(), fixture.config.TenantID, fixture.profile.AccountID, AccountProviderIdentity{Provider: "apple", Subject: "historical-apple", UserEmail: "parent@example.com"}); err != nil {
		t.Fatal(err)
	}
	key := newErasureStatusKey(t)
	status, operation := erasureHTTP(t, fixture, http.MethodDelete, "/auth/account", key)
	if status != 202 || operation["account_state"] != "removed" || operation["state"] != "blocked" || operation["reason"] != appleManualReason || operation["expires_at"] != nil {
		t.Fatalf("missing grant outcome: %d %+v", status, operation)
	}
	providers := operation["provider_revocations"].([]any)
	if len(providers) != 1 || providers[0].(map[string]any)["state"] != providerManual {
		t.Fatalf("provider status %+v", providers)
	}
	if _, err := fixture.accounts.ResolveAccountProfile(context.Background(), fixture.config.TenantID, fixture.profile.AccountID); err == nil {
		t.Fatal("local account retained")
	}
	if _, err := fixture.accounts.UpsertProviderAccount(context.Background(), fixture.config.TenantID, AccountProviderIdentity{Provider: "apple", Subject: "historical-apple", UserEmail: "parent@example.com"}); err == nil {
		t.Fatal("manual revocation fence bypassed")
	}
	if status, retry := erasureHTTP(t, fixture, http.MethodGet, "/auth/account-erasure", key); status != 200 || retry["account_state"] != "removed" {
		t.Fatalf("status capability recovery: %d %+v", status, retry)
	}
}

type appleRevokeTestTransport struct {
	target string
	base   http.RoundTripper
}

func (transport appleRevokeTestTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.String() == appleRevokeEndpoint {
		copy := request.Clone(request.Context())
		target, err := url.Parse(transport.target + "/auth/revoke")
		if err != nil {
			return nil, err
		}
		copy.URL = target
		return transport.base.RoundTrip(copy)
	}
	return transport.base.RoundTrip(request)
}

func TestAppleGrantCaptureAndErasureRestartHTTP(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var failRevoke atomic.Bool
	failRevoke.Store(true)
	var revokes atomic.Int64
	var exchangeMismatch atomic.Bool
	var missingRefresh atomic.Bool
	var nativeToken string
	provider := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/auth/keys":
			_ = json.NewEncoder(response).Encode(mockAppleJWKS(key, "grant-key"))
		case "/auth/token":
			if err := request.ParseForm(); err != nil {
				t.Error(err)
				response.WriteHeader(400)
				return
			}
			if request.PostForm.Get("client_id") != "com.example.ios" || request.PostForm.Get("redirect_uri") != "" {
				t.Errorf("native code audience/redirect mismatch: %v", request.PostForm)
				response.WriteHeader(400)
				return
			}
			idToken := request.PostForm.Get("code")
			if exchangeMismatch.Load() {
				idToken = mintMockAppleIDToken(t, key, "grant-key", "com.example.ios", "different-subject", "parent@example.com", "", "nonce")
			}
			refresh := "captured-sensitive-refresh"
			if missingRefresh.Load() {
				refresh = ""
			}
			_ = json.NewEncoder(response).Encode(map[string]any{"id_token": idToken, "refresh_token": refresh})
		case "/auth/revoke":
			revokes.Add(1)
			_ = request.ParseForm()
			if request.PostForm.Get("client_id") != "com.example.ios" || request.PostForm.Get("token") != "captured-sensitive-refresh" || request.PostForm.Get("token_type_hint") != "refresh_token" {
				t.Errorf("wrong revocation form %v", request.PostForm)
				response.WriteHeader(400)
				return
			}
			if failRevoke.Load() {
				response.WriteHeader(503)
				return
			}
			response.WriteHeader(200)
		default:
			response.WriteHeader(404)
		}
	}))
	defer provider.Close()
	client := provider.Client()
	client.Transport = appleRevokeTestTransport{provider.URL, client.Transport}
	ProvideAppleOAuthHTTPClient(client)
	defer ProvideAppleOAuthHTTPClient(nil)
	config := newTestServerConfig()
	config.AccountManagementEnabled = true
	config.AppleOAuth = AppleOAuthConfig{Enabled: true, ClientID: "com.example.web", NativeClientIDs: []string{"com.example.ios"}, PrivateKey: generateTestAppleClientPrivateKeyPEM(t), TeamID: "TEAM", KeyID: "KEY", TokenEndpoint: provider.URL + "/auth/token", JWKSURL: provider.URL + "/auth/keys"}
	databaseURL := sqliteDatabaseURL(t)
	users, err := NewDatabaseUserStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	box := newTestProviderGrantCipher(t)
	users.SetProviderGrantCipher(box)
	refresh, err := NewDatabaseRefreshTokenStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	registry := NewSingleTenantRegistry(config)
	revoker := NewAppleAccountRevoker(users, func(context.Context, string) (AppleOAuthConfig, error) { return config.AppleOAuth, nil }, client)
	router := gin.New()
	MountAuthRoutesWithPassword(router, registry, users, refresh, nil, users, newTestPasswordResetDispatcher(t), nil, nil, revoker)
	server := httptest.NewTLSServer(router)
	defer server.Close()
	browser := server.Client()
	browser.Jar, _ = cookiejar.New(nil)
	login := func() (*http.Response, map[string]any) {
		t.Helper()
		nonce := issueNonceViaClient(t, browser, server.URL)
		nativeToken = mintMockAppleIDToken(t, key, "grant-key", "com.example.ios", "grant-subject", "parent@example.com", "Parent", nonce)
		payload, _ := json.Marshal(map[string]string{"apple_id_token": nativeToken, "authorization_code": nativeToken, "nonce_token": nonce})
		response, err := browser.Post(server.URL+"/auth/apple/native", "application/json", bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		_ = json.NewDecoder(response.Body).Decode(&body)
		response.Body.Close()
		return response, body
	}
	exchangeMismatch.Store(true)
	response, _ := login()
	if response.StatusCode != 401 || len(response.Cookies()) != 0 {
		t.Fatalf("mismatched exchange accepted: %d", response.StatusCode)
	}
	exchangeMismatch.Store(false)
	missingRefresh.Store(true)
	response, _ = login()
	if response.StatusCode != 503 || len(response.Cookies()) != 0 {
		t.Fatalf("missing grant issued session: %d", response.StatusCode)
	}
	missingRefresh.Store(false)
	response, body := login()
	if response.StatusCode != 200 {
		t.Fatalf("native login=%d %+v", response.StatusCode, body)
	}
	publicID := body["user_id"].(string)
	profile, err := users.ResolveAccountForUser(context.Background(), config.TenantID, publicID)
	if err != nil {
		t.Fatal(err)
	}
	var grant databaseAppleGrant
	if err := users.db.Take(&grant).Error; err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(grant.Ciphertext, []byte("captured-sensitive-refresh")) || bytes.Contains(grant.Ciphertext, []byte("grant-subject")) {
		t.Fatal("unencrypted provider grant")
	}
	fixture := &erasureHTTPFixture{server: server, client: browser, accounts: users, refresh: refresh, profile: profile, config: config, databaseURL: databaseURL}
	statusKey := newErasureStatusKey(t)
	status, operation := erasureHTTP(t, fixture, http.MethodDelete, "/auth/account", statusKey)
	if status != 202 || operation["account_state"] != "removed" || operation["state"] != "blocked" || revokes.Load() != 1 {
		t.Fatalf("failed revocation/local removal: %d %+v requests=%d", status, operation, revokes.Load())
	}
	var grantRows int64
	users.db.Model(&databaseAppleGrant{}).Count(&grantRows)
	if grantRows != 0 {
		t.Fatal("account-owned grant survived purge")
	}
	var snapshots []databaseErasureProvider
	users.db.Find(&snapshots)
	if len(snapshots) != 1 || len(snapshots[0].Ciphertext) == 0 {
		t.Fatal("recovery grant lost")
	}
	raw, _ := users.db.DB()
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewDatabaseUserStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	reopened.SetProviderGrantCipher(box)
	reopened.now = func() time.Time { return time.Now().Add(time.Minute) }
	failRevoke.Store(false)
	resumedRevoker := NewAppleAccountRevoker(reopened, func(context.Context, string) (AppleOAuthConfig, error) { return config.AppleOAuth, nil }, client)
	coordinator, err := NewAccountErasureCoordinator(reopened, reopened, refresh, nil, resumedRevoker)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	recoveredRouter := gin.New()
	MountAuthRoutesWithPassword(recoveredRouter, registry, reopened, refresh, nil, reopened, newTestPasswordResetDispatcher(t), nil, nil, resumedRevoker)
	server.Config.Handler = recoveredRouter
	if status, receipt := erasureHTTP(t, fixture, http.MethodGet, "/auth/account-erasure", statusKey); status != 200 || receipt["state"] != "completed" || receipt["account_state"] != "removed" {
		t.Fatalf("restart completion: %d %+v", status, receipt)
	}
	var final databaseErasureProvider
	reopened.db.Take(&final)
	if final.State != providerRevoked || len(final.Ciphertext) != 0 || final.SubjectHash != "" {
		t.Fatalf("completed provider secret retained %+v", final)
	}
	if revokes.Load() != 2 {
		t.Fatalf("restart did not retry exact captured grant: %d", revokes.Load())
	}
}

func TestAppleErasureVerifiedNotificationHTTP(t *testing.T) {
	fixture := newErasureHTTPFixture(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(response).Encode(mockAppleJWKS(key, "notification-key"))
	}))
	defer provider.Close()
	ProvideAppleOAuthHTTPClient(provider.Client())
	defer ProvideAppleOAuthHTTPClient(nil)
	fixture.config.AppleOAuth = AppleOAuthConfig{Enabled: true, ClientID: "com.example.service", NotificationAudience: "com.example.primary", JWKSURL: provider.URL}
	router := gin.New()
	MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(fixture.config), fixture.accounts, fixture.refresh, nil, fixture.accounts, newTestPasswordResetDispatcher(t), nil, nil)
	fixture.server.Config.Handler = router
	subject := "historical-notification-subject"
	if _, err := fixture.accounts.LinkProviderIdentity(context.Background(), fixture.config.TenantID, fixture.profile.AccountID, AccountProviderIdentity{Provider: "apple", Subject: subject, UserEmail: "parent@example.com"}); err != nil {
		t.Fatal(err)
	}
	secondSubject := "second-historical-subject"
	if _, err := fixture.accounts.LinkProviderIdentity(context.Background(), fixture.config.TenantID, fixture.profile.AccountID, AccountProviderIdentity{Provider: "apple", Subject: secondSubject, UserEmail: "parent@example.com"}); err != nil {
		t.Fatal(err)
	}
	statusKey := newErasureStatusKey(t)
	_, operation := erasureHTTP(t, fixture, http.MethodDelete, "/auth/account", statusKey)
	if operation["account_state"] != "removed" || operation["reason"] != appleManualReason {
		t.Fatalf("notification prerequisite %+v", operation)
	}
	claims := jwt.MapClaims{"iss": appleIssuer, "aud": "com.example.primary", "iat": time.Now().Add(time.Second).Unix(), "jti": "current-consent", "events": map[string]any{"type": "consent-revoked", "sub": subject, "event_time": time.Now().Add(time.Second).Unix()}}
	post := func(claims jwt.MapClaims, signingKey *rsa.PrivateKey) int {
		t.Helper()
		token := mintMockAppleIDTokenWithClaims(t, signingKey, "notification-key", claims)
		body, _ := json.Marshal(map[string]string{"payload": token})
		response, err := fixture.client.Post(fixture.server.URL+"/auth/apple/notifications", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		return response.StatusCode
	}
	badKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name       string
		change     func(jwt.MapClaims, map[string]any)
		signingKey *rsa.PrivateKey
		status     int
	}{
		{"signature", func(jwt.MapClaims, map[string]any) {}, badKey, 401},
		{"issuer", func(c jwt.MapClaims, e map[string]any) { c["iss"] = "https://other.example" }, key, 401},
		{"audience", func(c jwt.MapClaims, e map[string]any) { c["aud"] = "other-primary" }, key, 401},
		{"subject", func(c jwt.MapClaims, e map[string]any) { e["sub"] = "other-subject" }, key, 204},
		{"stale", func(c jwt.MapClaims, e map[string]any) { e["event_time"] = time.Now().Add(-time.Minute).Unix() }, key, 204},
		{"same-second", func(c jwt.MapClaims, e map[string]any) { e["event_time"] = time.Now().Unix() }, key, 204},
		{"future", func(c jwt.MapClaims, e map[string]any) { e["event_time"] = time.Now().Add(10 * time.Minute).Unix() }, key, 401},
		{"email-only", func(c jwt.MapClaims, e map[string]any) { e["type"] = "email-disabled" }, key, 204},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			encoded, _ := json.Marshal(claims)
			var candidate jwt.MapClaims
			_ = json.Unmarshal(encoded, &candidate)
			candidate["jti"] = testCase.name
			testCase.change(candidate, candidate["events"].(map[string]any))
			if status := post(candidate, testCase.signingKey); status != testCase.status {
				t.Fatalf("invalid notification status=%d want=%d", status, testCase.status)
			}
			if _, receipt := erasureHTTP(t, fixture, http.MethodGet, "/auth/account-erasure", statusKey); receipt["state"] == "completed" {
				t.Fatalf("invalid notification completed operation %+v", receipt)
			}
		})
	}
	if status := post(claims, key); status != http.StatusNoContent {
		t.Fatalf("verified notification status=%d", status)
	}
	if _, receipt := erasureHTTP(t, fixture, http.MethodGet, "/auth/account-erasure", statusKey); receipt["state"] == "completed" {
		t.Fatal("first subject completed second subject obligation")
	}
	claims["jti"] = "second-account-deleted"
	claims["events"].(map[string]any)["sub"] = secondSubject
	claims["events"].(map[string]any)["type"] = "account-deleted"
	if status := post(claims, key); status != 204 {
		t.Fatalf("second subject event=%d", status)
	}
	if status, receipt := erasureHTTP(t, fixture, http.MethodGet, "/auth/account-erasure", statusKey); status != 200 || receipt["state"] != "completed" {
		t.Fatalf("manual provider completion: %d %+v", status, receipt)
	}
	if status := post(claims, key); status != http.StatusNoContent {
		t.Fatalf("duplicate notification=%d", status)
	}
	// A delayed receipt from the first operation cannot acknowledge a new generation.
	fixture.accounts.now = func() time.Time { return time.Now().Add(10 * time.Second) }
	recreated, err := fixture.accounts.UpsertProviderAccount(context.Background(), fixture.config.TenantID, AccountProviderIdentity{Provider: "apple", Subject: secondSubject, UserEmail: "parent@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := MintAppJWT(NewSystemClock(), fixture.config.TenantID, recreated.UserID, recreated.UserEmail, recreated.DisplayName, recreated.AvatarURL, recreated.Roles, fixture.config.AppJWTIssuer, fixture.config.AppJWTSigningKey, fixture.config.SessionTTL)
	if err != nil {
		t.Fatal(err)
	}
	origin, _ := url.Parse(fixture.server.URL)
	fixture.client.Jar.SetCookies(origin, []*http.Cookie{{Name: fixture.config.SessionCookieName, Value: token, Path: "/", Secure: true}})
	newerKey := newErasureStatusKey(t)
	status, newer := erasureHTTP(t, fixture, http.MethodDelete, "/auth/account", newerKey)
	if status != 202 || newer["state"] != "blocked" {
		t.Fatalf("new generation: %d %+v", status, newer)
	}
	if status := post(claims, key); status != 204 {
		t.Fatalf("old duplicate notification: %d", status)
	}
	claims["jti"] = "delayed-old-generation"
	if status := post(claims, key); status != 204 {
		t.Fatalf("delayed old event: %d", status)
	}
	if _, receipt := erasureHTTP(t, fixture, http.MethodGet, "/auth/account-erasure", newerKey); receipt["state"] == "completed" {
		t.Fatal("old event completed newer generation")
	}

}

func TestAppleErasureNotificationCannotRegressInFlightGrantHTTP(t *testing.T) {
	fixture := newErasureHTTPFixture(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	first, second := "concurrent-subject-a", "concurrent-subject-b"
	if hashOpaque(first) > hashOpaque(second) {
		first, second = second, first
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	var unblock sync.Once
	defer unblock.Do(func() { close(release) })
	var secondRequests atomic.Int64
	provider := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/auth/keys" {
			_ = json.NewEncoder(response).Encode(mockAppleJWKS(key, "concurrent-key"))
			return
		}
		_ = request.ParseForm()
		if request.PostForm.Get("token") == "first-refresh" {
			close(entered)
			<-release
			response.WriteHeader(200)
			return
		}
		if request.PostForm.Get("token") == "second-refresh" {
			secondRequests.Add(1)
			response.WriteHeader(503)
			return
		}
		response.WriteHeader(400)
	}))
	defer provider.Close()
	providerClient := provider.Client()
	providerClient.Transport = appleRevokeTestTransport{provider.URL, providerClient.Transport}
	ProvideAppleOAuthHTTPClient(providerClient)
	defer ProvideAppleOAuthHTTPClient(nil)
	config := fixture.config
	config.AppleOAuth = AppleOAuthConfig{Enabled: true, ClientID: "com.example.service", NativeClientIDs: []string{"com.example.ios"}, NotificationAudience: "com.example.primary", TeamID: "TEAM", KeyID: "KEY", PrivateKey: generateTestAppleClientPrivateKeyPEM(t), JWKSURL: provider.URL + "/auth/keys"}
	for index, subject := range []string{first, second} {
		if _, err := fixture.accounts.LinkProviderIdentity(context.Background(), config.TenantID, fixture.profile.AccountID, AccountProviderIdentity{Provider: "apple", Subject: subject, UserEmail: "parent@example.com"}); err != nil {
			t.Fatal(err)
		}
		token := []string{"first-refresh", "second-refresh"}[index]
		if err := persistAppleLoginGrant(context.Background(), fixture.accounts, config.TenantID, fixture.profile.AccountID, appleIdentity{Subject: subject, Audience: "com.example.ios"}, appleTokenResponse{RefreshToken: token}); err != nil {
			t.Fatal(err)
		}
	}
	registry := NewSingleTenantRegistry(config)
	revoker := NewAppleAccountRevoker(fixture.accounts, func(context.Context, string) (AppleOAuthConfig, error) { return config.AppleOAuth, nil }, providerClient)
	router := gin.New()
	MountAuthRoutesWithPassword(router, registry, fixture.accounts, fixture.refresh, nil, fixture.accounts, newTestPasswordResetDispatcher(t), nil, nil, revoker)
	fixture.server.Config.Handler = router
	statusKey := newErasureStatusKey(t)
	result := make(chan map[string]any, 1)
	go func() {
		_, operation := erasureHTTP(t, fixture, http.MethodDelete, "/auth/account", statusKey)
		result <- operation
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first grant revocation did not start")
	}
	claims := jwt.MapClaims{"iss": appleIssuer, "aud": "com.example.primary", "iat": time.Now().Add(time.Second).Unix(), "jti": "concurrent-second-ack", "events": map[string]any{"type": "consent-revoked", "sub": second, "event_time": time.Now().Add(time.Second).Unix()}}
	signed := mintMockAppleIDTokenWithClaims(t, key, "concurrent-key", claims)
	body, _ := json.Marshal(map[string]string{"payload": signed})
	response, err := fixture.client.Post(fixture.server.URL+AppleNotificationPath, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatalf("concurrent notification: %d", response.StatusCode)
	}
	unblock.Do(func() { close(release) })
	operation := <-result
	if operation["state"] != "completed" || secondRequests.Load() != 0 {
		t.Fatalf("notification progress regressed: %+v second_requests=%d", operation, secondRequests.Load())
	}
	var obligation databaseErasureProvider
	if err := fixture.accounts.db.Where("provider = ?", accountProviderApple).Take(&obligation).Error; err != nil {
		t.Fatal(err)
	}
	if obligation.State != providerRevoked || len(obligation.Ciphertext) != 0 {
		t.Fatal("acknowledged grant/token restored")
	}
}

func TestAppleErasureLegacySchemaReopenHTTP(t *testing.T) {
	for _, completed := range []bool{false, true} {
		t.Run(fmt.Sprint("completed=", completed), func(t *testing.T) {
			fixture := newErasureHTTPFixture(t)
			key := newErasureStatusKey(t)
			var original databaseAccountErasure
			if completed {
				if status, operation := erasureHTTP(t, fixture, http.MethodDelete, "/auth/account", key); status != 202 || operation["state"] != erasureCompleted {
					t.Fatalf("completed legacy setup: %d %+v", status, operation)
				}
				if err := fixture.accounts.db.Take(&original).Error; err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := fixture.accounts.LinkProviderIdentity(context.Background(), fixture.config.TenantID, fixture.profile.AccountID, AccountProviderIdentity{Provider: "apple", Subject: "legacy-apple-subject", UserEmail: "parent@example.com"}); err != nil {
					t.Fatal(err)
				}
				id, err := newOpaqueAccountID()
				if err != nil {
					t.Fatal(err)
				}
				user, account := fixture.profile.UserID, fixture.profile.AccountID
				now := time.Now().Unix()
				original = databaseAccountErasure{UserID: &user, AccountID: &account, OperationID: id, TenantID: fixture.config.TenantID, StatusHash: hashOpaque(key), State: erasureBlocked, Reason: erasureProviderUnavailable, Phase: erasureProviderPhase, CreatedUnix: now, UpdatedUnix: now}
				if err := fixture.accounts.db.Create(&original).Error; err != nil {
					t.Fatal(err)
				}
				if err := fixture.accounts.db.Model(&databaseAccountRecord{}).Where("account_id = ?", account).Update("account_state", accountStateErasing).Error; err != nil {
					t.Fatal(err)
				}
			}
			// Model the actual version-eight columns before the public store reopen.
			for _, column := range []string{"AccountState", "ProviderSnapshot"} {
				if err := fixture.accounts.db.Migrator().DropColumn(&databaseAccountErasure{}, column); err != nil {
					t.Fatal(err)
				}
			}
			if err := fixture.accounts.db.Model(&schemaMigrationRecord{}).Where(schemaMigrationLookupByName, userStoreErrorPrefix).Update("version", 8).Error; err != nil {
				t.Fatal(err)
			}
			raw, _ := fixture.accounts.db.DB()
			if err := raw.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := NewDatabaseUserStore(context.Background(), fixture.databaseURL)
			if err != nil {
				t.Fatal(err)
			}
			reopened.SetProviderGrantCipher(newTestProviderGrantCipher(t))
			config := fixture.config
			config.AppleOAuth = AppleOAuthConfig{Enabled: true, ClientID: "com.example.service", NotificationAudience: "com.example.explicit-primary"}
			notificationKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(mockAppleJWKS(notificationKey, "legacy-notification-key"))
			}))
			defer provider.Close()
			ProvideAppleOAuthHTTPClient(provider.Client())
			defer ProvideAppleOAuthHTTPClient(nil)
			config.AppleOAuth.JWKSURL = provider.URL

			revoker := NewAppleAccountRevoker(reopened, func(context.Context, string) (AppleOAuthConfig, error) { return config.AppleOAuth, nil }, nil)
			coordinator, err := NewAccountErasureCoordinator(reopened, reopened, fixture.refresh, nil, revoker)
			if err != nil {
				t.Fatal(err)
			}
			resumeErr := coordinator.Resume(context.Background())
			if completed && resumeErr != nil {
				t.Fatal(resumeErr)
			}
			if !completed && !errors.Is(resumeErr, errAppleManual) {
				t.Fatalf("legacy recovery failure: %v", resumeErr)
			}
			router := gin.New()
			MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(config), reopened, fixture.refresh, nil, reopened, newTestPasswordResetDispatcher(t), nil, nil, revoker)
			fixture.server.Config.Handler = router
			status, receipt := erasureHTTP(t, fixture, http.MethodGet, "/auth/account-erasure", key)
			if status != 200 || receipt["operation_id"] != original.OperationID || receipt["account_state"] != erasureAccountRemoved {
				t.Fatalf("legacy receipt: %d %+v", status, receipt)
			}
			expected := erasureCompleted
			if !completed {
				expected = erasureBlocked
			}
			if receipt["state"] != expected {
				t.Fatalf("legacy operation state %+v", receipt)
			}
			if !completed {
				var obligation databaseErasureProvider
				if err := reopened.db.Where("operation_id = ? AND provider = ?", original.OperationID, accountProviderApple).Take(&obligation).Error; err != nil {
					t.Fatal(err)
				}
				clear, err := reopened.providerGrantCipher.OpenProviderGrant(appleErasureBinding(config.TenantID, original.OperationID), obligation.Ciphertext)
				if err != nil {
					t.Fatal(err)
				}
				var snapshot appleErasureSnapshot
				if err := json.Unmarshal(clear, &snapshot); err != nil {
					t.Fatal(err)
				}
				if snapshot.NotificationAudience != "com.example.explicit-primary" || len(snapshot.Grants) != 1 || snapshot.Grants[0].Subject != "legacy-apple-subject" {
					t.Fatalf("legacy explicit binding lost %+v", snapshot)
				}
				claims := jwt.MapClaims{"iss": appleIssuer, "aud": "com.example.explicit-primary", "iat": time.Now().Add(time.Second).Unix(), "jti": "legacy-ack", "events": map[string]any{"type": "consent-revoked", "sub": "legacy-apple-subject", "event_time": time.Now().Add(time.Second).Unix()}}
				signed := mintMockAppleIDTokenWithClaims(t, notificationKey, "legacy-notification-key", claims)
				payload, _ := json.Marshal(map[string]string{"payload": signed})
				response, err := fixture.client.Post(fixture.server.URL+AppleNotificationPath, "application/json", bytes.NewReader(payload))
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if response.StatusCode != 204 {
					t.Fatalf("legacy verified notification=%d", response.StatusCode)
				}
				if status, final := erasureHTTP(t, fixture, http.MethodGet, "/auth/account-erasure", key); status != 200 || final["state"] != erasureCompleted || final["operation_id"] != original.OperationID {
					t.Fatalf("legacy notification completion: %d %+v", status, final)
				}

			}
		})
	}
}

package authkit

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/tyemirov/tauth/internal/tenants"
	"github.com/tyemirov/tauth/pkg/sessionvalidator"
	"go.uber.org/zap/zaptest"
	"google.golang.org/api/idtoken"
)

type inProcessTransport struct {
	handler http.Handler
}

func (transport *inProcessTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if transport.handler == nil {
		return nil, errors.New("in_process_transport.handler_missing")
	}
	if request == nil {
		return nil, errors.New("in_process_transport.request_missing")
	}
	if request.URL == nil {
		return nil, errors.New("in_process_transport.url_missing")
	}

	requestClone := request.Clone(request.Context())
	requestClone.RequestURI = ""
	if requestClone.Host == "" {
		requestClone.Host = requestClone.URL.Host
	}
	if requestClone.URL.Scheme == "https" {
		requestClone.TLS = &tls.ConnectionState{}
	} else {
		requestClone.TLS = nil
	}

	recorder := httptest.NewRecorder()
	transport.handler.ServeHTTP(recorder, requestClone)
	response := recorder.Result()
	response.Request = requestClone
	response.TLS = requestClone.TLS
	return response, nil
}

type inProcessServer struct {
	URL        string
	httpClient *http.Client
}

func newInProcessServer(handler http.Handler, useTLS bool) *inProcessServer {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}

	return &inProcessServer{
		URL: scheme + "://in-process.local",
		httpClient: &http.Client{
			Transport: &inProcessTransport{handler: handler},
		},
	}
}

func (server *inProcessServer) Client() *http.Client {
	return server.httpClient
}

func (server *inProcessServer) Close() {}

type controllableClock struct {
	current time.Time
}

func (clock *controllableClock) Now() time.Time {
	return clock.current
}

func (clock *controllableClock) Advance(duration time.Duration) {
	clock.current = clock.current.Add(duration)
}

type authCookieState struct {
	session string
	refresh string
}

const testHostHeader = "X-Test-Host"

func testHostOverrideMiddleware(defaultHost string) gin.HandlerFunc {
	return func(context *gin.Context) {
		host := strings.TrimSpace(context.GetHeader(testHostHeader))
		if host == "" {
			host = defaultHost
		}
		if host != "" {
			context.Request.Host = host
		}
		context.Next()
	}
}

func captureAuthCookies(state authCookieState, cookies []*http.Cookie, config ServerConfig) authCookieState {
	for _, cookie := range cookies {
		switch cookie.Name {
		case config.SessionCookieName:
			state.session = cookie.Value
		case config.RefreshCookieName:
			state.refresh = cookie.Value
		}
	}
	return state
}

func applyAuthCookies(request *http.Request, state authCookieState, config ServerConfig) {
	host := request.URL.Hostname()
	if state.session != "" {
		request.AddCookie(&http.Cookie{
			Name:   config.SessionCookieName,
			Value:  state.session,
			Domain: host,
			Path:   "/",
		})
	}
	if state.refresh != "" {
		request.AddCookie(&http.Cookie{
			Name:   config.RefreshCookieName,
			Value:  state.refresh,
			Domain: host,
			Path:   "/auth",
		})
	}
}

type mutableUserStore struct {
	inner      *testUserStore
	upsertErr  error
	profileErr error
}

func newMutableUserStore() *mutableUserStore {
	return &mutableUserStore{inner: newTestUserStore()}
}

func (store *mutableUserStore) UpsertGoogleUser(ctx context.Context, tenantID string, googleSub string, userEmail string, userDisplayName string, userAvatarURL string) (string, []string, error) {
	if store.upsertErr != nil {
		return "", nil, store.upsertErr
	}
	return store.inner.UpsertGoogleUser(ctx, tenantID, googleSub, userEmail, userDisplayName, userAvatarURL)
}

func (store *mutableUserStore) UpsertProviderUser(ctx context.Context, tenantID string, provider string, providerID string, userEmail string, userDisplayName string, userAvatarURL string) (string, []string, error) {
	if store.upsertErr != nil {
		return "", nil, store.upsertErr
	}
	return store.inner.UpsertProviderUser(ctx, tenantID, provider, providerID, userEmail, userDisplayName, userAvatarURL)
}

func (store *mutableUserStore) UpsertPasswordUser(ctx context.Context, tenantID string, userEmail string, userDisplayName string, userAvatarURL string) (string, []string, error) {
	if store.upsertErr != nil {
		return "", nil, store.upsertErr
	}
	return store.inner.UpsertPasswordUser(ctx, tenantID, userEmail, userDisplayName, userAvatarURL)
}

func (store *mutableUserStore) UpsertAccountUser(ctx context.Context, tenantID string, accountID string, userEmail string, userDisplayName string, userAvatarURL string) (string, []string, error) {
	if store.upsertErr != nil {
		return "", nil, store.upsertErr
	}
	return store.inner.UpsertAccountUser(ctx, tenantID, accountID, userEmail, userDisplayName, userAvatarURL)
}

func (store *mutableUserStore) GetUserProfile(ctx context.Context, tenantID string, applicationUserID string) (string, string, string, []string, error) {
	if store.profileErr != nil {
		return "", "", "", nil, store.profileErr
	}
	return store.inner.GetUserProfile(ctx, tenantID, applicationUserID)
}

type controlledNonceStore struct {
	token      string
	issueErr   error
	consumeErr error
}

func (store *controlledNonceStore) Issue(ctx context.Context, tenantID string) (string, error) {
	if store.issueErr != nil {
		return "", store.issueErr
	}
	store.token = "nonce-token"
	return store.token, nil
}

func (store *controlledNonceStore) Consume(ctx context.Context, tenantID string, token string) error {
	if store.consumeErr != nil {
		return store.consumeErr
	}
	if token != store.token {
		return ErrNonceNotFound
	}
	return nil
}

type revokeFailureRefreshStore struct {
	delegate  RefreshTokenStore
	revokeErr error
}

func (store revokeFailureRefreshStore) Issue(ctx context.Context, tenantID string, applicationUserID string, expiresUnix int64, previousTokenID string) (string, string, error) {
	return store.delegate.Issue(ctx, tenantID, applicationUserID, expiresUnix, previousTokenID)
}

func (store revokeFailureRefreshStore) Validate(ctx context.Context, tenantID string, tokenOpaque string) (string, string, int64, error) {
	return store.delegate.Validate(ctx, tenantID, tokenOpaque)
}

func (store revokeFailureRefreshStore) Revoke(ctx context.Context, tenantID string, tokenID string) error {
	if store.revokeErr != nil {
		return store.revokeErr
	}
	return store.delegate.Revoke(ctx, tenantID, tokenID)
}

func (store revokeFailureRefreshStore) RevokeUser(ctx context.Context, tenantID string, applicationUserID string) error {
	return store.delegate.RevokeUser(ctx, tenantID, applicationUserID)
}

func buildMultiTenantRegistry(base ServerConfig) TenantRegistry {
	configA := base
	configA.TenantID = "tenant-a"
	configA.GoogleWebClientID = "client-tenant-a"
	configA.CookieDomain = "tenant-a.local"
	configA.SessionCookieName = base.SessionCookieName + "_tenant-a"
	configA.RefreshCookieName = base.RefreshCookieName + "_tenant-a"
	configB := base
	configB.TenantID = "tenant-b"
	configB.GoogleWebClientID = "client-tenant-b"
	configB.CookieDomain = "tenant-b.local"
	configB.SessionCookieName = base.SessionCookieName + "_tenant-b"
	configB.RefreshCookieName = base.RefreshCookieName + "_tenant-b"
	return NewTenantRegistryFromMap(configA.TenantID, map[string]ServerConfig{
		configA.TenantID: configA,
		configB.TenantID: configB,
	})
}

func mustLoadTenantsConfigFromString(t *testing.T, contents string) tenants.Config {
	t.Helper()
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "tenants.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write tenants file: %v", err)
	}
	cfg, err := tenants.LoadConfig(path)
	if err != nil {
		t.Fatalf("load tenants config: %v", err)
	}
	return cfg
}

func newMobileNativeTestServerConfig() ServerConfig {
	config := newTestServerConfig()
	config.GoogleNativeClientID = ""
	config.NativeGoogleClients = []NativeGoogleClientConfig{
		{
			Platform: "ios",
			ClientID: "ios-client-id",
			RedirectURIs: []string{
				"com.promptdew.mobile://oauth2redirect/google",
				"https://promptdew.mprlab.com/oauth/google/callback",
			},
		},
		{
			Platform:     "android",
			ClientID:     "android-client-id",
			RedirectURIs: []string{"com.promptdew.mobile:/oauth2redirect/google"},
		},
	}
	return config
}

func stringSliceContains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func TestHTTPAuthLifecycleEndToEnd(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"valid-token": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-http",
					"email":          "user@example.com",
					"email_verified": true,
					"name":           "HTTP User",
					"nonce":          "",
				},
			},
			expectedAudience: "client-id",
		},
	}}

	clock := &controllableClock{current: time.Now().UTC()}
	metrics := NewCounterMetrics()

	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(clock)
	defer ProvideClock(nil)
	ProvideMetrics(metrics)
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(t))
	defer ProvideLogger(nil)

	config := newTestServerConfig()
	registry := NewSingleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()

	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

	server := newInProcessServer(router, true)
	defer server.Close()

	client := server.Client()
	state := authCookieState{}

	loginResp, _ := loginWithNonce(t, client, server.URL, validator, "valid-token")
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from login, got %d", loginResp.StatusCode)
	}
	state = captureAuthCookies(state, loginResp.Cookies(), config)
	_ = loginResp.Body.Close()

	if state.session == "" || state.refresh == "" {
		t.Fatalf("expected session and refresh cookies after login")
	}

	meReq, err := http.NewRequest(http.MethodGet, server.URL+"/me", nil)
	if err != nil {
		t.Fatalf("building /me request failed: %v", err)
	}
	applyAuthCookies(meReq, state, config)
	meResp, err := client.Do(meReq)
	if err != nil {
		t.Fatalf("/me request failed: %v", err)
	}
	if meResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /me, got %d", meResp.StatusCode)
	}
	var profile map[string]interface{}
	if decodeErr := json.NewDecoder(meResp.Body).Decode(&profile); decodeErr != nil {
		t.Fatalf("failed to decode /me payload: %v", decodeErr)
	}
	_ = meResp.Body.Close()
	if profile["user_id"] != "google:sub-http" {
		t.Fatalf("unexpected user_id: %v", profile["user_id"])
	}

	refreshReq, err := http.NewRequest(http.MethodPost, server.URL+"/auth/refresh", nil)
	if err != nil {
		t.Fatalf("building refresh request failed: %v", err)
	}
	applyAuthCookies(refreshReq, state, config)
	refreshResp, err := client.Do(refreshReq)
	if err != nil {
		t.Fatalf("refresh request failed: %v", err)
	}
	if refreshResp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 from refresh, got %d", refreshResp.StatusCode)
	}
	state = captureAuthCookies(state, refreshResp.Cookies(), config)
	_ = refreshResp.Body.Close()

	// Tamper session to confirm rejection.
	state.session = "tampered-session"
	tamperedReq, err := http.NewRequest(http.MethodGet, server.URL+"/me", nil)
	if err != nil {
		t.Fatalf("building tampered /me request failed: %v", err)
	}
	applyAuthCookies(tamperedReq, state, config)
	tamperedResp, err := client.Do(tamperedReq)
	if err != nil {
		t.Fatalf("tampered /me request failed: %v", err)
	}
	if tamperedResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 from tampered /me, got %d", tamperedResp.StatusCode)
	}
	_ = tamperedResp.Body.Close()

	// Restore valid session via fresh login.
	state.session = ""
	state.refresh = ""
	loginResp2, _ := loginWithNonce(t, client, server.URL, validator, "valid-token")
	if loginResp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from second login, got %d", loginResp2.StatusCode)
	}
	state = captureAuthCookies(state, loginResp2.Cookies(), config)
	_ = loginResp2.Body.Close()

	logoutReq, err := http.NewRequest(http.MethodPost, server.URL+"/auth/logout", nil)
	if err != nil {
		t.Fatalf("building logout request failed: %v", err)
	}
	applyAuthCookies(logoutReq, state, config)
	logoutResp, err := client.Do(logoutReq)
	if err != nil {
		t.Fatalf("logout request failed: %v", err)
	}
	if logoutResp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 from logout, got %d", logoutResp.StatusCode)
	}
	for _, cookie := range logoutResp.Cookies() {
		if cookie.Name == config.SessionCookieName && cookie.Path != "/" {
			t.Fatalf("expected session cookie path /, got %s", cookie.Path)
		}
		if cookie.Name == config.RefreshCookieName && cookie.Path != "/auth" {
			t.Fatalf("expected refresh cookie path /auth, got %s", cookie.Path)
		}
	}
	state = captureAuthCookies(state, logoutResp.Cookies(), config)
	_ = logoutResp.Body.Close()

	postLogoutReq, err := http.NewRequest(http.MethodGet, server.URL+"/me", nil)
	if err != nil {
		t.Fatalf("building post logout request failed: %v", err)
	}
	applyAuthCookies(postLogoutReq, state, config)
	postLogoutResp, err := client.Do(postLogoutReq)
	if err != nil {
		t.Fatalf("post logout /me request failed: %v", err)
	}
	if postLogoutResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 after logout, got %d", postLogoutResp.StatusCode)
	}
	_ = postLogoutResp.Body.Close()

	if metrics.Count(metricAuthLoginSuccess) == 0 {
		t.Fatalf("expected auth.login.success metric increment")
	}
	if metrics.Count(metricAuthRefreshSuccess) == 0 {
		t.Fatalf("expected auth.refresh.success metric increment")
	}
	if metrics.Count(metricAuthLogoutSuccess) == 0 {
		t.Fatalf("expected auth.logout.success metric increment")
	}
}

func TestHTTPSessionStatusReturnsProfileOrNoContentWithoutUnauthorizedNoise(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"session-status-token": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-session-status",
					"email":          "session@example.com",
					"email_verified": true,
					"name":           "Session Status User",
					"nonce":          "",
				},
			},
			expectedAudience: "client-id",
		},
	}}

	clock := &controllableClock{current: time.Now().UTC()}
	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(clock)
	defer ProvideClock(nil)
	ProvideLogger(zaptest.NewLogger(t))
	defer ProvideLogger(nil)

	config := newTestServerConfig()
	registry := NewSingleTenantRegistry(config)
	refreshStore := NewMemoryRefreshTokenStore()
	router := gin.New()
	MountAuthRoutes(router, registry, newTestUserStore(), refreshStore, nil)

	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()

	anonymousRequest, err := http.NewRequest(http.MethodGet, server.URL+"/auth/session", nil)
	if err != nil {
		t.Fatalf("build anonymous session request: %v", err)
	}
	anonymousResponse, err := client.Do(anonymousRequest)
	if err != nil {
		t.Fatalf("anonymous session request failed: %v", err)
	}
	if anonymousResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 for anonymous session probe, got %d", anonymousResponse.StatusCode)
	}
	_ = anonymousResponse.Body.Close()

	loginResponse, _ := loginWithNonce(t, client, server.URL, validator, "session-status-token")
	if loginResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from login, got %d", loginResponse.StatusCode)
	}
	state := captureAuthCookies(authCookieState{}, loginResponse.Cookies(), config)
	_ = loginResponse.Body.Close()
	if state.session == "" || state.refresh == "" {
		t.Fatalf("expected session and refresh cookies after login")
	}

	sessionRequest, err := http.NewRequest(http.MethodGet, server.URL+"/auth/session", nil)
	if err != nil {
		t.Fatalf("build authenticated session request: %v", err)
	}
	applyAuthCookies(sessionRequest, state, config)
	sessionResponse, err := client.Do(sessionRequest)
	if err != nil {
		t.Fatalf("authenticated session request failed: %v", err)
	}
	if sessionResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for authenticated session probe, got %d", sessionResponse.StatusCode)
	}
	var sessionProfile map[string]interface{}
	if decodeErr := json.NewDecoder(sessionResponse.Body).Decode(&sessionProfile); decodeErr != nil {
		t.Fatalf("decode session profile: %v", decodeErr)
	}
	_ = sessionResponse.Body.Close()
	if sessionProfile["user_id"] != "google:sub-session-status" || sessionProfile["user_email"] != "session@example.com" {
		t.Fatalf("unexpected session profile: %#v", sessionProfile)
	}

	state.session = "tampered-session"
	restoredRequest, err := http.NewRequest(http.MethodGet, server.URL+"/auth/session", nil)
	if err != nil {
		t.Fatalf("build restored session request: %v", err)
	}
	applyAuthCookies(restoredRequest, state, config)
	restoredResponse, err := client.Do(restoredRequest)
	if err != nil {
		t.Fatalf("restored session request failed: %v", err)
	}
	if restoredResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after refresh-backed session probe, got %d", restoredResponse.StatusCode)
	}
	state = captureAuthCookies(state, restoredResponse.Cookies(), config)
	var restoredProfile map[string]interface{}
	if decodeErr := json.NewDecoder(restoredResponse.Body).Decode(&restoredProfile); decodeErr != nil {
		t.Fatalf("decode restored profile: %v", decodeErr)
	}
	_ = restoredResponse.Body.Close()
	if restoredProfile["user_id"] != "google:sub-session-status" {
		t.Fatalf("unexpected restored profile: %#v", restoredProfile)
	}
	if state.session == "" || state.session == "tampered-session" {
		t.Fatalf("expected session probe to issue a fresh session cookie")
	}

	state.session = "tampered-session"
	state.refresh = "tampered-refresh"
	expiredRequest, err := http.NewRequest(http.MethodGet, server.URL+"/auth/session", nil)
	if err != nil {
		t.Fatalf("build expired session request: %v", err)
	}
	applyAuthCookies(expiredRequest, state, config)
	expiredResponse, err := client.Do(expiredRequest)
	if err != nil {
		t.Fatalf("expired session request failed: %v", err)
	}
	if expiredResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 for expired session probe, got %d", expiredResponse.StatusCode)
	}
	_ = expiredResponse.Body.Close()
}

func TestHTTPSessionStatusRevokeFailureReturnsInternalServerError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"session-revoke-token": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-session-revoke",
					"email":          "revoke@example.com",
					"email_verified": true,
					"name":           "Session Revoke User",
					"nonce":          "",
				},
			},
			expectedAudience: "client-id",
		},
	}}

	clock := &controllableClock{current: time.Now().UTC()}
	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(clock)
	defer ProvideClock(nil)
	ProvideLogger(zaptest.NewLogger(t))
	defer ProvideLogger(nil)

	config := newTestServerConfig()
	registry := NewSingleTenantRegistry(config)
	refreshStore := revokeFailureRefreshStore{
		delegate:  NewMemoryRefreshTokenStore(),
		revokeErr: errors.New("refresh_store.revoke.injected"),
	}
	router := gin.New()
	MountAuthRoutes(router, registry, newTestUserStore(), refreshStore, nil)

	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()

	loginResponse, _ := loginWithNonce(t, client, server.URL, validator, "session-revoke-token")
	if loginResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from login, got %d", loginResponse.StatusCode)
	}
	state := captureAuthCookies(authCookieState{}, loginResponse.Cookies(), config)
	_ = loginResponse.Body.Close()
	if state.session == "" || state.refresh == "" {
		t.Fatalf("expected session and refresh cookies after login")
	}

	state.session = "tampered-session"
	sessionRequest, err := http.NewRequest(http.MethodGet, server.URL+"/auth/session", nil)
	if err != nil {
		t.Fatalf("build session request: %v", err)
	}
	applyAuthCookies(sessionRequest, state, config)
	sessionResponse, err := client.Do(sessionRequest)
	if err != nil {
		t.Fatalf("session request failed: %v", err)
	}
	defer sessionResponse.Body.Close()
	if sessionResponse.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 when session restore cannot revoke previous refresh token, got %d", sessionResponse.StatusCode)
	}
	emittedState := captureAuthCookies(authCookieState{}, sessionResponse.Cookies(), config)
	if emittedState.session != "" || emittedState.refresh != "" {
		t.Fatalf("expected failed session restore to avoid writing rotated cookies")
	}
}

func TestHTTPAuthTenantHeaderOverride(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"token-a": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-tenant-a",
					"email":          "tenant-a@example.com",
					"email_verified": true,
					"name":           "Tenant A User",
					"picture":        "https://example.com/a.png",
					"nonce":          "",
				},
			},
			expectedAudience: "client-tenant-a",
		},
		"token-b": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-tenant-b",
					"email":          "tenant-b@example.com",
					"email_verified": true,
					"name":           "Tenant B User",
					"picture":        "https://example.com/b.png",
					"nonce":          "",
				},
			},
			expectedAudience: "client-tenant-b",
		},
	}}

	clock := &controllableClock{current: time.Now().UTC()}
	metrics := NewCounterMetrics()

	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(clock)
	defer ProvideClock(nil)
	ProvideMetrics(metrics)
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(t))
	defer ProvideLogger(nil)

	baseConfig := newTestServerConfig()
	registry := buildMultiTenantRegistry(baseConfig)

	tenantConfig := mustLoadTenantsConfigFromString(t, `{
		"tenants": [
			{
				"id": "tenant-a",
				"display_name": "Tenant A",
				"tenant_origins": ["https://tenant-a.localhost"],
				"google_web_client_id": "client-tenant-a",
				"jwt_signing_key": "tenant-a-key",
				"cookie_domain": "tenant-a.localhost",
				"session_cookie_name": "app_session_tenant_a",
				"refresh_cookie_name": "app_refresh_tenant_a",
				"session_ttl": "15m",
				"refresh_ttl": "1440h",
				"nonce_ttl": "5m",
				"allow_insecure_http": true
			},
			{
				"id": "tenant-b",
				"display_name": "Tenant B",
				"tenant_origins": ["https://tenant-b.localhost"],
				"google_web_client_id": "client-tenant-b",
				"jwt_signing_key": "tenant-b-key",
				"cookie_domain": "tenant-b.localhost",
				"session_cookie_name": "app_session_tenant_b",
				"refresh_cookie_name": "app_refresh_tenant_b",
				"session_ttl": "15m",
				"refresh_ttl": "1440h",
				"nonce_ttl": "5m",
				"allow_insecure_http": true
			}
		]
	}`)

	resolver, err := tenants.NewResolver(tenantConfig, tenants.WithHeaderOverride(""))
	if err != nil {
		t.Fatalf("create resolver: %v", err)
	}

	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(testHostOverrideMiddleware("tenant-a.localhost"))
	router.Use(tenants.TenantMiddleware(resolver, http.StatusNotFound))
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

	server := newInProcessServer(router, true)
	defer server.Close()

	client := server.Client()

	tenantHosts := map[string]string{
		"tenant-a": "tenant-a.localhost",
		"tenant-b": "tenant-b.localhost",
	}

	loginTenant := func(tenantID string, token string) authCookieState {
		response, _ := loginWithTenantHeader(t, client, server.URL, validator, token, tenantID, tenantHosts[tenantID])
		if response.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 from login for %s, got %d", tenantID, response.StatusCode)
		}
		state := captureAuthCookies(authCookieState{}, response.Cookies(), registry.Config(tenantID))
		_ = response.Body.Close()
		return state
	}

	stateA := loginTenant("tenant-a", "token-a")
	stateB := loginTenant("tenant-b", "token-b")

	assertProfile := func(state authCookieState, tenantID string, expectedUser string) {
		request, err := http.NewRequest(http.MethodGet, server.URL+"/me", nil)
		if err != nil {
			t.Fatalf("build /me request: %v", err)
		}
		request.Header.Set("X-TAuth-Tenant", tenantID)
		request.Header.Set(testHostHeader, tenantHosts[tenantID])
		applyAuthCookies(request, state, registry.Config(tenantID))
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("/me request failed: %v", err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 from /me for %s, got %d", tenantID, response.StatusCode)
		}
		var payload map[string]interface{}
		if decodeErr := json.NewDecoder(response.Body).Decode(&payload); decodeErr != nil {
			t.Fatalf("decode /me payload: %v", decodeErr)
		}
		if payload["user_id"] != expectedUser {
			t.Fatalf("expected user %s, got %v", expectedUser, payload["user_id"])
		}
	}

	assertProfile(stateA, "tenant-a", "google:sub-tenant-a")
	assertProfile(stateB, "tenant-b", "google:sub-tenant-b")

	crossRequest, err := http.NewRequest(http.MethodGet, server.URL+"/me", nil)
	if err != nil {
		t.Fatalf("build cross request: %v", err)
	}
	crossRequest.Header.Set("X-TAuth-Tenant", "tenant-b")
	crossRequest.Header.Set(testHostHeader, tenantHosts["tenant-b"])
	applyAuthCookies(crossRequest, stateA, registry.Config("tenant-a"))
	crossResponse, err := client.Do(crossRequest)
	if err != nil {
		t.Fatalf("cross /me request failed: %v", err)
	}
	defer crossResponse.Body.Close()
	if crossResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 when tenant headers mismatch, got %d", crossResponse.StatusCode)
	}
}

func TestHTTPAuthOriginsResolveSharedHostTenants(t *testing.T) {
	gin.SetMode(gin.TestMode)

	clock := &controllableClock{current: time.Now().UTC()}
	metrics := NewCounterMetrics()

	ProvideGoogleTokenValidator(&fakeGoogleValidator{})
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(clock)
	defer ProvideClock(nil)
	ProvideMetrics(metrics)
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(t))
	defer ProvideLogger(nil)

	baseConfig := newTestServerConfig()
	notesConfig := baseConfig
	notesConfig.TenantID = "notes"
	notesConfig.GoogleWebClientID = "notes-client"
	mprConfig := baseConfig
	mprConfig.TenantID = "mpr-sites"
	mprConfig.GoogleWebClientID = "mpr-client"
	registry := NewTenantRegistryFromMap(notesConfig.TenantID, map[string]ServerConfig{
		notesConfig.TenantID: notesConfig,
		mprConfig.TenantID:   mprConfig,
	})

	tenantConfig := mustLoadTenantsConfigFromString(t, `{
		"tenants": [
			{
				"id": "notes",
				"display_name": "Gravity Notes",
				"tenant_origins": ["https://shared.localhost", "http://localhost:8000"],
				"google_web_client_id": "notes-client",
				"jwt_signing_key": "notes-key",
				"cookie_domain": "",
				"session_cookie_name": "app_session_notes",
				"refresh_cookie_name": "app_refresh_notes",
				"session_ttl": "15m",
				"refresh_ttl": "1440h",
				"nonce_ttl": "5m",
				"allow_insecure_http": true
			},
			{
				"id": "mpr-sites",
				"display_name": "MPR Sites",
				"tenant_origins": ["https://shared.localhost", "http://localhost:4173"],
				"google_web_client_id": "mpr-client",
				"jwt_signing_key": "mpr-key",
				"cookie_domain": "",
				"session_cookie_name": "app_session_mpr",
				"refresh_cookie_name": "app_refresh_mpr",
				"session_ttl": "15m",
				"refresh_ttl": "1440h",
				"nonce_ttl": "5m",
				"allow_insecure_http": true
			}
		]
	}`)

	resolver, err := tenants.NewResolver(tenantConfig)
	if err != nil {
		t.Fatalf("create resolver: %v", err)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(testHostOverrideMiddleware("shared.localhost"))
	router.Use(tenants.TenantMiddleware(resolver, http.StatusNotFound))
	MountAuthRoutes(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), &controlledNonceStore{})

	server := newInProcessServer(router, false)
	defer server.Close()

	client := server.Client()

	testCases := []struct {
		name       string
		origin     string
		wantStatus int
	}{
		{
			name:       "notes origin allowed",
			origin:     "http://localhost:8000",
			wantStatus: http.StatusOK,
		},
		{
			name:       "mpr origin allowed",
			origin:     "http://localhost:4173",
			wantStatus: http.StatusOK,
		},
		{
			name:       "unknown origin rejected",
			origin:     "http://unknown.localhost",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "missing origin rejected",
			origin:     "",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, testCase := range testCases {
		tc := testCase
		t.Run(tc.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodPost, server.URL+"/auth/nonce", nil)
			if err != nil {
				t.Fatalf("build nonce request: %v", err)
			}
			if tc.origin != "" {
				request.Header.Set("Origin", tc.origin)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatalf("request nonce failed: %v", err)
			}
			defer response.Body.Close()
			if response.StatusCode != tc.wantStatus {
				t.Fatalf("expected status %d, got %d", tc.wantStatus, response.StatusCode)
			}
			if tc.wantStatus == http.StatusOK {
				var payload struct {
					Nonce string `json:"nonce"`
				}
				if decodeErr := json.NewDecoder(response.Body).Decode(&payload); decodeErr != nil {
					t.Fatalf("decode nonce payload: %v", decodeErr)
				}
				if payload.Nonce == "" {
					t.Fatalf("expected nonce token in payload")
				}
			}
		})
	}
}

func TestHTTPAuthAllowsMultipleTenantSessionsFromSingleClient(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"notes-token": {
			payload:          &idtoken.Payload{Claims: map[string]interface{}{"iss": "https://accounts.google.com", "sub": "sub-notes", "email": "notes@example.com", "email_verified": true, "name": "Notes User", "nonce": ""}},
			expectedAudience: "notes-client",
		},
		"mpr-token": {
			payload:          &idtoken.Payload{Claims: map[string]interface{}{"iss": "https://accounts.google.com", "sub": "sub-mpr", "email": "mpr@example.com", "email_verified": true, "name": "MPR User", "nonce": ""}},
			expectedAudience: "mpr-client",
		},
	}}

	clock := &controllableClock{current: time.Now().UTC()}
	metrics := NewCounterMetrics()

	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(clock)
	defer ProvideClock(nil)
	ProvideMetrics(metrics)
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(t))
	defer ProvideLogger(nil)

	baseConfig := newTestServerConfig()
	notesConfig := baseConfig
	notesConfig.TenantID = "notes"
	notesConfig.GoogleWebClientID = "notes-client"
	notesConfig.SessionCookieName = notesConfig.SessionCookieName + "_notes"
	notesConfig.RefreshCookieName = notesConfig.RefreshCookieName + "_notes"
	mprConfig := baseConfig
	mprConfig.TenantID = "mpr-sites"
	mprConfig.GoogleWebClientID = "mpr-client"
	mprConfig.SessionCookieName = mprConfig.SessionCookieName + "_mpr"
	mprConfig.RefreshCookieName = mprConfig.RefreshCookieName + "_mpr"

	registry := NewTenantRegistryFromMap(notesConfig.TenantID, map[string]ServerConfig{
		notesConfig.TenantID: notesConfig,
		mprConfig.TenantID:   mprConfig,
	})

	tenantConfig := mustLoadTenantsConfigFromString(t, `{
		"tenants": [
			{"id":"notes","display_name":"Notes","tenant_origins":["https://shared.localhost","http://localhost:8000"],"google_web_client_id":"notes-client","jwt_signing_key":"notes-key","cookie_domain":"","session_cookie_name":"app_session_notes","refresh_cookie_name":"app_refresh_notes","session_ttl":"15m","refresh_ttl":"1440h","nonce_ttl":"5m","allow_insecure_http":true},
			{"id":"mpr-sites","display_name":"MPR","tenant_origins":["https://shared.localhost","http://localhost:4173"],"google_web_client_id":"mpr-client","jwt_signing_key":"mpr-key","cookie_domain":"","session_cookie_name":"app_session_mpr","refresh_cookie_name":"app_refresh_mpr","session_ttl":"15m","refresh_ttl":"1440h","nonce_ttl":"5m","allow_insecure_http":true}
		]}`)

	resolver, err := tenants.NewResolver(tenantConfig)
	if err != nil {
		t.Fatalf("create resolver: %v", err)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(testHostOverrideMiddleware("shared.localhost"))
	router.Use(tenants.TenantMiddleware(resolver, http.StatusNotFound))
	MountAuthRoutes(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), nil)

	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()

	loginWithOrigin := func(token string, origin string, tenantID string) authCookieState {
		headers := map[string]string{
			testHostHeader: "shared.localhost",
			"Origin":       origin,
		}
		response, _ := loginWithNonceAndHeaders(t, client, server.URL, validator, token, headers)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 from login for %s, got %d", origin, response.StatusCode)
		}
		state := captureAuthCookies(authCookieState{}, response.Cookies(), registry.Config(tenantID))
		_ = response.Body.Close()
		return state
	}

	mprState := loginWithOrigin("mpr-token", "http://localhost:4173", "mpr-sites")
	notesState := loginWithOrigin("notes-token", "http://localhost:8000", "notes")

	callMe := func(origin string, tenantID string, state authCookieState) int {
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/me", nil)
		req.Header.Set(testHostHeader, "shared.localhost")
		req.Header.Set("Origin", origin)
		applyAuthCookies(req, state, registry.Config(tenantID))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("/me request failed: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if status := callMe("http://localhost:8000", "notes", notesState); status != http.StatusOK {
		t.Fatalf("expected 200 from /me for notes, got %d", status)
	}
	if status := callMe("http://localhost:4173", "mpr-sites", mprState); status != http.StatusOK {
		t.Fatalf("expected 200 from /me for mpr, got %d", status)
	}
}

func TestHTTPAuthOriginLifecycleWithoutTenantHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"notes-token": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-notes",
					"email":          "notes@example.com",
					"email_verified": true,
					"name":           "Notes User",
					"nonce":          "",
				},
			},
			expectedAudience: "notes-client",
		},
		"mpr-token": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-mpr",
					"email":          "mpr@example.com",
					"email_verified": true,
					"name":           "MPR User",
					"nonce":          "",
				},
			},
			expectedAudience: "mpr-client",
		},
	}}

	clock := &controllableClock{current: time.Now().UTC()}
	metrics := NewCounterMetrics()

	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(clock)
	defer ProvideClock(nil)
	ProvideMetrics(metrics)
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(t))
	defer ProvideLogger(nil)

	baseConfig := newTestServerConfig()
	notesConfig := baseConfig
	notesConfig.TenantID = "notes"
	notesConfig.GoogleWebClientID = "notes-client"
	mprConfig := baseConfig
	mprConfig.TenantID = "mpr-sites"
	mprConfig.GoogleWebClientID = "mpr-client"

	registry := NewTenantRegistryFromMap(notesConfig.TenantID, map[string]ServerConfig{
		notesConfig.TenantID: notesConfig,
		mprConfig.TenantID:   mprConfig,
	})

	tenantConfig := mustLoadTenantsConfigFromString(t, `{
		"tenants": [
			{
				"id": "notes",
				"display_name": "Gravity Notes",
				"tenant_origins": ["https://shared.localhost", "http://localhost:8000"],
				"google_web_client_id": "notes-client",
				"jwt_signing_key": "notes-key",
				"cookie_domain": "",
				"session_cookie_name": "app_session_notes",
				"refresh_cookie_name": "app_refresh_notes",
				"session_ttl": "15m",
				"refresh_ttl": "1440h",
				"nonce_ttl": "5m",
				"allow_insecure_http": true
			},
			{
				"id": "mpr-sites",
				"display_name": "MPR Sites",
				"tenant_origins": ["https://shared.localhost", "http://localhost:4173"],
				"google_web_client_id": "mpr-client",
				"jwt_signing_key": "mpr-key",
				"cookie_domain": "",
				"session_cookie_name": "app_session_mpr",
				"refresh_cookie_name": "app_refresh_mpr",
				"session_ttl": "15m",
				"refresh_ttl": "1440h",
				"nonce_ttl": "5m",
				"allow_insecure_http": true
			}
		]
	}`)

	resolver, err := tenants.NewResolver(tenantConfig)
	if err != nil {
		t.Fatalf("create resolver: %v", err)
	}

	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()
	nonceStore := &controlledNonceStore{}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(testHostOverrideMiddleware("shared.localhost"))
	router.Use(tenants.TenantMiddleware(resolver, http.StatusNotFound))
	MountAuthRoutes(router, registry, userStore, refreshStore, nonceStore)

	server := newInProcessServer(router, true)
	defer server.Close()

	client := server.Client()

	loginWithOrigin := func(origin string, token string, tenantID string) authCookieState {
		headers := map[string]string{
			testHostHeader: "shared.localhost",
			"Origin":       origin,
		}
		response, _ := loginWithNonceAndHeaders(t, client, server.URL, validator, token, headers)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 from login for %s, got %d", tenantID, response.StatusCode)
		}
		state := captureAuthCookies(authCookieState{}, response.Cookies(), registry.Config(tenantID))
		_ = response.Body.Close()
		return state
	}

	notesState := loginWithOrigin("http://localhost:8000", "notes-token", "notes")
	mprState := loginWithOrigin("http://localhost:4173", "mpr-token", "mpr-sites")

	assertProfile := func(state authCookieState, origin string, tenantID string, expectedUser string) {
		request, err := http.NewRequest(http.MethodGet, server.URL+"/me", nil)
		if err != nil {
			t.Fatalf("build /me request: %v", err)
		}
		request.Header.Set(testHostHeader, "shared.localhost")
		request.Header.Set("Origin", origin)
		applyAuthCookies(request, state, registry.Config(tenantID))
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("/me request failed: %v", err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 from /me for %s, got %d", tenantID, response.StatusCode)
		}
		var payload map[string]interface{}
		if decodeErr := json.NewDecoder(response.Body).Decode(&payload); decodeErr != nil {
			t.Fatalf("decode /me payload: %v", decodeErr)
		}
		if payload["user_id"] != expectedUser {
			t.Fatalf("expected user %s, got %v", expectedUser, payload["user_id"])
		}
	}

	assertRefresh := func(state authCookieState, origin string, tenantID string) {
		request, err := http.NewRequest(http.MethodPost, server.URL+"/auth/refresh", nil)
		if err != nil {
			t.Fatalf("build refresh request: %v", err)
		}
		request.Header.Set(testHostHeader, "shared.localhost")
		request.Header.Set("Origin", origin)
		applyAuthCookies(request, state, registry.Config(tenantID))
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("refresh request failed: %v", err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("expected 204 from refresh for %s, got %d", tenantID, response.StatusCode)
		}
	}

	assertProfile(notesState, "http://localhost:8000", "notes", "google:sub-notes")
	assertProfile(mprState, "http://localhost:4173", "mpr-sites", "google:sub-mpr")
	assertRefresh(notesState, "http://localhost:8000", "notes")
	assertRefresh(mprState, "http://localhost:4173", "mpr-sites")

	crossRequest, err := http.NewRequest(http.MethodGet, server.URL+"/me", nil)
	if err != nil {
		t.Fatalf("build cross request: %v", err)
	}
	crossRequest.Header.Set(testHostHeader, "shared.localhost")
	crossRequest.Header.Set("Origin", "http://localhost:4173")
	applyAuthCookies(crossRequest, notesState, registry.Config("notes"))
	crossResponse, err := client.Do(crossRequest)
	if err != nil {
		t.Fatalf("cross /me request failed: %v", err)
	}
	defer crossResponse.Body.Close()
	if crossResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 when session used with mismatched origin, got %d", crossResponse.StatusCode)
	}
}

func TestHTTPAuthRefreshFailureScenarios(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"valid-token": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-refresh-failure",
					"email":          "user@example.com",
					"email_verified": true,
					"name":           "HTTP User",
				},
			},
			expectedAudience: "client-id",
		},
	}}

	clock := &controllableClock{current: time.Now().UTC()}
	metrics := NewCounterMetrics()

	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(clock)
	defer ProvideClock(nil)
	ProvideMetrics(metrics)
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(t))
	defer ProvideLogger(nil)

	config := newTestServerConfig()
	registry := NewSingleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()

	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

	server := newInProcessServer(router, true)
	defer server.Close()

	client := server.Client()
	state := authCookieState{}

	loginResp, _ := loginWithNonce(t, client, server.URL, validator, "valid-token")
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from login, got %d", loginResp.StatusCode)
	}
	state = captureAuthCookies(state, loginResp.Cookies(), config)
	_ = loginResp.Body.Close()

	if state.refresh == "" {
		t.Fatalf("missing refresh cookie after login")
	}

	state.refresh = "invalid-refresh-cookie"

	refreshReq, err := http.NewRequest(http.MethodPost, server.URL+"/auth/refresh", nil)
	if err != nil {
		t.Fatalf("building refresh request failed: %v", err)
	}
	applyAuthCookies(refreshReq, state, config)
	refreshResp, err := client.Do(refreshReq)
	if err != nil {
		t.Fatalf("refresh request failed: %v", err)
	}
	defer refreshResp.Body.Close()
	if refreshResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 from invalid refresh token, got %d", refreshResp.StatusCode)
	}

	if len(refreshResp.Cookies()) != 0 {
		t.Fatalf("expected refresh failure not to modify cookies")
	}

	if metrics.Count(metricAuthRefreshFailure) == 0 {
		t.Fatalf("expected auth.refresh.failure metric increment")
	}
}

func TestHTTPAuthRefreshUsesValidCookieAmongDuplicates(testContext *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"valid-token": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-refresh-duplicate",
					"email":          "user@example.com",
					"email_verified": true,
					"name":           "HTTP User",
				},
			},
			expectedAudience: "client-id",
		},
	}}

	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(NewSystemClock())
	defer ProvideClock(nil)
	ProvideMetrics(NewCounterMetrics())
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(testContext))
	defer ProvideLogger(nil)

	config := newTestServerConfig()
	registry := NewSingleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()

	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

	server := newInProcessServer(router, true)
	defer server.Close()

	client := server.Client()

	loginResponse, _ := loginWithNonce(testContext, client, server.URL, validator, "valid-token")
	if loginResponse.StatusCode != http.StatusOK {
		testContext.Fatalf("expected 200 from login, got %d", loginResponse.StatusCode)
	}
	state := captureAuthCookies(authCookieState{}, loginResponse.Cookies(), config)
	_ = loginResponse.Body.Close()

	if state.refresh == "" {
		testContext.Fatalf("missing refresh cookie after login")
	}

	refreshRequest, requestErr := http.NewRequest(http.MethodPost, server.URL+"/auth/refresh", nil)
	if requestErr != nil {
		testContext.Fatalf("building refresh request failed: %v", requestErr)
	}
	refreshRequest.AddCookie(&http.Cookie{
		Name:   config.RefreshCookieName,
		Value:  "invalid-refresh-cookie",
		Domain: refreshRequest.URL.Hostname(),
		Path:   "/auth",
	})
	applyAuthCookies(refreshRequest, state, config)

	refreshResponse, responseErr := client.Do(refreshRequest)
	if responseErr != nil {
		testContext.Fatalf("refresh request failed: %v", responseErr)
	}
	_ = refreshResponse.Body.Close()
	if refreshResponse.StatusCode != http.StatusNoContent {
		testContext.Fatalf("expected 204 from refresh with duplicate cookies, got %d", refreshResponse.StatusCode)
	}
}

type validateFailureRefreshStore struct {
	delegate    RefreshTokenStore
	validateErr error
}

func (store validateFailureRefreshStore) Issue(ctx context.Context, tenantID string, applicationUserID string, expiresUnix int64, previousTokenID string) (string, string, error) {
	return store.delegate.Issue(ctx, tenantID, applicationUserID, expiresUnix, previousTokenID)
}

func (store validateFailureRefreshStore) Validate(ctx context.Context, tenantID string, tokenOpaque string) (string, string, int64, error) {
	return "", "", 0, store.validateErr
}

func (store validateFailureRefreshStore) Revoke(ctx context.Context, tenantID string, tokenID string) error {
	return store.delegate.Revoke(ctx, tenantID, tokenID)
}

func (store validateFailureRefreshStore) RevokeUser(ctx context.Context, tenantID string, applicationUserID string) error {
	return store.delegate.RevokeUser(ctx, tenantID, applicationUserID)
}

func TestHTTPAuthRefreshValidateInternalErrorReturns500(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"valid-token": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-refresh-store",
					"email":          "user@example.com",
					"email_verified": true,
					"name":           "HTTP User",
				},
			},
			expectedAudience: "client-id",
		},
	}}

	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(NewSystemClock())
	defer ProvideClock(nil)
	ProvideMetrics(NewCounterMetrics())
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(t))
	defer ProvideLogger(nil)

	config := newTestServerConfig()
	registry := NewSingleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := validateFailureRefreshStore{
		delegate:    NewMemoryRefreshTokenStore(),
		validateErr: errors.New("refresh store unavailable"),
	}

	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

	server := newInProcessServer(router, true)
	defer server.Close()

	client := server.Client()
	loginResp, _ := loginWithNonce(t, client, server.URL, validator, "valid-token")
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from login, got %d", loginResp.StatusCode)
	}
	state := captureAuthCookies(authCookieState{}, loginResp.Cookies(), config)
	_ = loginResp.Body.Close()

	refreshReq, err := http.NewRequest(http.MethodPost, server.URL+"/auth/refresh", nil)
	if err != nil {
		t.Fatalf("building refresh request failed: %v", err)
	}
	applyAuthCookies(refreshReq, state, config)
	refreshResp, err := client.Do(refreshReq)
	if err != nil {
		t.Fatalf("refresh request failed: %v", err)
	}
	defer refreshResp.Body.Close()
	if refreshResp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 from refresh store error, got %d", refreshResp.StatusCode)
	}
	if len(refreshResp.Cookies()) != 0 {
		t.Fatalf("expected no cookies to be modified on internal refresh errors")
	}
}

func TestHTTPAuthRefreshRevokedDoesNotClearCookies(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"valid-token": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-refresh-revoked",
					"email":          "user@example.com",
					"email_verified": true,
					"name":           "HTTP User",
				},
			},
			expectedAudience: "client-id",
		},
	}}

	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(NewSystemClock())
	defer ProvideClock(nil)
	ProvideMetrics(NewCounterMetrics())
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(t))
	defer ProvideLogger(nil)

	config := newTestServerConfig()
	registry := NewSingleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()

	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()

	loginResp, _ := loginWithNonce(t, client, server.URL, validator, "valid-token")
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from login, got %d", loginResp.StatusCode)
	}
	state := captureAuthCookies(authCookieState{}, loginResp.Cookies(), config)
	_ = loginResp.Body.Close()

	_, tokenID, _, validateErr := refreshStore.Validate(context.Background(), config.TenantID, state.refresh)
	if validateErr != nil {
		t.Fatalf("validate refresh token failed: %v", validateErr)
	}
	if revokeErr := refreshStore.Revoke(context.Background(), config.TenantID, tokenID); revokeErr != nil {
		t.Fatalf("revoke refresh token failed: %v", revokeErr)
	}

	refreshReq, err := http.NewRequest(http.MethodPost, server.URL+"/auth/refresh", nil)
	if err != nil {
		t.Fatalf("building refresh request failed: %v", err)
	}
	applyAuthCookies(refreshReq, state, config)
	refreshResp, err := client.Do(refreshReq)
	if err != nil {
		t.Fatalf("refresh request failed: %v", err)
	}
	defer refreshResp.Body.Close()
	if refreshResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 from revoked refresh token, got %d", refreshResp.StatusCode)
	}
	if len(refreshResp.Cookies()) != 0 {
		t.Fatalf("expected revoked refresh failure not to modify cookies")
	}
}

func TestHTTPAuthRefreshProfileStoreError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"profile-token": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-profile",
					"email":          "user@example.com",
					"email_verified": true,
					"name":           "Profile User",
					"picture":        "https://example.com/avatar.png",
					"nonce":          "",
				},
			},
			expectedAudience: "client-id",
		},
	}}

	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(NewSystemClock())
	defer ProvideClock(nil)
	ProvideMetrics(NewCounterMetrics())
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(t))
	defer ProvideLogger(nil)

	config := newTestServerConfig()
	registry := NewSingleTenantRegistry(config)
	store := newMutableUserStore()
	refreshStore := NewMemoryRefreshTokenStore()

	router := gin.New()
	MountAuthRoutes(router, registry, store, refreshStore, nil)

	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()

	loginResp, _ := loginWithNonce(t, client, server.URL, validator, "profile-token")
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from login, got %d", loginResp.StatusCode)
	}
	state := captureAuthCookies(authCookieState{}, loginResp.Cookies(), config)
	_ = loginResp.Body.Close()

	store.inner.setProfile(config.TenantID, "google:sub-profile", testUserProfile{
		email:   "user@example.com",
		display: "Profile User",
		avatar:  "https://example.com/avatar.png",
		roles:   []string{"user"},
	})
	store.profileErr = errors.New("profile failure")

	refreshReq, err := http.NewRequest(http.MethodPost, server.URL+"/auth/refresh", nil)
	if err != nil {
		t.Fatalf("build refresh request: %v", err)
	}
	applyAuthCookies(refreshReq, state, config)
	refreshResp, err := client.Do(refreshReq)
	if err != nil {
		t.Fatalf("refresh request failed: %v", err)
	}
	defer refreshResp.Body.Close()
	if refreshResp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 when profile store fails, got %d", refreshResp.StatusCode)
	}
	if len(refreshResp.Cookies()) != 0 {
		t.Fatalf("expected profile store failure not to modify cookies")
	}
}

func TestHTTPAuthMultiTenantRequiresTenantMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	registry := NewTenantRegistryFromMap("tenant-a", map[string]ServerConfig{
		"tenant-a": newTestServerConfig(),
		"tenant-b": newTestServerConfig(),
	})

	router := gin.New()
	MountAuthRoutes(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), nil)

	server := newInProcessServer(router, true)
	defer server.Close()

	client := server.Client()
	request, err := http.NewRequest(http.MethodPost, server.URL+"/auth/nonce", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 when tenant context missing, got %d", response.StatusCode)
	}
}

func TestHTTPAuthConcurrentRefreshAcrossTenants(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"token-ps": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-ps",
					"email":          "ps@example.com",
					"email_verified": true,
					"name":           "PS User",
				},
			},
			expectedAudience: "client-ps",
		},
		"token-loopaware": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-loopaware",
					"email":          "loopaware@example.com",
					"email_verified": true,
					"name":           "Loopaware User",
				},
			},
			expectedAudience: "client-loopaware",
		},
		"token-gravity": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-gravity",
					"email":          "gravity@example.com",
					"email_verified": true,
					"name":           "Gravity User",
				},
			},
			expectedAudience: "client-gravity",
		},
	}}

	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(NewSystemClock())
	defer ProvideClock(nil)
	ProvideMetrics(NewCounterMetrics())
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(t))
	defer ProvideLogger(nil)

	tenantConfigs := map[string]ServerConfig{
		"ps": {
			GoogleWebClientID: "client-ps",
			AppJWTSigningKey:  []byte("ps-signing-key-1234567890"),
			AppJWTIssuer:      "test-issuer",
			TenantID:          "ps",
			CookieDomain:      "",
			SessionCookieName: "app_session_ps",
			RefreshCookieName: "app_refresh_ps",
			SessionTTL:        time.Minute,
			RefreshTTL:        15 * time.Minute,
			NonceTTL:          5 * time.Minute,
			SameSiteMode:      http.SameSiteStrictMode,
			AllowInsecureHTTP: true,
		},
		"loopaware": {
			GoogleWebClientID: "client-loopaware",
			AppJWTSigningKey:  []byte("loopaware-signing-key-1234567890"),
			AppJWTIssuer:      "test-issuer",
			TenantID:          "loopaware",
			CookieDomain:      "",
			SessionCookieName: "app_session_loopaware",
			RefreshCookieName: "app_refresh_loopaware",
			SessionTTL:        time.Minute,
			RefreshTTL:        15 * time.Minute,
			NonceTTL:          5 * time.Minute,
			SameSiteMode:      http.SameSiteStrictMode,
			AllowInsecureHTTP: true,
		},
		"gravity": {
			GoogleWebClientID: "client-gravity",
			AppJWTSigningKey:  []byte("gravity-signing-key-1234567890"),
			AppJWTIssuer:      "test-issuer",
			TenantID:          "gravity",
			CookieDomain:      "",
			SessionCookieName: "app_session_gravity",
			RefreshCookieName: "app_refresh_gravity",
			SessionTTL:        time.Minute,
			RefreshTTL:        15 * time.Minute,
			NonceTTL:          5 * time.Minute,
			SameSiteMode:      http.SameSiteStrictMode,
			AllowInsecureHTTP: true,
		},
	}

	registry := NewTenantRegistryFromMap("ps", tenantConfigs)
	tenantConfig := mustLoadTenantsConfigFromString(t, `{
		"tenants": [
			{
				"id": "ps",
				"display_name": "ProductScanner",
				"tenant_origins": ["https://shared.localhost", "http://ps.localhost"],
				"google_web_client_id": "client-ps",
				"jwt_signing_key": "ps-signing",
				"cookie_domain": "",
				"session_cookie_name": "app_session_ps",
				"refresh_cookie_name": "app_refresh_ps",
				"session_ttl": "1m",
				"refresh_ttl": "15m",
				"nonce_ttl": "5m",
				"allow_insecure_http": true
			},
			{
				"id": "loopaware",
				"display_name": "Loopaware",
				"tenant_origins": ["https://shared.localhost", "http://loopaware.localhost"],
				"google_web_client_id": "client-loopaware",
				"jwt_signing_key": "loopaware-signing",
				"cookie_domain": "",
				"session_cookie_name": "app_session_loopaware",
				"refresh_cookie_name": "app_refresh_loopaware",
				"session_ttl": "1m",
				"refresh_ttl": "15m",
				"nonce_ttl": "5m",
				"allow_insecure_http": true
			},
			{
				"id": "gravity",
				"display_name": "Gravity",
				"tenant_origins": ["https://shared.localhost", "http://gravity.localhost"],
				"google_web_client_id": "client-gravity",
				"jwt_signing_key": "gravity-signing",
				"cookie_domain": "",
				"session_cookie_name": "app_session_gravity",
				"refresh_cookie_name": "app_refresh_gravity",
				"session_ttl": "1m",
				"refresh_ttl": "15m",
				"nonce_ttl": "5m",
				"allow_insecure_http": true
			}
		]
	}`)

	resolver, err := tenants.NewResolver(tenantConfig)
	if err != nil {
		t.Fatalf("create resolver: %v", err)
	}

	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(testHostOverrideMiddleware("shared.localhost"))
	router.Use(tenants.TenantMiddleware(resolver, http.StatusNotFound))
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()

	testCases := []struct {
		name            string
		tenantID        string
		origin          string
		loginToken      string
		expectedUserID  string
		refreshAttempts int
	}{
		{
			name:            "ProductScanner",
			tenantID:        "ps",
			origin:          "http://ps.localhost",
			loginToken:      "token-ps",
			expectedUserID:  "google:sub-ps",
			refreshAttempts: 20,
		},
		{
			name:            "Loopaware",
			tenantID:        "loopaware",
			origin:          "http://loopaware.localhost",
			loginToken:      "token-loopaware",
			expectedUserID:  "google:sub-loopaware",
			refreshAttempts: 20,
		},
		{
			name:            "Gravity",
			tenantID:        "gravity",
			origin:          "http://gravity.localhost",
			loginToken:      "token-gravity",
			expectedUserID:  "google:sub-gravity",
			refreshAttempts: 20,
		},
	}

	type tenantState struct {
		config ServerConfig
		state  authCookieState
	}

	stateByTenant := make(map[string]tenantState, len(testCases))
	for _, testCase := range testCases {
		headers := map[string]string{
			testHostHeader: "shared.localhost",
			"Origin":       testCase.origin,
		}
		loginResponse, _ := loginWithNonceAndHeaders(t, client, server.URL, validator, testCase.loginToken, headers)
		if loginResponse.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 from login for %s, got %d", testCase.tenantID, loginResponse.StatusCode)
		}
		config := registry.Config(testCase.tenantID)
		state := captureAuthCookies(authCookieState{}, loginResponse.Cookies(), config)
		_ = loginResponse.Body.Close()
		if state.refresh == "" || state.session == "" {
			t.Fatalf("expected session+refresh cookies for %s", testCase.tenantID)
		}
		stateByTenant[testCase.tenantID] = tenantState{config: config, state: state}
	}

	refreshTenant := func(testCase struct {
		name            string
		tenantID        string
		origin          string
		loginToken      string
		expectedUserID  string
		refreshAttempts int
	}) error {
		tenantValue := stateByTenant[testCase.tenantID]
		currentState := tenantValue.state
		config := tenantValue.config

		for attemptIndex := 0; attemptIndex < testCase.refreshAttempts; attemptIndex++ {
			refreshRequest, err := http.NewRequest(http.MethodPost, server.URL+"/auth/refresh", nil)
			if err != nil {
				return err
			}
			refreshRequest.Header.Set(testHostHeader, "shared.localhost")
			refreshRequest.Header.Set("Origin", testCase.origin)
			applyAuthCookies(refreshRequest, currentState, config)
			refreshResponse, err := client.Do(refreshRequest)
			if err != nil {
				return err
			}
			_ = refreshResponse.Body.Close()
			if refreshResponse.StatusCode != http.StatusNoContent {
				return errors.New("refresh did not return 204")
			}
			currentState = captureAuthCookies(currentState, refreshResponse.Cookies(), config)

			meRequest, err := http.NewRequest(http.MethodGet, server.URL+"/me", nil)
			if err != nil {
				return err
			}
			meRequest.Header.Set(testHostHeader, "shared.localhost")
			meRequest.Header.Set("Origin", testCase.origin)
			applyAuthCookies(meRequest, currentState, config)
			meResponse, err := client.Do(meRequest)
			if err != nil {
				return err
			}
			if meResponse.StatusCode != http.StatusOK {
				_ = meResponse.Body.Close()
				return errors.New("me did not return 200")
			}
			var payload map[string]interface{}
			if decodeErr := json.NewDecoder(meResponse.Body).Decode(&payload); decodeErr != nil {
				_ = meResponse.Body.Close()
				return decodeErr
			}
			_ = meResponse.Body.Close()
			userID, _ := payload["user_id"].(string)
			if userID != testCase.expectedUserID {
				return errors.New("unexpected user id")
			}
		}
		return nil
	}

	var waitGroup sync.WaitGroup
	errorChannel := make(chan error, len(testCases))
	for _, testCase := range testCases {
		testCaseCopy := testCase
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			if err := refreshTenant(testCaseCopy); err != nil {
				errorChannel <- err
			}
		}()
	}
	waitGroup.Wait()
	close(errorChannel)

	for err := range errorChannel {
		if err != nil {
			t.Fatalf("concurrent refresh failed: %v", err)
		}
	}
}

func TestHTTPAuthConcurrentRefreshAcrossTenantsWithPersistentStores(testContext *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"token-ps": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-ps",
					"email":          "ps@example.com",
					"email_verified": true,
					"name":           "PS User",
				},
			},
			expectedAudience: "client-ps",
		},
		"token-loopaware": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-loopaware",
					"email":          "loopaware@example.com",
					"email_verified": true,
					"name":           "Loopaware User",
				},
			},
			expectedAudience: "client-loopaware",
		},
		"token-gravity": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-gravity",
					"email":          "gravity@example.com",
					"email_verified": true,
					"name":           "Gravity User",
				},
			},
			expectedAudience: "client-gravity",
		},
	}}

	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(NewSystemClock())
	defer ProvideClock(nil)
	ProvideMetrics(NewCounterMetrics())
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(testContext))
	defer ProvideLogger(nil)

	tenantConfigs := map[string]ServerConfig{
		"ps": {
			GoogleWebClientID: "client-ps",
			AppJWTSigningKey:  []byte("ps-signing-key-1234567890"),
			AppJWTIssuer:      "test-issuer",
			TenantID:          "ps",
			CookieDomain:      "",
			SessionCookieName: "app_session_ps",
			RefreshCookieName: "app_refresh_ps",
			SessionTTL:        time.Minute,
			RefreshTTL:        15 * time.Minute,
			NonceTTL:          5 * time.Minute,
			SameSiteMode:      http.SameSiteStrictMode,
			AllowInsecureHTTP: true,
		},
		"loopaware": {
			GoogleWebClientID: "client-loopaware",
			AppJWTSigningKey:  []byte("loopaware-signing-key-1234567890"),
			AppJWTIssuer:      "test-issuer",
			TenantID:          "loopaware",
			CookieDomain:      "",
			SessionCookieName: "app_session_loopaware",
			RefreshCookieName: "app_refresh_loopaware",
			SessionTTL:        time.Minute,
			RefreshTTL:        15 * time.Minute,
			NonceTTL:          5 * time.Minute,
			SameSiteMode:      http.SameSiteStrictMode,
			AllowInsecureHTTP: true,
		},
		"gravity": {
			GoogleWebClientID: "client-gravity",
			AppJWTSigningKey:  []byte("gravity-signing-key-1234567890"),
			AppJWTIssuer:      "test-issuer",
			TenantID:          "gravity",
			CookieDomain:      "",
			SessionCookieName: "app_session_gravity",
			RefreshCookieName: "app_refresh_gravity",
			SessionTTL:        time.Minute,
			RefreshTTL:        15 * time.Minute,
			NonceTTL:          5 * time.Minute,
			SameSiteMode:      http.SameSiteStrictMode,
			AllowInsecureHTTP: true,
		},
	}

	registry := NewTenantRegistryFromMap("ps", tenantConfigs)
	tenantConfig := mustLoadTenantsConfigFromString(testContext, `{
		"tenants": [
			{
				"id": "ps",
				"display_name": "ProductScanner",
				"tenant_origins": ["https://shared.localhost", "http://ps.localhost"],
				"google_web_client_id": "client-ps",
				"jwt_signing_key": "ps-signing",
				"cookie_domain": "",
				"session_cookie_name": "app_session_ps",
				"refresh_cookie_name": "app_refresh_ps",
				"session_ttl": "1m",
				"refresh_ttl": "15m",
				"nonce_ttl": "5m",
				"allow_insecure_http": true
			},
			{
				"id": "loopaware",
				"display_name": "Loopaware",
				"tenant_origins": ["https://shared.localhost", "http://loopaware.localhost"],
				"google_web_client_id": "client-loopaware",
				"jwt_signing_key": "loopaware-signing",
				"cookie_domain": "",
				"session_cookie_name": "app_session_loopaware",
				"refresh_cookie_name": "app_refresh_loopaware",
				"session_ttl": "1m",
				"refresh_ttl": "15m",
				"nonce_ttl": "5m",
				"allow_insecure_http": true
			},
			{
				"id": "gravity",
				"display_name": "Gravity",
				"tenant_origins": ["https://shared.localhost", "http://gravity.localhost"],
				"google_web_client_id": "client-gravity",
				"jwt_signing_key": "gravity-signing",
				"cookie_domain": "",
				"session_cookie_name": "app_session_gravity",
				"refresh_cookie_name": "app_refresh_gravity",
				"session_ttl": "1m",
				"refresh_ttl": "15m",
				"nonce_ttl": "5m",
				"allow_insecure_http": true
			}
		]
	}`)

	resolver, err := tenants.NewResolver(tenantConfig)
	if err != nil {
		testContext.Fatalf("create resolver: %v", err)
	}

	databaseURL := sqliteDatabaseURL(testContext)
	userStore, userStoreErr := NewDatabaseUserStore(context.Background(), databaseURL)
	if userStoreErr != nil {
		testContext.Fatalf("create user store: %v", userStoreErr)
	}
	refreshStore, refreshStoreErr := NewDatabaseRefreshTokenStore(context.Background(), databaseURL)
	if refreshStoreErr != nil {
		testContext.Fatalf("create refresh store: %v", refreshStoreErr)
	}
	nonceStore, nonceStoreErr := NewDatabaseNonceStoreWithTTLResolver(context.Background(), databaseURL, func(tenantID string) time.Duration {
		return registry.Config(tenantID).NonceTTL
	})
	if nonceStoreErr != nil {
		testContext.Fatalf("create nonce store: %v", nonceStoreErr)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(testHostOverrideMiddleware("shared.localhost"))
	router.Use(tenants.TenantMiddleware(resolver, http.StatusNotFound))
	MountAuthRoutes(router, registry, userStore, refreshStore, nonceStore)

	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()

	testCases := []struct {
		name            string
		tenantID        string
		origin          string
		loginToken      string
		expectedUserID  string
		refreshAttempts int
	}{
		{
			name:            "ProductScanner",
			tenantID:        "ps",
			origin:          "http://ps.localhost",
			loginToken:      "token-ps",
			expectedUserID:  "google:sub-ps",
			refreshAttempts: 10,
		},
		{
			name:            "Loopaware",
			tenantID:        "loopaware",
			origin:          "http://loopaware.localhost",
			loginToken:      "token-loopaware",
			expectedUserID:  "google:sub-loopaware",
			refreshAttempts: 10,
		},
		{
			name:            "Gravity",
			tenantID:        "gravity",
			origin:          "http://gravity.localhost",
			loginToken:      "token-gravity",
			expectedUserID:  "google:sub-gravity",
			refreshAttempts: 10,
		},
	}

	type tenantState struct {
		config ServerConfig
		state  authCookieState
	}

	stateByTenant := make(map[string]tenantState, len(testCases))
	for _, testCase := range testCases {
		headers := map[string]string{
			testHostHeader: "shared.localhost",
			"Origin":       testCase.origin,
		}
		loginResponse, _ := loginWithNonceAndHeaders(testContext, client, server.URL, validator, testCase.loginToken, headers)
		if loginResponse.StatusCode != http.StatusOK {
			testContext.Fatalf("expected 200 from login for %s, got %d", testCase.tenantID, loginResponse.StatusCode)
		}
		config := registry.Config(testCase.tenantID)
		state := captureAuthCookies(authCookieState{}, loginResponse.Cookies(), config)
		_ = loginResponse.Body.Close()
		if state.refresh == "" || state.session == "" {
			testContext.Fatalf("expected session+refresh cookies for %s", testCase.tenantID)
		}
		stateByTenant[testCase.tenantID] = tenantState{config: config, state: state}
	}

	refreshTenant := func(testCase struct {
		name            string
		tenantID        string
		origin          string
		loginToken      string
		expectedUserID  string
		refreshAttempts int
	}) error {
		tenantValue := stateByTenant[testCase.tenantID]
		currentState := tenantValue.state
		config := tenantValue.config

		for attemptIndex := 0; attemptIndex < testCase.refreshAttempts; attemptIndex++ {
			refreshRequest, err := http.NewRequest(http.MethodPost, server.URL+"/auth/refresh", nil)
			if err != nil {
				return err
			}
			refreshRequest.Header.Set(testHostHeader, "shared.localhost")
			refreshRequest.Header.Set("Origin", testCase.origin)
			applyAuthCookies(refreshRequest, currentState, config)
			refreshResponse, err := client.Do(refreshRequest)
			if err != nil {
				return err
			}
			_ = refreshResponse.Body.Close()
			if refreshResponse.StatusCode != http.StatusNoContent {
				return errors.New("refresh did not return 204")
			}
			currentState = captureAuthCookies(currentState, refreshResponse.Cookies(), config)

			meRequest, err := http.NewRequest(http.MethodGet, server.URL+"/me", nil)
			if err != nil {
				return err
			}
			meRequest.Header.Set(testHostHeader, "shared.localhost")
			meRequest.Header.Set("Origin", testCase.origin)
			applyAuthCookies(meRequest, currentState, config)
			meResponse, err := client.Do(meRequest)
			if err != nil {
				return err
			}
			if meResponse.StatusCode != http.StatusOK {
				_ = meResponse.Body.Close()
				return errors.New("me did not return 200")
			}
			var payload map[string]interface{}
			if decodeErr := json.NewDecoder(meResponse.Body).Decode(&payload); decodeErr != nil {
				_ = meResponse.Body.Close()
				return decodeErr
			}
			_ = meResponse.Body.Close()
			userID, _ := payload["user_id"].(string)
			if userID != testCase.expectedUserID {
				return errors.New("unexpected user id")
			}
		}
		return nil
	}

	var waitGroup sync.WaitGroup
	errorChannel := make(chan error, len(testCases))
	for _, testCase := range testCases {
		testCaseCopy := testCase
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			if err := refreshTenant(testCaseCopy); err != nil {
				errorChannel <- err
			}
		}()
	}
	waitGroup.Wait()
	close(errorChannel)

	for err := range errorChannel {
		if err != nil {
			testContext.Fatalf("concurrent refresh failed: %v", err)
		}
	}
}

func TestHTTPAuthNonceIssueFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)

	registry := NewSingleTenantRegistry(newTestServerConfig())
	router := gin.New()
	MountAuthRoutes(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), &controlledNonceStore{issueErr: errors.New("nonce issue failure")})

	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()

	request, err := http.NewRequest(http.MethodPost, server.URL+"/auth/nonce", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 when nonce store fails, got %d", response.StatusCode)
	}
}

func TestHTTPAuthLoginNonceConsumeFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"nonce-consume-token": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-consume",
					"email":          "user@example.com",
					"email_verified": true,
					"name":           "Consume Failure",
					"picture":        "https://example.com/avatar.png",
					"nonce":          "",
				},
			},
			expectedAudience: "client-id",
		},
	}}

	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(NewSystemClock())
	defer ProvideClock(nil)
	ProvideMetrics(NewCounterMetrics())
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(t))
	defer ProvideLogger(nil)

	nonceStore := &controlledNonceStore{consumeErr: ErrNonceNotFound}
	registry := NewSingleTenantRegistry(newTestServerConfig())
	router := gin.New()
	MountAuthRoutes(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), nonceStore)

	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()

	nonce := issueNonceViaClient(t, client, server.URL)
	result := validator.results["nonce-consume-token"]
	result.payload.Claims["nonce"] = nonce
	validator.results["nonce-consume-token"] = result

	body := map[string]string{
		"google_id_token": "nonce-consume-token",
		"nonce_token":     nonce,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/auth/google", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 when nonce consume fails, got %d", response.StatusCode)
	}
}

func TestHTTPAuthLoginMissingNonce(t *testing.T) {
	gin.SetMode(gin.TestMode)

	setupValidator := &fakeGoogleValidator{}
	ProvideGoogleTokenValidator(setupValidator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(NewSystemClock())
	defer ProvideClock(nil)
	ProvideMetrics(NewCounterMetrics())
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(t))
	defer ProvideLogger(nil)

	registry := NewSingleTenantRegistry(newTestServerConfig())
	router := gin.New()
	MountAuthRoutes(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), nil)

	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()

	body := map[string]string{
		"google_id_token": "any-token",
		"nonce_token":     "",
	}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/auth/google", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing nonce, got %d", response.StatusCode)
	}
	var result map[string]string
	if decodeErr := json.NewDecoder(response.Body).Decode(&result); decodeErr != nil {
		t.Fatalf("decode result: %v", decodeErr)
	}
	if result["error"] != "missing_nonce" {
		t.Fatalf("expected missing_nonce error, got %v", result["error"])
	}
}

func TestHTTPNativeGoogleConfigEndpointUsesTenantHeaderOverride(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantConfig := mustLoadTenantsConfigFromString(t, `{
		"tenants": [
			{
				"id": "tenant-a",
				"display_name": "Tenant A",
				"tenant_origins": ["https://tenant-a.localhost"],
				"google_web_client_id": "client-tenant-a",
				"google_native_client_id": "native-client-tenant-a",
				"jwt_signing_key": "tenant-a-key",
				"cookie_domain": "",
				"session_cookie_name": "app_session_tenant_a",
				"refresh_cookie_name": "app_refresh_tenant_a",
				"session_ttl": "15m",
				"refresh_ttl": "1440h",
				"nonce_ttl": "5m",
				"allow_insecure_http": true
			},
			{
				"id": "tenant-b",
				"display_name": "Tenant B",
				"tenant_origins": ["https://tenant-b.localhost"],
				"google_web_client_id": "client-tenant-b",
				"google_native_client_id": "native-client-tenant-b",
				"jwt_signing_key": "tenant-b-key",
				"cookie_domain": "",
				"session_cookie_name": "app_session_tenant_b",
				"refresh_cookie_name": "app_refresh_tenant_b",
				"session_ttl": "15m",
				"refresh_ttl": "1440h",
				"nonce_ttl": "5m",
				"allow_insecure_http": true
			}
		]
	}`)
	baseConfig := newTestServerConfig()
	registry, registryErr := BuildTenantRegistry(baseConfig, tenantConfig, NewSameSiteResolver(false))
	if registryErr != nil {
		t.Fatalf("build registry: %v", registryErr)
	}
	resolver, resolverErr := tenants.NewResolver(tenantConfig, tenants.WithHeaderOverride(""))
	if resolverErr != nil {
		t.Fatalf("create resolver: %v", resolverErr)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(tenants.TenantMiddleware(resolver, http.StatusNotFound))
	MountAuthRoutes(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), nil)

	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()

	missingTenantRequest, err := http.NewRequest(http.MethodGet, server.URL+"/auth/google/native/config", nil)
	if err != nil {
		t.Fatalf("build missing tenant request: %v", err)
	}
	missingTenantResponse, err := client.Do(missingTenantRequest)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer missingTenantResponse.Body.Close()
	if missingTenantResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 without origin or tenant override, got %d", missingTenantResponse.StatusCode)
	}

	validRequest, err := http.NewRequest(http.MethodGet, server.URL+"/auth/google/native/config", nil)
	if err != nil {
		t.Fatalf("build native config request: %v", err)
	}
	validRequest.Header.Set("X-TAuth-Tenant", "tenant-b")

	validResponse, err := client.Do(validRequest)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer validResponse.Body.Close()
	if validResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with tenant override, got %d", validResponse.StatusCode)
	}

	var payload nativeGoogleConfigResponse
	if decodeErr := json.NewDecoder(validResponse.Body).Decode(&payload); decodeErr != nil {
		t.Fatalf("decode payload: %v", decodeErr)
	}
	if payload.ClientID != "native-client-tenant-b" {
		t.Fatalf("unexpected client id: %s", payload.ClientID)
	}
}

func TestHTTPNativeGoogleMobileConfigReturnsPlatformMetadata(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantConfig := mustLoadTenantsConfigFromString(t, `
tenants:
  - id: mobile
    display_name: Mobile
    tenant_origins: ["https://mobile.localhost"]
    google_web_client_id: "web-client-id"
    google_native_clients:
      - platform: ios
        client_id: "ios-client-id"
        redirect_uris:
          - "com.promptdew.mobile://oauth2redirect/google"
          - "https://promptdew.mprlab.com/oauth/google/callback"
      - platform: android
        client_id: "android-client-id"
        redirect_uris:
          - "com.promptdew.mobile:/oauth2redirect/google"
    jwt_signing_key: "mobile-key"
    cookie_domain: ""
    session_cookie_name: "app_session_mobile"
    refresh_cookie_name: "app_refresh_mobile"
    session_ttl: "15m"
    refresh_ttl: "1440h"
    nonce_ttl: "5m"
    allow_insecure_http: true
`)
	baseConfig := newTestServerConfig()
	registry, registryErr := BuildTenantRegistry(baseConfig, tenantConfig, NewSameSiteResolver(false))
	if registryErr != nil {
		t.Fatalf("build registry: %v", registryErr)
	}
	resolver, resolverErr := tenants.NewResolver(tenantConfig, tenants.WithHeaderOverride(""))
	if resolverErr != nil {
		t.Fatalf("create resolver: %v", resolverErr)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(tenants.TenantMiddleware(resolver, http.StatusNotFound))
	MountAuthRoutes(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), nil)

	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()

	testCases := []struct {
		platform         string
		expectedClient   string
		expectedRedirect string
	}{
		{
			platform:         "ios",
			expectedClient:   "ios-client-id",
			expectedRedirect: "com.promptdew.mobile://oauth2redirect/google",
		},
		{
			platform:         "android",
			expectedClient:   "android-client-id",
			expectedRedirect: "com.promptdew.mobile:/oauth2redirect/google",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.platform, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, server.URL+"/auth/google/native/config?platform="+testCase.platform, nil)
			if err != nil {
				t.Fatalf("build native config request: %v", err)
			}
			request.Header.Set("X-TAuth-Tenant", "mobile")

			response, err := client.Do(request)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("expected 200, got %d", response.StatusCode)
			}

			var payload nativeGoogleConfigResponse
			if decodeErr := json.NewDecoder(response.Body).Decode(&payload); decodeErr != nil {
				t.Fatalf("decode payload: %v", decodeErr)
			}
			if payload.ClientID != testCase.expectedClient {
				t.Fatalf("expected client %s, got %s", testCase.expectedClient, payload.ClientID)
			}
			if len(payload.ClientIDs) != 1 || payload.ClientIDs[0] != testCase.expectedClient {
				t.Fatalf("unexpected client ids: %#v", payload.ClientIDs)
			}
			if payload.Platform != testCase.platform {
				t.Fatalf("expected platform %s, got %s", testCase.platform, payload.Platform)
			}
			if !payload.PKCERequired || !stringSliceContains(payload.CodeChallengeMethodsSupported, googleCodeChallengeMethodS256) {
				t.Fatalf("expected PKCE S256 metadata, got required=%v methods=%#v", payload.PKCERequired, payload.CodeChallengeMethodsSupported)
			}
			if payload.ResponseType != googleOAuthResponseTypeCode {
				t.Fatalf("expected response type code, got %s", payload.ResponseType)
			}
			if !stringSliceContains(payload.RedirectURIs, testCase.expectedRedirect) {
				t.Fatalf("expected redirect %s in %#v", testCase.expectedRedirect, payload.RedirectURIs)
			}
			if len(payload.Clients) != 1 || payload.Clients[0].Platform != testCase.platform {
				t.Fatalf("unexpected native clients: %#v", payload.Clients)
			}
		})
	}
}

func TestHTTPNativeMobileGoogleLoginLifecycleAndSessionCompatibility(t *testing.T) {
	gin.SetMode(gin.TestMode)

	testCases := []struct {
		platform    string
		token       string
		audience    string
		redirectURI string
	}{
		{
			platform:    "ios",
			token:       "ios-token",
			audience:    "ios-client-id",
			redirectURI: "com.promptdew.mobile://oauth2redirect/google",
		},
		{
			platform:    "android",
			token:       "android-token",
			audience:    "android-client-id",
			redirectURI: "com.promptdew.mobile:/oauth2redirect/google",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.platform, func(t *testing.T) {
			config := newMobileNativeTestServerConfig()
			validator := &fakeGoogleValidator{results: map[string]validatorResult{
				testCase.token: {
					payload: &idtoken.Payload{
						Claims: map[string]interface{}{
							"iss":            googleIssuerHTTPS,
							"sub":            "sub-" + testCase.platform,
							"email":          testCase.platform + "@example.com",
							"email_verified": true,
							"name":           "Mobile User",
							"picture":        "https://example.com/mobile.png",
							"nonce":          "mobile-nonce",
						},
					},
					expectedAudience: testCase.audience,
				},
			}}
			ProvideGoogleTokenValidator(validator)
			defer ProvideGoogleTokenValidator(nil)
			ProvideClock(NewSystemClock())
			defer ProvideClock(nil)
			ProvideMetrics(NewCounterMetrics())
			defer ProvideMetrics(nil)
			ProvideLogger(zaptest.NewLogger(t))
			defer ProvideLogger(nil)

			router := gin.New()
			MountAuthRoutes(router, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), nil)

			server := newInProcessServer(router, true)
			defer server.Close()
			client := server.Client()

			body := map[string]string{
				"google_id_token": testCase.token,
				"nonce_token":     "mobile-nonce",
				"platform":        testCase.platform,
				"redirect_uri":    testCase.redirectURI,
			}
			payloadBytes, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("marshal payload: %v", err)
			}
			request, err := http.NewRequest(http.MethodPost, server.URL+"/auth/google/native", bytes.NewReader(payloadBytes))
			if err != nil {
				t.Fatalf("build login request: %v", err)
			}
			request.Header.Set("Content-Type", "application/json")

			response, err := client.Do(request)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("expected 200, got %d", response.StatusCode)
			}

			cookies := collectCookies(response.Cookies())
			sessionCookie := cookies[config.SessionCookieName]
			if sessionCookie == nil {
				t.Fatalf("missing session cookie")
			}
			refreshCookie := cookies[config.RefreshCookieName]
			if refreshCookie == nil {
				t.Fatalf("missing refresh cookie")
			}
			sessionClaimsValidator, validatorErr := sessionvalidator.New(sessionvalidator.Config{
				SigningKey: config.AppJWTSigningKey,
				Issuer:     config.AppJWTIssuer,
				CookieName: config.SessionCookieName,
			})
			if validatorErr != nil {
				t.Fatalf("build session validator: %v", validatorErr)
			}
			claims, validateErr := sessionClaimsValidator.ValidateToken(sessionCookie.Value)
			if validateErr != nil {
				t.Fatalf("validate mobile session token: %v", validateErr)
			}
			if claims.GetTenantID() != config.TenantID || claims.GetUserEmail() != testCase.platform+"@example.com" {
				t.Fatalf("unexpected claims tenant=%s email=%s", claims.GetTenantID(), claims.GetUserEmail())
			}

			if testCase.platform == "ios" {
				refreshRequest, refreshErr := http.NewRequest(http.MethodPost, server.URL+"/auth/refresh", nil)
				if refreshErr != nil {
					t.Fatalf("build refresh request: %v", refreshErr)
				}
				refreshRequest.AddCookie(refreshCookie)
				refreshResponse, refreshErr := client.Do(refreshRequest)
				if refreshErr != nil {
					t.Fatalf("refresh request failed: %v", refreshErr)
				}
				defer refreshResponse.Body.Close()
				if refreshResponse.StatusCode != http.StatusNoContent {
					t.Fatalf("expected refresh 204, got %d", refreshResponse.StatusCode)
				}
				refreshedCookies := collectCookies(refreshResponse.Cookies())
				refreshedSessionCookie := refreshedCookies[config.SessionCookieName]
				if refreshedSessionCookie == nil {
					t.Fatalf("missing refreshed session cookie")
				}
				if _, validateErr := sessionClaimsValidator.ValidateToken(refreshedSessionCookie.Value); validateErr != nil {
					t.Fatalf("validate refreshed session token: %v", validateErr)
				}
				refreshedRefreshCookie := refreshedCookies[config.RefreshCookieName]
				if refreshedRefreshCookie == nil {
					t.Fatalf("missing refreshed refresh cookie")
				}

				logoutRequest, logoutErr := http.NewRequest(http.MethodPost, server.URL+"/auth/logout", nil)
				if logoutErr != nil {
					t.Fatalf("build logout request: %v", logoutErr)
				}
				logoutRequest.AddCookie(refreshedRefreshCookie)
				logoutResponse, logoutErr := client.Do(logoutRequest)
				if logoutErr != nil {
					t.Fatalf("logout request failed: %v", logoutErr)
				}
				defer logoutResponse.Body.Close()
				if logoutResponse.StatusCode != http.StatusNoContent {
					t.Fatalf("expected logout 204, got %d", logoutResponse.StatusCode)
				}
				logoutCookies := collectCookies(logoutResponse.Cookies())
				if logoutCookies[config.SessionCookieName] == nil || logoutCookies[config.SessionCookieName].MaxAge != -1 {
					t.Fatalf("expected cleared session cookie")
				}
				if logoutCookies[config.RefreshCookieName] == nil || logoutCookies[config.RefreshCookieName].MaxAge != -1 {
					t.Fatalf("expected cleared refresh cookie")
				}
			}
		})
	}
}

func TestHTTPNativeMobileGoogleLoginRejectsWrongPlatformAudience(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newMobileNativeTestServerConfig()
	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"android-token": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            googleIssuerHTTPS,
					"sub":            "sub-android",
					"email":          "android@example.com",
					"email_verified": true,
					"name":           "Android User",
					"nonce":          "mobile-nonce",
				},
			},
			expectedAudience: "android-client-id",
		},
	}}
	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)

	router := gin.New()
	MountAuthRoutes(router, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), nil)

	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()

	body := map[string]string{
		"google_id_token": "android-token",
		"nonce_token":     "mobile-nonce",
		"platform":        "ios",
		"redirect_uri":    "com.promptdew.mobile://oauth2redirect/google",
	}
	payloadBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/auth/google/native", bytes.NewReader(payloadBytes))
	if err != nil {
		t.Fatalf("build login request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", response.StatusCode)
	}
	var payload map[string]string
	if decodeErr := json.NewDecoder(response.Body).Decode(&payload); decodeErr != nil {
		t.Fatalf("decode payload: %v", decodeErr)
	}
	if payload["error"] != "invalid_google_token" {
		t.Fatalf("expected invalid_google_token, got %v", payload["error"])
	}
}

func TestHTTPNativeMobileGoogleLoginRejectsInvalidRedirectURI(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newMobileNativeTestServerConfig()
	router := gin.New()
	MountAuthRoutes(router, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), nil)

	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()

	testCases := []struct {
		name        string
		redirectURI string
	}{
		{
			name:        "missing",
			redirectURI: "",
		},
		{
			name:        "unconfigured",
			redirectURI: "com.promptdew.mobile://unexpected",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			body := map[string]string{
				"google_id_token": "ios-token",
				"nonce_token":     "mobile-nonce",
				"platform":        "ios",
			}
			if testCase.redirectURI != "" {
				body["redirect_uri"] = testCase.redirectURI
			}
			payloadBytes, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("marshal payload: %v", err)
			}
			request, err := http.NewRequest(http.MethodPost, server.URL+"/auth/google/native", bytes.NewReader(payloadBytes))
			if err != nil {
				t.Fatalf("build login request: %v", err)
			}
			request.Header.Set("Content-Type", "application/json")

			response, err := client.Do(request)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", response.StatusCode)
			}
			var payload map[string]string
			if decodeErr := json.NewDecoder(response.Body).Decode(&payload); decodeErr != nil {
				t.Fatalf("decode payload: %v", decodeErr)
			}
			if payload["error"] != errorNativeGoogleRedirectURIInvalid {
				t.Fatalf("expected invalid redirect error, got %v", payload["error"])
			}
		})
	}
}

func TestHTTPNativeGoogleLoginValidationMatrix(t *testing.T) {
	gin.SetMode(gin.TestMode)

	testCases := []struct {
		name           string
		configure      func(config *ServerConfig)
		validator      *fakeGoogleValidator
		nonceToken     string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "missing_request_nonce",
			validator:      &fakeGoogleValidator{},
			nonceToken:     "",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "missing_nonce",
		},
		{
			name:           "invalid_google_token",
			validator:      &fakeGoogleValidator{results: map[string]validatorResult{}},
			nonceToken:     "native-nonce",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "invalid_google_token",
		},
		{
			name: "invalid_issuer",
			validator: &fakeGoogleValidator{results: map[string]validatorResult{
				"native-token": {
					payload: &idtoken.Payload{
						Claims: map[string]interface{}{
							"iss":            "https://issuer.invalid",
							"sub":            "sub-invalid-issuer",
							"email":          "issuer@example.com",
							"email_verified": true,
							"name":           "Issuer User",
							"nonce":          "native-nonce",
						},
					},
					expectedAudience: "native-client-id",
				},
			}},
			nonceToken:     "native-nonce",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "invalid_issuer",
		},
		{
			name: "missing_nonce_claim",
			validator: &fakeGoogleValidator{results: map[string]validatorResult{
				"native-token": {
					payload: &idtoken.Payload{
						Claims: map[string]interface{}{
							"iss":            googleIssuerHTTPS,
							"sub":            "sub-missing-nonce",
							"email":          "nonce@example.com",
							"email_verified": true,
							"name":           "Nonce User",
						},
					},
					expectedAudience: "native-client-id",
				},
			}},
			nonceToken:     "native-nonce",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "invalid_nonce",
		},
		{
			name: "nonce_mismatch",
			validator: &fakeGoogleValidator{results: map[string]validatorResult{
				"native-token": {
					payload: &idtoken.Payload{
						Claims: map[string]interface{}{
							"iss":            googleIssuerHTTPS,
							"sub":            "sub-nonce-mismatch",
							"email":          "nonce@example.com",
							"email_verified": true,
							"name":           "Nonce User",
							"nonce":          "other-nonce",
						},
					},
					expectedAudience: "native-client-id",
				},
			}},
			nonceToken:     "native-nonce",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "invalid_nonce",
		},
		{
			name: "unverified_identity",
			validator: &fakeGoogleValidator{results: map[string]validatorResult{
				"native-token": {
					payload: &idtoken.Payload{
						Claims: map[string]interface{}{
							"iss":            googleIssuerHTTPS,
							"sub":            "sub-unverified",
							"email":          "native@example.com",
							"email_verified": false,
							"name":           "Unverified User",
							"nonce":          "native-nonce",
						},
					},
					expectedAudience: "native-client-id",
				},
			}},
			nonceToken:     "native-nonce",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "unverified_identity",
		},
		{
			name: "user_not_allowed",
			configure: func(config *ServerConfig) {
				config.AllowedUsers = map[string]struct{}{"allowed@example.com": {}}
			},
			validator: &fakeGoogleValidator{results: map[string]validatorResult{
				"native-token": {
					payload: &idtoken.Payload{
						Claims: map[string]interface{}{
							"iss":            googleIssuerHTTPS,
							"sub":            "sub-disallowed",
							"email":          "denied@example.com",
							"email_verified": true,
							"name":           "Denied User",
							"nonce":          "native-nonce",
						},
					},
					expectedAudience: "native-client-id",
				},
			}},
			nonceToken:     "native-nonce",
			expectedStatus: http.StatusForbidden,
			expectedError:  errorUserNotAllowed,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ProvideGoogleTokenValidator(testCase.validator)
			defer ProvideGoogleTokenValidator(nil)
			ProvideClock(NewSystemClock())
			defer ProvideClock(nil)
			ProvideMetrics(NewCounterMetrics())
			defer ProvideMetrics(nil)
			ProvideLogger(zaptest.NewLogger(t))
			defer ProvideLogger(nil)

			config := newTestServerConfig()
			if testCase.configure != nil {
				testCase.configure(&config)
			}
			registry := NewSingleTenantRegistry(config)
			router := gin.New()
			MountAuthRoutes(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), nil)

			server := newInProcessServer(router, true)
			defer server.Close()
			client := server.Client()

			body := map[string]string{
				"google_id_token": "native-token",
				"nonce_token":     testCase.nonceToken,
			}
			payloadBytes, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("marshal payload: %v", err)
			}
			request, err := http.NewRequest(http.MethodPost, server.URL+"/auth/google/native", bytes.NewReader(payloadBytes))
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			request.Header.Set("Content-Type", "application/json")

			response, err := client.Do(request)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer response.Body.Close()
			if response.StatusCode != testCase.expectedStatus {
				t.Fatalf("expected %d, got %d", testCase.expectedStatus, response.StatusCode)
			}

			var payload map[string]string
			if decodeErr := json.NewDecoder(response.Body).Decode(&payload); decodeErr != nil {
				t.Fatalf("decode payload: %v", decodeErr)
			}
			if payload["error"] != testCase.expectedError {
				t.Fatalf("expected %s, got %v", testCase.expectedError, payload["error"])
			}
		})
	}
}

func TestHTTPAuthLoginNonceMismatch(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"nonce-token": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-nonce-mismatch",
					"email":          "user@example.com",
					"email_verified": true,
					"name":           "Nonce User",
					"picture":        "https://example.com/avatar.png",
					"nonce":          hashOpaque("other-value"),
				},
			},
			expectedAudience: "client-id",
		},
	}}

	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(NewSystemClock())
	defer ProvideClock(nil)
	ProvideMetrics(NewCounterMetrics())
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(t))
	defer ProvideLogger(nil)

	registry := NewSingleTenantRegistry(newTestServerConfig())
	router := gin.New()
	MountAuthRoutes(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), nil)

	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()

	nonce := issueNonceViaClient(t, client, server.URL)
	result := validator.results["nonce-token"]
	result.payload.Claims["nonce"] = hashOpaque("other-value")
	validator.results["nonce-token"] = result
	body := map[string]string{
		"google_id_token": "nonce-token",
		"nonce_token":     nonce,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/auth/google", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for nonce mismatch, got %d", response.StatusCode)
	}
}

func TestHTTPAuthLoginRejectsPreviousNonceClaim(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"resync-token": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-resync",
					"email":          "user@example.com",
					"email_verified": true,
					"name":           "Resync User",
					"picture":        "https://example.com/avatar.png",
					"nonce":          "",
				},
			},
			expectedAudience: "client-id",
		},
	}}

	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(NewSystemClock())
	defer ProvideClock(nil)
	ProvideMetrics(NewCounterMetrics())
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(t))
	defer ProvideLogger(nil)

	registry := NewSingleTenantRegistry(newTestServerConfig())
	nonceStore := NewMemoryNonceStore(5 * time.Minute)
	router := gin.New()
	MountAuthRoutes(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), nonceStore)

	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()

	firstNonce := issueNonceViaClient(t, client, server.URL)
	secondNonce := issueNonceViaClient(t, client, server.URL)

	result := validator.results["resync-token"]
	result.payload.Claims["nonce"] = firstNonce
	validator.results["resync-token"] = result

	payloadBody, err := json.Marshal(map[string]string{
		"google_id_token": "resync-token",
		"nonce_token":     secondNonce,
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/auth/google", bytes.NewReader(payloadBody))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 when google nonce differs from submitted nonce, got %d", response.StatusCode)
	}
}

func TestHTTPAuthLoginRejectsEmptyGoogleNonce(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"empty-nonce": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-empty-nonce",
					"email":          "user@example.com",
					"email_verified": true,
					"name":           "Empty Nonce",
					"picture":        "https://example.com/avatar.png",
					"nonce":          "",
				},
			},
			expectedAudience: "client-id",
		},
	}}

	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(NewSystemClock())
	defer ProvideClock(nil)
	ProvideMetrics(NewCounterMetrics())
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(t))
	defer ProvideLogger(nil)

	registry := NewSingleTenantRegistry(newTestServerConfig())
	router := gin.New()
	MountAuthRoutes(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), nil)

	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()

	nonce := issueNonceViaClient(t, client, server.URL)
	result := validator.results["empty-nonce"]
	result.payload.Claims["nonce"] = ""
	validator.results["empty-nonce"] = result
	payloadBody, err := json.Marshal(map[string]string{
		"google_id_token": "empty-nonce",
		"nonce_token":     nonce,
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/auth/google", bytes.NewReader(payloadBody))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 when google omits nonce claim, got %d", response.StatusCode)
	}
}

func TestHTTPAuthLoginUserStoreError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"user-store-token": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-user-store",
					"email":          "user@example.com",
					"email_verified": true,
					"name":           "Store User",
					"picture":        "https://example.com/avatar.png",
					"nonce":          "",
				},
			},
			expectedAudience: "client-id",
		},
	}}

	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(NewSystemClock())
	defer ProvideClock(nil)
	ProvideMetrics(NewCounterMetrics())
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(t))
	defer ProvideLogger(nil)

	config := newTestServerConfig()
	registry := NewSingleTenantRegistry(config)
	store := &failingUserStore{upsertErr: errors.New("user store error")}
	router := gin.New()
	MountAuthRoutes(router, registry, store, NewMemoryRefreshTokenStore(), nil)

	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()

	nonce := issueNonceViaClient(t, client, server.URL)
	result := validator.results["user-store-token"]
	result.payload.Claims["nonce"] = nonce
	validator.results["user-store-token"] = result

	body := map[string]string{
		"google_id_token": "user-store-token",
		"nonce_token":     nonce,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/auth/google", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 when user store fails, got %d", response.StatusCode)
	}
}

func TestHTTPAuthLoginHonorsForwardedProto(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"forwarded-token": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-forwarded",
					"email":          "user@example.com",
					"email_verified": true,
					"name":           "Forwarded Proto",
					"picture":        "https://example.com/avatar.png",
					"nonce":          "",
				},
			},
			expectedAudience: "client-id",
		},
	}}

	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(NewSystemClock())
	defer ProvideClock(nil)
	ProvideMetrics(NewCounterMetrics())
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(t))
	defer ProvideLogger(nil)

	config := newTestServerConfig()
	config.AllowInsecureHTTP = false
	registry := NewSingleTenantRegistry(config)
	router := gin.New()
	MountAuthRoutes(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), nil)

	server := newInProcessServer(router, false)
	defer server.Close()
	client := server.Client()

	nonce := issueNonceViaClient(t, client, server.URL)
	result := validator.results["forwarded-token"]
	result.payload.Claims["nonce"] = nonce
	validator.results["forwarded-token"] = result

	body := map[string]string{
		"google_id_token": "forwarded-token",
		"nonce_token":     nonce,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/auth/google", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Forwarded-Proto", "https")

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when forwarded proto indicates https, got %d", response.StatusCode)
	}
}

func TestHTTPAuthLoginUsesDefaultValidatorFactory(t *testing.T) {
	gin.SetMode(gin.TestMode)

	originalFactory := newGoogleTokenValidator
	defer func() {
		newGoogleTokenValidator = originalFactory
		validatorCache.Lock()
		validatorCache.value = nil
		validatorCache.Unlock()
	}()

	called := false
	defaultValidator := &fakeGoogleValidator{results: map[string]validatorResult{
		"default-token": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-default",
					"email":          "user@example.com",
					"email_verified": true,
					"name":           "Default Factory",
					"picture":        "https://example.com/avatar.png",
					"nonce":          "",
				},
			},
			expectedAudience: "client-id",
		},
	}}
	newGoogleTokenValidator = func(ctx context.Context) (GoogleTokenValidator, error) {
		called = true
		return defaultValidator, nil
	}

	ProvideClock(NewSystemClock())
	defer ProvideClock(nil)
	ProvideMetrics(NewCounterMetrics())
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(t))
	defer ProvideLogger(nil)

	registry := NewSingleTenantRegistry(newTestServerConfig())
	router := gin.New()
	MountAuthRoutes(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), nil)

	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()

	nonce := issueNonceViaClient(t, client, server.URL)
	result := defaultValidator.results["default-token"]
	result.payload.Claims["nonce"] = nonce
	defaultValidator.results["default-token"] = result
	body := map[string]string{
		"google_id_token": "default-token",
		"nonce_token":     nonce,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/auth/google", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}
	if !called {
		t.Fatalf("expected default validator factory to be invoked")
	}
}

func TestHTTPAuthLoginRefreshIssueFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"refresh-issue-token": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-refresh-issue",
					"email":          "user@example.com",
					"email_verified": true,
					"name":           "Refresh Issue",
					"picture":        "https://example.com/avatar.png",
					"nonce":          "",
				},
			},
			expectedAudience: "client-id",
		},
	}}

	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(NewSystemClock())
	defer ProvideClock(nil)
	ProvideMetrics(NewCounterMetrics())
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(t))
	defer ProvideLogger(nil)

	registry := NewSingleTenantRegistry(newTestServerConfig())
	refreshStore := &stubRefreshStore{
		issueFunc: func(ctx context.Context, tenantID string, applicationUserID string, expiresUnix int64, previousTokenID string) (string, string, error) {
			return "", "", errors.New("refresh issue failure")
		},
	}

	router := gin.New()
	MountAuthRoutes(router, registry, newTestUserStore(), refreshStore, nil)

	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()

	nonce := issueNonceViaClient(t, client, server.URL)
	result := validator.results["refresh-issue-token"]
	result.payload.Claims["nonce"] = nonce
	validator.results["refresh-issue-token"] = result

	body := map[string]string{
		"google_id_token": "refresh-issue-token",
		"nonce_token":     nonce,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/auth/google", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 when refresh store issue fails, got %d", response.StatusCode)
	}
}

func TestHTTPAuthRefreshIssueFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"refresh-token": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-refresh",
					"email":          "user@example.com",
					"email_verified": true,
					"name":           "Refresh User",
					"picture":        "https://example.com/avatar.png",
					"nonce":          "",
				},
			},
			expectedAudience: "client-id",
		},
	}}

	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(NewSystemClock())
	defer ProvideClock(nil)
	ProvideMetrics(NewCounterMetrics())
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(t))
	defer ProvideLogger(nil)

	config := newTestServerConfig()
	registry := NewSingleTenantRegistry(config)
	var issuedOpaque string
	refreshStore := &stubRefreshStore{
		issueFunc: func(ctx context.Context, tenantID string, applicationUserID string, expiresUnix int64, previousTokenID string) (string, string, error) {
			if issuedOpaque == "" {
				issuedOpaque = "opaque-initial"
				return "token-initial", issuedOpaque, nil
			}
			return "", "", errors.New("second issue failure")
		},
		validateFunc: func(ctx context.Context, tenantID string, tokenOpaque string) (string, string, int64, error) {
			if tokenOpaque != issuedOpaque {
				return "", "", 0, errors.New("unexpected token")
			}
			return "google:sub-refresh", "token-initial", time.Now().Add(time.Minute).Unix(), nil
		},
		revokeFunc: func(ctx context.Context, tenantID string, tokenID string) error {
			return nil
		},
	}

	router := gin.New()
	store := newMutableUserStore()
	MountAuthRoutes(router, registry, store, refreshStore, nil)

	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()

	loginResp, _ := loginWithNonce(t, client, server.URL, validator, "refresh-token")
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from login, got %d", loginResp.StatusCode)
	}
	state := captureAuthCookies(authCookieState{}, loginResp.Cookies(), config)
	_ = loginResp.Body.Close()

	refreshReq, err := http.NewRequest(http.MethodPost, server.URL+"/auth/refresh", nil)
	if err != nil {
		t.Fatalf("build refresh request: %v", err)
	}
	applyAuthCookies(refreshReq, state, config)
	refreshResp, err := client.Do(refreshReq)
	if err != nil {
		t.Fatalf("refresh request failed: %v", err)
	}
	defer refreshResp.Body.Close()
	if refreshResp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 when refresh issuance fails, got %d", refreshResp.StatusCode)
	}
}

func TestNewGoogleTokenValidatorDelegatesToFactory(t *testing.T) {
	originalFactory := newGoogleTokenValidator
	defer func() {
		newGoogleTokenValidator = originalFactory
	}()

	called := false
	newGoogleTokenValidator = func(ctx context.Context) (GoogleTokenValidator, error) {
		called = true
		return &fakeGoogleValidator{}, nil
	}

	if _, err := NewGoogleTokenValidator(context.Background()); err != nil {
		t.Fatalf("unexpected error invoking default validator: %v", err)
	}
	if !called {
		t.Fatalf("expected underlying factory to be invoked")
	}
}

func TestHTTPAuthLoginRejectsInvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{}
	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(NewSystemClock())
	defer ProvideClock(nil)
	ProvideMetrics(NewCounterMetrics())
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(t))
	defer ProvideLogger(nil)

	registry := NewSingleTenantRegistry(newTestServerConfig())
	router := gin.New()
	MountAuthRoutes(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), nil)

	server := newInProcessServer(router, true)
	defer server.Close()

	request, err := http.NewRequest(http.MethodPost, server.URL+"/auth/google", strings.NewReader("not-json"))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", response.StatusCode)
	}
	var payload map[string]string
	if decodeErr := json.NewDecoder(response.Body).Decode(&payload); decodeErr != nil {
		t.Fatalf("decode payload: %v", decodeErr)
	}
	if payload["error"] != "invalid_json" {
		t.Fatalf("expected invalid_json error, got %v", payload["error"])
	}
}

func TestHTTPAuthLoginRequiresHTTPS(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"secure-token": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-secure",
					"email":          "user@example.com",
					"email_verified": true,
					"name":           "Secure User",
					"picture":        "https://example.com/avatar.png",
					"nonce":          "",
				},
			},
			expectedAudience: "client-id",
		},
	}}

	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(NewSystemClock())
	defer ProvideClock(nil)
	ProvideMetrics(NewCounterMetrics())
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(t))
	defer ProvideLogger(nil)

	config := newTestServerConfig()
	config.AllowInsecureHTTP = false
	registry := NewSingleTenantRegistry(config)
	router := gin.New()
	MountAuthRoutes(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), nil)

	server := newInProcessServer(router, false)
	defer server.Close()
	client := server.Client()

	nonce := issueNonceViaClient(t, client, server.URL)
	result := validator.results["secure-token"]
	result.payload.Claims["nonce"] = nonce
	validator.results["secure-token"] = result

	body := map[string]string{
		"google_id_token": "secure-token",
		"nonce_token":     nonce,
	}
	buffer, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	request, err := http.NewRequest(http.MethodPost, server.URL+"/auth/google", bytes.NewReader(buffer))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Host = "beta.localhost"

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for insecure HTTP, got %d", response.StatusCode)
	}
	var payload map[string]string
	if decodeErr := json.NewDecoder(response.Body).Decode(&payload); decodeErr != nil {
		t.Fatalf("decode payload: %v", decodeErr)
	}
	if payload["error"] != "https_required" {
		t.Fatalf("expected https_required error, got %v", payload["error"])
	}
}

func TestHTTPAuthLoginUnverifiedIdentity(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"unverified-token": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-unverified",
					"email":          "user@example.com",
					"email_verified": false,
					"name":           "Unverified User",
					"picture":        "https://example.com/avatar.png",
					"nonce":          "",
				},
			},
			expectedAudience: "client-id",
		},
	}}

	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(NewSystemClock())
	defer ProvideClock(nil)
	ProvideMetrics(NewCounterMetrics())
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(t))
	defer ProvideLogger(nil)

	registry := NewSingleTenantRegistry(newTestServerConfig())
	router := gin.New()
	MountAuthRoutes(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), nil)

	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()

	nonce := issueNonceViaClient(t, client, server.URL)
	result := validator.results["unverified-token"]
	result.payload.Claims["nonce"] = nonce
	validator.results["unverified-token"] = result

	body := map[string]string{
		"google_id_token": "unverified-token",
		"nonce_token":     nonce,
	}
	buffer, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	request, err := http.NewRequest(http.MethodPost, server.URL+"/auth/google", bytes.NewReader(buffer))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unverified identity, got %d", response.StatusCode)
	}
	var payload map[string]string
	if decodeErr := json.NewDecoder(response.Body).Decode(&payload); decodeErr != nil {
		t.Fatalf("decode payload: %v", decodeErr)
	}
	if payload["error"] != "unverified_identity" {
		t.Fatalf("expected unverified_identity error, got %v", payload["error"])
	}
}

func TestHTTPAuthLoginRejectsDisallowedUser(testingHandle *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"disallowed-token": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-disallowed",
					"email":          "denied@example.com",
					"email_verified": true,
					"name":           "Denied User",
					"picture":        "https://example.com/avatar.png",
					"nonce":          "",
				},
			},
			expectedAudience: "client-id",
		},
	}}

	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(NewSystemClock())
	defer ProvideClock(nil)
	ProvideMetrics(NewCounterMetrics())
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(testingHandle))
	defer ProvideLogger(nil)

	config := newTestServerConfig()
	config.AllowedUsers = map[string]struct{}{"allowed@example.com": {}}
	registry := NewSingleTenantRegistry(config)
	router := gin.New()
	MountAuthRoutes(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), nil)

	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()

	nonce := issueNonceViaClient(testingHandle, client, server.URL)
	result := validator.results["disallowed-token"]
	result.payload.Claims["nonce"] = nonce
	validator.results["disallowed-token"] = result

	body := map[string]string{
		"google_id_token": "disallowed-token",
		"nonce_token":     nonce,
	}
	payload, marshalErr := json.Marshal(body)
	if marshalErr != nil {
		testingHandle.Fatalf("marshal payload: %v", marshalErr)
	}

	request, requestErr := http.NewRequest(http.MethodPost, server.URL+"/auth/google", bytes.NewReader(payload))
	if requestErr != nil {
		testingHandle.Fatalf("build request: %v", requestErr)
	}
	request.Header.Set("Content-Type", "application/json")

	response, responseErr := client.Do(request)
	if responseErr != nil {
		testingHandle.Fatalf("request failed: %v", responseErr)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		testingHandle.Fatalf("expected 403 for disallowed user, got %d", response.StatusCode)
	}
	var responsePayload map[string]string
	if decodeErr := json.NewDecoder(response.Body).Decode(&responsePayload); decodeErr != nil {
		testingHandle.Fatalf("decode payload: %v", decodeErr)
	}
	if responsePayload["error"] != errorUserNotAllowed {
		testingHandle.Fatalf("expected %s error, got %v", errorUserNotAllowed, responsePayload["error"])
	}
}

func TestHTTPAuthLoginRejectsEmptyAllowlist(testingHandle *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"empty-allowlist-token": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-empty-allowlist",
					"email":          "user@example.com",
					"email_verified": true,
					"name":           "Empty Allowlist",
					"picture":        "https://example.com/avatar.png",
					"nonce":          "",
				},
			},
			expectedAudience: "client-id",
		},
	}}

	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(NewSystemClock())
	defer ProvideClock(nil)
	ProvideMetrics(NewCounterMetrics())
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(testingHandle))
	defer ProvideLogger(nil)

	config := newTestServerConfig()
	config.AllowedUsers = map[string]struct{}{}
	registry := NewSingleTenantRegistry(config)
	router := gin.New()
	MountAuthRoutes(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), nil)

	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()

	nonce := issueNonceViaClient(testingHandle, client, server.URL)
	result := validator.results["empty-allowlist-token"]
	result.payload.Claims["nonce"] = nonce
	validator.results["empty-allowlist-token"] = result

	body := map[string]string{
		"google_id_token": "empty-allowlist-token",
		"nonce_token":     nonce,
	}
	payload, marshalErr := json.Marshal(body)
	if marshalErr != nil {
		testingHandle.Fatalf("marshal payload: %v", marshalErr)
	}

	request, requestErr := http.NewRequest(http.MethodPost, server.URL+"/auth/google", bytes.NewReader(payload))
	if requestErr != nil {
		testingHandle.Fatalf("build request: %v", requestErr)
	}
	request.Header.Set("Content-Type", "application/json")

	response, responseErr := client.Do(request)
	if responseErr != nil {
		testingHandle.Fatalf("request failed: %v", responseErr)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		testingHandle.Fatalf("expected 403 for empty allowlist, got %d", response.StatusCode)
	}
	var responsePayload map[string]string
	if decodeErr := json.NewDecoder(response.Body).Decode(&responsePayload); decodeErr != nil {
		testingHandle.Fatalf("decode payload: %v", decodeErr)
	}
	if responsePayload["error"] != errorUserNotAllowed {
		testingHandle.Fatalf("expected %s error, got %v", errorUserNotAllowed, responsePayload["error"])
	}
}

func TestHTTPAuthLoginAllowsListedUser(testingHandle *testing.T) {
	gin.SetMode(gin.TestMode)

	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"allowed-token": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-allowed",
					"email":          "ALLOWED@EXAMPLE.COM",
					"email_verified": true,
					"name":           "Allowed User",
					"picture":        "https://example.com/avatar.png",
					"nonce":          "",
				},
			},
			expectedAudience: "client-id",
		},
	}}

	ProvideGoogleTokenValidator(validator)
	defer ProvideGoogleTokenValidator(nil)
	ProvideClock(NewSystemClock())
	defer ProvideClock(nil)
	ProvideMetrics(NewCounterMetrics())
	defer ProvideMetrics(nil)
	ProvideLogger(zaptest.NewLogger(testingHandle))
	defer ProvideLogger(nil)

	config := newTestServerConfig()
	config.AllowedUsers = map[string]struct{}{"allowed@example.com": {}}
	registry := NewSingleTenantRegistry(config)
	router := gin.New()
	MountAuthRoutes(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), nil)

	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()

	nonce := issueNonceViaClient(testingHandle, client, server.URL)
	result := validator.results["allowed-token"]
	result.payload.Claims["nonce"] = nonce
	validator.results["allowed-token"] = result

	body := map[string]string{
		"google_id_token": "allowed-token",
		"nonce_token":     nonce,
	}
	payload, marshalErr := json.Marshal(body)
	if marshalErr != nil {
		testingHandle.Fatalf("marshal payload: %v", marshalErr)
	}

	request, requestErr := http.NewRequest(http.MethodPost, server.URL+"/auth/google", bytes.NewReader(payload))
	if requestErr != nil {
		testingHandle.Fatalf("build request: %v", requestErr)
	}
	request.Header.Set("Content-Type", "application/json")

	response, responseErr := client.Do(request)
	if responseErr != nil {
		testingHandle.Fatalf("request failed: %v", responseErr)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		testingHandle.Fatalf("expected 200 for allowed user, got %d", response.StatusCode)
	}
}

func TestHTTPAppleOAuthStartAndCallbackMintSession(testingHandle *testing.T) {
	gin.SetMode(gin.TestMode)

	rsaKey, keyErr := rsa.GenerateKey(rand.Reader, 2048)
	if keyErr != nil {
		testingHandle.Fatalf("generate mock Apple signing key: %v", keyErr)
	}
	appleKeyID := "apple-test-key"
	expectedNonce := ""
	var tokenRequest url.Values

	appleRouter := http.NewServeMux()
	appleRouter.HandleFunc("/auth/token", func(responseWriter http.ResponseWriter, request *http.Request) {
		if parseErr := request.ParseForm(); parseErr != nil {
			http.Error(responseWriter, parseErr.Error(), http.StatusBadRequest)
			return
		}
		tokenRequest = request.PostForm
		idToken := mintMockAppleIDToken(testingHandle, rsaKey, appleKeyID, "com.example.web", "apple-subject", "apple@example.com", "Apple User", expectedNonce)
		responseWriter.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(responseWriter).Encode(map[string]interface{}{
			"access_token":  "apple-access-token",
			"expires_in":    3600,
			"id_token":      idToken,
			"refresh_token": "discarded-apple-refresh",
			"token_type":    "Bearer",
		})
	})
	appleRouter.HandleFunc("/auth/keys", func(responseWriter http.ResponseWriter, request *http.Request) {
		responseWriter.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(responseWriter).Encode(mockAppleJWKS(rsaKey, appleKeyID))
	})
	appleServer := newInProcessServer(appleRouter, true)
	defer appleServer.Close()

	ProvideAppleOAuthHTTPClient(appleServer.Client())
	defer ProvideAppleOAuthHTTPClient(nil)

	config := newTestServerConfig()
	config.TenantOrigins = []string{"https://product.example.com"}
	config.AppleOAuth = AppleOAuthConfig{
		Enabled:               true,
		ClientID:              "com.example.web",
		TeamID:                "TEAMID1234",
		KeyID:                 "KEYID12345",
		PrivateKey:            generateTestAppleClientPrivateKeyPEM(testingHandle),
		RedirectURI:           "https://in-process.local/auth/apple/callback",
		Scopes:                []string{"openid", "email", "name"},
		AuthorizationEndpoint: appleServer.URL + "/auth/authorize",
		TokenEndpoint:         appleServer.URL + "/auth/token",
		JWKSURL:               appleServer.URL + "/auth/keys",
	}
	registry := NewSingleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()
	clock := &controllableClock{current: time.Now().UTC()}
	ProvideClock(clock)
	defer ProvideClock(nil)

	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)
	server := newInProcessServer(router, true)
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(request *http.Request, requests []*http.Request) error {
		return http.ErrUseLastResponse
	}

	startAppleAuthorization := func(startURL string) (url.Values, string) {
		startRequest, startErr := http.NewRequest(http.MethodGet, startURL, nil)
		if startErr != nil {
			testingHandle.Fatalf("build Apple start request: %v", startErr)
		}
		startResponse, startErr := client.Do(startRequest)
		if startErr != nil {
			testingHandle.Fatalf("Apple start request failed: %v", startErr)
		}
		defer startResponse.Body.Close()
		if startResponse.StatusCode != http.StatusFound {
			testingHandle.Fatalf("expected Apple start redirect, got %d", startResponse.StatusCode)
		}
		authorizationURL, parseErr := url.Parse(startResponse.Header.Get("Location"))
		if parseErr != nil {
			testingHandle.Fatalf("parse Apple authorization redirect: %v", parseErr)
		}
		query := authorizationURL.Query()
		state := query.Get("state")
		nonce := query.Get("nonce")
		if state == "" || nonce == "" {
			testingHandle.Fatalf("expected state and nonce in Apple authorization redirect: %s", authorizationURL.String())
		}
		if query.Get("client_id") != "com.example.web" || query.Get("redirect_uri") != config.AppleOAuth.RedirectURI {
			testingHandle.Fatalf("unexpected Apple authorization query: %s", authorizationURL.RawQuery)
		}
		return query, state
	}

	query, state := startAppleAuthorization(server.URL + "/auth/apple/start")
	expectedNonce = query.Get("nonce")
	callbackURL := server.URL + "/auth/apple/callback?code=apple-code&state=" + url.QueryEscape(state)
	callbackRequest, callbackErr := http.NewRequest(http.MethodGet, callbackURL, nil)
	if callbackErr != nil {
		testingHandle.Fatalf("build Apple callback request: %v", callbackErr)
	}
	callbackResponse, callbackErr := client.Do(callbackRequest)
	if callbackErr != nil {
		testingHandle.Fatalf("Apple callback request failed: %v", callbackErr)
	}
	defer callbackResponse.Body.Close()
	if callbackResponse.StatusCode != http.StatusOK {
		testingHandle.Fatalf("expected Apple callback to mint a session, got %d", callbackResponse.StatusCode)
	}
	if tokenRequest.Get("client_id") != "com.example.web" || tokenRequest.Get("code") != "apple-code" || tokenRequest.Get("grant_type") != "authorization_code" {
		testingHandle.Fatalf("unexpected Apple token request form: %#v", tokenRequest)
	}
	if tokenRequest.Get("redirect_uri") != config.AppleOAuth.RedirectURI || tokenRequest.Get("client_secret") == "" {
		testingHandle.Fatalf("expected Apple token request redirect_uri and client_secret, got %#v", tokenRequest)
	}
	var profile map[string]interface{}
	if decodeErr := json.NewDecoder(callbackResponse.Body).Decode(&profile); decodeErr != nil {
		testingHandle.Fatalf("decode Apple callback profile: %v", decodeErr)
	}
	if profile["user_id"] != "apple:apple-subject" || profile["user_email"] != "apple@example.com" {
		testingHandle.Fatalf("unexpected Apple profile: %#v", profile)
	}
	cookies := captureAuthCookies(authCookieState{}, callbackResponse.Cookies(), config)
	if cookies.session == "" || cookies.refresh == "" {
		testingHandle.Fatalf("expected Apple callback to set session and refresh cookies")
	}

	returnToURL := "https://product.example.com/library?login=apple"
	returnQuery, returnState := startAppleAuthorization(server.URL + "/auth/apple/start?return_to=" + url.QueryEscape(returnToURL))
	expectedNonce = returnQuery.Get("nonce")
	redirectCallbackURL := server.URL + "/auth/apple/callback?code=apple-code-return&state=" + url.QueryEscape(returnState)
	redirectCallbackRequest, redirectCallbackErr := http.NewRequest(http.MethodGet, redirectCallbackURL, nil)
	if redirectCallbackErr != nil {
		testingHandle.Fatalf("build Apple redirect callback request: %v", redirectCallbackErr)
	}
	redirectCallbackResponse, redirectCallbackErr := client.Do(redirectCallbackRequest)
	if redirectCallbackErr != nil {
		testingHandle.Fatalf("Apple redirect callback request failed: %v", redirectCallbackErr)
	}
	defer redirectCallbackResponse.Body.Close()
	if redirectCallbackResponse.StatusCode != http.StatusSeeOther {
		testingHandle.Fatalf("expected Apple callback to redirect to return_to, got %d", redirectCallbackResponse.StatusCode)
	}
	if redirectCallbackResponse.Header.Get("Location") != returnToURL {
		testingHandle.Fatalf("expected return_to redirect %q, got %q", returnToURL, redirectCallbackResponse.Header.Get("Location"))
	}
	if tokenRequest.Get("code") != "apple-code-return" {
		testingHandle.Fatalf("expected second Apple code exchange, got %#v", tokenRequest)
	}
	redirectCookies := captureAuthCookies(authCookieState{}, redirectCallbackResponse.Cookies(), config)
	if redirectCookies.session == "" || redirectCookies.refresh == "" {
		testingHandle.Fatalf("expected Apple redirect callback to set session and refresh cookies")
	}
}

func TestHTTPAppleOAuthStartRejectsUnregisteredReturnTo(testingHandle *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newTestServerConfig()
	config.TenantOrigins = []string{"https://allowed.example.com"}
	config.AppleOAuth = AppleOAuthConfig{
		Enabled:               true,
		ClientID:              "com.example.web",
		TeamID:                "TEAMID1234",
		KeyID:                 "KEYID12345",
		PrivateKey:            generateTestAppleClientPrivateKeyPEM(testingHandle),
		RedirectURI:           "https://in-process.local/auth/apple/callback",
		Scopes:                []string{"openid", "email", "name"},
		AuthorizationEndpoint: "https://appleid.apple.com/auth/authorize",
		TokenEndpoint:         "https://appleid.apple.com/auth/token",
		JWKSURL:               "https://appleid.apple.com/auth/keys",
	}

	router := gin.New()
	MountAuthRoutes(router, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), nil)
	server := newInProcessServer(router, true)
	defer server.Close()

	request, requestErr := http.NewRequest(http.MethodGet, server.URL+"/auth/apple/start?return_to="+url.QueryEscape("https://evil.example.com/app"), nil)
	if requestErr != nil {
		testingHandle.Fatalf("build Apple start request: %v", requestErr)
	}
	response, responseErr := server.Client().Do(request)
	if responseErr != nil {
		testingHandle.Fatalf("Apple start request failed: %v", responseErr)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		testingHandle.Fatalf("expected invalid return_to rejection, got %d", response.StatusCode)
	}
	var payload map[string]interface{}
	if decodeErr := json.NewDecoder(response.Body).Decode(&payload); decodeErr != nil {
		testingHandle.Fatalf("decode invalid return_to response: %v", decodeErr)
	}
	if payload["error"] != errorAppleReturnToInvalid {
		testingHandle.Fatalf("expected invalid_return_to, got %#v", payload)
	}
}

func issueNonceViaClient(t *testing.T, client *http.Client, baseURL string) string {
	return issueNonceViaClientWithHeaders(t, client, baseURL, nil)
}

func issueNonceViaClientWithHeaders(t *testing.T, client *http.Client, baseURL string, headers map[string]string) string {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/auth/nonce", nil)
	if err != nil {
		t.Fatalf("build nonce request: %v", err)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request nonce: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /auth/nonce, got %d", response.StatusCode)
	}
	var payload struct {
		Nonce string `json:"nonce"`
	}
	if decodeErr := json.NewDecoder(response.Body).Decode(&payload); decodeErr != nil {
		t.Fatalf("decode nonce payload: %v", decodeErr)
	}
	if payload.Nonce == "" {
		t.Fatalf("nonce payload empty")
	}
	return payload.Nonce
}

func loginWithNonce(t *testing.T, client *http.Client, baseURL string, validator *fakeGoogleValidator, token string) (*http.Response, string) {
	return loginWithNonceAndHeaders(t, client, baseURL, validator, token, nil)
}

func loginWithNonceAndHeaders(t *testing.T, client *http.Client, baseURL string, validator *fakeGoogleValidator, token string, headers map[string]string) (*http.Response, string) {
	t.Helper()
	nonce := issueNonceViaClientWithHeaders(t, client, baseURL, headers)
	result, ok := validator.results[token]
	if !ok {
		t.Fatalf("token %s not configured in validator", token)
	}
	if result.payload == nil {
		t.Fatalf("validator payload missing for token %s", token)
	}
	result.payload.Claims["nonce"] = nonce
	validator.results[token] = result
	loginPayload, marshalErr := json.Marshal(map[string]string{
		"google_id_token": token,
		"nonce_token":     nonce,
	})
	if marshalErr != nil {
		t.Fatalf("marshal login payload: %v", marshalErr)
	}
	request, err := http.NewRequest(http.MethodPost, baseURL+"/auth/google", bytes.NewReader(loginPayload))
	if err != nil {
		t.Fatalf("build login request failed: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	return response, nonce
}
func loginWithTenantHeader(t *testing.T, client *http.Client, baseURL string, validator *fakeGoogleValidator, token string, tenantID string, host string) (*http.Response, string) {
	headers := map[string]string{
		"X-TAuth-Tenant": tenantID,
	}
	if strings.TrimSpace(host) != "" {
		headers[testHostHeader] = host
	}
	return loginWithNonceAndHeaders(t, client, baseURL, validator, token, headers)
}

func generateTestAppleClientPrivateKeyPEM(testingHandle *testing.T) string {
	testingHandle.Helper()
	privateKey, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if keyErr != nil {
		testingHandle.Fatalf("generate Apple client private key: %v", keyErr)
	}
	encodedKey, marshalErr := x509.MarshalPKCS8PrivateKey(privateKey)
	if marshalErr != nil {
		testingHandle.Fatalf("marshal Apple client private key: %v", marshalErr)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey}))
}

func mintMockAppleIDToken(testingHandle *testing.T, privateKey *rsa.PrivateKey, keyID string, audience string, subject string, email string, displayName string, nonce string) string {
	testingHandle.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":            appleIssuer,
		"aud":            audience,
		"sub":            subject,
		"email":          email,
		"email_verified": "true",
		"name":           displayName,
		"nonce":          nonce,
		"iat":            time.Now().UTC().Unix(),
		"exp":            time.Now().UTC().Add(time.Minute).Unix(),
	})
	token.Header["kid"] = keyID
	signedToken, signErr := token.SignedString(privateKey)
	if signErr != nil {
		testingHandle.Fatalf("sign mock Apple ID token: %v", signErr)
	}
	return signedToken
}

func mockAppleJWKS(privateKey *rsa.PrivateKey, keyID string) map[string]interface{} {
	publicKey := privateKey.PublicKey
	return map[string]interface{}{
		"keys": []map[string]string{
			{
				"kty": "RSA",
				"kid": keyID,
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(bigEndianExponent(publicKey.E)),
			},
		},
	}
}

func bigEndianExponent(value int) []byte {
	if value == 0 {
		return []byte{0}
	}
	bytesValue := []byte{}
	for remaining := value; remaining > 0; remaining >>= 8 {
		bytesValue = append([]byte{byte(remaining & 0xff)}, bytesValue...)
	}
	return bytesValue
}

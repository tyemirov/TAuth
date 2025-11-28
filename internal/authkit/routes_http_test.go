package authkit

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/tenants"
	"go.uber.org/zap/zaptest"
	"google.golang.org/api/idtoken"
)

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

func buildMultiTenantRegistry(base ServerConfig) TenantRegistry {
	configA := base
	configA.TenantID = "tenant-a"
	configA.GoogleWebClientID = "client-tenant-a"
	configA.CookieDomain = "tenant-a.local"
	configB := base
	configB.TenantID = "tenant-b"
	configB.GoogleWebClientID = "client-tenant-b"
	configB.CookieDomain = "tenant-b.local"
	return NewTenantRegistryFromMap(configA.TenantID, map[string]ServerConfig{
		configA.TenantID: configA,
		configB.TenantID: configB,
	})
}

func mustLoadTenantsConfigFromString(t *testing.T, contents string) tenants.Config {
	t.Helper()
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "tenants.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write tenants file: %v", err)
	}
	cfg, err := tenants.LoadConfig(path)
	if err != nil {
		t.Fatalf("load tenants config: %v", err)
	}
	return cfg
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

	server := httptest.NewTLSServer(router)
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
				"hosts": ["tenant-a.localhost"],
				"google_web_client_id": "client-tenant-a",
				"cookie_domain": "tenant-a.localhost",
				"session_ttl": "15m",
				"refresh_ttl": "1440h",
				"nonce_ttl": "5m",
				"allow_insecure_http": true
			},
			{
				"id": "tenant-b",
				"display_name": "Tenant B",
				"hosts": ["tenant-b.localhost"],
				"google_web_client_id": "client-tenant-b",
				"cookie_domain": "tenant-b.localhost",
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
	router.Use(tenants.TenantMiddleware(resolver, http.StatusNotFound))
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

	server := httptest.NewTLSServer(router)
	defer server.Close()

	client := server.Client()

	loginTenant := func(tenantID string, token string) authCookieState {
		response, _ := loginWithTenantHeader(t, client, server.URL, validator, token, tenantID)
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

	server := httptest.NewTLSServer(router)
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
	if refreshResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 from revoked refresh token, got %d", refreshResp.StatusCode)
	}
	_ = refreshResp.Body.Close()

	if metrics.Count(metricAuthRefreshFailure) == 0 {
		t.Fatalf("expected auth.refresh.failure metric increment")
	}
}

func mustParseURL(raw string) *url.URL {
	parsed, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return parsed
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
func loginWithTenantHeader(t *testing.T, client *http.Client, baseURL string, validator *fakeGoogleValidator, token string, tenantID string) (*http.Response, string) {
	headers := map[string]string{"X-TAuth-Tenant": tenantID}
	return loginWithNonceAndHeaders(t, client, baseURL, validator, token, headers)
}

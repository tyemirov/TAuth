package authkit

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
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
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()

	router := gin.New()
	MountAuthRoutes(router, config, userStore, refreshStore)

	server := httptest.NewTLSServer(router)
	defer server.Close()

	client := server.Client()
	state := authCookieState{}

	loginBody := []byte(`{"google_id_token":"valid-token"}`)
	loginResp, err := client.Post(server.URL+"/auth/google", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}
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
	loginResp2, err := client.Post(server.URL+"/auth/google", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("second login failed: %v", err)
	}
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
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()

	router := gin.New()
	MountAuthRoutes(router, config, userStore, refreshStore)

	server := httptest.NewTLSServer(router)
	defer server.Close()

	client := server.Client()
	state := authCookieState{}

	loginResp, err := client.Post(server.URL+"/auth/google", "application/json", bytes.NewReader([]byte(`{"google_id_token":"valid-token"}`)))
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from login, got %d", loginResp.StatusCode)
	}
	state = captureAuthCookies(state, loginResp.Cookies(), config)
	_ = loginResp.Body.Close()

	if state.refresh == "" {
		t.Fatalf("missing refresh cookie after login")
	}

	_, tokenID, _, validateErr := refreshStore.Validate(context.Background(), state.refresh)
	if validateErr != nil {
		t.Fatalf("validate refresh token failed: %v", validateErr)
	}
	if revokeErr := refreshStore.Revoke(context.Background(), tokenID); revokeErr != nil {
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

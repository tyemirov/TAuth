package authkit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"google.golang.org/api/idtoken"
)

type validatorResult struct {
	payload          *idtoken.Payload
	err              error
	expectedAudience string
}

type fakeGoogleValidator struct {
	results map[string]validatorResult
}

func (validator *fakeGoogleValidator) Validate(ctx context.Context, token string, audience string) (*idtoken.Payload, error) {
	result, ok := validator.results[token]
	if !ok {
		return nil, errors.New("token_not_found")
	}
	if result.expectedAudience != "" && result.expectedAudience != audience {
		return nil, errors.New("audience_mismatch")
	}
	if result.err != nil {
		return nil, result.err
	}
	return result.payload, nil
}

func withValidatorFactory(t *testing.T, factory func(context.Context) (GoogleTokenValidator, error)) func() {
	t.Helper()
	previous := newGoogleTokenValidator
	newGoogleTokenValidator = factory
	return func() {
		newGoogleTokenValidator = previous
	}
}

type testUserStore struct {
	profiles map[string]testUserProfile
}

type testUserProfile struct {
	email   string
	display string
	roles   []string
}

func newTestUserStore() *testUserStore {
	return &testUserStore{profiles: make(map[string]testUserProfile)}
}

func (store *testUserStore) UpsertGoogleUser(ctx context.Context, googleSub string, userEmail string, userDisplayName string) (string, []string, error) {
	applicationUserID := "google:" + googleSub
	profile := testUserProfile{
		email:   userEmail,
		display: userDisplayName,
		roles:   []string{"user"},
	}
	store.profiles[applicationUserID] = profile
	return applicationUserID, profile.roles, nil
}

func (store *testUserStore) GetUserProfile(ctx context.Context, applicationUserID string) (string, string, []string, error) {
	profile, ok := store.profiles[applicationUserID]
	if !ok {
		return "", "", nil, errors.New("user_not_found")
	}
	return profile.email, profile.display, profile.roles, nil
}

type failingUserStore struct {
	upsertErr  error
	profileErr error
}

func (store *failingUserStore) UpsertGoogleUser(ctx context.Context, googleSub string, userEmail string, userDisplayName string) (string, []string, error) {
	return "", nil, store.upsertErr
}

func (store *failingUserStore) GetUserProfile(ctx context.Context, applicationUserID string) (string, string, []string, error) {
	return "", "", nil, store.profileErr
}

type stubRefreshStore struct {
	issueFunc    func(ctx context.Context, applicationUserID string, expiresUnix int64, previousTokenID string) (string, string, error)
	validateFunc func(ctx context.Context, tokenOpaque string) (string, string, int64, error)
	revokeFunc   func(ctx context.Context, tokenID string) error
}

func (store *stubRefreshStore) Issue(ctx context.Context, applicationUserID string, expiresUnix int64, previousTokenID string) (string, string, error) {
	if store.issueFunc != nil {
		return store.issueFunc(ctx, applicationUserID, expiresUnix, previousTokenID)
	}
	return "", "", nil
}

func (store *stubRefreshStore) Validate(ctx context.Context, tokenOpaque string) (string, string, int64, error) {
	if store.validateFunc != nil {
		return store.validateFunc(ctx, tokenOpaque)
	}
	return "", "", 0, errors.New("validate_not_configured")
}

func (store *stubRefreshStore) Revoke(ctx context.Context, tokenID string) error {
	if store.revokeFunc != nil {
		return store.revokeFunc(ctx, tokenID)
	}
	return nil
}

func newTestServerConfig() ServerConfig {
	return ServerConfig{
		GoogleWebClientID: "client-id",
		AppJWTSigningKey:  []byte("secret-key-1234567890"),
		AppJWTIssuer:      "test-issuer",
		CookieDomain:      "",
		SessionCookieName: "app_session",
		RefreshCookieName: "app_refresh",
		SessionTTL:        time.Minute,
		RefreshTTL:        15 * time.Minute,
		SameSiteMode:      http.SameSiteStrictMode,
		AllowInsecureHTTP: true,
	}
}

func collectCookies(cookies []*http.Cookie) map[string]*http.Cookie {
	collected := make(map[string]*http.Cookie)
	for _, cookie := range cookies {
		collected[cookie.Name] = cookie
	}
	return collected
}

func addCookies(request *http.Request, cookies map[string]*http.Cookie, names ...string) {
	for _, name := range names {
		if cookie, ok := cookies[name]; ok {
			request.AddCookie(cookie)
		}
	}
}

func TestAuthLifecycle(t *testing.T) {
	gin.SetMode(gin.TestMode)

	payload := &idtoken.Payload{
		Claims: map[string]interface{}{
			"iss":            "https://accounts.google.com",
			"sub":            "sub-123",
			"email":          "user@example.com",
			"email_verified": true,
			"name":           "Test User",
		},
	}

	restoreValidator := withValidatorFactory(t, func(ctx context.Context) (GoogleTokenValidator, error) {
		return &fakeGoogleValidator{
			results: map[string]validatorResult{
				"valid-token": {
					payload:          payload,
					expectedAudience: "client-id",
				},
			},
		}, nil
	})
	defer restoreValidator()

	config := newTestServerConfig()
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()

	router := gin.New()
	MountAuthRoutes(router, config, userStore, refreshStore)

	loginRequest := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBufferString(`{"google_id_token":"valid-token","nonce":"n"}`))
	loginRequest.Header.Set("Content-Type", "application/json")
	loginResponse := httptest.NewRecorder()
	router.ServeHTTP(loginResponse, loginRequest)

	if loginResponse.Code != http.StatusOK {
		t.Fatalf("expected 200 from login, got %d", loginResponse.Code)
	}

	cookies := collectCookies(loginResponse.Result().Cookies())
	if _, ok := cookies[config.SessionCookieName]; !ok {
		t.Fatalf("missing session cookie")
	}
	if _, ok := cookies[config.RefreshCookieName]; !ok {
		t.Fatalf("missing refresh cookie")
	}

	if _, ok := userStore.profiles["google:sub-123"]; !ok {
		t.Fatalf("user not persisted after login")
	}

	meRequest := httptest.NewRequest(http.MethodGet, "/me", nil)
	addCookies(meRequest, cookies, config.SessionCookieName)
	meResponse := httptest.NewRecorder()
	router.ServeHTTP(meResponse, meRequest)
	if meResponse.Code != http.StatusOK {
		t.Fatalf("expected 200 from /me, got %d", meResponse.Code)
	}
	var mePayload map[string]interface{}
	if err := json.NewDecoder(meResponse.Body).Decode(&mePayload); err != nil {
		t.Fatalf("failed to decode /me payload: %v", err)
	}
	if mePayload["user_id"] != "google:sub-123" {
		t.Fatalf("unexpected user_id: %v", mePayload["user_id"])
	}

	refreshRequest := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	addCookies(refreshRequest, cookies, config.RefreshCookieName)
	refreshResponse := httptest.NewRecorder()
	router.ServeHTTP(refreshResponse, refreshRequest)
	if refreshResponse.Code != http.StatusNoContent {
		t.Fatalf("expected 204 from refresh, got %d", refreshResponse.Code)
	}
	for name, cookie := range collectCookies(refreshResponse.Result().Cookies()) {
		cookies[name] = cookie
	}

	secureRouter := gin.New()
	secureRouter.Use(RequireSession(config))
	secureRouter.GET("/secure", func(contextGin *gin.Context) {
		claims, ok := contextGin.MustGet("auth_claims").(*JwtCustomClaims)
		if !ok {
			contextGin.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		contextGin.JSON(http.StatusOK, gin.H{"user_id": claims.UserID})
	})

	secureRequest := httptest.NewRequest(http.MethodGet, "/secure", nil)
	addCookies(secureRequest, cookies, config.SessionCookieName)
	secureResponse := httptest.NewRecorder()
	secureRouter.ServeHTTP(secureResponse, secureRequest)
	if secureResponse.Code != http.StatusOK {
		t.Fatalf("expected 200 from secure route, got %d", secureResponse.Code)
	}

	logoutRequest := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	addCookies(logoutRequest, cookies, config.RefreshCookieName)
	logoutResponse := httptest.NewRecorder()
	router.ServeHTTP(logoutResponse, logoutRequest)
	if logoutResponse.Code != http.StatusNoContent {
		t.Fatalf("expected 204 from logout, got %d", logoutResponse.Code)
	}
	for name, cookie := range collectCookies(logoutResponse.Result().Cookies()) {
		cookies[name] = cookie
	}

	postLogoutRequest := httptest.NewRequest(http.MethodGet, "/me", nil)
	addCookies(postLogoutRequest, cookies, config.SessionCookieName)
	postLogoutResponse := httptest.NewRecorder()
	router.ServeHTTP(postLogoutResponse, postLogoutRequest)
	if postLogoutResponse.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after logout, got %d", postLogoutResponse.Code)
	}
}

func TestAuthGoogleRequiresHTTPS(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restoreValidator := withValidatorFactory(t, func(ctx context.Context) (GoogleTokenValidator, error) {
		return &fakeGoogleValidator{
			results: map[string]validatorResult{
				"valid-token": {
					payload: &idtoken.Payload{
						Claims: map[string]interface{}{
							"iss":            "https://accounts.google.com",
							"sub":            "sub-https",
							"email":          "https@example.com",
							"email_verified": true,
							"name":           "Secure",
						},
					},
					expectedAudience: "client-id",
				},
			},
		}, nil
	})
	defer restoreValidator()

	config := newTestServerConfig()
	config.AllowInsecureHTTP = false
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()

	router := gin.New()
	MountAuthRoutes(router, config, userStore, refreshStore)

	plainRequest := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBufferString(`{"google_id_token":"valid-token"}`))
	plainRequest.Header.Set("Content-Type", "application/json")
	plainResponse := httptest.NewRecorder()
	router.ServeHTTP(plainResponse, plainRequest)
	if plainResponse.Code != http.StatusBadRequest {
		t.Fatalf("expected https_required rejection, got %d", plainResponse.Code)
	}

	forwardedRequest := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBufferString(`{"google_id_token":"valid-token"}`))
	forwardedRequest.Header.Set("Content-Type", "application/json")
	forwardedRequest.Header.Set("X-Forwarded-Proto", "https")
	forwardedResponse := httptest.NewRecorder()
	router.ServeHTTP(forwardedResponse, forwardedRequest)
	if forwardedResponse.Code != http.StatusOK {
		t.Fatalf("expected 200 with forwarded https, got %d", forwardedResponse.Code)
	}

	forwardedHeaderRequest := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBufferString(`{"google_id_token":"valid-token"}`))
	forwardedHeaderRequest.Header.Set("Content-Type", "application/json")
	forwardedHeaderRequest.Header.Set("Forwarded", "proto=https;host=example.com")
	forwardedHeaderResponse := httptest.NewRecorder()
	router.ServeHTTP(forwardedHeaderResponse, forwardedHeaderRequest)
	if forwardedHeaderResponse.Code != http.StatusOK {
		t.Fatalf("expected 200 with Forwarded https, got %d", forwardedHeaderResponse.Code)
	}

	localhostRequest := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBufferString(`{"google_id_token":"valid-token"}`))
	localhostRequest.Header.Set("Content-Type", "application/json")
	localhostRequest.Host = "localhost:8080"
	localhostResponse := httptest.NewRecorder()
	router.ServeHTTP(localhostResponse, localhostRequest)
	if localhostResponse.Code != http.StatusOK {
		t.Fatalf("expected 200 for localhost override, got %d", localhostResponse.Code)
	}
}

func TestAuthGoogleValidatorFailures(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newTestServerConfig()
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()
	router := gin.New()

	restoreValidator := withValidatorFactory(t, func(ctx context.Context) (GoogleTokenValidator, error) {
		return nil, errors.New("factory_failure")
	})
	MountAuthRoutes(router, config, userStore, refreshStore)

	request := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBufferString(`{"google_id_token":"valid-token"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when validator factory fails, got %d", response.Code)
	}
	restoreValidator()

	restoreValidator = withValidatorFactory(t, func(ctx context.Context) (GoogleTokenValidator, error) {
		return &fakeGoogleValidator{
			results: map[string]validatorResult{
				"bad-token": {
					err:              errors.New("invalid"),
					expectedAudience: "client-id",
				},
			},
		}, nil
	})
	defer restoreValidator()

	failureRouter := gin.New()
	MountAuthRoutes(failureRouter, config, userStore, refreshStore)

	failureRequest := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBufferString(`{"google_id_token":"bad-token"}`))
	failureRequest.Header.Set("Content-Type", "application/json")
	failureResponse := httptest.NewRecorder()
	failureRouter.ServeHTTP(failureResponse, failureRequest)
	if failureResponse.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid google token, got %d", failureResponse.Code)
	}
}

func TestAuthGoogleValidationBranches(t *testing.T) {
	gin.SetMode(gin.TestMode)

	results := map[string]validatorResult{
		"wrong-issuer": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://example.com",
					"sub":            "sub-1",
					"email":          "user@example.com",
					"email_verified": true,
					"name":           "Example",
				},
			},
			expectedAudience: "client-id",
		},
		"unverified": {
			payload: &idtoken.Payload{
				Claims: map[string]interface{}{
					"iss":            "https://accounts.google.com",
					"sub":            "sub-2",
					"email":          "user@example.com",
					"email_verified": false,
					"name":           "Example",
				},
			},
			expectedAudience: "client-id",
		},
	}

	restoreValidator := withValidatorFactory(t, func(ctx context.Context) (GoogleTokenValidator, error) {
		return &fakeGoogleValidator{results: results}, nil
	})
	defer restoreValidator()

	config := newTestServerConfig()
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()
	router := gin.New()
	MountAuthRoutes(router, config, userStore, refreshStore)

	for token, expectedStatus := range map[string]int{
		"wrong-issuer": http.StatusUnauthorized,
		"unverified":   http.StatusUnauthorized,
	} {
		request := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBufferString(`{"google_id_token":"`+token+`"}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != expectedStatus {
			t.Fatalf("token %s expected status %d, got %d", token, expectedStatus, response.Code)
		}
	}
}

func TestRefreshAndLogoutGuards(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restoreValidator := withValidatorFactory(t, func(ctx context.Context) (GoogleTokenValidator, error) {
		return &fakeGoogleValidator{
			results: map[string]validatorResult{
				"valid-token": {
					payload: &idtoken.Payload{
						Claims: map[string]interface{}{
							"iss":            "https://accounts.google.com",
							"sub":            "sub-refresh",
							"email":          "user@example.com",
							"email_verified": true,
							"name":           "Refresh",
						},
					},
					expectedAudience: "client-id",
				},
			},
		}, nil
	})
	defer restoreValidator()

	config := newTestServerConfig()
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()
	router := gin.New()
	MountAuthRoutes(router, config, userStore, refreshStore)

	noCookieResponse := httptest.NewRecorder()
	router.ServeHTTP(noCookieResponse, httptest.NewRequest(http.MethodPost, "/auth/refresh", nil))
	if noCookieResponse.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when refresh cookie missing, got %d", noCookieResponse.Code)
	}

	loginReq := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBufferString(`{"google_id_token":"valid-token"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginResp := httptest.NewRecorder()
	router.ServeHTTP(loginResp, loginReq)
	if loginResp.Code != http.StatusOK {
		t.Fatalf("unexpected login status: %d", loginResp.Code)
	}
	cookies := collectCookies(loginResp.Result().Cookies())

	logoutWithoutCookie := httptest.NewRecorder()
	router.ServeHTTP(logoutWithoutCookie, httptest.NewRequest(http.MethodPost, "/auth/logout", nil))
	if logoutWithoutCookie.Code != http.StatusNoContent {
		t.Fatalf("logout without cookie should still return 204, got %d", logoutWithoutCookie.Code)
	}

	protected := gin.New()
	protected.Use(RequireSession(config))
	protected.GET("/protected", func(contextGin *gin.Context) {
		contextGin.Status(http.StatusOK)
	})

	badSessionRequest := httptest.NewRequest(http.MethodGet, "/protected", nil)
	badSessionRequest.AddCookie(&http.Cookie{Name: config.SessionCookieName, Value: "tampered"})
	badSessionResponse := httptest.NewRecorder()
	protected.ServeHTTP(badSessionResponse, badSessionRequest)
	if badSessionResponse.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for tampered session, got %d", badSessionResponse.Code)
	}

	authenticatedRequest := httptest.NewRequest(http.MethodGet, "/protected", nil)
	addCookies(authenticatedRequest, cookies, config.SessionCookieName)
	authenticatedResponse := httptest.NewRecorder()
	protected.ServeHTTP(authenticatedResponse, authenticatedRequest)
	if authenticatedResponse.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid session, got %d", authenticatedResponse.Code)
	}
}

func TestAuthGoogleBindJSONFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newTestServerConfig()
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()
	router := gin.New()
	MountAuthRoutes(router, config, userStore, refreshStore)

	request := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBufferString("{"))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed JSON, got %d", response.Code)
	}
}

func TestAuthGoogleMissingToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newTestServerConfig()
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()
	router := gin.New()
	MountAuthRoutes(router, config, userStore, refreshStore)

	request := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBufferString(`{"google_id_token":""}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when google token missing, got %d", response.Code)
	}
}

func TestAuthGoogleUserStoreError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restoreValidator := withValidatorFactory(t, func(ctx context.Context) (GoogleTokenValidator, error) {
		return &fakeGoogleValidator{
			results: map[string]validatorResult{
				"valid-token": {
					payload: &idtoken.Payload{Claims: map[string]interface{}{
						"iss":            "https://accounts.google.com",
						"sub":            "sub-err",
						"email":          "user@example.com",
						"email_verified": true,
						"name":           "Example",
					}},
					expectedAudience: "client-id",
				},
			},
		}, nil
	})
	defer restoreValidator()

	config := newTestServerConfig()
	userStore := &failingUserStore{upsertErr: errors.New("upsert_fail")}
	refreshStore := NewMemoryRefreshTokenStore()
	router := gin.New()
	MountAuthRoutes(router, config, userStore, refreshStore)

	request := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBufferString(`{"google_id_token":"valid-token"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when user upsert fails, got %d", response.Code)
	}
}

func TestAuthGoogleRefreshIssueError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restoreValidator := withValidatorFactory(t, func(ctx context.Context) (GoogleTokenValidator, error) {
		return &fakeGoogleValidator{
			results: map[string]validatorResult{
				"valid-token": {
					payload: &idtoken.Payload{Claims: map[string]interface{}{
						"iss":            "https://accounts.google.com",
						"sub":            "sub-refresh-err",
						"email":          "user@example.com",
						"email_verified": true,
						"name":           "Example",
					}},
					expectedAudience: "client-id",
				},
			},
		}, nil
	})
	defer restoreValidator()

	config := newTestServerConfig()
	userStore := newTestUserStore()
	refreshStore := &stubRefreshStore{
		issueFunc: func(ctx context.Context, applicationUserID string, expiresUnix int64, previousTokenID string) (string, string, error) {
			return "", "", errors.New("issue_fail")
		},
	}
	router := gin.New()
	MountAuthRoutes(router, config, userStore, refreshStore)

	request := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBufferString(`{"google_id_token":"valid-token"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when issuing refresh token fails, got %d", response.Code)
	}
}

func TestAuthRefreshExpiredToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newTestServerConfig()
	userStore := newTestUserStore()
	refreshStore := &stubRefreshStore{
		validateFunc: func(ctx context.Context, tokenOpaque string) (string, string, int64, error) {
			return "user", "token", time.Now().Add(-time.Minute).Unix(), nil
		},
	}
	router := gin.New()
	MountAuthRoutes(router, config, userStore, refreshStore)

	request := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	request.AddCookie(&http.Cookie{Name: config.RefreshCookieName, Value: "expired"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired refresh token, got %d", response.Code)
	}
}

func TestAuthRefreshProfileFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newTestServerConfig()
	userStore := &failingUserStore{profileErr: errors.New("profile_fail")}
	refreshStore := &stubRefreshStore{
		validateFunc: func(ctx context.Context, tokenOpaque string) (string, string, int64, error) {
			return "user", "token", time.Now().Add(time.Minute).Unix(), nil
		},
	}
	router := gin.New()
	MountAuthRoutes(router, config, userStore, refreshStore)

	request := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	request.AddCookie(&http.Cookie{Name: config.RefreshCookieName, Value: "refresh"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when profile lookup fails, got %d", response.Code)
	}
}

func TestAuthRefreshIssueFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newTestServerConfig()
	userStore := newTestUserStore()
	userStore.profiles["user"] = testUserProfile{email: "user@example.com", display: "User", roles: []string{"user"}}
	refreshStore := &stubRefreshStore{
		validateFunc: func(ctx context.Context, tokenOpaque string) (string, string, int64, error) {
			return "user", "token", time.Now().Add(time.Minute).Unix(), nil
		},
		issueFunc: func(ctx context.Context, applicationUserID string, expiresUnix int64, previousTokenID string) (string, string, error) {
			return "", "", errors.New("issue_fail")
		},
	}
	router := gin.New()
	MountAuthRoutes(router, config, userStore, refreshStore)

	request := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	request.AddCookie(&http.Cookie{Name: config.RefreshCookieName, Value: "refresh"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when issuing replacement refresh token fails, got %d", response.Code)
	}
}

func TestAuthRefreshRevokeFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newTestServerConfig()
	userStore := newTestUserStore()
	userStore.profiles["user"] = testUserProfile{email: "user@example.com", display: "User", roles: []string{"user"}}
	refreshStore := &stubRefreshStore{
		validateFunc: func(ctx context.Context, tokenOpaque string) (string, string, int64, error) {
			return "user", "token", time.Now().Add(time.Minute).Unix(), nil
		},
		issueFunc: func(ctx context.Context, applicationUserID string, expiresUnix int64, previousTokenID string) (string, string, error) {
			return "token-new", "opaque-new", nil
		},
		revokeFunc: func(ctx context.Context, tokenID string) error {
			return errors.New("revoke_fail")
		},
	}
	router := gin.New()
	MountAuthRoutes(router, config, userStore, refreshStore)

	request := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	request.AddCookie(&http.Cookie{Name: config.RefreshCookieName, Value: "refresh"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when revoking old refresh token fails, got %d", response.Code)
	}
}

func TestRequireSessionIssuerMismatch(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newTestServerConfig()
	token, _, err := MintAppJWT(NewSystemClock(), "user", "user@example.com", "User", []string{"user"}, config.AppJWTIssuer, config.AppJWTSigningKey, config.SessionTTL)
	if err != nil {
		t.Fatalf("failed to mint token: %v", err)
	}

	mismatchConfig := config
	mismatchConfig.AppJWTIssuer = "another-issuer"

	router := gin.New()
	router.Use(RequireSession(mismatchConfig))
	router.GET("/secure", func(contextGin *gin.Context) {
		contextGin.Status(http.StatusOK)
	})

	request := httptest.NewRequest(http.MethodGet, "/secure", nil)
	request.AddCookie(&http.Cookie{Name: mismatchConfig.SessionCookieName, Value: token})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for issuer mismatch, got %d", response.Code)
	}
}

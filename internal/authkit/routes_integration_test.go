package authkit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
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
	validatorCache.Lock()
	validatorCache.value = nil
	validatorCache.Unlock()
	return func() {
		newGoogleTokenValidator = previous
		validatorCache.Lock()
		validatorCache.value = nil
		validatorCache.Unlock()
	}
}

type testUserStore struct {
	profiles map[string]map[string]testUserProfile
}

type testUserProfile struct {
	email   string
	display string
	avatar  string
	roles   []string
}

func newTestUserStore() *testUserStore {
	return &testUserStore{profiles: make(map[string]map[string]testUserProfile)}
}

func singleTenantRegistry(config ServerConfig) TenantRegistry {
	return NewSingleTenantRegistry(config)
}

func (store *testUserStore) UpsertGoogleUser(ctx context.Context, tenantID string, googleSub string, userEmail string, userDisplayName string, userAvatarURL string) (string, []string, error) {
	return store.UpsertProviderUser(ctx, tenantID, "google", googleSub, userEmail, userDisplayName, userAvatarURL)
}

func (store *testUserStore) UpsertProviderUser(ctx context.Context, tenantID string, provider string, providerID string, userEmail string, userDisplayName string, userAvatarURL string) (string, []string, error) {
	applicationUserID := strings.ToLower(strings.TrimSpace(provider)) + ":" + strings.TrimSpace(providerID)
	profile := testUserProfile{
		email:   userEmail,
		display: userDisplayName,
		avatar:  userAvatarURL,
		roles:   []string{"user"},
	}
	if _, exists := store.profiles[tenantID]; !exists {
		store.profiles[tenantID] = make(map[string]testUserProfile)
	}
	store.profiles[tenantID][applicationUserID] = profile
	return applicationUserID, profile.roles, nil
}

func (store *testUserStore) UpsertPasswordUser(ctx context.Context, tenantID string, userEmail string, userDisplayName string, userAvatarURL string) (string, []string, error) {
	applicationUserID := "email:" + userEmail
	profile := testUserProfile{
		email:   userEmail,
		display: userDisplayName,
		avatar:  userAvatarURL,
		roles:   []string{"user"},
	}
	if _, exists := store.profiles[tenantID]; !exists {
		store.profiles[tenantID] = make(map[string]testUserProfile)
	}
	store.profiles[tenantID][applicationUserID] = profile
	return applicationUserID, profile.roles, nil
}

func (store *testUserStore) UpsertAccountUser(ctx context.Context, tenantID string, accountID string, userEmail string, userDisplayName string, userAvatarURL string) (string, []string, error) {
	profile := testUserProfile{
		email:   userEmail,
		display: userDisplayName,
		avatar:  userAvatarURL,
		roles:   []string{"user"},
	}
	if _, exists := store.profiles[tenantID]; !exists {
		store.profiles[tenantID] = make(map[string]testUserProfile)
	}
	store.profiles[tenantID][accountID] = profile
	return accountID, profile.roles, nil
}

func (store *testUserStore) GetUserProfile(ctx context.Context, tenantID string, applicationUserID string) (string, string, string, []string, error) {
	tenantProfiles, exists := store.profiles[tenantID]
	if !exists {
		return "", "", "", nil, errors.New("user_not_found")
	}
	profile, ok := tenantProfiles[applicationUserID]
	if !ok {
		return "", "", "", nil, errors.New("user_not_found")
	}
	return profile.email, profile.display, profile.avatar, profile.roles, nil
}

func (store *testUserStore) setProfile(tenantID string, applicationUserID string, profile testUserProfile) {
	if _, exists := store.profiles[tenantID]; !exists {
		store.profiles[tenantID] = make(map[string]testUserProfile)
	}
	store.profiles[tenantID][applicationUserID] = profile
}

type failingUserStore struct {
	upsertErr  error
	profileErr error
}

func (store *failingUserStore) UpsertGoogleUser(ctx context.Context, tenantID string, googleSub string, userEmail string, userDisplayName string, userAvatarURL string) (string, []string, error) {
	return "", nil, store.upsertErr
}

func (store *failingUserStore) UpsertProviderUser(ctx context.Context, tenantID string, provider string, providerID string, userEmail string, userDisplayName string, userAvatarURL string) (string, []string, error) {
	return "", nil, store.upsertErr
}

func (store *failingUserStore) UpsertPasswordUser(ctx context.Context, tenantID string, userEmail string, userDisplayName string, userAvatarURL string) (string, []string, error) {
	return "", nil, store.upsertErr
}

func (store *failingUserStore) UpsertAccountUser(ctx context.Context, tenantID string, accountID string, userEmail string, userDisplayName string, userAvatarURL string) (string, []string, error) {
	return "", nil, store.upsertErr
}

func (store *failingUserStore) GetUserProfile(ctx context.Context, tenantID string, applicationUserID string) (string, string, string, []string, error) {
	return "", "", "", nil, store.profileErr
}

type stubRefreshStore struct {
	issueFunc      func(ctx context.Context, tenantID string, applicationUserID string, expiresUnix int64, previousTokenID string) (string, string, error)
	validateFunc   func(ctx context.Context, tenantID string, tokenOpaque string) (string, string, int64, error)
	revokeFunc     func(ctx context.Context, tenantID string, tokenID string) error
	revokeUserFunc func(ctx context.Context, tenantID string, applicationUserID string) error
}

func (store *stubRefreshStore) Issue(ctx context.Context, tenantID string, applicationUserID string, expiresUnix int64, previousTokenID string) (string, string, error) {
	if store.issueFunc != nil {
		return store.issueFunc(ctx, tenantID, applicationUserID, expiresUnix, previousTokenID)
	}
	return "", "", nil
}

func (store *stubRefreshStore) Validate(ctx context.Context, tenantID string, tokenOpaque string) (string, string, int64, error) {
	if store.validateFunc != nil {
		return store.validateFunc(ctx, tenantID, tokenOpaque)
	}
	return "", "", 0, errors.New("validate_not_configured")
}

func (store *stubRefreshStore) Revoke(ctx context.Context, tenantID string, tokenID string) error {
	if store.revokeFunc != nil {
		return store.revokeFunc(ctx, tenantID, tokenID)
	}
	return nil
}

func (store *stubRefreshStore) RevokeUser(ctx context.Context, tenantID string, applicationUserID string) error {
	if store.revokeUserFunc != nil {
		return store.revokeUserFunc(ctx, tenantID, applicationUserID)
	}
	return nil
}

func newTestServerConfig() ServerConfig {
	return ServerConfig{
		GoogleWebClientID:    "client-id",
		GoogleNativeClientID: "native-client-id",
		AppJWTSigningKey:     []byte("secret-key-1234567890"),
		AppJWTIssuer:         "test-issuer",
		TenantID:             "tenant-test",
		CookieDomain:         "",
		SessionCookieName:    "app_session",
		RefreshCookieName:    "app_refresh",
		SessionTTL:           time.Minute,
		RefreshTTL:           15 * time.Minute,
		NonceTTL:             5 * time.Minute,
		SameSiteMode:         http.SameSiteStrictMode,
		AllowInsecureHTTP:    true,
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

func issueNonceForTest(t *testing.T, handler http.Handler) string {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/auth/nonce", nil)
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 from /auth/nonce, got %d", recorder.Code)
	}
	var payload struct {
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
		t.Fatalf("decode nonce payload: %v", err)
	}
	if payload.Nonce == "" {
		t.Fatalf("nonce payload empty")
	}
	return payload.Nonce
}

func prepareLoginBody(t *testing.T, router http.Handler, payload *idtoken.Payload, token string) []byte {
	t.Helper()
	nonce := issueNonceForTest(t, router)
	payload.Claims["nonce"] = nonce
	body, err := json.Marshal(map[string]string{
		"google_id_token": token,
		"nonce_token":     nonce,
	})
	if err != nil {
		t.Fatalf("marshal login payload: %v", err)
	}
	return body
}

func TestAuthLifecycle(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newTestServerConfig()
	registry := singleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()

	payload := &idtoken.Payload{
		Claims: map[string]interface{}{
			"iss":            "https://accounts.google.com",
			"sub":            "sub-123",
			"email":          "user@example.com",
			"email_verified": true,
			"name":           "Test User",
			"picture":        "https://example.com/avatar.png",
			"nonce":          "",
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

	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

	body := prepareLoginBody(t, router, payload, "valid-token")
	loginRequest := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBuffer(body))
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
	if session := cookies[config.SessionCookieName]; session.Secure {
		t.Fatalf("expected insecure session cookie when AllowInsecureHTTP=true")
	}
	if _, ok := cookies[config.RefreshCookieName]; !ok {
		t.Fatalf("missing refresh cookie")
	}
	if refresh := cookies[config.RefreshCookieName]; refresh.Secure {
		t.Fatalf("expected insecure refresh cookie when AllowInsecureHTTP=true")
	}

	if tenantProfiles, exists := userStore.profiles[config.TenantID]; !exists {
		t.Fatalf("tenant profiles missing after login")
	} else if _, ok := tenantProfiles["google:sub-123"]; !ok {
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
	if mePayload["avatar_url"] != "https://example.com/avatar.png" {
		t.Fatalf("unexpected avatar_url: %v", mePayload["avatar_url"])
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
	secureRouter.Use(RequireSession(registry))
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

func TestGoogleLoginReturnsNotConfiguredWhenTenantHasNoGoogleWebClient(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newTestServerConfig()
	config.GoogleWebClientID = ""
	registry := singleTenantRegistry(config)

	router := gin.New()
	MountAuthRoutes(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), nil)

	loginRequest := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBufferString(`{"google_id_token":"token","nonce_token":"nonce"}`))
	loginRequest.Header.Set("Content-Type", "application/json")
	loginResponse := httptest.NewRecorder()
	router.ServeHTTP(loginResponse, loginRequest)

	if loginResponse.Code != http.StatusNotFound {
		t.Fatalf("expected 404 from Google login, got %d", loginResponse.Code)
	}
	var payload map[string]string
	if decodeErr := json.NewDecoder(loginResponse.Body).Decode(&payload); decodeErr != nil {
		t.Fatalf("decode response: %v", decodeErr)
	}
	if payload["error"] != errorGoogleLoginNotConfigured {
		t.Fatalf("expected %s, got %s", errorGoogleLoginNotConfigured, payload["error"])
	}
}

func TestPasswordLoginLifecycle(testingHandle *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newTestServerConfig()
	config.PasswordAuthEnabled = true
	registry := singleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()
	passwordStore := NewMemoryPasswordCredentialStore()
	passwordHash, hashErr := HashPassword("correct horse battery staple")
	if hashErr != nil {
		testingHandle.Fatalf("failed to hash password: %v", hashErr)
	}
	seedErr := passwordStore.UpsertPasswordCredential(context.Background(), config.TenantID, PasswordCredentialSeed{
		UserEmail:    "user@example.com",
		DisplayName:  "Password User",
		AvatarURL:    "https://example.com/password.png",
		PasswordHash: passwordHash,
	})
	if seedErr != nil {
		testingHandle.Fatalf("failed to seed password credential: %v", seedErr)
	}

	router := gin.New()
	MountAuthRoutesWithPassword(router, registry, userStore, refreshStore, nil, passwordStore)

	body, marshalErr := json.Marshal(map[string]string{
		"email":    "USER@example.com",
		"password": "correct horse battery staple",
	})
	if marshalErr != nil {
		testingHandle.Fatalf("marshal password body: %v", marshalErr)
	}
	loginRequest := httptest.NewRequest(http.MethodPost, "/auth/password/login", bytes.NewBuffer(body))
	loginRequest.Header.Set("Content-Type", "application/json")
	loginResponse := httptest.NewRecorder()
	router.ServeHTTP(loginResponse, loginRequest)

	if loginResponse.Code != http.StatusOK {
		testingHandle.Fatalf("expected 200 from password login, got %d: %s", loginResponse.Code, loginResponse.Body.String())
	}
	var profile map[string]interface{}
	if decodeErr := json.NewDecoder(loginResponse.Body).Decode(&profile); decodeErr != nil {
		testingHandle.Fatalf("decode password login response: %v", decodeErr)
	}
	if profile["user_id"] != "email:user@example.com" || profile["user_email"] != "user@example.com" || profile["display"] != "Password User" {
		testingHandle.Fatalf("unexpected profile payload: %#v", profile)
	}
	cookies := collectCookies(loginResponse.Result().Cookies())
	if cookies[config.SessionCookieName] == nil || cookies[config.RefreshCookieName] == nil {
		testingHandle.Fatalf("expected session and refresh cookies")
	}

	meRequest := httptest.NewRequest(http.MethodGet, "/me", nil)
	addCookies(meRequest, cookies, config.SessionCookieName)
	meResponse := httptest.NewRecorder()
	router.ServeHTTP(meResponse, meRequest)
	if meResponse.Code != http.StatusOK {
		testingHandle.Fatalf("expected 200 from /me after password login, got %d", meResponse.Code)
	}
}

func TestPasswordLoginRejectsInvalidCredentials(testingHandle *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newTestServerConfig()
	config.PasswordAuthEnabled = true
	registry := singleTenantRegistry(config)
	router := gin.New()
	MountAuthRoutesWithPassword(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), nil, NewMemoryPasswordCredentialStore())

	body := []byte(`{"email":"missing@example.com","password":"wrong-password"}`)
	request := httptest.NewRequest(http.MethodPost, "/auth/password/login", bytes.NewBuffer(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		testingHandle.Fatalf("expected 401 for invalid password credentials, got %d", response.Code)
	}
	var payload map[string]string
	if decodeErr := json.NewDecoder(response.Body).Decode(&payload); decodeErr != nil {
		testingHandle.Fatalf("decode invalid credentials payload: %v", decodeErr)
	}
	if payload["error"] != errorPasswordCredentialInvalid {
		testingHandle.Fatalf("unexpected error payload: %#v", payload)
	}
}

func TestPasswordLoginDisabledReturnsNotFound(testingHandle *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newTestServerConfig()
	registry := singleTenantRegistry(config)
	router := gin.New()
	MountAuthRoutesWithPassword(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), nil, NewMemoryPasswordCredentialStore())

	body := []byte(`{"email":"user@example.com","password":"correct horse battery staple"}`)
	request := httptest.NewRequest(http.MethodPost, "/auth/password/login", bytes.NewBuffer(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		testingHandle.Fatalf("expected 404 when password auth is disabled, got %d", response.Code)
	}
	var payload map[string]string
	if decodeErr := json.NewDecoder(response.Body).Decode(&payload); decodeErr != nil {
		testingHandle.Fatalf("decode disabled password payload: %v", decodeErr)
	}
	if payload["error"] != errorPasswordAuthNotConfigured {
		testingHandle.Fatalf("unexpected error payload: %#v", payload)
	}
}

func TestAccountManagementPasswordSignupVerifyAndReset(testingHandle *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newTestServerConfig()
	config.PasswordAuthEnabled = true
	config.AccountManagementEnabled = true
	config.PasswordSignupEnabled = true
	config.ReturnChallengeTokens = true
	config.EmailVerificationTTL = time.Minute
	config.PasswordResetTTL = time.Minute
	registry := singleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()
	accountStore := NewMemoryPasswordCredentialStore()
	router := gin.New()
	MountAuthRoutesWithPassword(router, registry, userStore, refreshStore, nil, accountStore)

	signupBody := []byte(`{"email":"New@Example.com","password":"correct horse battery staple","display_name":"New User"}`)
	signupResponse := httptest.NewRecorder()
	signupRequest := httptest.NewRequest(http.MethodPost, "/auth/password/signup", bytes.NewBuffer(signupBody))
	signupRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(signupResponse, signupRequest)
	if signupResponse.Code != http.StatusAccepted {
		testingHandle.Fatalf("expected signup 202, got %d: %s", signupResponse.Code, signupResponse.Body.String())
	}
	var signupPayload map[string]interface{}
	if decodeErr := json.NewDecoder(signupResponse.Body).Decode(&signupPayload); decodeErr != nil {
		testingHandle.Fatalf("decode signup payload: %v", decodeErr)
	}
	verificationToken, _ := signupPayload["verification_token"].(string)
	accountID, _ := signupPayload["account_id"].(string)
	if verificationToken == "" || !strings.HasPrefix(accountID, accountIDPrefix) {
		testingHandle.Fatalf("expected verification token and account id, got %#v", signupPayload)
	}

	unverifiedLogin := httptest.NewRecorder()
	loginBody := []byte(`{"email":"new@example.com","password":"correct horse battery staple"}`)
	loginRequest := httptest.NewRequest(http.MethodPost, "/auth/password/login", bytes.NewBuffer(loginBody))
	loginRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(unverifiedLogin, loginRequest)
	if unverifiedLogin.Code != http.StatusForbidden {
		testingHandle.Fatalf("expected unverified login 403, got %d", unverifiedLogin.Code)
	}

	verifyResponse := httptest.NewRecorder()
	verifyRequest := httptest.NewRequest(http.MethodPost, "/auth/password/verify-email", bytes.NewBuffer([]byte(`{"token":"`+verificationToken+`"}`)))
	verifyRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(verifyResponse, verifyRequest)
	if verifyResponse.Code != http.StatusOK {
		testingHandle.Fatalf("expected verify 200, got %d: %s", verifyResponse.Code, verifyResponse.Body.String())
	}
	var verifyPayload map[string]interface{}
	if decodeErr := json.NewDecoder(verifyResponse.Body).Decode(&verifyPayload); decodeErr != nil {
		testingHandle.Fatalf("decode verify payload: %v", decodeErr)
	}
	if verifyPayload["user_id"] != accountID || verifyPayload["user_email"] != "new@example.com" {
		testingHandle.Fatalf("unexpected verified profile: %#v", verifyPayload)
	}
	verifiedCookies := collectCookies(verifyResponse.Result().Cookies())
	if verifiedCookies[config.SessionCookieName] == nil || verifiedCookies[config.RefreshCookieName] == nil {
		testingHandle.Fatalf("expected verified session cookies")
	}

	resetStartResponse := httptest.NewRecorder()
	resetStartRequest := httptest.NewRequest(http.MethodPost, "/auth/password/reset/start", bytes.NewBuffer([]byte(`{"email":"new@example.com"}`)))
	resetStartRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(resetStartResponse, resetStartRequest)
	if resetStartResponse.Code != http.StatusAccepted {
		testingHandle.Fatalf("expected reset start 202, got %d", resetStartResponse.Code)
	}
	var resetStartPayload map[string]interface{}
	if decodeErr := json.NewDecoder(resetStartResponse.Body).Decode(&resetStartPayload); decodeErr != nil {
		testingHandle.Fatalf("decode reset start payload: %v", decodeErr)
	}
	resetToken, _ := resetStartPayload["reset_token"].(string)
	if resetToken == "" {
		testingHandle.Fatalf("expected reset token in test config")
	}

	resetCompleteResponse := httptest.NewRecorder()
	resetCompleteRequest := httptest.NewRequest(http.MethodPost, "/auth/password/reset/complete", bytes.NewBuffer([]byte(`{"token":"`+resetToken+`","password":"new correct horse battery staple"}`)))
	resetCompleteRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(resetCompleteResponse, resetCompleteRequest)
	if resetCompleteResponse.Code != http.StatusOK {
		testingHandle.Fatalf("expected reset complete 200, got %d: %s", resetCompleteResponse.Code, resetCompleteResponse.Body.String())
	}

	oldRefreshRequest := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	addCookies(oldRefreshRequest, verifiedCookies, config.RefreshCookieName)
	oldRefreshResponse := httptest.NewRecorder()
	router.ServeHTTP(oldRefreshResponse, oldRefreshRequest)
	if oldRefreshResponse.Code != http.StatusUnauthorized {
		testingHandle.Fatalf("expected old refresh cookie revoked after reset, got %d", oldRefreshResponse.Code)
	}

	newLoginResponse := httptest.NewRecorder()
	newLoginRequest := httptest.NewRequest(http.MethodPost, "/auth/password/login", bytes.NewBuffer([]byte(`{"email":"new@example.com","password":"new correct horse battery staple"}`)))
	newLoginRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(newLoginResponse, newLoginRequest)
	if newLoginResponse.Code != http.StatusOK {
		testingHandle.Fatalf("expected login with reset password, got %d: %s", newLoginResponse.Code, newLoginResponse.Body.String())
	}
}

func TestAccountManagementSeededPasswordLoginUsesAccountSession(testingHandle *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newTestServerConfig()
	config.PasswordAuthEnabled = true
	config.AccountManagementEnabled = true
	registry := singleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()
	accountStore := NewMemoryPasswordCredentialStore()
	passwordHash, hashErr := HashPassword("correct horse battery staple")
	if hashErr != nil {
		testingHandle.Fatalf("failed to hash seeded password: %v", hashErr)
	}
	if credentialErr := accountStore.UpsertPasswordCredential(context.Background(), config.TenantID, PasswordCredentialSeed{
		UserEmail:    "Seeded@Example.com",
		DisplayName:  "Seeded User",
		AvatarURL:    "https://example.com/seeded.png",
		PasswordHash: passwordHash,
	}); credentialErr != nil {
		testingHandle.Fatalf("failed to seed password credential: %v", credentialErr)
	}
	router := gin.New()
	MountAuthRoutesWithPassword(router, registry, userStore, refreshStore, nil, accountStore)

	loginResponse := httptest.NewRecorder()
	loginRequest := httptest.NewRequest(http.MethodPost, "/auth/password/login", bytes.NewBuffer([]byte(`{"email":"seeded@example.com","password":"correct horse battery staple"}`)))
	loginRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusOK {
		testingHandle.Fatalf("expected seeded account login 200, got %d: %s", loginResponse.Code, loginResponse.Body.String())
	}
	var loginPayload map[string]interface{}
	if decodeErr := json.NewDecoder(loginResponse.Body).Decode(&loginPayload); decodeErr != nil {
		testingHandle.Fatalf("decode seeded login payload: %v", decodeErr)
	}
	expectedAccountID := accountIDForEmail(config.TenantID, "seeded@example.com")
	if loginPayload["user_id"] != expectedAccountID {
		testingHandle.Fatalf("expected account user id %s, got %#v", expectedAccountID, loginPayload)
	}
	cookies := collectCookies(loginResponse.Result().Cookies())

	changeResponse := httptest.NewRecorder()
	changeRequest := httptest.NewRequest(http.MethodPost, "/auth/account/password/change", bytes.NewBuffer([]byte(`{"current_password":"correct horse battery staple","new_password":"new correct horse battery staple"}`)))
	changeRequest.Header.Set("Content-Type", "application/json")
	addCookies(changeRequest, cookies, config.SessionCookieName)
	router.ServeHTTP(changeResponse, changeRequest)
	if changeResponse.Code != http.StatusOK {
		testingHandle.Fatalf("expected seeded account password change 200, got %d: %s", changeResponse.Code, changeResponse.Body.String())
	}
	changedCookies := collectCookies(changeResponse.Result().Cookies())

	disableResponse := httptest.NewRecorder()
	disableRequest := httptest.NewRequest(http.MethodPost, "/auth/account/disable", nil)
	addCookies(disableRequest, changedCookies, config.SessionCookieName)
	router.ServeHTTP(disableResponse, disableRequest)
	if disableResponse.Code != http.StatusNoContent {
		testingHandle.Fatalf("expected disable 204, got %d: %s", disableResponse.Code, disableResponse.Body.String())
	}

	staleChangeResponse := httptest.NewRecorder()
	staleChangeRequest := httptest.NewRequest(http.MethodPost, "/auth/account/password/change", bytes.NewBuffer([]byte(`{"current_password":"new correct horse battery staple","new_password":"disabled account password"}`)))
	staleChangeRequest.Header.Set("Content-Type", "application/json")
	addCookies(staleChangeRequest, changedCookies, config.SessionCookieName)
	router.ServeHTTP(staleChangeResponse, staleChangeRequest)
	if staleChangeResponse.Code != http.StatusForbidden {
		testingHandle.Fatalf("expected stale disabled-account password change 403, got %d: %s", staleChangeResponse.Code, staleChangeResponse.Body.String())
	}
	var staleChangePayload map[string]string
	if decodeErr := json.NewDecoder(staleChangeResponse.Body).Decode(&staleChangePayload); decodeErr != nil {
		testingHandle.Fatalf("decode stale change payload: %v", decodeErr)
	}
	if staleChangePayload["error"] != errorAccountDisabled {
		testingHandle.Fatalf("expected disabled account error, got %#v", staleChangePayload)
	}

	disabledLoginResponse := httptest.NewRecorder()
	disabledLoginRequest := httptest.NewRequest(http.MethodPost, "/auth/password/login", bytes.NewBuffer([]byte(`{"email":"seeded@example.com","password":"new correct horse battery staple"}`)))
	disabledLoginRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(disabledLoginResponse, disabledLoginRequest)
	if disabledLoginResponse.Code != http.StatusForbidden {
		testingHandle.Fatalf("expected disabled password login 403, got %d: %s", disabledLoginResponse.Code, disabledLoginResponse.Body.String())
	}
}

func TestAccountManagementRejectsUnlinkingLastIdentity(testingHandle *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newTestServerConfig()
	config.PasswordAuthEnabled = true
	config.AccountManagementEnabled = true
	config.PasswordSignupEnabled = true
	config.ReturnChallengeTokens = true
	config.EmailVerificationTTL = time.Minute
	registry := singleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()
	accountStore := NewMemoryPasswordCredentialStore()
	router := gin.New()
	MountAuthRoutesWithPassword(router, registry, userStore, refreshStore, nil, accountStore)

	signupResponse := httptest.NewRecorder()
	signupRequest := httptest.NewRequest(http.MethodPost, "/auth/password/signup", bytes.NewBuffer([]byte(`{"email":"solo@example.com","password":"correct horse battery staple"}`)))
	signupRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(signupResponse, signupRequest)
	var signupPayload map[string]interface{}
	if decodeErr := json.NewDecoder(signupResponse.Body).Decode(&signupPayload); decodeErr != nil {
		testingHandle.Fatalf("decode signup payload: %v", decodeErr)
	}
	verificationToken, _ := signupPayload["verification_token"].(string)

	verifyResponse := httptest.NewRecorder()
	verifyRequest := httptest.NewRequest(http.MethodPost, "/auth/password/verify-email", bytes.NewBuffer([]byte(`{"token":"`+verificationToken+`"}`)))
	verifyRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(verifyResponse, verifyRequest)
	if verifyResponse.Code != http.StatusOK {
		testingHandle.Fatalf("expected verify 200, got %d", verifyResponse.Code)
	}
	cookies := collectCookies(verifyResponse.Result().Cookies())

	unlinkResponse := httptest.NewRecorder()
	unlinkRequest := httptest.NewRequest(http.MethodPost, "/auth/account/unlink", bytes.NewBuffer([]byte(`{"provider":"password","provider_id":"solo@example.com"}`)))
	unlinkRequest.Header.Set("Content-Type", "application/json")
	addCookies(unlinkRequest, cookies, config.SessionCookieName)
	router.ServeHTTP(unlinkResponse, unlinkRequest)
	if unlinkResponse.Code != http.StatusConflict {
		testingHandle.Fatalf("expected last identity unlink conflict, got %d: %s", unlinkResponse.Code, unlinkResponse.Body.String())
	}
}

func TestNativeGoogleConfigLifecycle(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newTestServerConfig()
	registry := singleTenantRegistry(config)
	router := gin.New()
	MountAuthRoutes(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), nil)

	request := httptest.NewRequest(http.MethodGet, "/auth/google/native/config", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200 from native config, got %d", response.Code)
	}

	var payload nativeGoogleConfigResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode native config payload: %v", err)
	}
	if payload.ClientID != config.GoogleNativeClientID {
		t.Fatalf("unexpected client_id: %s", payload.ClientID)
	}
	if payload.AuthorizationEndpoint != googleAuthorizationEndpoint {
		t.Fatalf("unexpected authorization endpoint: %s", payload.AuthorizationEndpoint)
	}
	if payload.TokenEndpoint != googleTokenEndpoint {
		t.Fatalf("unexpected token endpoint: %s", payload.TokenEndpoint)
	}
	if len(payload.Scopes) != len(googleNativeScopes) {
		t.Fatalf("unexpected scopes length: %d", len(payload.Scopes))
	}
}

func TestNativeGoogleLoginLifecycle(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newTestServerConfig()
	registry := singleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()

	payload := &idtoken.Payload{
		Claims: map[string]interface{}{
			"iss":            googleIssuerHTTPS,
			"sub":            "sub-native-123",
			"email":          "native@example.com",
			"email_verified": true,
			"name":           "Native User",
			"picture":        "https://example.com/native.png",
			"nonce":          "native-nonce",
		},
	}

	restoreValidator := withValidatorFactory(t, func(ctx context.Context) (GoogleTokenValidator, error) {
		return &fakeGoogleValidator{
			results: map[string]validatorResult{
				"valid-native-token": {
					payload:          payload,
					expectedAudience: config.GoogleNativeClientID,
				},
			},
		}, nil
	})
	defer restoreValidator()

	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

	body, err := json.Marshal(map[string]string{
		"google_id_token": "valid-native-token",
		"nonce_token":     "native-nonce",
	})
	if err != nil {
		t.Fatalf("marshal native login payload: %v", err)
	}

	loginRequest := httptest.NewRequest(http.MethodPost, "/auth/google/native", bytes.NewBuffer(body))
	loginRequest.Header.Set("Content-Type", "application/json")
	loginResponse := httptest.NewRecorder()
	router.ServeHTTP(loginResponse, loginRequest)

	if loginResponse.Code != http.StatusOK {
		t.Fatalf("expected 200 from native login, got %d", loginResponse.Code)
	}

	cookies := collectCookies(loginResponse.Result().Cookies())
	if _, ok := cookies[config.SessionCookieName]; !ok {
		t.Fatalf("missing session cookie")
	}
	if _, ok := cookies[config.RefreshCookieName]; !ok {
		t.Fatalf("missing refresh cookie")
	}

	if tenantProfiles, exists := userStore.profiles[config.TenantID]; !exists {
		t.Fatalf("tenant profiles missing after native login")
	} else if _, ok := tenantProfiles["google:sub-native-123"]; !ok {
		t.Fatalf("user not persisted after native login")
	}
}

func TestNativeGoogleConfigReturnsNotFoundWhenClientMissing(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newTestServerConfig()
	config.GoogleNativeClientID = ""
	registry := singleTenantRegistry(config)
	router := gin.New()
	MountAuthRoutes(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), nil)

	request := httptest.NewRequest(http.MethodGet, "/auth/google/native/config", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404 from native config, got %d", response.Code)
	}
	var payload map[string]string
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode native config error payload: %v", err)
	}
	if payload["error"] != errorNativeGoogleLoginNotConfigured {
		t.Fatalf("unexpected error payload: %v", payload["error"])
	}
}

func TestNativeGoogleLoginReturnsNotFoundWhenClientMissing(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newTestServerConfig()
	config.GoogleNativeClientID = ""
	registry := singleTenantRegistry(config)
	router := gin.New()
	MountAuthRoutes(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), nil)

	body, err := json.Marshal(map[string]string{
		"google_id_token": "any-token",
		"nonce_token":     "native-nonce",
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/auth/google/native", bytes.NewBuffer(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404 from native login, got %d", response.Code)
	}
	var payload map[string]string
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode native login error payload: %v", err)
	}
	if payload["error"] != errorNativeGoogleLoginNotConfigured {
		t.Fatalf("unexpected error payload: %v", payload["error"])
	}
}

func TestAuthGoogleRequiresHTTPS(t *testing.T) {
	gin.SetMode(gin.TestMode)

	payload := &idtoken.Payload{Claims: map[string]interface{}{
		"iss":            "https://accounts.google.com",
		"sub":            "sub-https",
		"email":          "https@example.com",
		"email_verified": true,
		"name":           "Secure",
		"picture":        "https://example.com/avatar.png",
		"nonce":          "",
	}}
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
	config.AllowInsecureHTTP = false
	registry := singleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()

	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

	plainBody := prepareLoginBody(t, router, payload, "valid-token")
	plainRequest := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBuffer(plainBody))
	plainRequest.Header.Set("Content-Type", "application/json")
	plainResponse := httptest.NewRecorder()
	router.ServeHTTP(plainResponse, plainRequest)
	if plainResponse.Code != http.StatusBadRequest {
		t.Fatalf("expected https_required rejection, got %d", plainResponse.Code)
	}

	forwardedBody := prepareLoginBody(t, router, payload, "valid-token")
	forwardedRequest := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBuffer(forwardedBody))
	forwardedRequest.Header.Set("Content-Type", "application/json")
	forwardedRequest.Header.Set("X-Forwarded-Proto", "https")
	forwardedResponse := httptest.NewRecorder()
	router.ServeHTTP(forwardedResponse, forwardedRequest)
	if forwardedResponse.Code != http.StatusOK {
		t.Fatalf("expected 200 with forwarded https, got %d", forwardedResponse.Code)
	}

	forwardedHeaderBody := prepareLoginBody(t, router, payload, "valid-token")
	forwardedHeaderRequest := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBuffer(forwardedHeaderBody))
	forwardedHeaderRequest.Header.Set("Content-Type", "application/json")
	forwardedHeaderRequest.Header.Set("Forwarded", "proto=https;host=example.com")
	forwardedHeaderResponse := httptest.NewRecorder()
	router.ServeHTTP(forwardedHeaderResponse, forwardedHeaderRequest)
	if forwardedHeaderResponse.Code != http.StatusOK {
		t.Fatalf("expected 200 with Forwarded https, got %d", forwardedHeaderResponse.Code)
	}

	localhostBody := prepareLoginBody(t, router, payload, "valid-token")
	localhostRequest := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBuffer(localhostBody))
	localhostRequest.Header.Set("Content-Type", "application/json")
	localhostRequest.Host = "localhost:8080"
	localhostResponse := httptest.NewRecorder()
	router.ServeHTTP(localhostResponse, localhostRequest)
	if localhostResponse.Code != http.StatusOK {
		t.Fatalf("expected 200 for localhost override, got %d", localhostResponse.Code)
	}
}

func TestAuthCookiesSecureWhenHTTPSOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)

	payload := &idtoken.Payload{Claims: map[string]interface{}{
		"iss":            "https://accounts.google.com",
		"sub":            "sub-secure-cookies",
		"email":          "secure@example.com",
		"email_verified": true,
		"name":           "Secure Cookies",
		"picture":        "https://example.com/avatar.png",
		"nonce":          "",
	}}
	restoreValidator := withValidatorFactory(t, func(ctx context.Context) (GoogleTokenValidator, error) {
		return &fakeGoogleValidator{
			results: map[string]validatorResult{
				"valid-token-secure": {
					payload:          payload,
					expectedAudience: "client-id",
				},
			},
		}, nil
	})
	defer restoreValidator()

	config := newTestServerConfig()
	config.AllowInsecureHTTP = false
	config.SameSiteMode = http.SameSiteNoneMode
	registry := singleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()

	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

	body := prepareLoginBody(t, router, payload, "valid-token-secure")
	request := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBuffer(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Forwarded-Proto", "https")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200 from secure login, got %d", response.Code)
	}

	cookies := collectCookies(response.Result().Cookies())
	session, ok := cookies[config.SessionCookieName]
	if !ok {
		t.Fatalf("missing session cookie")
	}
	if !session.Secure {
		t.Fatalf("expected secure session cookie when AllowInsecureHTTP=false")
	}
	refresh, ok := cookies[config.RefreshCookieName]
	if !ok {
		t.Fatalf("missing refresh cookie")
	}
	if !refresh.Secure {
		t.Fatalf("expected secure refresh cookie when AllowInsecureHTTP=false")
	}
}

func TestAuthGoogleValidatorFailures(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newTestServerConfig()
	registry := singleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()
	router := gin.New()

	restoreValidator := withValidatorFactory(t, func(ctx context.Context) (GoogleTokenValidator, error) {
		return nil, errors.New("factory_failure")
	})
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

	dummyPayload := &idtoken.Payload{Claims: map[string]interface{}{"nonce": ""}}
	body := prepareLoginBody(t, router, dummyPayload, "valid-token")
	request := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBuffer(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when validator factory fails, got %d", response.Code)
	}
	restoreValidator()

	badPayload := &idtoken.Payload{Claims: map[string]interface{}{
		"nonce": "",
	}}
	restoreValidator = withValidatorFactory(t, func(ctx context.Context) (GoogleTokenValidator, error) {
		return &fakeGoogleValidator{
			results: map[string]validatorResult{
				"bad-token": {
					err:              errors.New("invalid"),
					expectedAudience: "client-id",
					payload:          badPayload,
				},
			},
		}, nil
	})
	defer restoreValidator()

	failureRouter := gin.New()
	MountAuthRoutes(failureRouter, registry, userStore, refreshStore, nil)
	failureBody := prepareLoginBody(t, failureRouter, badPayload, "bad-token")
	failureRequest := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBuffer(failureBody))
	failureRequest.Header.Set("Content-Type", "application/json")
	failureResponse := httptest.NewRecorder()
	failureRouter.ServeHTTP(failureResponse, failureRequest)
	if failureResponse.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid google token, got %d", failureResponse.Code)
	}
}

func TestAuthGoogleSuccessMetrics(t *testing.T) {
	gin.SetMode(gin.TestMode)

	metrics := NewCounterMetrics()
	ProvideMetrics(metrics)
	defer ProvideMetrics(nil)

	core, observed := observer.New(zap.InfoLevel)
	ProvideLogger(zap.New(core))
	defer ProvideLogger(nil)

	payload := &idtoken.Payload{Claims: map[string]interface{}{
		"iss":            "https://accounts.google.com",
		"sub":            "sub-success",
		"email":          "user@example.com",
		"email_verified": true,
		"name":           "User",
		"picture":        "https://example.com/avatar.png",
		"nonce":          "",
	}}
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
	registry := singleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()

	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)
	body := prepareLoginBody(t, router, payload, "valid-token")
	request := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBuffer(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected success, got %d", response.Code)
	}
	if metrics.Count(metricAuthLoginSuccess) != 1 {
		t.Fatalf("expected auth.login.success metric to increment")
	}
	if observed.Len() != 0 {
		t.Fatalf("did not expect warnings on successful login")
	}
}

func TestAuthGoogleUserStoreFailureLogsAndMetrics(t *testing.T) {
	gin.SetMode(gin.TestMode)

	metrics := NewCounterMetrics()
	ProvideMetrics(metrics)
	defer ProvideMetrics(nil)

	core, observed := observer.New(zap.WarnLevel)
	ProvideLogger(zap.New(core))
	defer ProvideLogger(nil)

	payload := &idtoken.Payload{Claims: map[string]interface{}{
		"iss":            "https://accounts.google.com",
		"sub":            "sub-fail",
		"email":          "user@example.com",
		"email_verified": true,
		"name":           "User",
		"picture":        "https://example.com/avatar.png",
		"nonce":          "",
	}}
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
	registry := singleTenantRegistry(config)
	userStore := &failingUserStore{upsertErr: errors.New("upsert-fail")}
	refreshStore := NewMemoryRefreshTokenStore()

	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

	body := prepareLoginBody(t, router, payload, "valid-token")
	request := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBuffer(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", response.Code)
	}
	if metrics.Count(metricAuthLoginFailure) != 1 {
		t.Fatalf("expected auth.login.failure metric to increment")
	}
	warnLogs := observed.FilterMessage("auth")
	if warnLogs.Len() == 0 {
		t.Fatalf("expected warning log for user store failure")
	}
	if warnLogs.All()[0].Context[0].Key != "code" || warnLogs.All()[0].Context[0].String != "auth.login.user_store" {
		t.Fatalf("expected auth.login.user_store code, got %v", warnLogs.All()[0].Context)
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
					"picture":        "https://example.com/avatar.png",
					"nonce":          "",
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
					"picture":        "https://example.com/avatar.png",
					"nonce":          "",
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
	registry := singleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()
	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

	for token, expectedStatus := range map[string]int{
		"wrong-issuer": http.StatusUnauthorized,
		"unverified":   http.StatusUnauthorized,
	} {
		payload := results[token].payload
		body := prepareLoginBody(t, router, payload, token)
		request := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBuffer(body))
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

	payload := &idtoken.Payload{Claims: map[string]interface{}{
		"iss":            "https://accounts.google.com",
		"sub":            "sub-refresh",
		"email":          "user@example.com",
		"email_verified": true,
		"name":           "Refresh",
		"picture":        "https://example.com/avatar.png",
		"nonce":          "",
	}}

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
	registry := singleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()

	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

	noCookieResponse := httptest.NewRecorder()
	router.ServeHTTP(noCookieResponse, httptest.NewRequest(http.MethodPost, "/auth/refresh", nil))
	if noCookieResponse.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when refresh cookie missing, got %d", noCookieResponse.Code)
	}

	body := prepareLoginBody(t, router, payload, "valid-token")
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBuffer(body))
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
	protected.Use(RequireSession(registry))
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
	registry := singleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()
	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

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
	registry := singleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()
	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

	nonce := issueNonceForTest(t, router)
	request := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBufferString(`{"google_id_token":"","nonce_token":"`+nonce+`"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when google token missing, got %d", response.Code)
	}
}

func TestAuthGoogleMissingNonce(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newTestServerConfig()
	registry := singleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()
	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

	request := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBufferString(`{"google_id_token":"valid-token"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when nonce token missing, got %d", response.Code)
	}
}

func TestAuthGoogleNonceMismatch(t *testing.T) {
	gin.SetMode(gin.TestMode)

	payload := &idtoken.Payload{Claims: map[string]interface{}{
		"iss":            "https://accounts.google.com",
		"sub":            "sub-mismatch",
		"email":          "user@example.com",
		"email_verified": true,
		"name":           "Mismatch",
		"picture":        "https://example.com/avatar.png",
		"nonce":          "expected-nonce",
	}}

	restoreValidator := withValidatorFactory(t, func(ctx context.Context) (GoogleTokenValidator, error) {
		return &fakeGoogleValidator{
			results: map[string]validatorResult{"valid-token": {payload: payload, expectedAudience: "client-id"}},
		}, nil
	})
	defer restoreValidator()

	config := newTestServerConfig()
	registry := singleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()
	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

	issuedNonce := issueNonceForTest(t, router)
	payload.Claims["nonce"] = "expected-nonce"
	body := []byte(`{"google_id_token":"valid-token","nonce_token":"` + issuedNonce + `"}`)
	request := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBuffer(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when nonce mismatches, got %d", response.Code)
	}
}

func TestAuthGoogleAcceptsHashedNonceClaim(t *testing.T) {
	gin.SetMode(gin.TestMode)

	payload := &idtoken.Payload{Claims: map[string]interface{}{
		"iss":            "https://accounts.google.com",
		"sub":            "sub-hash",
		"email":          "hash@example.com",
		"email_verified": true,
		"name":           "Hashed Nonce",
		"picture":        "https://example.com/avatar.png",
		"nonce":          "",
	}}

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
	registry := singleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()
	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

	nonce := issueNonceForTest(t, router)
	payload.Claims["nonce"] = hashOpaque(nonce)

	requestBody, err := json.Marshal(map[string]string{
		"google_id_token": "valid-token",
		"nonce_token":     nonce,
	})
	if err != nil {
		t.Fatalf("marshal login payload: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBuffer(requestBody))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200 when nonce claim is hashed, got %d", response.Code)
	}
	if tenantProfiles, exists := userStore.profiles[config.TenantID]; !exists {
		t.Fatalf("tenant profiles missing after hashed nonce login")
	} else if _, ok := tenantProfiles["google:sub-hash"]; !ok {
		t.Fatalf("expected hashed nonce login to persist user profile")
	}
}

func TestAuthGoogleRejectsMissingNonceClaim(t *testing.T) {
	gin.SetMode(gin.TestMode)

	payload := &idtoken.Payload{Claims: map[string]interface{}{
		"iss":            "https://accounts.google.com",
		"sub":            "sub-missing-nonce",
		"email":          "user@example.com",
		"email_verified": true,
		"name":           "Missing Nonce",
		"picture":        "https://example.com/avatar.png",
		"nonce":          "",
	}}

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
	registry := singleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := NewMemoryRefreshTokenStore()
	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

	nonce := issueNonceForTest(t, router)
	body := []byte(`{"google_id_token":"valid-token","nonce_token":"` + nonce + `"}`)
	request := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBuffer(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when google omits nonce claim, got %d", response.Code)
	}
}

func TestAuthGoogleUserStoreError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	payload := &idtoken.Payload{Claims: map[string]interface{}{
		"iss":            "https://accounts.google.com",
		"sub":            "sub-err",
		"email":          "user@example.com",
		"email_verified": true,
		"name":           "Example",
		"picture":        "https://example.com/avatar.png",
		"nonce":          "",
	}}
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
	registry := singleTenantRegistry(config)
	userStore := &failingUserStore{upsertErr: errors.New("upsert_fail")}
	refreshStore := NewMemoryRefreshTokenStore()
	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

	body := prepareLoginBody(t, router, payload, "valid-token")
	request := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBuffer(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when user upsert fails, got %d", response.Code)
	}
}

func TestAuthGoogleRefreshIssueError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	payload := &idtoken.Payload{Claims: map[string]interface{}{
		"iss":            "https://accounts.google.com",
		"sub":            "sub-refresh-err",
		"email":          "user@example.com",
		"email_verified": true,
		"name":           "Example",
		"picture":        "https://example.com/avatar.png",
		"nonce":          "",
	}}
	restoreValidator := withValidatorFactory(t, func(ctx context.Context) (GoogleTokenValidator, error) {
		return &fakeGoogleValidator{
			results: map[string]validatorResult{"valid-token": {payload: payload, expectedAudience: "client-id"}},
		}, nil
	})
	defer restoreValidator()

	config := newTestServerConfig()
	registry := singleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := &stubRefreshStore{
		issueFunc: func(ctx context.Context, tenantID string, applicationUserID string, expiresUnix int64, previousTokenID string) (string, string, error) {
			return "", "", errors.New("issue_fail")
		},
	}
	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

	body := prepareLoginBody(t, router, payload, "valid-token")
	request := httptest.NewRequest(http.MethodPost, "/auth/google", bytes.NewBuffer(body))
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
	registry := singleTenantRegistry(config)
	userStore := newTestUserStore()
	refreshStore := &stubRefreshStore{
		validateFunc: func(ctx context.Context, tenantID string, tokenOpaque string) (string, string, int64, error) {
			return "", "", 0, ErrRefreshTokenExpired
		},
	}
	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

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
	registry := singleTenantRegistry(config)
	userStore := &failingUserStore{profileErr: errors.New("profile_fail")}
	refreshStore := &stubRefreshStore{
		validateFunc: func(ctx context.Context, tenantID string, tokenOpaque string) (string, string, int64, error) {
			return "user", "token", time.Now().Add(time.Minute).Unix(), nil
		},
	}
	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

	request := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	request.AddCookie(&http.Cookie{Name: config.RefreshCookieName, Value: "refresh"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when profile lookup fails, got %d", response.Code)
	}
}

func TestAuthRefreshIssueFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := newTestServerConfig()
	registry := singleTenantRegistry(config)
	userStore := newTestUserStore()
	userStore.setProfile(config.TenantID, "user", testUserProfile{email: "user@example.com", display: "User", avatar: "https://example.com/avatar.png", roles: []string{"user"}})
	refreshStore := &stubRefreshStore{
		validateFunc: func(ctx context.Context, tenantID string, tokenOpaque string) (string, string, int64, error) {
			return "user", "token", time.Now().Add(time.Minute).Unix(), nil
		},
		issueFunc: func(ctx context.Context, tenantID string, applicationUserID string, expiresUnix int64, previousTokenID string) (string, string, error) {
			return "", "", errors.New("issue_fail")
		},
	}
	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

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
	registry := singleTenantRegistry(config)
	userStore := newTestUserStore()
	userStore.setProfile(config.TenantID, "user", testUserProfile{email: "user@example.com", display: "User", avatar: "https://example.com/avatar.png", roles: []string{"user"}})
	refreshStore := &stubRefreshStore{
		validateFunc: func(ctx context.Context, tenantID string, tokenOpaque string) (string, string, int64, error) {
			return "user", "token", time.Now().Add(time.Minute).Unix(), nil
		},
		issueFunc: func(ctx context.Context, tenantID string, applicationUserID string, expiresUnix int64, previousTokenID string) (string, string, error) {
			return "token-new", "opaque-new", nil
		},
		revokeFunc: func(ctx context.Context, tenantID string, tokenID string) error {
			return errors.New("revoke_fail")
		},
	}
	router := gin.New()
	MountAuthRoutes(router, registry, userStore, refreshStore, nil)

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
	token, _, err := MintAppJWT(NewSystemClock(), config.TenantID, "user", "user@example.com", "User", "https://example.com/avatar.png", []string{"user"}, config.AppJWTIssuer, config.AppJWTSigningKey, config.SessionTTL)
	if err != nil {
		t.Fatalf("failed to mint token: %v", err)
	}

	mismatchConfig := config
	mismatchConfig.AppJWTIssuer = "another-issuer"
	mismatchRegistry := singleTenantRegistry(mismatchConfig)

	router := gin.New()
	router.Use(RequireSession(mismatchRegistry))
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

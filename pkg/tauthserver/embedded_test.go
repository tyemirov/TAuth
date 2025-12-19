package tauthserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/authkit"
	"google.golang.org/api/idtoken"
)

type stubUserStore struct{}

func (store stubUserStore) UpsertGoogleUser(ctx context.Context, tenantID string, googleSub string, userEmail string, userDisplayName string, userAvatarURL string) (string, []string, error) {
	return "user-123", []string{"user"}, nil
}

func (store stubUserStore) GetUserProfile(ctx context.Context, tenantID string, applicationUserID string) (string, string, string, []string, error) {
	return "user@example.com", "Demo User", "https://example.com/avatar.png", []string{"user"}, nil
}

type stubGoogleValidator struct {
	payload *idtoken.Payload
}

func (validator stubGoogleValidator) Validate(ctx context.Context, idToken string, audience string) (*idtoken.Payload, error) {
	return validator.payload, nil
}

func TestNewEmbeddedAuthServerRejectsMissingConfig(testingHandle *testing.T) {
	refreshStore := authkit.NewMemoryRefreshTokenStore()
	testCases := []struct {
		name       string
		configPath string
		userStore  UserStore
		refresh    RefreshTokenStore
		code       string
	}{
		{
			name:       "missing config path",
			configPath: "",
			userStore:  stubUserStore{},
			refresh:    refreshStore,
			code:       errorCodeMissingConfigPath,
		},
		{
			name:       "missing user store",
			configPath: "tenants.yaml",
			userStore:  nil,
			refresh:    refreshStore,
			code:       errorCodeMissingUserStore,
		},
		{
			name:       "missing refresh store",
			configPath: "tenants.yaml",
			userStore:  stubUserStore{},
			refresh:    nil,
			code:       errorCodeMissingRefreshTokenStore,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		testingHandle.Run(testCase.name, func(testingHandle *testing.T) {
			_, err := NewEmbeddedAuthServer(testCase.configPath, testCase.userStore, testCase.refresh)
			if err == nil {
				testingHandle.Fatalf("expected error for %s", testCase.name)
			}
			if !strings.Contains(err.Error(), testCase.code) {
				testingHandle.Fatalf("expected error to contain %s", testCase.code)
			}
		})
	}
}

func TestEmbeddedAuthServerMountsAuthRoutes(testingHandle *testing.T) {
	gin.SetMode(gin.TestMode)
	configPath := writeTenantConfigFile(testingHandle)
	refreshStore := authkit.NewMemoryRefreshTokenStore()
	payload := &idtoken.Payload{
		Claims: map[string]interface{}{
			"iss":            "https://accounts.google.com",
			"sub":            "google-subject",
			"email":          "user@example.com",
			"email_verified": true,
			"name":           "Demo User",
			"picture":        "https://example.com/avatar.png",
		},
	}
	server, err := NewEmbeddedAuthServer(
		configPath,
		stubUserStore{},
		refreshStore,
		WithGoogleTokenValidator(stubGoogleValidator{payload: payload}),
	)
	if err != nil {
		testingHandle.Fatalf("init embedded server: %v", err)
	}
	testingHandle.Cleanup(server.Close)

	router := gin.New()
	if mountErr := server.Mount(router); mountErr != nil {
		testingHandle.Fatalf("mount auth routes: %v", mountErr)
	}

	nonceResponse := performRequest(router, http.MethodPost, "http://localhost/auth/nonce", nil)
	if nonceResponse.Code != http.StatusOK {
		testingHandle.Fatalf("expected /auth/nonce 200, got %d", nonceResponse.Code)
	}
	var noncePayload struct {
		Nonce string `json:"nonce"`
	}
	if decodeErr := json.NewDecoder(nonceResponse.Body).Decode(&noncePayload); decodeErr != nil {
		testingHandle.Fatalf("decode nonce response: %v", decodeErr)
	}
	if noncePayload.Nonce == "" {
		testingHandle.Fatalf("expected nonce value")
	}

	googleRequestBody, _ := json.Marshal(map[string]string{
		"google_id_token": "valid-token",
		"nonce_token":     noncePayload.Nonce,
	})
	googleResponse := performRequest(router, http.MethodPost, "http://localhost/auth/google", bytes.NewBuffer(googleRequestBody))
	if googleResponse.Code != http.StatusOK {
		testingHandle.Fatalf("expected /auth/google 200, got %d", googleResponse.Code)
	}

	meResponse := performRequest(router, http.MethodGet, "http://localhost/me", nil)
	if meResponse.Code != http.StatusUnauthorized {
		testingHandle.Fatalf("expected /me 401, got %d", meResponse.Code)
	}

	unknownHostResponse := performRequest(router, http.MethodPost, "http://unknown.example.com/auth/nonce", nil)
	if unknownHostResponse.Code != http.StatusNotFound {
		testingHandle.Fatalf("expected unknown host 404, got %d", unknownHostResponse.Code)
	}

	invalidGoogleResponse := performRequest(router, http.MethodPost, "http://localhost/auth/google", bytes.NewBufferString("{}"))
	if invalidGoogleResponse.Code != http.StatusBadRequest {
		testingHandle.Fatalf("expected invalid /auth/google 400, got %d", invalidGoogleResponse.Code)
	}
}

func performRequest(router *gin.Engine, method string, url string, body *bytes.Buffer) *httptest.ResponseRecorder {
	requestBody := body
	if requestBody == nil {
		requestBody = bytes.NewBufferString("")
	}
	request, _ := http.NewRequest(method, url, requestBody)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func writeTenantConfigFile(testingHandle *testing.T) string {
	testingHandle.Helper()
	tempDir := testingHandle.TempDir()
	configPath := filepath.Join(tempDir, "tenants.yaml")
	payload := []byte(`tenants:
  - id: "demo"
    display_name: "Demo tenant"
    allowed_hosts:
      - "localhost"
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    jwt_signing_key: "demo-signing-key"
    cookie_domain: ""
    session_cookie_name: "app_session"
    refresh_cookie_name: "app_refresh"
    session_ttl: "15m"
    refresh_ttl: "720h"
    nonce_ttl: "5m"
    allow_insecure_http: true
`)
	if writeErr := os.WriteFile(configPath, payload, 0600); writeErr != nil {
		testingHandle.Fatalf("write config: %v", writeErr)
	}
	return configPath
}

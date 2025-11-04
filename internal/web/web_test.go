package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	webassets "github.com/tyemirov/tauth/web"
	"go.uber.org/zap"
)

func TestServeEmbeddedStaticJS(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/client.js", func(contextGin *gin.Context) {
		ServeEmbeddedStaticJS(contextGin, webassets.FS, "auth-client.js")
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/client.js", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	if contentType := recorder.Header().Get("Content-Type"); contentType == "" {
		t.Fatalf("expected content type header")
	}

	missRouter := gin.New()
	missRouter.GET("/missing.js", func(contextGin *gin.Context) {
		ServeEmbeddedStaticJS(contextGin, webassets.FS, "missing.js")
	})
	missRecorder := httptest.NewRecorder()
	missRouter.ServeHTTP(missRecorder, httptest.NewRequest(http.MethodGet, "/missing.js", nil))
	if missRecorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing asset, got %d", missRecorder.Code)
	}
}

func TestPermissiveCORS(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	router := gin.New()
	middleware, err := PermissiveCORS([]string{"http://localhost"})
	if err != nil {
		t.Fatalf("unexpected error configuring CORS: %v", err)
	}
	router.Use(middleware)
	router.OPTIONS("/resource", func(contextGin *gin.Context) {
		contextGin.Status(http.StatusNoContent)
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodOptions, "/resource", nil)
	request.Header.Set("Origin", "http://localhost")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected 204 from preflight, got %d", recorder.Code)
	}
	if origin := recorder.Header().Get("Access-Control-Allow-Origin"); origin != "http://localhost" {
		t.Fatalf("unexpected allowed origin header: %q", origin)
	}
}

func TestPermissiveCORSRejectsBlankOrigins(t *testing.T) {
	if _, err := PermissiveCORS(nil); err == nil {
		t.Fatalf("expected error for nil origin list")
	}
	if _, err := PermissiveCORS([]string{"  "}); err == nil {
		t.Fatalf("expected error for whitespace origin")
	}
}

type stubClaims struct {
	userID    string
	userEmail string
	display   string
	roles     []string
	expires   time.Time
}

func (claims stubClaims) GetUserID() string {
	return claims.userID
}

func (claims stubClaims) GetUserEmail() string {
	return claims.userEmail
}

func (claims stubClaims) GetUserDisplayName() string {
	return claims.display
}

func (claims stubClaims) GetUserRoles() []string {
	return claims.roles
}

func (claims stubClaims) GetExpiresAt() time.Time {
	return claims.expires
}

func TestHandleWhoAmI(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	store := NewInMemoryUsers()
	store.Users["google:sub-1"] = UserProfile{
		Email:     "user@example.com",
		Display:   "Demo User",
		AvatarURL: "https://example.com/avatar.png",
		Roles:     []string{"user"},
	}

	router := gin.New()
	router.Use(func(contextGin *gin.Context) {
		contextGin.Set("auth_claims", stubClaims{
			userID:    "google:sub-1",
			userEmail: "user@example.com",
			display:   "Demo User",
			roles:     []string{"user"},
			expires:   time.Unix(1700000000, 0),
		})
		contextGin.Next()
	})
	router.GET("/me", HandleWhoAmI(store, zap.NewNop()))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/me", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}
	if payload["user_id"] != "google:sub-1" {
		t.Fatalf("unexpected user_id: %v", payload["user_id"])
	}
	if payload["user_email"] != "user@example.com" {
		t.Fatalf("unexpected user_email: %v", payload["user_email"])
	}
	if payload["display"] != "Demo User" {
		t.Fatalf("unexpected display: %v", payload["display"])
	}
	if payload["avatar_url"] != "https://example.com/avatar.png" {
		t.Fatalf("unexpected avatar_url: %v", payload["avatar_url"])
	}
	if _, ok := payload["roles"]; !ok {
		t.Fatalf("expected roles in response")
	}
	if _, ok := payload["expires"]; !ok {
		t.Fatalf("expected expires in response")
	}
}

func TestHandleWhoAmIMissingClaims(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	store := NewInMemoryUsers()
	router := gin.New()
	router.GET("/me", HandleWhoAmI(store, zap.NewNop()))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/me", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when claims missing, got %d", recorder.Code)
	}
}

func TestHandleWhoAmIMissingUser(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	store := NewInMemoryUsers()
	router := gin.New()
	router.Use(func(contextGin *gin.Context) {
		contextGin.Set("auth_claims", stubClaims{
			userID:    "google:missing",
			userEmail: "missing@example.com",
			display:   "Missing",
			roles:     []string{"user"},
			expires:   time.Now().Add(time.Minute),
		})
		contextGin.Next()
	})
	router.GET("/me", HandleWhoAmI(store, zap.NewNop()))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/me", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when user missing, got %d", recorder.Code)
	}
}

func TestInMemoryUsers(t *testing.T) {
	t.Parallel()
	store := NewInMemoryUsers()
	userID, roles, err := store.UpsertGoogleUser(nil, "sub-1", "user@example.com", "User", "https://example.com/avatar.png")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if userID == "" {
		t.Fatalf("expected user id")
	}
	if len(roles) == 0 {
		t.Fatalf("expected default role")
	}

	email, display, avatarURL, storedRoles, err := store.GetUserProfile(nil, userID)
	if err != nil {
		t.Fatalf("unexpected error retrieving profile: %v", err)
	}
	if email == "" || display == "" || avatarURL == "" || len(storedRoles) == 0 {
		t.Fatalf("incomplete profile returned")
	}

	if _, _, _, _, err := store.GetUserProfile(nil, "missing"); err == nil {
		t.Fatalf("expected error for missing user")
	}
}

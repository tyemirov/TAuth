package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/tyemirov/tauth/internal/authkit"
	webassets "github.com/tyemirov/tauth/web"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
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
	router.Use(PermissiveCORS())
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
	if recorder.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Fatalf("CORS headers missing")
	}
}

func TestHandleWhoAmIReturnsStoredProfile(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	store := NewInMemoryUsers()
	userID, _, err := store.UpsertGoogleUser(t.Context(), "sub-1", "user@example.com", "User One")
	if err != nil {
		t.Fatalf("unexpected upsert error: %v", err)
	}

	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	router := gin.New()
	router.Use(func(contextGin *gin.Context) {
		contextGin.Set("auth_claims", &authkit.JwtCustomClaims{
			UserID:          userID,
			UserEmail:       "user@example.com",
			UserDisplayName: "User One",
			UserRoles:       []string{"user"},
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			},
		})
		contextGin.Next()
	})
	router.GET("/api/me", HandleWhoAmI(logger, store))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON payload: %v", err)
	}
	if payload["user_id"] != userID {
		t.Fatalf("expected user_id %q, got %v", userID, payload["user_id"])
	}
	if payload["user_email"] != "user@example.com" {
		t.Fatalf("expected user_email user@example.com, got %v", payload["user_email"])
	}
	if payload["display"] != "User One" {
		t.Fatalf("expected display User One, got %v", payload["display"])
	}
	roles, ok := payload["roles"].([]interface{})
	if !ok || len(roles) != 1 || roles[0] != "user" {
		t.Fatalf("expected roles [user], got %v", payload["roles"])
	}
	if _, ok := payload["expires"]; !ok {
		t.Fatalf("expected expires in response")
	}
	if logs.Len() != 0 {
		t.Fatalf("expected no warnings, got %d entries", logs.Len())
	}
}

func TestHandleWhoAmILogsWhenProfileMissing(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	store := NewInMemoryUsers()
	core, logs := observer.New(zap.WarnLevel)
	logger := zap.New(core)

	router := gin.New()
	router.Use(func(contextGin *gin.Context) {
		contextGin.Set("auth_claims", &authkit.JwtCustomClaims{
			UserID:          "missing-user",
			UserEmail:       "ghost@example.com",
			UserDisplayName: "Ghost",
			UserRoles:       []string{"ghost"},
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			},
		})
		contextGin.Next()
	})
	router.GET("/api/me", HandleWhoAmI(logger, store))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}
	if logs.Len() == 0 {
		t.Fatalf("expected log entry for missing profile")
	}
	entry := logs.All()[0]
	if entry.Level != zapcore.WarnLevel {
		t.Fatalf("expected warn level log, got %v", entry.Level)
	}
	if code := entry.ContextMap()["code"]; code != "api.me.profile_missing" {
		t.Fatalf("expected code api.me.profile_missing, got %v", code)
	}
}

func TestInMemoryUsers(t *testing.T) {
	t.Parallel()
	store := NewInMemoryUsers()
	userID, roles, err := store.UpsertGoogleUser(nil, "sub-1", "user@example.com", "User")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if userID == "" {
		t.Fatalf("expected user id")
	}
	if len(roles) == 0 {
		t.Fatalf("expected default role")
	}

	email, display, storedRoles, err := store.GetUserProfile(nil, userID)
	if err != nil {
		t.Fatalf("unexpected error retrieving profile: %v", err)
	}
	if email == "" || display == "" || len(storedRoles) == 0 {
		t.Fatalf("incomplete profile returned")
	}

	if _, _, _, err := store.GetUserProfile(nil, "missing"); !errors.Is(err, ErrUserProfileNotFound) {
		t.Fatalf("expected ErrUserProfileNotFound, got %v", err)
	}
}

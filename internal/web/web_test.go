package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	webassets "github.com/tyemirov/tauth/web"
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

func TestHandleWhoAmI(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/me", HandleWhoAmI())

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/me", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
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

	if _, _, _, err := store.GetUserProfile(nil, "missing"); err == nil {
		t.Fatalf("expected error for missing user")
	}
}

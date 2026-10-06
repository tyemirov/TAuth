package authkit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"google.golang.org/api/idtoken"
)

func TestApplicationSubjectMountedDatabaseHTTP(t *testing.T) {
	config := newTestServerConfig()
	databaseURL := sqliteDatabaseURL(t)
	users, err := NewDatabaseUserStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := NewDatabaseRefreshTokenStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw, _ := refresh.db.DB(); raw.Close() })
	registry := NewSingleTenantRegistry(config)
	validator := &fakeGoogleValidator{results: map[string]validatorResult{
		"mounted-google": {payload: &idtoken.Payload{Claims: map[string]interface{}{
			"iss": "https://accounts.google.com", "sub": "mounted-stable", "email": "parent@example.com", "email_verified": true, "name": "Parent",
		}}},
	}}
	ProvideGoogleTokenValidator(validator)
	t.Cleanup(func() { ProvideGoogleTokenValidator(nil) })
	newRouter := func() *gin.Engine {
		router := gin.New()
		MountAuthRoutes(router, registry, users, refresh, nil, users)
		return router
	}
	server := httptest.NewTLSServer(newRouter())
	t.Cleanup(server.Close)
	client := server.Client()
	client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	readProfile := func(response *http.Response) passwordSeedHTTPProfile {
		t.Helper()
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("mounted database route %s: status=%d", response.Request.URL.Path, response.StatusCode)
		}
		var profile passwordSeedHTTPProfile
		if err := json.NewDecoder(response.Body).Decode(&profile); err != nil {
			t.Fatal(err)
		}
		return profile
	}
	login := func() passwordSeedHTTPProfile {
		response, _ := loginWithNonce(t, client, server.URL, validator, "mounted-google")
		return readProfile(response)
	}
	before := login()
	if validateOpaqueAccountID(before.UserID) != nil {
		t.Fatalf("invalid public subject: %s", before.UserID)
	}
	requestProfile := func(method, path string) passwordSeedHTTPProfile {
		request, err := http.NewRequest(method, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return readProfile(response)
	}
	if after := requestProfile(http.MethodGet, "/auth/session"); after.UserID != before.UserID {
		t.Fatalf("session subject changed: %+v", after)
	}
	refreshResponse, err := client.Post(server.URL+"/auth/refresh", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	refreshResponse.Body.Close()
	if refreshResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("refresh: status=%d", refreshResponse.StatusCode)
	}
	if after := requestProfile(http.MethodGet, "/auth/session"); after.UserID != before.UserID {
		t.Fatalf("refresh subject changed: %+v", after)
	}
	raw, _ := users.db.DB()
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	users, err = NewDatabaseUserStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw, _ := users.db.DB(); raw.Close() })
	server.Config.Handler = newRouter()
	if after := requestProfile(http.MethodGet, "/auth/session"); after.UserID != before.UserID {
		t.Fatalf("restart session subject changed: %+v", after)
	}
	if after := login(); after.UserID != before.UserID {
		t.Fatalf("restart login subject changed: %+v", after)
	}
	managedConfig := config
	managedConfig.AccountManagementEnabled = true
	registry.configs[config.TenantID] = managedConfig
	statusKey := newErasureStatusKey(t)
	request, err := http.NewRequest(http.MethodDelete, server.URL+accountProfilePath, strings.NewReader(`{"status_key":"`+statusKey+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("erasure without password storage: status=%d", response.StatusCode)
	}
	var operation struct {
		State string `json:"state"`
	}
	if err := json.NewDecoder(response.Body).Decode(&operation); err != nil {
		t.Fatal(err)
	}
	if operation.State != erasureCompleted {
		t.Fatalf("erasure did not complete: %+v", operation)
	}
}

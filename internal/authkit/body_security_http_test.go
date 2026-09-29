package authkit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSecurityAuthBodyLimits(t *testing.T) {
	router := gin.New()
	MountAuthRoutes(router, NewSingleTenantRegistry(newTestServerConfig()), newTestUserStore(), NewMemoryRefreshTokenStore(), nil)
	server := httptest.NewServer(router)
	defer server.Close()
	for _, path := range []string{"/auth/google", "/auth/google/native", "/auth/apple/callback", "/auth/password/login"} {
		for _, chunked := range []bool{false, true} {
			request, err := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader(`{"google_id_token":"`+strings.Repeat("x", 64*1024)+`"}`))
			if err != nil {
				t.Fatal(err)
			}
			if chunked {
				request.ContentLength = -1
			}
			request.Header.Set("Content-Type", "application/json")
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusRequestEntityTooLarge {
				t.Errorf("%s chunked=%v: want 413, got %d", path, chunked, response.StatusCode)
			}
		}
	}
	response, err := server.Client().Post(server.URL+"/auth/nonce", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("normal request: %d", response.StatusCode)
	}
}

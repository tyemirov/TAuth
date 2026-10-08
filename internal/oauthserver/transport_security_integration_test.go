package oauthserver

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestOAuthCredentialRoutesRejectForgedTransport(t *testing.T) {
	fixture := newGitHubOAuthFixture(t, "memory", false)
	router := gin.New()
	if err := fixture.server.Mount(router); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(router)
	defer server.Close()
	for _, route := range router.Routes() {
		if route.Path == authorizationServerMetadataPath || route.Path == endpointPath(fixture.server.config.JWKSURI()) {
			continue
		}
		t.Run(route.Method+route.Path, func(t *testing.T) {
			for _, signal := range []string{"plain", "xfp", "forwarded", "host"} {
				request, err := http.NewRequest(route.Method, server.URL+route.Path, strings.NewReader(""))
				if err != nil {
					t.Fatal(err)
				}
				switch signal {
				case "xfp":
					request.Header.Set("X-Forwarded-Proto", "https")
				case "forwarded":
					request.Header.Set("Forwarded", "proto=https")
				case "host":
					request.Host = "localhost:8080"
				}
				response, err := server.Client().Do(request)
				if err != nil {
					t.Fatal(err)
				}
				body, readErr := io.ReadAll(response.Body)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if !strings.Contains(string(body), `"error":"https_required"`) {
					t.Errorf("%s: expected transport error, got %s", signal, body)
				}
				response.Body.Close()
				if response.StatusCode != http.StatusBadRequest {
					t.Errorf("%s status %d", signal, response.StatusCode)
				}
				if len(response.Cookies()) != 0 {
					t.Errorf("%s set cookies", signal)
				}
			}
		})
	}
}

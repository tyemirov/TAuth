package oauthserver

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/tenants"
)

func TestGitHubOAuthBrowserFixture(t *testing.T) {
	if os.Getenv("TAUTH_GITHUB_OAUTH_BROWSER_FIXTURE") != "1" {
		t.Skip("fixture runs through test-github-oauth-browser-server")
	}
	const resourceID = "https://resource.example/"
	fixture := newGitHubOAuthFixture(t, "sqlite", true, func(document *tenants.FileDocument) {
		document.Tenants[0].AllowInsecureHTTP = false
		document.Tenants[0].TenantOrigins = []string{"https://app.example.com"}
		document.Tenants[0].OAuth.Resources[0].Identifier = resourceID
		document.Tenants[0].OAuth.Clients[0].Grants[0].Resource = resourceID
	})
	if fixture.server.config.AllowInsecureHTTP() {
		t.Fatal("browser fixture permits insecure OAuth HTTP")
	}
	original := fixture.provider.Server.Config.Handler
	fixture.provider.Server.Config.Handler = http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/login/oauth/authorize":
			response.Header().Set("Content-Type", "text/html")
			_, err := fmt.Fprintf(response, `<!doctype html><html lang="en"><title>GitHub fixture</title><a id="github-approve" href="/test/complete?%s">Approve GitHub login</a></html>`, html.EscapeString(request.URL.RawQuery))
			if err != nil {
				t.Error(err)
			}
		case "/test/complete":
			clone := request.Clone(request.Context())
			copyURL := *request.URL
			copyURL.Path = "/login/oauth/authorize"
			clone.URL = &copyURL
			original.ServeHTTP(response, clone)
		default:
			original.ServeHTTP(response, request)
		}
	})
	router := fixture.listener.Config.Handler.(*gin.Engine)
	stop := make(chan struct{})
	var once sync.Once
	router.POST("/test/shutdown", func(ctx *gin.Context) { ctx.Status(204); once.Do(func() { close(stop) }) })
	digest := sha256.Sum256([]byte(strings.Repeat("b", 43)))
	providerURL, err := url.Parse(fixture.provider.Server.URL)
	if err != nil {
		t.Fatal(err)
	}
	providerURL.Host = "localhost:" + providerURL.Port()
	config := map[string]string{
		"issuer": fixture.issuer, "provider": providerURL.String(), "clientID": testOAuthClient, "resource": resourceID, "redirectURI": testOAuthRedirect,
		"authorize": authorizationURL(fixture.issuer, base64.RawURLEncoding.EncodeToString(digest[:]), "cross-site-state", testOAuthRedirect, resourceID, testOAuthScope, testOAuthClient),
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("GITHUB_OAUTH_BROWSER_FIXTURE %s\n", encoded)
	<-stop
}

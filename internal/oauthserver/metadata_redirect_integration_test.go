package oauthserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tyemirov/tauth/internal/tenants"
)

// documentMetadataResolver injects provider documents while retaining their real parser.
type documentMetadataResolver map[string]clientMetadataDocument

func (documents documentMetadataResolver) Resolve(_ context.Context, clientID string) (Client, error) {
	document, exists := documents[clientID]
	if !exists {
		return Client{}, ErrUnknownClient
	}
	payload, err := json.Marshal(document)
	if err != nil {
		return Client{}, err
	}
	return parseClientMetadataDocument(clientID, payload)
}

func nativeMetadataDocument(clientID string, redirects ...string) clientMetadataDocument {
	return clientMetadataDocument{
		ClientID: clientID, ClientName: "Native Metadata Client", ApplicationType: "native",
		RedirectURIs: redirects, GrantTypes: []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: "none",
	}
}

func TestMetadataRedirectAuthorization(t *testing.T) {
	fixture := newGitHubOAuthFixture(t, "memory", false)
	documents := documentMetadataResolver{}
	fixture.server.metadataResolver = documents
	for _, scenario := range []struct {
		name, declared, requested, applicationType string
		accepted                                   bool
	}{
		{"IPv4 first port", "http://127.0.0.1/callback", "http://127.0.0.1:51196/callback", "native", true},
		{"IPv4 second port", "http://127.0.0.1/callback", "http://127.0.0.1:61234/callback", "native", true},
		{"IPv6 first port", "http://[::1]/callback", "http://[::1]:51196/callback", "native", true},
		{"IPv6 second port", "http://[::1]/callback", "http://[::1]:61234/callback", "native", true},
		{"declared port varies", "http://127.0.0.1:49152/callback", "http://127.0.0.1:51196/callback", "native", true},
		{"uppercase scheme IPv4", "HTTP://127.0.0.1/callback", "HTTP://127.0.0.1:51196/callback", "native", true},
		{"uppercase scheme IPv6", "HTTP://[::1]/callback", "HTTP://[::1]:61234/callback", "native", true},
		{"mixed scheme declared port", "HtTp://127.0.0.1:49152/callback?a=1", "HtTp://127.0.0.1:51196/callback?a=1", "native", true},
		{"minimum port", "http://127.0.0.1/callback", "http://127.0.0.1:1/callback", "native", true},
		{"maximum port", "http://127.0.0.1/callback", "http://127.0.0.1:65535/callback", "native", true},
		{"exact query", "http://127.0.0.1/callback?a=1", "http://127.0.0.1:51196/callback?a=1", "native", true},
		{"exact localhost", "http://localhost/callback", "http://localhost/callback", "native", true},
		{"exact HTTPS", "https://client.example/callback", "https://client.example/callback", "web", true},
		{"other loopback", "http://127.0.0.1/callback", "http://127.0.0.2:51196/callback", "native", false},
		{"non-loopback", "http://127.0.0.1/callback", "http://192.0.2.1:51196/callback", "native", false},
		{"undeclared IPv6", "http://127.0.0.1/callback", "http://[::1]:51196/callback", "native", false},
		{"undeclared IPv4", "http://[::1]/callback", "http://127.0.0.1:51196/callback", "native", false},
		{"IPv6 spelling", "http://[::1]/callback", "http://[0:0:0:0:0:0:0:1]:51196/callback", "native", false},
		{"localhost port", "http://localhost/callback", "http://localhost:51196/callback", "native", false},
		{"scheme", "http://127.0.0.1/callback", "https://127.0.0.1:51196/callback", "native", false},
		{"scheme spelling", "http://127.0.0.1/callback", "HTTP://127.0.0.1:51196/callback", "native", false},
		{"uppercase scheme changed", "HTTP://127.0.0.1/callback", "http://127.0.0.1:51196/callback", "native", false},
		{"path", "http://127.0.0.1/callback", "http://127.0.0.1:51196/other", "native", false},
		{"escaped path", "http://127.0.0.1/callback", "http://127.0.0.1:51196/%63allback", "native", false},
		{"query", "http://127.0.0.1/callback?a=1", "http://127.0.0.1:51196/callback?a=2", "native", false},
		{"empty query", "http://127.0.0.1/callback", "http://127.0.0.1:51196/callback?", "native", false},
		{"fragment", "http://127.0.0.1/callback", "http://127.0.0.1:51196/callback#secret", "native", false},
		{"empty fragment", "http://127.0.0.1/callback", "http://127.0.0.1:51196/callback#", "native", false},
		{"userinfo", "http://127.0.0.1/callback", "http://user@127.0.0.1:51196/callback", "native", false},
		{"zero port", "http://127.0.0.1/callback", "http://127.0.0.1:0/callback", "native", false},
		{"large port", "http://127.0.0.1/callback", "http://127.0.0.1:65536/callback", "native", false},
		{"negative port", "http://127.0.0.1/callback", "http://127.0.0.1:-1/callback", "native", false},
		{"text port", "http://127.0.0.1/callback", "http://127.0.0.1:abc/callback", "native", false},
		{"empty port", "http://127.0.0.1/callback", "http://127.0.0.1:/callback", "native", false},
		{"web HTTP loopback", "http://127.0.0.1/callback", "http://127.0.0.1:51196/callback", "web", false},
		{"web HTTPS loopback", "https://127.0.0.1/callback", "https://127.0.0.1:51196/callback", "web", false},
		{"native HTTPS loopback", "https://127.0.0.1/callback", "https://127.0.0.1:51196/callback", "native", false},
		{"HTTPS port", "https://client.example/callback", "https://client.example:51196/callback", "native", false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			document := nativeMetadataDocument(testMetadataClient, scenario.declared)
			document.ApplicationType = scenario.applicationType
			documents[testMetadataClient] = document
			response := doRequest(t, fixture.client, http.MethodGet, authorizationURL(fixture.issuer,
				pkceChallenge(strings.Repeat("a", 43)), "state", scenario.requested, testOAuthResource, testOAuthScope, testMetadataClient), nil)
			if !scenario.accepted {
				if response.StatusCode != http.StatusBadRequest || response.Header.Get("Location") != "" {
					t.Fatalf("invalid destination accepted: status=%d location=%s", response.StatusCode, response.Header.Get("Location"))
				}
				readBody(t, response)
				return
			}
			assertStatus(t, response, http.StatusSeeOther)
			location := response.Header.Get("Location")
			readBody(t, response)
			if !strings.HasPrefix(location, fixture.issuer+"/oauth/login?request=") {
				t.Fatalf("missing login destination: %s", location)
			}
			page := doRequest(t, fixture.client, http.MethodGet, location, nil)
			assertStatus(t, page, http.StatusOK)
			assertBrowserContentSafe(t, readBody(t, page), "Native Metadata Client", "Continue with GitHub")
		})
	}
}

func TestMetadataNativeBrowserFlow(t *testing.T) {
	for _, storage := range []string{"memory", "sqlite"} {
		t.Run(storage, func(t *testing.T) {
			fixture := newGitHubOAuthFixture(t, storage, true)
			fixture.server.metadataResolver = documentMetadataResolver{
				testMetadataClient: nativeMetadataDocument(testMetadataClient, "http://127.0.0.1/callback", "http://localhost/callback", "http://[::1]/callback"),
			}
			verifier := strings.Repeat("a", 43)
			// Establish the existing account through the registered client's provider login.
			callback, _ := fixture.begin(t, "existing-account", verifier, testOAuthClient, testOAuthRedirect)
			fixture.approve(t, fixture.complete(t, callback))
			profile := doRequest(t, fixture.client, http.MethodGet, fixture.issuer+"/me", nil)
			assertStatus(t, profile, http.StatusOK)
			var existing struct {
				UserID string `json:"user_id"`
			}
			if err := json.Unmarshal([]byte(readBody(t, profile)), &existing); err != nil || existing.UserID == "" {
				t.Fatalf("existing account profile: %v %#v", err, existing)
			}
			var err error
			fixture.client.Jar, err = cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			// Keep two login transactions open with distinct ports and PKCE challenges.
			callbacks := []string{"http://127.0.0.1:51196/callback", "http://127.0.0.1:61234/callback"}
			verifiers := []string{verifier, strings.Repeat("b", 43)}
			providerCallbacks := make([]string, len(callbacks))
			for index, redirect := range callbacks {
				providerCallbacks[index], _ = fixture.begin(t, fmt.Sprintf("state-%d", index), verifiers[index], testMetadataClient, redirect)
			}
			for index, providerCallback := range providerCallbacks {
				consent := fixture.complete(t, providerCallback)
				destination := fixture.approve(t, consent)
				if !strings.HasPrefix(destination, callbacks[index]+"?") || queryValue(t, destination, "state") != fmt.Sprintf("state-%d", index) || queryValue(t, destination, "iss") != fixture.issuer {
					t.Fatalf("callback binding changed: %s", destination)
				}
				form := codeTokenForm(queryValue(t, destination, "code"), verifiers[1-index])
				form.Set("client_id", testMetadataClient)
				assertOAuthError(t, doRequest(t, fixture.client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(form.Encode())), "invalid_grant")
				form.Set("code_verifier", verifiers[index])
				response := doRequest(t, fixture.client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(form.Encode()))
				assertStatus(t, response, http.StatusOK)
				tokens := decodeTokenResponse(t, response)
				validator := newResourceValidator(t, fixture.issuer, fixture.signer.JWKS(), time.Now)
				claims, err := validator.ValidateToken(context.Background(), tokens.AccessToken)
				if err != nil || claims.Subject != existing.UserID || claims.ClientID != testMetadataClient || claims.Scope != testOAuthScope || claims.TenantID != "demo" {
					t.Fatalf("account or resource grant changed: %#v %v", claims, err)
				}
				assertOAuthError(t, doRequest(t, fixture.client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(form.Encode())), "invalid_grant")
				refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}, "client_id": {testMetadataClient}, "resource": {testOAuthResource}}
				response = doRequest(t, fixture.client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(refresh.Encode()))
				assertStatus(t, response, http.StatusOK)
				rotated := decodeTokenResponse(t, response)
				if rotated.RefreshToken == tokens.RefreshToken {
					t.Fatal("refresh token did not rotate")
				}
				revoke := url.Values{"token": {rotated.RefreshToken}, "client_id": {testMetadataClient}}
				response = doRequest(t, fixture.client, http.MethodPost, fixture.issuer+"/oauth/revoke", strings.NewReader(revoke.Encode()))
				assertStatus(t, response, http.StatusOK)
				readBody(t, response)
				refresh.Set("refresh_token", rotated.RefreshToken)
				assertOAuthError(t, doRequest(t, fixture.client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(refresh.Encode())), "invalid_grant")
			}
			// The active account proceeds straight to consent and can deny the request.
			redirect := "http://[::1]:61234/callback"
			response := doRequest(t, fixture.client, http.MethodGet, authorizationURL(fixture.issuer, pkceChallenge(verifier), "deny-state", redirect, testOAuthResource, testOAuthScope, testMetadataClient), nil)
			assertStatus(t, response, http.StatusSeeOther)
			consent := response.Header.Get("Location")
			readBody(t, response)
			if !strings.HasPrefix(consent, fixture.issuer+"/oauth/consent?request=") {
				t.Fatalf("existing session did not reach consent: %s", consent)
			}
			page := doRequest(t, fixture.client, http.MethodGet, consent, nil)
			assertStatus(t, page, http.StatusOK)
			assertBrowserContentSafe(t, readBody(t, page), "Native Metadata Client", "verified GitHub user ID")
			denial := url.Values{"request": {queryValue(t, consent, "request")}, "decision": {"deny"}}
			response = doRequest(t, fixture.client, http.MethodPost, fixture.issuer+"/oauth/consent", strings.NewReader(denial.Encode()))
			assertStatus(t, response, http.StatusSeeOther)
			destination := response.Header.Get("Location")
			readBody(t, response)
			if !strings.HasPrefix(destination, redirect+"?") || queryValue(t, destination, "state") != "deny-state" || queryValue(t, destination, "iss") != fixture.issuer || queryValue(t, destination, "error") != "access_denied" || strings.Contains(destination, "code=") {
				t.Fatalf("invalid denial callback: %s", destination)
			}
		})
	}
}

func TestMetadataPortRulePreservesRegisteredLimits(t *testing.T) {
	fixture := newGitHubOAuthFixture(t, "memory", false, func(document *tenants.FileDocument) {
		client := &document.Tenants[0].OAuth.Clients[0]
		client.RedirectURIs = []string{"http://127.0.0.1/callback"}
		client.LoopbackPortRange = tenants.FileOAuthLoopbackPortRange{Minimum: 49152, Maximum: 51200}
	})
	for _, port := range []int{49151, 49152, 51196, 51200, 51201} {
		t.Run(fmt.Sprint(port), func(t *testing.T) {
			response := doRequest(t, fixture.client, http.MethodGet, authorizationURL(fixture.issuer,
				pkceChallenge(strings.Repeat("a", 43)), "state", fmt.Sprintf("http://127.0.0.1:%d/callback", port),
				testOAuthResource, testOAuthScope, testOAuthClient), nil)
			if port < 49152 || port > 51200 {
				assertOAuthError(t, response, "invalid_request")
			} else {
				assertStatus(t, response, http.StatusSeeOther)
				readBody(t, response)
			}
		})
	}
}

func TestMetadataInvalidDeclaredRedirect(t *testing.T) {
	fixture := newGitHubOAuthFixture(t, "memory", false)
	documents := documentMetadataResolver{}
	fixture.server.metadataResolver = documents
	for _, redirect := range []string{
		"http://127.0.0.1:0/callback", "http://127.0.0.1:65536/callback", "http://127.0.0.1:/callback",
		"http://127.0.0.1:abc/callback", "http://user@127.0.0.1/callback", "http://127.0.0.1/callback#",
	} {
		t.Run(redirect, func(t *testing.T) {
			documents[testMetadataClient] = nativeMetadataDocument(testMetadataClient, redirect)
			response := doRequest(t, fixture.client, http.MethodGet, authorizationURL(fixture.issuer,
				pkceChallenge(strings.Repeat("a", 43)), "state", redirect, testOAuthResource, testOAuthScope, testMetadataClient), nil)
			assertOAuthError(t, response, "unauthorized_client")
		})
	}
}

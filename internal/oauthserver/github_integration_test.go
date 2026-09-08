package oauthserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/tenants"
	"github.com/tyemirov/tauth/internal/testsupport"
	"github.com/tyemirov/tauth/internal/web"
)

func TestGitHubOAuthLoginAndConsent(t *testing.T) {
	for _, scenario := range []struct {
		storage  string
		disclose bool
	}{{"memory", true}, {"sqlite", true}, {"memory", false}} {
		t.Run(fmt.Sprintf("%s/disclose=%v", scenario.storage, scenario.disclose), func(t *testing.T) { testGitHubOAuthFlow(t, scenario.storage, scenario.disclose) })
	}
}

type githubOAuthFixture struct {
	issuer   string
	client   *http.Client
	server   *Server
	provider *testsupport.GitHub
	sessions *authkit.OAuthBrowserSessions
	accounts accountCredentialStore
	signer   *Signer
}

func newGitHubOAuthFixture(t *testing.T, storage string, disclose bool) *githubOAuthFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	listener := httptest.NewUnstartedServer(router)
	issuer := "https://" + listener.Listener.Addr().String()
	config, _ := loadOAuthTestConfig(t, issuer)
	document := config.TenantDocument()
	if disclose {
		document.Tenants[0].OAuth.Resources[0].Scopes[0].IdentityProviders = []string{"github"}
	}
	document.Tenants[0].GoogleWebClientID = ""
	document.Tenants[0].PasswordAuth = tenants.FilePasswordAuth{}
	document.Tenants[0].GitHubOAuth = tenants.FileGitHubOAuth{Enabled: true, ClientID: "github-client", ClientSecret: "test-secret", RedirectURI: issuer + tenants.GitHubCallbackPath}
	document.Tenants[0].AccountManagement = tenants.FileAccountManagement{Enabled: true, ReturnChallengeTokens: true}
	tenantConfig, err := tenants.LoadConfigFromDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := authkit.BuildTenantRegistry(authkit.ServerConfig{AppJWTIssuer: "tauth"}, tenantConfig, authkit.NewSameSiteResolver(true))
	if err != nil {
		t.Fatal(err)
	}
	var users authkit.UserStore = web.NewInMemoryUsers()
	var refresh authkit.RefreshTokenStore = authkit.NewMemoryRefreshTokenStore()
	nonces := authkit.NewMemoryNonceStore(time.Minute)
	var accounts accountCredentialStore = authkit.NewMemoryPasswordCredentialStore()
	var store Store = NewMemoryStore()
	transactions := authkit.NewMemoryGitHubTransactionStore()
	if storage == "sqlite" {
		databaseURL := "sqlite://" + filepath.Join(t.TempDir(), "oauth-github.sqlite")
		persistent, err := authkit.NewDatabaseUserStore(context.Background(), databaseURL)
		if err != nil {
			t.Fatal(err)
		}
		users, accounts = persistent, persistent
		refresh, err = authkit.NewDatabaseRefreshTokenStore(context.Background(), databaseURL)
		if err != nil {
			t.Fatal(err)
		}
		transactions, err = authkit.NewDatabaseGitHubTransactionStore(context.Background(), databaseURL)
		if err != nil {
			t.Fatal(err)
		}
		store, err = NewDatabaseStore(context.Background(), databaseURL)
		if err != nil {
			t.Fatal(err)
		}
	}
	sessions := authkit.NewOAuthBrowserSessions(registry, users, refresh, nonces, accounts)
	oauthRegistry, err := NewRegistry(tenantConfig)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(config.OAuthServer())
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(config.OAuthServer(), oauthRegistry, store, signer, fixtureMetadataResolver{}, sessions)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Mount(router); err != nil {
		t.Fatal(err)
	}
	provider := testsupport.NewGitHub()
	t.Cleanup(provider.Server.Close)
	login, err := authkit.NewGitHubLogin(sessions, transactions, authkit.NewGitHubProvider(provider), server)
	if err != nil {
		t.Fatal(err)
	}
	login.Mount(router)
	authkit.MountAuthRoutesWithPassword(router, registry, users, refresh, nonces, accounts, nil, server.store)
	listener.StartTLS()
	t.Cleanup(listener.Close)
	client := listener.Client()
	client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &githubOAuthFixture{issuer, client, server, provider, sessions, accounts, signer}
}

func testGitHubOAuthFlow(t *testing.T, storage string, disclose bool) {
	fixture := newGitHubOAuthFixture(t, storage, disclose)
	issuer, client, provider := fixture.issuer, fixture.client, fixture.provider
	sessions, accounts, signer := fixture.sessions, fixture.accounts, fixture.signer
	response := doRequest(t, client, http.MethodGet, issuer+"/.well-known/oauth-authorization-server", nil)
	assertStatus(t, response, 200)
	response.Body.Close()
	verifier := strings.Repeat("c", 43)
	digest := sha256.Sum256([]byte(verifier))
	authorize := authorizationURL(issuer, base64.RawURLEncoding.EncodeToString(digest[:]), "client-state", testOAuthRedirect, testOAuthResource, testOAuthScope, testOAuthClient)
	response = doRequest(t, client, http.MethodGet, authorize, nil)
	assertStatus(t, response, 303)
	loginURL := response.Header.Get("Location")
	response.Body.Close()
	response = doRequest(t, client, http.MethodGet, loginURL, nil)
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || !strings.Contains(string(body), "Continue with GitHub") {
		t.Fatalf("GitHub-only OAuth login unavailable: status=%d", response.StatusCode)
	}
	match := regexp.MustCompile(`href="([^"]*auth/github/start[^"]*)"`).FindSubmatch(body)
	if len(match) != 2 {
		t.Fatal("GitHub login control missing destination")
	}
	startURL, err := url.Parse(html.UnescapeString(string(match[1])))
	if err != nil {
		t.Fatal(err)
	}
	base, _ := url.Parse(issuer)
	startURL = base.ResolveReference(startURL)
	response = doRequest(t, client, http.MethodGet, startURL.String(), nil)
	assertStatus(t, response, 302)
	providerURL, err := response.Location()
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	providerClient := *provider.Server.Client()
	providerClient.CheckRedirect = client.CheckRedirect
	response = doRequest(t, &providerClient, http.MethodGet, provider.Server.URL+providerURL.RequestURI(), nil)
	callback := response.Header.Get("Location")
	response.Body.Close()
	response = doRequest(t, client, http.MethodGet, callback, nil)
	assertStatus(t, response, 303)
	consentURL := response.Header.Get("Location")
	response.Body.Close()
	response = doRequest(t, client, http.MethodGet, consentURL, nil)
	assertStatus(t, response, 200)
	response.Body.Close()
	requestToken := queryValue(t, consentURL, "request")
	request, err := http.NewRequest(http.MethodPost, consentURL, strings.NewReader(url.Values{"request": {requestToken}, "decision": {"approve"}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", issuer)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	assertStatus(t, response, 303)
	code := queryValue(t, response.Header.Get("Location"), "code")
	response.Body.Close()
	response = doRequest(t, client, http.MethodPost, issuer+"/oauth/token", strings.NewReader(codeTokenForm(code, verifier).Encode()))
	assertStatus(t, response, 200)
	var tokens tokenResponsePayload
	if err := json.NewDecoder(response.Body).Decode(&tokens); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	claims, err := signer.ParseAccessToken(tokens.AccessToken, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(claims.Scope, testOAuthScope) || claims.Subject == "" {
		t.Fatal("resource grant changed")
	}
	if active, err := sessions.ActiveUser(context.Background(), "demo", claims.Subject); err != nil || !active {
		t.Fatal("OAuth subject does not resolve browser account")
	}
	if disclose {
		if len(claims.ProviderIdentities) != 1 || claims.ProviderIdentities[0].ProviderID != "9007199254740993" {
			t.Fatal("verified identity claim missing")
		}
	} else if len(claims.ProviderIdentities) != 0 {
		t.Fatal("identity disclosed without a scope")
	}
	validationTime := time.Now()
	validator := newResourceValidator(t, issuer, signer.JWKS(), func() time.Time { return validationTime })
	resource := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		claims, err := validator.ValidateRequest(request)
		if err != nil {
			response.WriteHeader(401)
			return
		}
		_ = json.NewEncoder(response).Encode(claims.ProviderIdentities)
	}))
	defer resource.Close()
	resourceRequest, err := http.NewRequest(http.MethodGet, resource.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resourceRequest.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	response, err = resource.Client().Do(resourceRequest)
	if err != nil {
		t.Fatal(err)
	}
	assertStatus(t, response, 200)
	response.Body.Close()
	refreshForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}, "client_id": {testOAuthClient}, "resource": {testOAuthResource}}
	response = doRequest(t, client, http.MethodPost, issuer+"/oauth/token", strings.NewReader(refreshForm.Encode()))
	assertStatus(t, response, 200)
	rotated := decodeTokenResponse(t, response)
	if _, err := accounts.LinkProviderIdentity(context.Background(), "demo", claims.Subject, authkit.AccountProviderIdentity{Provider: "google", Subject: "other-provider", UserEmail: "private@example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := accounts.UnlinkIdentity(context.Background(), "demo", claims.Subject, "github", "9007199254740993"); err != nil {
		t.Fatal(err)
	}
	refreshForm.Set("refresh_token", rotated.RefreshToken)
	response = doRequest(t, client, http.MethodPost, issuer+"/oauth/token", strings.NewReader(refreshForm.Encode()))
	if disclose {
		assertOAuthError(t, response, "invalid_grant")
	} else {
		assertStatus(t, response, 200)
		response.Body.Close()
	}
	response, err = resource.Client().Do(resourceRequest)
	if err != nil {
		t.Fatal(err)
	}
	assertStatus(t, response, 200)
	response.Body.Close()
	validationTime = time.Now().Add(2 * time.Minute)
	response, err = resource.Client().Do(resourceRequest)
	if err != nil {
		t.Fatal(err)
	}
	assertStatus(t, response, 401)
	response.Body.Close()
}

func (fixture *githubOAuthFixture) begin(t *testing.T, state, verifier, clientID, redirectURI string) (string, string) {
	t.Helper()
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	response := doRequest(t, fixture.client, http.MethodGet, authorizationURL(fixture.issuer, challenge, state, redirectURI, testOAuthResource, testOAuthScope, clientID), nil)
	assertStatus(t, response, 303)
	loginURL := response.Header.Get("Location")
	response.Body.Close()
	requestToken := queryValue(t, loginURL, "request")
	start := fixture.issuer + tenants.GitHubStartPath + "?" + url.Values{"tenant_id": {"demo"}, "operation": {"oauth"}, "oauth_request": {requestToken}}.Encode()
	response = doRequest(t, fixture.client, http.MethodGet, start, nil)
	assertStatus(t, response, 302)
	providerURL, err := response.Location()
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if providerURL.Query().Get("code_challenge") == challenge {
		t.Fatal("GitHub and resource PKCE challenges were shared")
	}
	providerClient := *fixture.provider.Server.Client()
	providerClient.CheckRedirect = fixture.client.CheckRedirect
	response = doRequest(t, &providerClient, http.MethodGet, fixture.provider.Server.URL+providerURL.RequestURI(), nil)
	assertStatus(t, response, 302)
	callback := response.Header.Get("Location")
	response.Body.Close()
	return callback, requestToken
}

func (fixture *githubOAuthFixture) complete(t *testing.T, callback string) string {
	t.Helper()
	response := doRequest(t, fixture.client, http.MethodGet, callback, nil)
	assertStatus(t, response, 303)
	consent := response.Header.Get("Location")
	response.Body.Close()
	response = doRequest(t, fixture.client, http.MethodGet, consent, nil)
	assertStatus(t, response, 200)
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "verified GitHub user ID") {
		t.Fatal("consent omits identity disclosure")
	}
	return consent
}

func (fixture *githubOAuthFixture) approve(t *testing.T, consent string) string {
	t.Helper()
	form := url.Values{"request": {queryValue(t, consent, "request")}, "decision": {"approve"}}
	request, err := http.NewRequest(http.MethodPost, consent, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", fixture.issuer)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := fixture.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	assertStatus(t, response, 303)
	destination := response.Header.Get("Location")
	response.Body.Close()
	return destination
}

func TestGitHubOAuthPendingRequestBoundaries(t *testing.T) {
	for _, storage := range []string{"memory", "sqlite"} {
		for _, scenario := range []string{"expired", "consumed", "tenant changed", "client redirect changed"} {
			t.Run(storage+"/"+scenario, func(t *testing.T) {
				fixture := newGitHubOAuthFixture(t, storage, true)
				callback, requestToken := fixture.begin(t, "pending", strings.Repeat("p", 43), testOAuthClient, testOAuthRedirect)
				switch scenario {
				case "expired":
					fixture.server.now = func() time.Time { return time.Now().Add(time.Hour) }
				case "consumed":
					if _, err := fixture.server.store.ConsumeAuthorizationRequest(context.Background(), requestToken, time.Now().Unix()); err != nil {
						t.Fatal(err)
					}
				case "tenant changed":
					policy := fixture.server.registry.resources[testOAuthResource]
					policy.TenantID = "another-tenant"
					fixture.server.registry.resources[testOAuthResource] = policy
				case "client redirect changed":
					policy := fixture.server.registry.tenants["demo"]
					client := policy.Clients[testOAuthClient]
					client.RedirectURIs = []string{"https://client.example/changed"}
					policy.Clients[testOAuthClient] = client
				}
				response := doRequest(t, fixture.client, http.MethodGet, callback, nil)
				assertStatus(t, response, 400)
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(body), "invalid_oauth_request") {
					t.Fatalf("unexpected error: %s", body)
				}
				if fixture.provider.Calls.Load() != 0 {
					t.Fatal("invalid continuation exchanged a provider code")
				}
				for _, cookie := range response.Cookies() {
					if cookie.Name == "app_session_demo" || cookie.Name == "app_refresh_demo" {
						t.Fatal("invalid continuation issued a session")
					}
				}
			})
		}
	}
}

func TestGitHubOAuthSimultaneousClients(t *testing.T) {
	for _, storage := range []string{"memory", "sqlite"} {
		t.Run(storage, func(t *testing.T) {
			fixture := newGitHubOAuthFixture(t, storage, true)
			firstVerifier, secondVerifier := strings.Repeat("f", 43), strings.Repeat("s", 43)
			firstCallback, firstRequest := fixture.begin(t, "first-client", firstVerifier, testOAuthClient, testOAuthRedirect)
			secondCallback, secondRequest := fixture.begin(t, "metadata-client", secondVerifier, testMetadataClient, testMetadataRedirect)
			if firstRequest == secondRequest {
				t.Fatal("simultaneous authorizations share pending state")
			}
			secondConsent := fixture.complete(t, secondCallback)
			firstConsent := fixture.complete(t, firstCallback)
			if queryValue(t, secondConsent, "request") != secondRequest || queryValue(t, firstConsent, "request") != firstRequest {
				t.Fatal("OAuth continuation selected another pending request")
			}
			firstDestination := fixture.approve(t, firstConsent)
			secondDestination := fixture.approve(t, secondConsent)
			if queryValue(t, firstDestination, "state") != "first-client" || queryValue(t, secondDestination, "state") != "metadata-client" {
				t.Fatal("resource client state changed")
			}
			var subject string
			for _, grant := range []struct{ destination, verifier, clientID string }{{firstDestination, firstVerifier, testOAuthClient}, {secondDestination, secondVerifier, testMetadataClient}} {
				form := codeTokenForm(queryValue(t, grant.destination, "code"), grant.verifier)
				form.Set("client_id", grant.clientID)
				response := doRequest(t, fixture.client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(form.Encode()))
				assertStatus(t, response, 200)
				tokens := decodeTokenResponse(t, response)
				claims, err := fixture.signer.ParseAccessToken(tokens.AccessToken, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				if claims.ClientID != grant.clientID || claims.ProviderIdentities[0].ProviderID != "9007199254740993" {
					t.Fatal("client or provider identity changed")
				}
				if subject != "" && subject != claims.Subject {
					t.Fatal("browser and resource clients received different accounts")
				}
				subject = claims.Subject
			}
		})
	}
}

func TestGitHubOAuthCurrentIdentityBeforeCodeAndExchange(t *testing.T) {
	for _, storage := range []string{"memory", "sqlite"} {
		for _, point := range []string{"authorization", "exchange"} {
			t.Run(storage+"/"+point, func(t *testing.T) {
				fixture := newGitHubOAuthFixture(t, storage, true)
				verifier := strings.Repeat("i", 43)
				callback, _ := fixture.begin(t, "identity", verifier, testOAuthClient, testOAuthRedirect)
				consent := fixture.complete(t, callback)
				request, err := http.NewRequest(http.MethodGet, consent, nil)
				if err != nil {
					t.Fatal(err)
				}
				for _, cookie := range fixture.client.Jar.Cookies(request.URL) {
					request.AddCookie(cookie)
				}
				accountID, authenticated, err := fixture.sessions.Resolve(request, "demo")
				if err != nil || !authenticated {
					t.Fatalf("browser account: authenticated=%v err=%v", authenticated, err)
				}
				var destination string
				if point == "exchange" {
					destination = fixture.approve(t, consent)
				}
				if _, err := fixture.accounts.LinkProviderIdentity(context.Background(), "demo", accountID, authkit.AccountProviderIdentity{Provider: "google", Subject: "remaining-login", UserEmail: "private@example.com"}); err != nil {
					t.Fatal(err)
				}
				if _, err := fixture.accounts.UnlinkIdentity(context.Background(), "demo", accountID, "github", "9007199254740993"); err != nil {
					t.Fatal(err)
				}
				if point == "authorization" {
					destination = fixture.approve(t, consent)
					if queryValue(t, destination, "error") != "access_denied" {
						t.Fatal("authorization accepted a missing required identity")
					}
					parsed, err := url.Parse(destination)
					if err != nil {
						t.Fatal(err)
					}
					if parsed.Query().Get("code") != "" {
						t.Fatal("failed identity validation issued a code")
					}
				} else {
					response := doRequest(t, fixture.client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(codeTokenForm(queryValue(t, destination, "code"), verifier).Encode()))
					assertOAuthError(t, response, "invalid_grant")
				}
			})
		}
	}
}

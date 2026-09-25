package oauthserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/tenants"
	"github.com/tyemirov/tauth/pkg/oauthvalidator"
)

func TestGitHubResourceCredentialsRequireServiceAndUserAuthority(t *testing.T) {
	for _, storage := range []string{"memory", "sqlite"} {
		t.Run(storage, func(t *testing.T) {
			const serviceKey = "fixture-resource-secret-01234567890123456789"
			fixture := newGitHubOAuthFixture(t, storage, true, func(document *tenants.FileDocument) {
				// Exercise the native configuration shape without depending on its Go fields.
				encoded, err := json.Marshal(document)
				if err != nil {
					t.Fatal(err)
				}
				var raw map[string]any
				if err := json.Unmarshal(encoded, &raw); err != nil {
					t.Fatal(err)
				}
				tenant := raw["tenants"].([]any)[0].(map[string]any)
				github := tenant["github_oauth"].(map[string]any)
				github["scopes"] = []string{"read:user", "repo", "user:email"}
				github["credential_key"] = strings.Repeat("v", 32)
				resource := tenant["oauth"].(map[string]any)["resources"].([]any)[0].(map[string]any)
				resource["github_credentials_key"] = serviceKey
				encoded, err = json.Marshal(raw)
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(encoded, document); err != nil {
					t.Fatal(err)
				}
			})
			fixture.provider.TokenJSON = `{"access_token":"provider-secret-token","token_type":"bearer","scope":"read:user,repo,user:email"}`
			fixture.provider.AuthorizationScopes = "read:user repo user:email"
			verifier := strings.Repeat("z", 43)
			callback, _ := fixture.begin(t, "repository-credential", verifier, testOAuthClient, testOAuthRedirect)
			consent := fixture.callbackDestination(t, callback)
			sessionRequest, err := http.NewRequest(http.MethodGet, consent, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, cookie := range fixture.client.Jar.Cookies(sessionRequest.URL) {
				sessionRequest.AddCookie(cookie)
			}
			accountID, authenticated, err := fixture.sessions.Resolve(sessionRequest, "demo")
			if err != nil || !authenticated {
				t.Fatalf("resolve account: authenticated=%v err=%v", authenticated, err)
			}
			if _, err := fixture.accounts.LinkProviderIdentity(t.Context(), "demo", accountID, authkit.AccountProviderIdentity{Provider: "github", Subject: "1", UserEmail: "second@example.com"}); err != nil {
				t.Fatal(err)
			}
			destination := fixture.approve(t, consent)
			response := doRequest(t, fixture.client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(codeTokenForm(queryValue(t, destination, "code"), verifier).Encode()))
			assertStatus(t, response, http.StatusOK)
			tokens := decodeTokenResponse(t, response)
			requestCredential := func(t *testing.T, key, token string, status int) {
				t.Helper()
				body, err := json.Marshal(map[string]string{"subject_token": token})
				if err != nil {
					t.Fatal(err)
				}
				request, err := http.NewRequest(http.MethodPost, fixture.issuer+"/oauth/github-credentials", strings.NewReader(string(body)))
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Authorization", "Bearer "+key)
				response, err := fixture.client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				assertStatus(t, response, status)
				if status == http.StatusOK {
					var credential struct {
						GitHubID    string `json:"github_id"`
						AccessToken string `json:"access_token"`
					}
					if err := json.NewDecoder(response.Body).Decode(&credential); err != nil {
						t.Fatal(err)
					}
					if credential.GitHubID != "9007199254740993" || credential.AccessToken != "provider-secret-token" {
						t.Fatal("credential identity changed")
					}
					if response.Header.Get("Cache-Control") != "no-store" {
						t.Fatal("credential response is cacheable")
					}
				}
			}
			requestCredential(t, "", tokens.AccessToken, http.StatusUnauthorized)
			requestCredential(t, "wrong-resource-key", tokens.AccessToken, http.StatusUnauthorized)
			requestCredential(t, serviceKey, "invalid-token", http.StatusUnauthorized)
			requestCredential(t, serviceKey, tokens.AccessToken, http.StatusOK)
			claims, err := fixture.signer.ParseAccessToken(tokens.AccessToken, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			grant := RefreshGrant{TenantID: claims.TenantID, UserID: claims.Subject, ClientID: claims.ClientID, Resource: claims.Audience[0], Scope: claims.Scope, ConsentID: claims.GrantID}
			if len(claims.ProviderIdentities) != 2 {
				t.Fatalf("expected two GitHub identities, got %v", claims.ProviderIdentities)
			}
			for _, scenario := range []struct {
				name       string
				identities oauthvalidator.ProviderIdentities
				status     int
			}{
				{"owner-first", oauthvalidator.ProviderIdentities{{Provider: "github", ProviderID: "9007199254740993"}, {Provider: "github", ProviderID: "1"}}, http.StatusOK},
				{"owner-last", oauthvalidator.ProviderIdentities{{Provider: "github", ProviderID: "1"}, {Provider: "github", ProviderID: "9007199254740993"}}, http.StatusOK},
				{"owner-absent", oauthvalidator.ProviderIdentities{{Provider: "github", ProviderID: "1"}}, http.StatusForbidden},
				{"wrong-provider", oauthvalidator.ProviderIdentities{{Provider: "google", ProviderID: "9007199254740993"}}, http.StatusUnauthorized},
				{"no-identities", nil, http.StatusForbidden},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					token, _, err := fixture.signer.MintAccessToken(grant, scenario.identities, time.Now(), time.Minute)
					if err != nil {
						t.Fatal(err)
					}
					requestCredential(t, serviceKey, token, scenario.status)
				})
			}
			for _, scenario := range []struct {
				name     string
				mutate   func(*RefreshGrant)
				issuedAt time.Time
				status   int
			}{
				{"expired", func(*RefreshGrant) {}, time.Now().Add(-2 * time.Hour), http.StatusUnauthorized},
				{"other-resource", func(value *RefreshGrant) { value.Resource = "https://other.example/mcp" }, time.Now(), http.StatusUnauthorized},
				{"other-tenant", func(value *RefreshGrant) { value.TenantID = "other-tenant" }, time.Now(), http.StatusUnauthorized},
				{"other-user", func(value *RefreshGrant) { value.UserID = "other-user" }, time.Now(), http.StatusForbidden},
				{"other-client", func(value *RefreshGrant) { value.ClientID = "other-client" }, time.Now(), http.StatusForbidden},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					selected := grant
					scenario.mutate(&selected)
					token, _, err := fixture.signer.MintAccessToken(selected, claims.ProviderIdentities, scenario.issuedAt, time.Minute)
					if err != nil {
						t.Fatal(err)
					}
					requestCredential(t, serviceKey, token, scenario.status)
				})
			}
			if _, err := fixture.accounts.UnlinkIdentity(t.Context(), "demo", accountID, "github", "9007199254740993"); err != nil {
				t.Fatal(err)
			}
			requestCredential(t, serviceKey, tokens.AccessToken, http.StatusForbidden)
			if _, err := fixture.accounts.LinkProviderIdentity(t.Context(), "demo", accountID, authkit.AccountProviderIdentity{Provider: "github", Subject: "9007199254740993", UserEmail: "private@example.com"}); err != nil {
				t.Fatal(err)
			}
			requestCredential(t, serviceKey, tokens.AccessToken, http.StatusOK)
			if err := fixture.server.store.RevokeConsent(t.Context(), claims.GrantID, time.Now().Unix()); err != nil {
				t.Fatal(err)
			}
			requestCredential(t, serviceKey, tokens.AccessToken, http.StatusForbidden)
		})
	}
}

func configureGitHubResourceCredentials(document *tenants.FileDocument) {
	tenant := &document.Tenants[0]
	tenant.GitHubOAuth.Scopes = []string{"read:user", "repo", "user:email"}
	tenant.GitHubOAuth.CredentialKey = strings.Repeat("v", 32)
	tenant.OAuth.Resources[0].GitHubCredentialsKey = strings.Repeat("s", 32)
}

func TestGitHubResourceCredentialsRequireDisclosureConfiguration(t *testing.T) {
	for _, disclose := range []bool{false, true} {
		t.Run(fmt.Sprint(disclose), func(t *testing.T) {
			config, _ := loadOAuthTestConfig(t, "https://auth.example.com")
			document := config.TenantDocument()
			document.Tenants[0].GitHubOAuth = tenants.FileGitHubOAuth{Enabled: true, ClientID: "github-client", ClientSecret: "test-secret", RedirectURI: "https://auth.example.com/auth/github/callback"}
			configureGitHubResourceCredentials(&document)
			if disclose {
				document.Tenants[0].OAuth.Resources[0].Scopes[0].IdentityProviders = []string{"github"}
			}
			_, err := tenants.LoadConfigFromDocument(document)
			if (err == nil) != disclose {
				t.Fatalf("disclose=%v: configuration error=%v", disclose, err)
			}
		})
	}
}

func TestGitHubResourceCredentialsRejectAuthorizationWithoutDisclosure(t *testing.T) {
	fixture := newGitHubOAuthFixture(t, "memory", false, func(document *tenants.FileDocument) {
		configureGitHubResourceCredentials(document)
		resource := &document.Tenants[0].OAuth.Resources[0]
		resource.Scopes = append(resource.Scopes, tenants.FileOAuthScope{Identifier: "github:identity", DisplayName: "GitHub identity", Description: "Disclose GitHub identity", IdentityProviders: []string{"github"}})
	})
	target := authorizationURL(fixture.issuer, strings.Repeat("a", 43), "missing-disclosure", testOAuthRedirect, testOAuthResource, testOAuthScope, testOAuthClient)
	response := doRequest(t, fixture.client, http.MethodGet, target, nil)
	defer response.Body.Close()
	assertStatus(t, response, http.StatusSeeOther)
	destination, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if destination.Query().Get("error") != "invalid_scope" || destination.Query().Get("state") != "missing-disclosure" {
		t.Fatalf("authorization without disclosure was not rejected: %s", destination)
	}
}

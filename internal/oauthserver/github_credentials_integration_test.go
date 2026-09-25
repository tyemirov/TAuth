package oauthserver

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tyemirov/tauth/internal/tenants"
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
			destination := fixture.approve(t, consent)
			response := doRequest(t, fixture.client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(codeTokenForm(queryValue(t, destination, "code"), verifier).Encode()))
			assertStatus(t, response, http.StatusOK)
			tokens := decodeTokenResponse(t, response)
			requestCredential := func(key, token string, status int) {
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
			requestCredential("", tokens.AccessToken, http.StatusUnauthorized)
			requestCredential("wrong-resource-key", tokens.AccessToken, http.StatusUnauthorized)
			requestCredential(serviceKey, "invalid-token", http.StatusUnauthorized)
			requestCredential(serviceKey, tokens.AccessToken, http.StatusOK)
			claims, err := fixture.signer.ParseAccessToken(tokens.AccessToken, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			grant := RefreshGrant{TenantID: claims.TenantID, UserID: claims.Subject, ClientID: claims.ClientID, Resource: claims.Audience[0], Scope: claims.Scope, ConsentID: claims.GrantID}
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
					requestCredential(serviceKey, token, scenario.status)
				})
			}
			if err := fixture.server.store.RevokeConsent(t.Context(), claims.GrantID, time.Now().Unix()); err != nil {
				t.Fatal(err)
			}
			requestCredential(serviceKey, tokens.AccessToken, http.StatusForbidden)
		})
	}
}

package oauthserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestGitHubDisclosureRequiresCurrentConsent(t *testing.T) {
	for _, storage := range []string{"memory", "sqlite", "sqlite-v1"} {
		for _, phase := range []string{"pending login", "pending consent", "code exchange", "refresh", "repeat authorization"} {
			t.Run(storage+"/"+phase, func(t *testing.T) {
				selectedStorage := storage
				if storage == "sqlite-v1" {
					selectedStorage = "sqlite"
				}
				fixture := newGitHubOAuthFixture(t, selectedStorage, false)
				verifier := strings.Repeat("d", 43)
				callback, _ := fixture.begin(t, "disclosure", verifier, testOAuthClient, testOAuthRedirect)
				if phase == "pending login" {
					enableGitHubDisclosure(fixture)
					response := doRequest(t, fixture.client, http.MethodGet, callback, nil)
					assertStatus(t, response, 400)
					response.Body.Close()
					if fixture.provider.Calls.Load() != 0 {
						t.Fatal("changed pending policy exchanged a provider code")
					}
					return
				}
				consent := fixture.callbackDestination(t, callback)
				response := doRequest(t, fixture.client, http.MethodGet, consent, nil)
				assertStatus(t, response, 200)
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(body), "verified GitHub user ID") {
					t.Fatal("initial consent unexpectedly disclosed GitHub identity")
				}
				if phase == "pending consent" {
					enableGitHubDisclosure(fixture)
					form := url.Values{"request": {queryValue(t, consent, "request")}, "decision": {"approve"}}
					request, err := http.NewRequest(http.MethodPost, consent, strings.NewReader(form.Encode()))
					if err != nil {
						t.Fatal(err)
					}
					request.Header.Set("Origin", fixture.issuer)
					request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					response, err = fixture.client.Do(request)
					if err != nil {
						t.Fatal(err)
					}
					assertOAuthError(t, response, "invalid_request")
					return
				}
				destination := fixture.approve(t, consent)
				code := queryValue(t, destination, "code")
				var tokens tokenResponsePayload
				if phase == "refresh" {
					response = doRequest(t, fixture.client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(codeTokenForm(code, verifier).Encode()))
					assertStatus(t, response, 200)
					tokens = decodeTokenResponse(t, response)
					claims, err := fixture.signer.ParseAccessToken(tokens.AccessToken, time.Now())
					if err != nil {
						t.Fatal(err)
					}
					if len(claims.ProviderIdentities) != 0 {
						t.Fatal("initial grant disclosed an unapproved identity")
					}
				}
				if storage == "sqlite-v1" {
					predecessorDisclosureSchema(t, fixture)
				}
				reopenDisclosureStore(t, fixture)
				if phase == "refresh" {
					response = refreshDisclosureGrant(t, fixture, tokens.RefreshToken)
					assertStatus(t, response, 200)
					tokens = decodeTokenResponse(t, response)
				}
				enableGitHubDisclosure(fixture)
				switch phase {
				case "code exchange":
					response = doRequest(t, fixture.client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(codeTokenForm(code, verifier).Encode()))
					assertOAuthError(t, response, "invalid_grant")
				case "refresh":
					response = refreshDisclosureGrant(t, fixture, tokens.RefreshToken)
					assertOAuthError(t, response, "invalid_grant")
				case "repeat authorization":
					digest := sha256.Sum256([]byte(verifier))
					authorize := authorizationURL(fixture.issuer, base64.RawURLEncoding.EncodeToString(digest[:]), "renewed", testOAuthRedirect, testOAuthResource, testOAuthScope, testOAuthClient)
					response = doRequest(t, fixture.client, http.MethodGet, authorize, nil)
					assertStatus(t, response, 303)
					consent = response.Header.Get("Location")
					response.Body.Close()
					if !strings.HasPrefix(consent, fixture.issuer+"/oauth/consent?") {
						t.Fatal("old consent bypassed the expanded disclosure prompt")
					}
					response = doRequest(t, fixture.client, http.MethodGet, consent, nil)
					assertStatus(t, response, 200)
					body, err := io.ReadAll(response.Body)
					response.Body.Close()
					if err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(string(body), "verified GitHub user ID") {
						t.Fatal("renewed consent omitted disclosure")
					}
					destination = fixture.approve(t, consent)
					response = doRequest(t, fixture.client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(codeTokenForm(queryValue(t, destination, "code"), verifier).Encode()))
					assertStatus(t, response, 200)
					tokens = decodeTokenResponse(t, response)
					reopenDisclosureStore(t, fixture)
					response = refreshDisclosureGrant(t, fixture, tokens.RefreshToken)
					assertStatus(t, response, 200)
					tokens = decodeTokenResponse(t, response)
					claims, err := fixture.signer.ParseAccessToken(tokens.AccessToken, time.Now())
					if err != nil {
						t.Fatal(err)
					}
					if len(claims.ProviderIdentities) != 1 || claims.ProviderIdentities[0].ProviderID != "9007199254740993" {
						t.Fatal("renewed disclosure consent was not preserved")
					}
				}
			})
		}
	}
}

func enableGitHubDisclosure(fixture *githubOAuthFixture) {
	resource := fixture.server.registry.resources[testOAuthResource].Resources[testOAuthResource]
	scope := resource.Scopes[testOAuthScope]
	scope.IdentityProviders = []string{"github"}
	resource.Scopes[testOAuthScope] = scope
}

func reopenDisclosureStore(t *testing.T, fixture *githubOAuthFixture) {
	t.Helper()
	if fixture.databaseURL == "" {
		return
	}
	store, err := NewDatabaseStore(context.Background(), fixture.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	fixture.server.store = store
}

func refreshDisclosureGrant(t *testing.T, fixture *githubOAuthFixture, refreshToken string) *http.Response {
	t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {testOAuthClient}, "resource": {testOAuthResource}}
	return doRequest(t, fixture.client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(form.Encode()))
}

// predecessorDisclosureSchema builds the persisted v1 shape for migration
// qualification. Production keeps only the current disclosure policy column.
func predecessorDisclosureSchema(t *testing.T, fixture *githubOAuthFixture) {
	t.Helper()
	store := fixture.server.store.(*DatabaseStore)
	for _, model := range []any{&databaseAuthorizationRequest{}, &databaseAuthorizationCode{}, &databaseConsent{}, &databaseOAuthRefreshToken{}} {
		if err := store.db.Migrator().DropColumn(model, "DisclosurePolicy"); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.db.Exec("UPDATE schema_migrations SET version = 1 WHERE store_name = ?", "oauth_store").Error; err != nil {
		t.Fatal(err)
	}
}

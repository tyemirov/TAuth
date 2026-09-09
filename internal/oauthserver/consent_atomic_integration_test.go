package oauthserver

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOAuthConsentStorageFailurePreservesRequest(t *testing.T) {
	for _, table := range []string{oauthConsentsTable, oauthAuthorizationCodesTable} {
		t.Run(table, func(t *testing.T) {
			fixture := newGitHubOAuthFixture(t, "sqlite", false)
			verifier := strings.Repeat("a", 43)
			callback, _ := fixture.begin(t, "atomic-consent", verifier, testOAuthClient, testOAuthRedirect)
			consentURL := fixture.callbackDestination(t, callback)
			store := fixture.server.store.(*DatabaseStore)
			trigger := "CREATE TRIGGER reject_oauth_write BEFORE INSERT ON " + table + " BEGIN SELECT RAISE(ABORT, 'injected storage failure'); END"
			if err := store.db.Exec(trigger).Error; err != nil {
				t.Fatal(err)
			}
			form := url.Values{"request": {queryValue(t, consentURL, "request")}, "decision": {"approve"}}
			response := doRequest(t, fixture.client, http.MethodPost, consentURL, strings.NewReader(form.Encode()))
			assertStatus(t, response, http.StatusInternalServerError)
			if body := readBody(t, response); !strings.Contains(body, `"error":"server_error"`) {
				t.Fatalf("unexpected storage error response: %s", body)
			}
			response = doRequest(t, fixture.client, http.MethodGet, consentURL, nil)
			assertStatus(t, response, http.StatusOK)
			response.Body.Close()
			for _, model := range []any{&databaseConsent{}, &databaseAuthorizationCode{}} {
				var count int64
				if err := store.db.Model(model).Count(&count).Error; err != nil || count != 0 {
					t.Fatalf("failed completion retained a partial grant: count=%d error=%v", count, err)
				}
			}
			if err := store.db.Exec("DROP TRIGGER reject_oauth_write").Error; err != nil {
				t.Fatal(err)
			}
			destination := fixture.approve(t, consentURL)
			code := queryValue(t, destination, "code")
			response = doRequest(t, fixture.client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(codeTokenForm(code, verifier).Encode()))
			assertStatus(t, response, http.StatusOK)
			response.Body.Close()
			response = doRequest(t, fixture.client, http.MethodPost, consentURL, strings.NewReader(form.Encode()))
			assertOAuthError(t, response, "invalid_request")
		})
	}
}

func TestOAuthConsentExistingGrantFailurePreservesRequest(t *testing.T) {
	fixture := newGitHubOAuthFixture(t, "sqlite", false)
	verifier := strings.Repeat("b", 43)
	callback, _ := fixture.begin(t, "first-consent", verifier, testOAuthClient, testOAuthRedirect)
	fixture.approve(t, fixture.callbackDestination(t, callback))
	store := fixture.server.store.(*DatabaseStore)
	if err := store.db.Exec("CREATE TRIGGER reject_oauth_write BEFORE INSERT ON " + oauthAuthorizationCodesTable + " BEGIN SELECT RAISE(ABORT, 'injected storage failure'); END").Error; err != nil {
		t.Fatal(err)
	}
	authorize := authorizationURL(fixture.issuer, pkceChallenge(verifier), "repeat-consent", testOAuthRedirect, testOAuthResource, testOAuthScope, testOAuthClient)
	response := doRequest(t, fixture.client, http.MethodGet, authorize, nil)
	assertStatus(t, response, http.StatusInternalServerError)
	response.Body.Close()
	var pending int64
	if err := store.db.Model(&databaseAuthorizationRequest{}).Where("state = ?", "repeat-consent").Count(&pending).Error; err != nil || pending != 1 {
		t.Fatalf("failed repeat authorization lost its request: count=%d error=%v", pending, err)
	}
}

func TestOAuthConsentCompletionPreservesMismatchedRequest(t *testing.T) {
	for _, storage := range []string{"memory", "sqlite"} {
		t.Run(storage, func(t *testing.T) {
			fixture := newGitHubOAuthFixture(t, storage, false)
			verifier := strings.Repeat("c", 43)
			callback, _ := fixture.begin(t, "bound-consent", verifier, testOAuthClient, testOAuthRedirect)
			consentURL := fixture.callbackDestination(t, callback)
			token := queryValue(t, consentURL, "request")
			ctx := context.Background()
			now := time.Now().Unix()
			pending, err := fixture.server.store.GetAuthorizationRequest(ctx, token, now)
			if err != nil {
				t.Fatal(err)
			}
			changed := pending
			changed.State = "different-request"
			if code, err := fixture.server.store.CompleteAuthorizationRequest(ctx, token, AuthorizationCompletion{Request: changed, NowUnix: now}); err == nil || code != "" {
				t.Fatal("completion accepted a different request")
			}
			fixture.approve(t, consentURL)
		})
	}
}

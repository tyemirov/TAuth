package authkit

import (
	"net/http"
	"testing"
)

func TestApplicationSubjectContinuityHTTP(t *testing.T) {
	fixture := newGitHubHTTPFixture(t, true, false)
	if status, body := githubHTTPResponse(t, fixture.client, fixture.callbackURL(t, "")); status != http.StatusSeeOther {
		t.Fatalf("initial login: %d %s", status, body)
	}
	original := fixture.profile(t)["user_id"]
	registry := fixture.login.sessions.registry
	config := registry.configs["github"]
	config.AccountManagementEnabled = true
	registry.configs["github"] = config
	if status, body := githubHTTPResponse(t, fixture.client, fixture.callbackURL(t, "")); status != http.StatusSeeOther {
		t.Fatalf("managed login: %d %s", status, body)
	}
	if current := fixture.profile(t)["user_id"]; current != original {
		t.Fatalf("account-management changed public user_id: before=%v after=%v", original, current)
	}
}

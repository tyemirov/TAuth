package authkit

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestAccountSignInMethodsHTTP(t *testing.T) {
	for _, database := range []bool{false, true} {
		fixture := newGitHubHTTPFixture(t, database, true)
		if status, _ := githubHTTPResponse(t, fixture.client, fixture.callbackURL(t, "")); status != http.StatusSeeOther {
			t.Fatalf("login: %d", status)
		}
		profile := fixture.profile(t)
		read := func(want []string) {
			t.Helper()
			response, err := fixture.client.Get(fixture.server.URL + accountProfilePath)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("account read status=%d", response.StatusCode)
			}
			if response.Header.Get("Cache-Control") != "no-store" {
				t.Fatal("account permits caching")
			}
			var data struct {
				UserID        string   `json:"user_id"`
				SignInMethods []string `json:"sign_in_methods"`
			}
			if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
				t.Fatal(err)
			}
			if data.UserID != profile["user_id"] || len(data.SignInMethods) != len(want) {
				t.Fatalf("account=%+v want=%v", data, want)
			}
			for i, method := range want {
				if data.SignInMethods[i] != method {
					t.Fatalf("methods=%v want=%v", data.SignInMethods, want)
				}
			}
		}
		read([]string{"github"})
		account, err := fixture.accounts.ResolveAccountForUser(context.Background(), "github", profile["user_id"].(string))
		if err != nil {
			t.Fatal(err)
		}
		challenge, err := fixture.accounts.CreatePasswordLink(context.Background(), "github", account.AccountID, AccountPasswordRequest{UserEmail: "linked@example.com", Password: "correct horse battery staple"}, time.Now().Add(time.Hour).Unix())
		if err != nil {
			t.Fatal(err)
		}
		read([]string{"github"}) // An unverified challenge is not a usable password.
		if _, err := fixture.accounts.VerifyPasswordLink(context.Background(), "github", account.AccountID, challenge.Token); err != nil {
			t.Fatal(err)
		}
		read([]string{"github", "password"})
		anonymousClient := *fixture.client
		anonymousClient.Jar = nil
		anonymous, err := anonymousClient.Get(fixture.server.URL + accountProfilePath)
		if err != nil {
			t.Fatal(err)
		}
		anonymous.Body.Close()
		if anonymous.StatusCode != http.StatusUnauthorized {
			t.Fatalf("anonymous status=%d", anonymous.StatusCode)
		}
	}
}

func TestAccountSignInMethodsRemainReadableWhenPasswordManagementIsDisabled(t *testing.T) {
	fixture := newGitHubHTTPFixture(t, false, false)
	if status, _ := githubHTTPResponse(t, fixture.client, fixture.callbackURL(t, "")); status != http.StatusSeeOther {
		t.Fatalf("login: %d", status)
	}
	response, err := fixture.client.Get(fixture.server.URL + accountProfilePath)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var data struct {
		Methods         []string `json:"sign_in_methods"`
		PasswordEnabled *bool    `json:"password_management_enabled"`
	}
	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || len(data.Methods) != 1 || data.Methods[0] != "github" || data.PasswordEnabled == nil || *data.PasswordEnabled {
		t.Fatalf("metadata unavailable or password offered: status=%d data=%+v", response.StatusCode, data)
	}
}

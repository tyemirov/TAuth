package authkit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/web"
)

const inMemoryUsersTestPassword = "correct horse battery staple"

type inMemoryUsersHTTPProfile struct {
	UserID string   `json:"user_id"`
	Email  string   `json:"user_email"`
	Roles  []string `json:"roles"`
}

func newInMemoryUsersHTTPServer(t *testing.T, emails []string) (*httptest.Server, *web.InMemoryUsers, ServerConfig) {
	t.Helper()
	config := newTestServerConfig()
	config.PasswordAuthEnabled = true
	config.AllowInsecureHTTP = false
	users := web.NewInMemoryUsers()
	credentials := NewMemoryPasswordCredentialStore()
	hash, err := HashPassword(inMemoryUsersTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	for _, email := range emails {
		if err := credentials.UpsertPasswordCredential(context.Background(), config.TenantID, PasswordCredentialSeed{UserEmail: email, DisplayName: email, PasswordHash: hash}); err != nil {
			t.Fatal(err)
		}
	}
	router := gin.New()
	MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(config), users, NewMemoryRefreshTokenStore(), nil, credentials, newTestPasswordResetDispatcher(t), nil, nil)
	server := httptest.NewTLSServer(router)
	t.Cleanup(server.Close)
	return server, users, config
}

func inMemoryUsersHTTPLogin(client *http.Client, serverURL, email string) (inMemoryUsersHTTPProfile, error) {
	response, err := client.Post(serverURL+"/auth/password/login", "application/json", strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q}`, email, inMemoryUsersTestPassword)))
	if err != nil {
		return inMemoryUsersHTTPProfile{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return inMemoryUsersHTTPProfile{}, fmt.Errorf("password login status=%d", response.StatusCode)
	}
	var profile inMemoryUsersHTTPProfile
	err = json.NewDecoder(response.Body).Decode(&profile)
	return profile, err
}

func inMemoryUsersHTTPMe(client *http.Client, serverURL string) (inMemoryUsersHTTPProfile, error) {
	response, err := client.Get(serverURL + "/me")
	if err != nil {
		return inMemoryUsersHTTPProfile{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return inMemoryUsersHTTPProfile{}, fmt.Errorf("profile status=%d", response.StatusCode)
	}
	var profile inMemoryUsersHTTPProfile
	err = json.NewDecoder(response.Body).Decode(&profile)
	return profile, err
}

func TestInMemoryUsersReturnedRolesHTTP(t *testing.T) {
	for _, operation := range []string{"upsert", "profile"} {
		t.Run(operation, func(t *testing.T) {
			const email = "user@example.com"
			server, users, config := newInMemoryUsersHTTPServer(t, []string{email})
			client := server.Client()
			var err error
			client.Jar, err = cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			login, err := inMemoryUsersHTTPLogin(client, server.URL, email)
			if err != nil || login.UserID == "" || login.Email != email || !slices.Equal(login.Roles, []string{"user"}) {
				t.Fatalf("login profile=%+v err=%v", login, err)
			}
			var retained []string
			if operation == "upsert" {
				_, retained, err = users.UpsertAccountUser(context.Background(), config.TenantID, login.UserID, email, email, "")
			} else {
				_, _, _, retained, err = users.GetUserProfile(context.Background(), config.TenantID, login.UserID)
			}
			if err != nil {
				t.Fatal(err)
			}
			retained[0] = "admin"
			response, err := client.Post(server.URL+"/auth/refresh", "application/json", nil)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusNoContent {
				t.Fatalf("refresh status=%d", response.StatusCode)
			}
			profile, err := inMemoryUsersHTTPMe(client, server.URL)
			if err != nil || profile.UserID != login.UserID || profile.Email != email || !slices.Equal(profile.Roles, []string{"user"}) {
				t.Fatalf("refreshed profile=%+v err=%v", profile, err)
			}
			_, _, _, storedRoles, err := users.GetUserProfile(context.Background(), config.TenantID, login.UserID)
			if err != nil || !slices.Equal(storedRoles, []string{"user"}) {
				t.Fatalf("%s caller changed stored role after HTTP login/refresh: roles=%v err=%v", operation, storedRoles, err)
			}
		})
	}
}

func TestInMemoryUsersParallelLoginHTTP(t *testing.T) {
	emails := []string{"first@example.com", "second@example.com", "third@example.com", "fourth@example.com"}
	server, users, config := newInMemoryUsersHTTPServer(t, emails)
	type result struct {
		profile inMemoryUsersHTTPProfile
		err     error
	}
	results := make(chan result, len(emails))
	ready := make(chan struct{})
	for _, email := range emails {
		go func() {
			client := server.Client()
			jar, err := cookiejar.New(nil)
			if err != nil {
				results <- result{err: err}
				return
			}
			// A separate client keeps each account's cookies isolated.
			accountClient := &http.Client{Transport: client.Transport, Jar: jar}
			<-ready
			login, err := inMemoryUsersHTTPLogin(accountClient, server.URL, email)
			if err != nil {
				results <- result{err: err}
				return
			}
			profile, err := inMemoryUsersHTTPMe(accountClient, server.URL)
			if err == nil && (profile.UserID != login.UserID || profile.Email != email || !slices.Equal(profile.Roles, []string{"user"})) {
				err = fmt.Errorf("account isolation: login=%+v profile=%+v", login, profile)
			}
			results <- result{profile: profile, err: err}
		}()
	}
	close(ready)
	seen := make(map[string]bool)
	for range emails {
		outcome := <-results
		if outcome.err != nil {
			t.Error(outcome.err)
			continue
		}
		if seen[outcome.profile.UserID] {
			t.Errorf("accounts shared user ID %q", outcome.profile.UserID)
		}
		seen[outcome.profile.UserID] = true
		email, _, _, roles, err := users.GetUserProfile(context.Background(), config.TenantID, outcome.profile.UserID)
		if err != nil || email != outcome.profile.Email || !slices.Equal(roles, []string{"user"}) {
			t.Errorf("stored concurrent login profile: email=%q roles=%v err=%v", email, roles, err)
		}
	}
}

package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/tenants"
	"github.com/tyemirov/tauth/internal/testconfig"
)

func accountLifecycleServerConfig(t *testing.T) appconfig.ApplicationConfig {
	t.Helper()
	config := sampleApplicationConfig()
	config.Server.DatabaseURL = "sqlite://" + filepath.Join(t.TempDir(), "tauth.db")
	config.Tenants = config.Tenants[:1]
	config.Tenants[0].CookieDomain = ""
	config.Tenants[0].AccountManagement = tenants.FileAccountManagement{
		Enabled: true,
		EmailDelivery: tenants.FileEmailDelivery{
			ServerAddress: "localhost:50051", APIKey: "fixture",
			EmailVerificationURL:     "https://alpha.localhost/verify",
			PasswordResetURL:         "https://alpha.localhost/reset",
			PasswordLinkURL:          "https://alpha.localhost/link",
			ConnectionTimeoutSeconds: 1, OperationTimeoutSeconds: 1,
		},
	}
	config.Tenants[0].PasswordAuth.Enabled = true
	return config
}

func accountLifecycleRequest(t *testing.T, server *httptest.Server, method, path, body string, cookies []*http.Cookie) (*http.Response, string) {
	t.Helper()
	request, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", "https://alpha.localhost")
	request.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response, string(payload)
}

func TestRunServerConfiguredAccountDisablementRestart(t *testing.T) {
	restoreValidator := withGoogleValidatorBuilderStub(func(context.Context) (authkit.GoogleTokenValidator, error) { return noopGoogleValidator{}, nil })
	defer restoreValidator()
	for _, state := range []string{"disabled", "disabling"} {
		t.Run(state, func(t *testing.T) {
			config := accountLifecycleServerConfig(t)
			hash, err := authkit.HashPassword("correct horse battery staple")
			if err != nil {
				t.Fatal(err)
			}
			config.Tenants[0].PasswordAuth.Users = []tenants.FilePasswordUser{
				{Email: "disabled@example.com", PasswordHash: hash},
				{Email: "active@example.com", PasswordHash: hash},
			}
			prepared := testconfig.Prepare(t, config)
			accounts, err := authkit.NewDatabaseUserStore(context.Background(), config.Server.DatabaseURL)
			if err != nil {
				t.Fatal(err)
			}
			var accountID string
			starts := 0
			restoreServe := withServeHTTPStub(func(server *http.Server) error {
				starts++
				listener := httptest.NewServer(server.Handler)
				defer listener.Close()
				if starts == 1 {
					response, body := accountLifecycleRequest(t, listener, http.MethodPost, "/auth/password/login", `{"email":"disabled@example.com","password":"correct horse battery staple"}`, nil)
					if response.StatusCode != http.StatusOK {
						t.Fatalf("initial login: %d %s", response.StatusCode, body)
					}
					profile, err := accounts.AuthenticatePassword(context.Background(), "alpha", "disabled@example.com", "correct horse battery staple")
					if err != nil {
						t.Fatal(err)
					}
					accountID = profile.AccountID
					if state == "disabled" {
						disabled, body := accountLifecycleRequest(t, listener, http.MethodPost, "/auth/account/disable", "{}", response.Cookies())
						if disabled.StatusCode != http.StatusNoContent {
							t.Fatalf("disable: %d %s", disabled.StatusCode, body)
						}
					} else if _, err := accounts.BeginAccountDisable(context.Background(), "alpha", accountID); err != nil {
						t.Fatal(err)
					}
				} else {
					profile, err := accounts.ResolveAccountProfile(context.Background(), "alpha", accountID)
					if err != nil || profile.State != "disabled" {
						t.Fatalf("restart changed account state: %+v %v", profile, err)
					}
					response, body := accountLifecycleRequest(t, listener, http.MethodPost, "/auth/password/login", `{"email":"disabled@example.com","password":"correct horse battery staple"}`, nil)
					if response.StatusCode != http.StatusForbidden || !strings.Contains(body, "account_disabled") {
						t.Fatalf("inactive login: %d %s", response.StatusCode, body)
					}
					response, body = accountLifecycleRequest(t, listener, http.MethodPost, "/auth/password/login", `{"email":"active@example.com","password":"correct horse battery staple"}`, nil)
					if response.StatusCode != http.StatusOK {
						t.Fatalf("active login after restart: %d %s", response.StatusCode, body)
					}
				}
				return http.ErrServerClosed
			})
			defer restoreServe()
			for restart := 0; restart < 2; restart++ {
				command := &cobra.Command{}
				command.SetContext(context.WithValue(context.Background(), appConfigContextKey, prepared))
				if err := runServer(command, nil); err != nil {
					t.Fatalf("startup %d: %v", restart+1, err)
				}
			}
			if starts != 2 {
				t.Fatalf("expected two starts, got %d", starts)
			}
		})
	}
}

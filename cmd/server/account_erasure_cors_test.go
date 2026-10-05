package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/testconfig"
)

func TestRunServerAccountErasureStatusCORS(t *testing.T) {
	config := accountLifecycleServerConfig(t)
	config.Server.EnableCORS = true
	config.Server.CORSAllowedOrigins = []string{"https://alpha.localhost"}
	accounts, err := authkit.NewDatabaseUserStore(context.Background(), config.Server.DatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := accounts.CreatePasswordSignup(context.Background(), "alpha", authkit.AccountPasswordRequest{
		UserEmail: "parent@example.com", DisplayName: "Parent", Password: "correct horse battery staple",
	}, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := accounts.VerifyEmailChallenge(context.Background(), "alpha", challenge.Token); err != nil {
		t.Fatal(err)
	}
	restoreValidator := withGoogleValidatorBuilderStub(func(context.Context) (authkit.GoogleTokenValidator, error) { return noopGoogleValidator{}, nil })
	defer restoreValidator()
	served := false
	restoreServe := withServeHTTPStub(func(server *http.Server) error {
		served = true
		listener := httptest.NewServer(server.Handler)
		defer listener.Close()
		for _, scenario := range []struct {
			origin string
			status int
		}{
			{"https://alpha.localhost", http.StatusNoContent},
			{"https://unknown.example", http.StatusForbidden},
		} {
			request, err := http.NewRequest(http.MethodOptions, listener.URL+authkit.AccountErasureStatusPath, nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Origin", scenario.origin)
			request.Header.Set("Access-Control-Request-Method", http.MethodGet)
			request.Header.Set("Access-Control-Request-Headers", "authorization,x-tauth-tenant")
			response, err := listener.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != scenario.status {
				t.Fatalf("preflight for %s: %d", scenario.origin, response.StatusCode)
			}
			if scenario.status == http.StatusNoContent {
				if response.Header.Get("Access-Control-Allow-Origin") != scenario.origin || response.Header.Get("Access-Control-Allow-Credentials") != "true" {
					t.Fatalf("preflight origin policy: %v", response.Header)
				}
				allowed := strings.Split(strings.ToLower(response.Header.Get("Access-Control-Allow-Headers")), ",")
				found := false
				for _, header := range allowed {
					if strings.TrimSpace(header) == "authorization" {
						found = true
					}
				}
				if !found {
					t.Fatalf("status capability blocked by preflight: %v", response.Header)
				}
			} else if response.Header.Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("unknown origin received CORS access")
			}
		}
		login, body := accountLifecycleRequest(t, listener, http.MethodPost, "/auth/password/login", `{"email":"parent@example.com","password":"correct horse battery staple"}`, nil)
		if login.StatusCode != http.StatusOK {
			t.Fatalf("login: %d %s", login.StatusCode, body)
		}
		key := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
		deleted, body := accountLifecycleRequest(t, listener, http.MethodDelete, "/auth/account", `{"status_key":"`+key+`"}`, login.Cookies())
		if deleted.StatusCode != http.StatusAccepted {
			t.Fatalf("erasure: %d %s", deleted.StatusCode, body)
		}
		var operation struct {
			ID string `json:"operation_id"`
		}
		if err := json.Unmarshal([]byte(body), &operation); err != nil || operation.ID == "" {
			t.Fatalf("erasure operation: %s %v", body, err)
		}
		for _, scenario := range []struct {
			origin, key string
			status      int
		}{
			{"https://alpha.localhost", key, http.StatusOK},
			{"https://alpha.localhost", "", http.StatusUnauthorized},
			{"https://alpha.localhost", base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("u", 32))), http.StatusNotFound},
			{"https://unknown.example", key, http.StatusForbidden},
		} {
			request, err := http.NewRequest(http.MethodGet, listener.URL+authkit.AccountErasureStatusPath, nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Origin", scenario.origin)
			if scenario.key != "" {
				request.Header.Set("Authorization", "Bearer "+scenario.key)
			}
			response, err := listener.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != scenario.status {
				t.Fatalf("status read for %s: %d", scenario.origin, response.StatusCode)
			}
			if scenario.status == http.StatusOK {
				var receipt struct {
					ID    string `json:"operation_id"`
					State string `json:"state"`
				}
				if err := json.NewDecoder(response.Body).Decode(&receipt); err != nil {
					t.Fatal(err)
				}
				if receipt.ID != operation.ID || receipt.State != "completed" {
					t.Fatalf("unexpected status: %+v", receipt)
				}
				if response.Header.Get("Access-Control-Allow-Origin") != scenario.origin || response.Header.Get("Cache-Control") != "no-store" {
					t.Fatalf("status headers: %v", response.Header)
				}
			}
			response.Body.Close()
		}
		return http.ErrServerClosed
	})
	defer restoreServe()
	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), appConfigContextKey, testconfig.Prepare(t, config)))
	if err := runServer(command, nil); err != nil {
		t.Fatal(err)
	}
	if !served {
		t.Fatal("server did not start")
	}
}

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/controlplane"
	"github.com/tyemirov/tauth/internal/testconfig"
	"github.com/tyemirov/tauth/pkg/sessionvalidator"
)

func TestConsoleSessionKeyReplacement(t *testing.T) {
	config := testconfig.Prepare(t, appconfig.ApplicationConfig{Server: appconfig.ServerSettings{EnableCORS: true, EnableTenantHeaderOverride: true}})
	store, err := controlplane.OpenExisting(context.Background(), config.Server.DatabaseURL, config.Server.TenantEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	console, err := store.Console(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	config.Server.CORSAllowedOrigins = console.TenantOrigins
	configPath := writeTempConfig(t, "server:\n  database_url: "+config.Server.DatabaseURL+"\n  tenant_encryption_key: "+config.Server.TenantEncryptionKey+"\n")
	newKey := strings.Repeat("replacement-key-", 3)
	replacement := base64.StdEncoding.EncodeToString([]byte(newKey))
	var ownerID, tenantPath, tenantID, oldSession string
	runReplacement := func(revision string) error {
		command := newRootCommand()
		command.SetArgs([]string{"--config", configPath, "tenant-key-replace", "--owner-id", ownerID, "--tenant-id", tenantID, "--revision", revision})
		command.SetIn(strings.NewReader(replacement))
		output := &bytes.Buffer{}
		command.SetOut(output)
		command.SetErr(output)
		err := command.Execute()
		if strings.Contains(output.String(), replacement) || strings.Contains(output.String(), newKey) {
			t.Fatal("replacement command exposed secret")
		}
		return err
	}
	restoreValidator := withGoogleValidatorBuilderStub(func(context.Context) (authkit.GoogleTokenValidator, error) { return consoleGoogleValidator{}, nil })
	defer restoreValidator()
	for stage := 0; stage < 2; stage++ {
		restore := withServeHTTPStub(func(server *http.Server) error {
			listener := httptest.NewTLSServer(server.Handler)
			defer listener.Close()
			client := listener.Client()
			client.Jar, _ = cookiejar.New(nil)
			owner := consoleHTTP{t: t, client: client, base: listener.URL, origin: console.TenantOrigins[0]}
			owner.login("owner", "console-client")
			ownerStatus := http.StatusOK
			if stage == 0 {
				ownerStatus = http.StatusCreated
			}
			own, _ := owner.request("PUT", "/api/management/owner-account", nil, ownerStatus)
			ownerID = own["id"].(string)
			if stage == 0 {
				tenant, headers := owner.request("POST", "/api/management/tenants", consoleTenantInput("Key replacement"), 201, "Idempotency-Key", "replace")
				tenantPath = headers.Get("Location")
				tenantID = tenant["id"].(string)
				_, headers = owner.request("GET", tenantPath+"/configuration", nil, 200)
				saved, headers := owner.request("PUT", tenantPath+"/configuration", map[string]any{"google_web_client_id": "app-google", "frontend_origins": []string{"http://localhost:9891"}, "api_base_url": "http://localhost:9892", "local_development": true, "session_ttl": "15m", "refresh_ttl": "720h"}, 200, "If-Match", headers.Get("ETag"))
				owner.request("POST", tenantPath+"/activations", map[string]any{"revision": saved["revision"]}, 201, "If-Match", headers.Get("ETag"), "Idempotency-Key", "active")
				app := owner
				app.origin = "http://localhost:9891"
				app.tenant = tenantID
				app.login("application-user", "app-google")
				u := listener.URL
				request, _ := http.NewRequest("GET", u, nil)
				for _, cookie := range client.Jar.Cookies(request.URL) {
					if cookie.Name == saved["session_cookie_name"] {
						oldSession = cookie.Value
					}
				}
				if oldSession == "" {
					t.Fatal("missing old session")
				}
				if err := runReplacement("2"); err == nil {
					t.Fatal("active tenant accepted key replacement")
				}
				_, headers = owner.request("GET", tenantPath, nil, 200)
				owner.request("PATCH", tenantPath, map[string]any{"state": "suspended"}, 200, "If-Match", headers.Get("ETag"))
			} else {
				saved, headers := owner.request("GET", tenantPath+"/configuration", nil, 200)
				if saved["revision"] != float64(3) {
					t.Fatal("replacement draft missing")
				}
				owner.request("POST", tenantPath+"/activations", map[string]any{"revision": float64(2)}, 412, "If-Match", headers.Get("ETag"), "Idempotency-Key", "old-key")
				owner.request("POST", tenantPath+"/activations", map[string]any{"revision": saved["revision"]}, 201, "If-Match", headers.Get("ETag"), "Idempotency-Key", "new-key")
				app := owner
				app.origin = "http://localhost:9891"
				app.tenant = tenantID
				app.login("application-user", "app-google")
				request, _ := http.NewRequest("GET", listener.URL, nil)
				var current string
				for _, cookie := range client.Jar.Cookies(request.URL) {
					if cookie.Name == saved["session_cookie_name"] {
						current = cookie.Value
					}
				}
				validator, err := sessionvalidator.New(sessionvalidator.Config{SigningKey: []byte(newKey), CookieName: saved["session_cookie_name"].(string)})
				if err != nil {
					t.Fatal(err)
				}
				for _, scenario := range []struct {
					token string
					valid bool
				}{{oldSession, false}, {current, true}} {
					request, _ := http.NewRequest("GET", "https://customer.example/private", nil)
					request.AddCookie(&http.Cookie{Name: saved["session_cookie_name"].(string), Value: scenario.token})
					claims, err := validator.ValidateRequest(request)
					if (err == nil) != scenario.valid {
						t.Fatalf("key replacement validation: %v", err)
					}
					if err == nil && claims.TenantID != tenantID {
						t.Fatal("wrong tenant after cutover")
					}
				}
				audit, _ := owner.request("GET", tenantPath+"/audit-events", nil, 200)
				encoded, _ := json.Marshal(audit)
				if strings.Contains(string(encoded), newKey) {
					t.Fatal("key in audit")
				}
			}
			return http.ErrServerClosed
		})
		command := &cobra.Command{}
		command.SetContext(context.WithValue(context.Background(), appConfigContextKey, config))
		err := runServer(command, nil)
		restore()
		if err != nil {
			t.Fatal(err)
		}
		if stage == 0 {
			if err := runReplacement("999"); err == nil {
				t.Fatal("stale key replacement accepted")
			}
			if err := runReplacement("2"); err != nil {
				t.Fatal(err)
			}
			if err := runReplacement("2"); err == nil {
				t.Fatal("replacement replay accepted")
			}
		}
	}

}

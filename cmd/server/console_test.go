package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/tyemirov/tauth/deployment/migrations"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/controlplane"
	"google.golang.org/api/idtoken"
)

const consoleTestOrigin = "https://console.example.com"

func TestConsoleRejectsRuntimeTenantYAML(t *testing.T) {
	path := writeTempConfig(t, "tenants: []\n")
	command := newRootCommand()
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	command.SetArgs([]string{"--config", path, "preflight"})
	if err := command.Execute(); err == nil {
		t.Fatal("runtime accepted obsolete tenant YAML")
	}
}

type consoleGoogleValidator struct{}

func (consoleGoogleValidator) Validate(_ context.Context, token, audience string) (*idtoken.Payload, error) {
	var claims map[string]any
	if err := json.Unmarshal([]byte(token), &claims); err != nil {
		return nil, err
	}
	if claims["aud"] != audience {
		return nil, errors.New("wrong audience")
	}
	return &idtoken.Payload{Claims: claims}, nil
}

func TestConsoleEnrollmentAndRestart(t *testing.T) {
	for _, insecure := range []bool{false, true} {
		for _, header := range []bool{false, true} {
			t.Run(fmt.Sprintf("insecure=%t/header=%t", insecure, header), func(t *testing.T) {
				testConsoleEnrollmentAndRestart(t, insecure, header)
			})
		}
	}
}

func testConsoleEnrollmentAndRestart(t *testing.T, insecure, header bool) {
	databaseURL := "sqlite://" + filepath.Join(t.TempDir(), "console.db")
	config := writeTempConfig(t, "admin:\n  emails: [vtyemirov@gmail.com]\nserver:\n  database_url: "+databaseURL+"\n  tenant_encryption_key: "+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32))+"\n  enable_cors: true\n  cors_allowed_origins: ["+consoleTestOrigin+"]\n  enable_tenant_header_override: true\n")
	users, err := authkit.NewDatabaseUserStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	existingUser, roles, err := users.UpsertGoogleUser(context.Background(), "imported", "existing", "existing@example.com", "Existing user", "")
	if err != nil {
		t.Fatal(err)
	}
	refreshes, err := authkit.NewDatabaseRefreshTokenStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	_, existingRefresh, err := refreshes.Issue(context.Background(), "imported", existingUser, time.Now().Add(time.Hour).Unix(), "")
	if err != nil {
		t.Fatal(err)
	}
	existingSession, _, err := authkit.MintAppJWT(authkit.NewSystemClock(), "imported", existingUser, "existing@example.com", "Existing user", "", roles, "tauth", []byte("imported-session-key$literal"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	consoleFile := func(client string) string {
		return writeTempConfig(t, fmt.Sprintf(`id: tauth-console
display_name: TAuth console
tenant_origins: [%s]
google_web_client_id: %s
jwt_signing_key: console-test-signing-key
session_cookie_name: tauth_console_session
refresh_cookie_name: tauth_console_refresh
session_ttl: 15m
refresh_ttl: 720h
account_management:
  enabled: true
  email_delivery:
    server_address: localhost:50051
    api_key: test-key
    connection_timeout_seconds: 1
    operation_timeout_seconds: 1
    email_verification_url: %s/verify
    password_reset_url: %s/reset
    password_link_url: %s/link
`, consoleTestOrigin, client, consoleTestOrigin, consoleTestOrigin, consoleTestOrigin))
	}
	bootstrapFile := consoleFile("console-client")
	sourceFile := writeTempConfig(t, fmt.Sprintf(`tenants:
  - id: imported
    display_name: Imported application
    tenant_origins: [https://customer.example.com, http://127.0.0.1:4443]
    google_web_client_id: ${IMPORT_GOOGLE_CLIENT}
    jwt_signing_key: ${IMPORT_SESSION_KEY}
    session_cookie_name: imported_session
    refresh_cookie_name: imported_refresh
    session_ttl: 15m
    refresh_ttl: 720h
    nonce_ttl: ${IMPORT_NONCE_TTL}
    allow_insecure_http: %t
    require_tenant_header: %t
`, insecure, header))
	t.Setenv("IMPORT_GOOGLE_CLIENT", "imported-client")
	t.Setenv("IMPORT_SESSION_KEY", "imported-session-key$literal")
	t.Setenv("IMPORT_NONCE_TTL", "5m")
	inspection := migrations.NewCommand()
	var inventory bytes.Buffer
	inspection.SetOut(&inventory)
	inspection.SetErr(io.Discard)
	inspection.SetArgs([]string{"--config", config, "--source", sourceFile, "--inspect"})
	if err := inspection.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(inventory.String(), "imported-session-key") || !strings.Contains(inventory.String(), `"id":"imported"`) {
		t.Fatal("invalid redacted inventory")
	}
	if err := os.Unsetenv("IMPORT_NONCE_TTL"); err != nil {
		t.Fatal(err)
	}
	missingInput := migrations.NewCommand()
	missingInput.SetOut(io.Discard)
	missingInput.SetErr(io.Discard)
	missingInput.SetArgs([]string{"--config", config, "--source", sourceFile, "--inspect"})
	if err := missingInput.Execute(); err == nil {
		t.Fatal("missing optional environment input was accepted")
	}
	t.Setenv("IMPORT_NONCE_TTL", "5m")
	execute := func(args ...string) error {
		command := newRootCommand()
		if len(args) > 0 && args[0] == "deployment-migration" {
			command = migrations.NewCommand()
			args = args[1:]
		}
		command.SetOut(io.Discard)
		command.SetErr(io.Discard)
		command.SetArgs(append([]string{"--config", config}, args...))
		return command.Execute()
	}
	if err := execute("console-bootstrap", "--tenant-file", bootstrapFile); err != nil {
		t.Fatal(err)
	}
	if err := execute("deployment-migration", "--source", sourceFile, "--import-id", "initial-import"); err == nil {
		t.Fatal("import before initial enrollment succeeded")
	}
	if err := execute("console-bootstrap", "--tenant-file", bootstrapFile); err != nil {
		t.Fatal("identical bootstrap:", err)
	}
	if err := execute("console-bootstrap", "--tenant-file", consoleFile("changed-client")); err == nil {
		t.Fatal("changed bootstrap accepted")
	}
	previous := buildGoogleTokenValidator
	buildGoogleTokenValidator = func(context.Context) (authkit.GoogleTokenValidator, error) { return consoleGoogleValidator{}, nil }
	t.Cleanup(func() { buildGoogleTokenValidator = previous })
	var ownerID string
	for attempt := 0; attempt < 2; attempt++ {
		activeClient := "console-client"
		if attempt == 1 {
			activeClient = "replacement.apps.googleusercontent.com"
			previousConfig, err := os.ReadFile(config)
			if err != nil {
				t.Fatal(err)
			}
			config = writeTempConfig(t, strings.Replace(string(previousConfig), "admin:\n  emails: [vtyemirov@gmail.com]\n", "", 1))
			store, err := controlplane.OpenExisting(context.Background(), databaseURL, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32)))
			if err != nil {
				t.Fatal(err)
			}
			before, err := store.Console(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			for _, inputs := range [][2]string{{"", activeClient}, {"wrong-client", activeClient}, {"console-client", ""}, {"console-client", "invalid"}, {"console-client", " x.apps.googleusercontent.com"}} {
				if err := execute("console-google-client-replace", "--expected-client-id", inputs[0], "--client-id", inputs[1]); err == nil {
					t.Fatalf("replacement accepted invalid inputs %q", inputs)
				}
				after, err := store.Console(context.Background())
				if err != nil || !reflect.DeepEqual(before, after) {
					t.Fatal("rejected replacement changed console", err)
				}
			}
			if err := execute("console-google-client-replace", "--expected-client-id", "console-client", "--client-id", activeClient); err != nil {
				t.Fatal(err)
			}
			after, err := store.Console(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			before.GoogleWebClientID = activeClient
			if !reflect.DeepEqual(before, after) {
				t.Fatal("replacement changed other console fields")
			}
			store.Close()
			if err := execute("console-google-client-replace", "--expected-client-id", "console-client", "--client-id", "other.apps.googleusercontent.com"); err == nil {
				t.Fatal("stale replacement succeeded")
			}
			if err := execute("console-google-client-replace", "--expected-client-id", activeClient, "--client-id", activeClient); err == nil {
				t.Fatal("unchanged replacement succeeded")
			}
			if err := execute("console-bootstrap", "--tenant-file", consoleFile(activeClient)); err != nil {
				t.Fatal("replacement bootstrap digest:", err)
			}
			if err := execute("console-bootstrap", "--tenant-file", bootstrapFile); err == nil {
				t.Fatal("obsolete bootstrap accepted")
			}
		}
		restore := withServeHTTPStub(func(server *http.Server) error {
			listener := httptest.NewTLSServer(server.Handler)
			defer listener.Close()
			client := listener.Client()
			client.Jar, _ = cookiejar.New(nil)
			requestOrigin := consoleTestOrigin
			request := func(method, path string, body any, status int) map[string]any {
				t.Helper()
				encoded, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				req, err := http.NewRequest(method, listener.URL+path, bytes.NewReader(encoded))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Origin", requestOrigin)
				if header && requestOrigin != consoleTestOrigin {
					req.Header.Set("X-TAuth-Tenant", "imported")
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-TAuth-CSRF", "1")
				response, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				data, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != status {
					t.Fatalf("%s %s: got %d, want %d: %s", method, path, response.StatusCode, status, data)
				}
				if strings.HasPrefix(path, "/api/management") && response.Header.Get("Cache-Control") != "no-store" {
					t.Fatal("management response is cacheable")
				}
				var result map[string]any
				if len(data) > 0 {
					if err := json.Unmarshal(data, &result); err != nil {
						t.Fatal(err)
					}
				}
				return result
			}
			login := func(subject, email, audience string, verified bool, status int) {
				t.Helper()
				nonce := request("POST", "/auth/nonce", nil, 200)["nonce"]
				payload, err := json.Marshal(map[string]any{"aud": audience, "iss": "https://accounts.google.com", "sub": subject, "email": email, "email_verified": verified, "nonce": nonce, "name": "Owner"})
				if err != nil {
					t.Fatal(err)
				}
				request("POST", "/auth/google", map[string]any{"google_id_token": string(payload), "nonce_token": nonce}, status)
			}
			request("GET", "/api/management/owner-account", nil, 401)
			request("GET", "/api/management/accounts", nil, 401)
			if attempt == 0 {
				login("initial", "vtyemirov@gmail.com", "customer-client", true, 401)
				login("initial", "vtyemirov@gmail.com", "console-client", false, 401)
				login("other", "other@example.com", activeClient, true, 200)
				request("PUT", "/api/management/owner-account", nil, 201)
				request("GET", "/api/management/accounts", nil, 403)
			}
			email := "vtyemirov@gmail.com"
			if attempt == 1 {
				email = "changed@example.com"
			}
			if request("GET", "/.well-known/tauth-console", nil, 200)["google_web_client_id"] != activeClient {
				t.Fatal("bootstrap returned wrong client")
			}
			if attempt == 1 {
				login("initial", email, "console-client", true, 401)
			}
			login("initial", email, activeClient, true, 200)
			for _, scenario := range []struct {
				origin, csrf, method string
				status               int
			}{
				{consoleTestOrigin, "", "PUT", 403},
				{"", "1", "PUT", 403},
				{consoleTestOrigin, "1", "DELETE", 405},
			} {
				req, err := http.NewRequest(scenario.method, listener.URL+"/api/management/owner-account", nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Origin", scenario.origin)
				req.Header.Set("X-TAuth-CSRF", scenario.csrf)
				response, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if response.StatusCode != scenario.status {
					t.Fatalf("owner boundary: got %d, want %d", response.StatusCode, scenario.status)
				}
			}
			customerToken, _, err := authkit.MintAppJWT(authkit.NewSystemClock(), "customer", "customer-user", "vtyemirov@gmail.com", "Owner", "", nil, "tauth", []byte("console-test-signing-key"), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			customerRequest, err := http.NewRequest("PUT", listener.URL+"/api/management/owner-account", nil)
			if err != nil {
				t.Fatal(err)
			}
			customerRequest.Header.Set("Origin", consoleTestOrigin)
			customerRequest.Header.Set("X-TAuth-CSRF", "1")
			customerRequest.AddCookie(&http.Cookie{Name: "tauth_console_session", Value: customerToken})
			isolatedClient := *listener.Client()
			isolatedClient.Jar = nil
			response, err := isolatedClient.Do(customerRequest)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != 401 {
				t.Fatal("customer tenant session accepted")
			}
			status := 201
			if attempt == 1 {
				status = 200
			}
			owner := request("PUT", "/api/management/owner-account", nil, status)
			if owner["administrator"] != (attempt == 0) {
				t.Fatal("administrator role does not match current verified email")
			}
			if attempt == 0 {
				accounts := request("GET", "/api/management/accounts?limit=1", nil, 200)
				if len(accounts["items"].([]any)) != 1 || accounts["next_cursor"] == "" {
					t.Fatal("account directory pagination failed")
				}
				request("POST", "/api/management/accounts", nil, 405)
				request("GET", "/api/management/accounts?limit=0", nil, 400)
			} else {
				request("GET", "/api/management/accounts", nil, 403)
			}
			if attempt == 0 {
				ownerID = owner["id"].(string)
			} else if owner["id"] != ownerID {
				t.Fatal("owner changed after restart and email change")
			}
			if request("GET", "/api/management/owner-account", nil, 200)["id"] != ownerID {
				t.Fatal("wrong owner")
			}
			request("PUT", "/api/management/owner-account", nil, 200)
			if attempt == 1 {
				collection := request("GET", "/api/management/tenants", nil, 200)
				items := collection["items"].([]any)
				if len(items) != 1 || items[0].(map[string]any)["id"] != "imported" {
					t.Fatal("owner cannot recover imported tenant collection")
				}
				gatewayListener := httptest.NewServer(server.Handler)
				defer gatewayListener.Close()
				verifyImportedProvisioning(consoleHTTP{t: t, client: client, base: listener.URL, origin: consoleTestOrigin, gatewayURL: gatewayListener.URL}, insecure, header)
			}
			if attempt == 0 {
				for retry := 0; retry < 2; retry++ {
					if err := execute("deployment-migration", "--source", sourceFile, "--import-id", "initial-import", "--owner-id", ownerID, "--app-id", "imported-app", "--app-name", "Imported App"); err != nil {
						t.Fatal(err)
					}
				}
				t.Setenv("IMPORT_GOOGLE_CLIENT", "changed-client")
				if err := execute("deployment-migration", "--source", sourceFile, "--import-id", "initial-import", "--owner-id", ownerID, "--app-id", "imported-app", "--app-name", "Imported App"); err == nil {
					t.Fatal("changed import accepted")
				}
				t.Setenv("IMPORT_GOOGLE_CLIENT", "")
			}
			request("POST", "/auth/account/disable", nil, 404)
			login("substitute", "vtyemirov@gmail.com", activeClient, true, 200)
			substituteStatus := 201
			if attempt == 1 {
				substituteStatus = 200
			}
			if request("PUT", "/api/management/owner-account", nil, substituteStatus)["id"] == ownerID {
				t.Fatal("separate subjects share owner")
			}
			request("GET", "/api/management/tenants/imported", nil, 404)
			if len(request("GET", "/api/management/tenants", nil, 200)["items"].([]any)) != 0 {
				t.Fatal("administrator can see another owner workspace")
			}
			login("other", "other@example.com", activeClient, true, 200)
			if request("PUT", "/api/management/owner-account", nil, 200)["id"] == ownerID {
				t.Fatal("distinct identities share owner")
			}
			if attempt == 1 {
				requestOrigin = "https://customer.example.com"
				address, err := url.Parse(listener.URL)
				if err != nil {
					t.Fatal(err)
				}
				client.Jar.SetCookies(address, []*http.Cookie{{Name: "imported_session", Value: existingSession, Path: "/", Secure: true}, {Name: "imported_refresh", Value: existingRefresh, Path: "/auth", Secure: true}})
				if request("GET", "/me", nil, 200)["user_id"] != existingUser {
					t.Fatal("existing application identity changed")
				}
				request("POST", "/auth/refresh", nil, 204)
				login("application-user", "user@example.com", "imported-client", true, 200)
				request("POST", "/auth/refresh", nil, 204)
				request("POST", "/auth/logout", nil, 204)
			}
			return http.ErrServerClosed
		})
		err := execute()
		restore()
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestConsoleDoesNotExposeMigrationCommand(t *testing.T) {
	for _, command := range newRootCommand().Commands() {
		if command.Name() == "tenant-import" {
			t.Fatal("deployment migration is exposed by the application")
		}
	}
}

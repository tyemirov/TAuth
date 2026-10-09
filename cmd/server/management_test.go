package main

import (
	"bytes"
	"context"
	"encoding/json"
	"google.golang.org/api/idtoken"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/controlplane"
	"github.com/tyemirov/tauth/internal/oauthserver"
	"github.com/tyemirov/tauth/internal/testconfig"
)

type consoleHTTP struct {
	t                    *testing.T
	client               *http.Client
	base, origin, tenant string
	gatewayURL           string
}

func (h consoleHTTP) request(method, path string, body any, status int, headers ...string) (map[string]any, http.Header) {
	h.t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		h.t.Fatal(err)
	}
	req, err := http.NewRequest(method, h.base+path, bytes.NewReader(data))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Origin", h.origin)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-TAuth-CSRF", "1")
	if h.tenant != "" {
		req.Header.Set("X-TAuth-Tenant", h.tenant)
	}
	for i := 0; i < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	response, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	if response.StatusCode != status {
		h.t.Fatalf("%s %s: %d want %d: %s", method, path, response.StatusCode, status, payload)
	}
	result := map[string]any{}
	if len(payload) > 0 && response.Header.Get("Content-Type") == "application/json; charset=utf-8" {
		if err := json.Unmarshal(payload, &result); err != nil {
			h.t.Fatal(err)
		}
	}
	if strings.HasPrefix(path, "/api/management/") && status != 204 {
		validateManagementResponse(h.t, method, path, status, result)
	}
	return result, response.Header
}
func (h consoleHTTP) login(subject, audience string) {
	h.t.Helper()
	nonce, _ := h.request("POST", "/auth/nonce", nil, 200)
	claims, _ := json.Marshal(map[string]any{"aud": audience, "iss": "https://accounts.google.com", "sub": subject, "email": subject + "@example.com", "email_verified": true, "nonce": nonce["nonce"], "name": subject})
	h.request("POST", "/auth/google", map[string]any{"google_id_token": string(claims), "nonce_token": nonce["nonce"]}, 200)
}
func TestConsoleTenantManagement(t *testing.T) {
	config := testconfig.Prepare(t, appconfig.ApplicationConfig{Server: appconfig.ServerSettings{EnableCORS: true, EnableTenantHeaderOverride: true}})
	store, err := controlplane.Open(context.Background(), config.Server.DatabaseURL, config.Server.TenantEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	console, err := store.Console(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	config.Server.CORSAllowedOrigins = []string{console.TenantOrigins[0]}
	restoreValidator := withGoogleValidatorBuilderStub(func(context.Context) (authkit.GoogleTokenValidator, error) { return consoleGoogleValidator{}, nil })
	defer restoreValidator()
	var tenantPath, tenantID string
	for attempt := 0; attempt < 2; attempt++ {
		restore := withServeHTTPStub(func(server *http.Server) error {
			listener := httptest.NewTLSServer(server.Handler)
			defer listener.Close()
			client := listener.Client()
			client.Jar, _ = cookiejar.New(nil)
			owner := consoleHTTP{t: t, client: client, base: listener.URL, origin: console.TenantOrigins[0]}
			owner.login("owner", "console-client")
			status := 201
			if attempt == 1 {
				status = 200
			}
			owner.request("PUT", controlplane.OwnerPath, nil, status)
			if attempt == 0 {
				body := owner.tenantInput("First app")
				body["environment"] = "development"
				tenant, header := owner.request("POST", "/api/management/tenants", body, 201, "Idempotency-Key", "first")
				tenantID = tenant["id"].(string)
				tenantPath = header.Get("Location")
				repeated, _ := owner.request("POST", "/api/management/tenants", body, 201, "Idempotency-Key", "first")
				if repeated["id"] != tenantID {
					t.Fatal("retry changed tenant")
				}
				owner.request("POST", "/api/management/tenants", owner.tenantInput("Different"), 409, "Idempotency-Key", "first")
				owner.request("POST", "/api/management/tenants", owner.tenantInput("Second app"), 201, "Idempotency-Key", "second")
				page, _ := owner.request("GET", "/api/management/tenants?limit=1", nil, 200)
				if len(page["items"].([]any)) != 1 || page["next_cursor"] == "" {
					t.Fatal("pagination missing")
				}
				owner.request("GET", "/api/management/tenants?limit=1&cursor="+page["next_cursor"].(string), nil, 200)
				_, header = owner.request("GET", tenantPath+"/configuration", nil, 200)
				draft := map[string]any{"google_web_client_id": "app-client", "frontend_origins": []string{"http://localhost:9191"}, "api_base_url": "http://localhost:9192", "local_development": true, "session_ttl": "15m", "refresh_ttl": "720h"}
				saved, updated := owner.request("PUT", tenantPath+"/configuration", draft, 200, "If-Match", header.Get("ETag"))
				owner.request("PUT", tenantPath+"/configuration", draft, 412, "If-Match", header.Get("ETag"))
				activation, _ := owner.request("POST", tenantPath+"/activations", map[string]any{"revision": saved["revision"]}, 201, "Idempotency-Key", "activate-first", "If-Match", updated.Get("ETag"))
				if activation["state"] != "succeeded" {
					t.Fatal("activation failed")
				}
				owner.request("POST", tenantPath+"/activations", map[string]any{"revision": saved["revision"]}, 201, "Idempotency-Key", "activate-first", "If-Match", updated.Get("ETag"))
				otherClient := listener.Client()
				otherClient.Jar, _ = cookiejar.New(nil)
				other := consoleHTTP{t: t, client: otherClient, base: listener.URL, origin: owner.origin}
				other.login("other-owner", "console-client")
				other.request("PUT", controlplane.OwnerPath, nil, 201)
				for _, path := range []string{tenantPath, tenantPath + "/configuration", tenantPath + "/activations", tenantPath + "/origin-proofs", tenantPath + "/audit-events"} {
					other.request("GET", path, nil, 404)
				}
				other.request("PUT", tenantPath+"/configuration", draft, 404, "If-Match", updated.Get("ETag"))
				other.request("POST", tenantPath+"/activations", map[string]any{"revision": saved["revision"]}, 404, "Idempotency-Key", "steal", "If-Match", updated.Get("ETag"))
			}
			app := consoleHTTP{t: t, client: client, base: listener.URL, origin: "http://localhost:9191", tenant: tenantID}
			unbound := app
			unbound.tenant = ""
			unbound.request("POST", "/auth/nonce", nil, 403)
			app.login("application-user", "app-client")
			app.request("POST", "/auth/refresh", nil, 204)
			if attempt == 1 {
				grants, err := oauthserver.NewDatabaseStore(context.Background(), config.Server.DatabaseURL)
				if err != nil {
					t.Fatal(err)
				}
				accounts, err := authkit.NewDatabaseUserStore(context.Background(), config.Server.DatabaseURL)
				if err != nil {
					t.Fatal(err)
				}
				oauthParent, err := accounts.UpsertProviderAccount(context.Background(), tenantID, authkit.AccountProviderIdentity{Provider: "google", Subject: "oauth-user", UserEmail: "oauth@example.com"})
				if err != nil {
					t.Fatal(err)
				}
				now := time.Now().UTC().Unix()
				consent, err := grants.SaveConsent(context.Background(), oauthserver.Consent{ConsentKey: oauthserver.ConsentKey{TenantID: tenantID, UserID: oauthParent.UserID, ClientID: "client", Resource: "https://resource.example", Scope: "read"}, CreatedAtUnix: now, ExpiresAtUnix: now + 3600})
				if err != nil {
					t.Fatal(err)
				}
				token, err := grants.IssueRefreshToken(context.Background(), oauthserver.RefreshGrant{ConsentID: consent.ID, TenantID: tenantID, UserID: oauthParent.UserID, ClientID: "client", Resource: "https://resource.example", Scope: "read", ExpiresAtUnix: now + 3600}, now)
				if err != nil {
					t.Fatal(err)
				}
				_, token, err = grants.RotateRefreshToken(context.Background(), token, "client", "https://resource.example", "read", now, func(context.Context, string, string) error { return nil })
				if err != nil {
					t.Fatal(err)
				}
				_, header := owner.request("GET", tenantPath, nil, 200)
				owner.request("PATCH", tenantPath, map[string]any{"state": "suspended"}, 200, "If-Match", header.Get("ETag"))
				app.request("POST", "/auth/refresh", nil, 403)
				_, _, err = grants.RotateRefreshToken(context.Background(), token, "client", "https://resource.example", "read", now, func(context.Context, string, string) error { return nil })
				if err == nil {
					t.Fatal("suspended OAuth grant remained usable")
				}
				saved, header := owner.request("GET", tenantPath+"/configuration", nil, 200)
				owner.request("POST", tenantPath+"/activations", map[string]any{"revision": saved["revision"]}, 201, "If-Match", header.Get("ETag"), "Idempotency-Key", "reactivate")
				app.request("POST", "/auth/refresh", nil, 401)
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
	}
}

func withManagementService(t *testing.T, validator authkit.GoogleTokenValidator, scenario func(consoleHTTP)) {
	t.Helper()
	config := testconfig.Prepare(t, appconfig.ApplicationConfig{Server: appconfig.ServerSettings{EnableCORS: true, EnableTenantHeaderOverride: true}})
	store, err := controlplane.Open(context.Background(), config.Server.DatabaseURL, config.Server.TenantEncryptionKey)
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
	config.Server.CORSAllowedOrigins = []string{console.TenantOrigins[0]}
	restoreValidator := withGoogleValidatorBuilderStub(func(context.Context) (authkit.GoogleTokenValidator, error) { return validator, nil })
	defer restoreValidator()
	restore := withServeHTTPStub(func(server *http.Server) error {
		listener := httptest.NewTLSServer(server.Handler)
		defer listener.Close()
		gatewayListener := httptest.NewServer(server.Handler)
		defer gatewayListener.Close()
		client := listener.Client()
		client.Jar, _ = cookiejar.New(nil)
		owner := consoleHTTP{t: t, client: client, base: listener.URL, origin: console.TenantOrigins[0], gatewayURL: gatewayListener.URL}
		owner.login("owner", "console-client")
		owner.request("PUT", controlplane.OwnerPath, nil, 201)
		scenario(owner)
		return http.ErrServerClosed
	})
	defer restore()
	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), appConfigContextKey, config))
	if err := runServer(command, nil); err != nil {
		t.Fatal(err)
	}
}

func TestConsoleAutomaticPublicationAndDomainConflicts(t *testing.T) {
	values := map[string]string{}
	original := lookupManagementTXT
	lookupManagementTXT = func(ctx context.Context, name string) ([]string, error) { return []string{values[name]}, nil }
	defer func() { lookupManagementTXT = original }()
	withManagementService(t, consoleGoogleValidator{}, func(owner consoleHTTP) {
		tenant, headers := owner.request("POST", controlplane.TenantsPath, owner.tenantInput("Production"), 201, "Idempotency-Key", "production")
		path := headers.Get("Location")
		tenantID := tenant["id"].(string)
		owner.request("DELETE", path, nil, 405)
		_, headers = owner.request("GET", path+"/configuration", nil, 200)
		input := map[string]any{"google_web_client_id": "production-client", "frontend_origins": []string{"https://customer.example"}, "api_base_url": "https://api.customer.example", "local_development": false, "session_ttl": "10m", "refresh_ttl": "720h"}
		owner.request("PUT", path+"/configuration", input, 428)
		owner.request("PUT", path+"/configuration", input, 403, "If-Match", headers.Get("ETag"), "X-TAuth-CSRF", "")
		saved, headers := owner.request("PUT", path+"/configuration", input, 200, "If-Match", headers.Get("ETag"))

		for _, hostname := range []string{"customer.example", "api.customer.example"} {
			proof, _ := owner.request("POST", path+"/origin-proofs", map[string]any{"revision": saved["revision"], "hostname": hostname}, 201, "Idempotency-Key", hostname)
			verify := path + "/origin-proofs/" + proof["id"].(string) + "/verifications"
			owner.request("POST", verify, map[string]any{}, 422, "Idempotency-Key", "missing")
			values[proof["name"].(string)] = proof["value"].(string)
			_, verificationHeaders := owner.request("POST", verify, map[string]any{}, 201, "Idempotency-Key", "verified")
			owner.request("GET", verificationHeaders.Get("Location"), nil, 200)
		}
		owner.request("POST", path+"/activations", map[string]any{"revision": saved["revision"]}, 201, "If-Match", headers.Get("ETag"), "Idempotency-Key", "verified")
		app := owner
		app.origin = "https://customer.example"
		app.tenant = tenantID
		app.login("user", "production-client")
		// Rejected edits leave both the stored configuration and active runtime unchanged.
		input["google_web_client_id"] = ""
		owner.request("PUT", path+"/configuration", input, 422, "If-Match", headers.Get("ETag"))
		app.login("still-active", "production-client")
		_, secondHeaders := owner.request("POST", controlplane.TenantsPath, owner.tenantInput("Conflict"), 201, "Idempotency-Key", "conflict")
		secondPath := secondHeaders.Get("Location")
		_, secondHeaders = owner.request("GET", secondPath+"/configuration", nil, 200)
		input["google_web_client_id"] = "other-client"
		owner.request("PUT", secondPath+"/configuration", input, 409, "If-Match", secondHeaders.Get("ETag"))
		input["frontend_origins"] = []string{owner.origin}
		input["api_base_url"] = owner.origin
		owner.request("PUT", secondPath+"/configuration", input, 409, "If-Match", secondHeaders.Get("ETag"))

	})
}

type blockingConsoleValidator struct{ entered, release chan struct{} }

func (v blockingConsoleValidator) Validate(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
	var claims map[string]any
	if err := json.Unmarshal([]byte(token), &claims); err != nil {
		return nil, err
	}
	if claims["sub"] == "in-flight" {
		close(v.entered)
		select {
		case <-v.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return (consoleGoogleValidator{}).Validate(ctx, token, audience)
}
func TestConsoleRequestRetainsRuntimeRevision(t *testing.T) {
	validator := blockingConsoleValidator{make(chan struct{}), make(chan struct{})}
	withManagementService(t, validator, func(owner consoleHTTP) {
		tenant, headers := owner.request("POST", controlplane.TenantsPath, owner.tenantInput("Concurrent"), 201, "Idempotency-Key", "new")
		path := headers.Get("Location")
		_, headers = owner.request("GET", path+"/configuration", nil, 200)
		input := map[string]any{"google_web_client_id": "old-client", "frontend_origins": []string{"http://localhost:8181"}, "api_base_url": "http://localhost:8182", "local_development": true, "session_ttl": "15m", "refresh_ttl": "720h"}
		saved, headers := owner.request("PUT", path+"/configuration", input, 200, "If-Match", headers.Get("ETag"))
		owner.request("POST", path+"/activations", map[string]any{"revision": saved["revision"]}, 201, "If-Match", headers.Get("ETag"), "Idempotency-Key", "old")
		app := owner
		app.origin = "http://localhost:8181"
		app.tenant = tenant["id"].(string)
		nonce, _ := app.request("POST", "/auth/nonce", nil, 200)
		claims, _ := json.Marshal(map[string]any{"aud": "old-client", "iss": "https://accounts.google.com", "sub": "in-flight", "email": "in-flight@example.com", "email_verified": true, "nonce": nonce["nonce"]})
		body, _ := json.Marshal(map[string]any{"google_id_token": string(claims), "nonce_token": nonce["nonce"]})
		req, err := http.NewRequest("POST", app.base+"/auth/google", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", app.origin)
		req.Header.Set("X-TAuth-Tenant", app.tenant)
		req.Header.Set("Content-Type", "application/json")
		done := make(chan int, 1)
		go func() {
			response, err := app.client.Do(req)
			if err != nil {
				done <- 0
				return
			}
			defer response.Body.Close()
			done <- response.StatusCode
		}()
		select {
		case <-validator.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("request did not enter provider")
		}
		input["google_web_client_id"] = "new-client"
		next, headers := owner.request("PUT", path+"/configuration", input, 200, "If-Match", headers.Get("ETag"))
		owner.request("POST", path+"/activations", map[string]any{"revision": next["revision"]}, 201, "If-Match", headers.Get("ETag"), "Idempotency-Key", "new")
		close(validator.release)
		if status := <-done; status != 200 {
			t.Fatalf("in-flight request lost revision: %d", status)
		}
		app.login("new-request", "new-client")
	})
}

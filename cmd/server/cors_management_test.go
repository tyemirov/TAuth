package main

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/spf13/cobra"
	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/controlplane"
	"github.com/tyemirov/tauth/internal/testconfig"
)

func TestConsoleCORSChangesRemainRestartSafe(t *testing.T) {
	for _, change := range []string{"origin", "suspension"} {
		t.Run(change, func(t *testing.T) {
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
			restoreValidator := withGoogleValidatorBuilderStub(func(context.Context) (authkit.GoogleTokenValidator, error) { return consoleGoogleValidator{}, nil })
			defer restoreValidator()
			const previousOrigin = "http://localhost:9691"
			const nextOrigin = "http://localhost:9693"
			var path, id string
			for stage := 0; stage < 5; stage++ {
				func() {
					restore := withServeHTTPStub(func(server *http.Server) error {
						listener := httptest.NewTLSServer(server.Handler)
						defer listener.Close()
						client := listener.Client()
						client.Jar, _ = cookiejar.New(nil)
						owner := consoleHTTP{t: t, client: client, base: listener.URL, origin: console.TenantOrigins[0]}
						owner.login("owner", "console-client")
						status := 200
						if stage == 0 {
							status = 201
						}
						owner.request("PUT", controlplane.OwnerPath, nil, status)
						if stage == 0 {
							tenant, headers := owner.request("POST", controlplane.TenantsPath, consoleTenantInput("CORS lifecycle"), 201, "Idempotency-Key", "cors-app")
							path = headers.Get("Location")
							id = tenant["id"].(string)
							_, headers = owner.request("GET", path+"/configuration", nil, 200)
							saved, headers := owner.request("PUT", path+"/configuration", map[string]any{"google_web_client_id": "app-client", "frontend_origins": []string{previousOrigin}, "api_base_url": "http://localhost:9692", "local_development": true, "session_ttl": "15m", "refresh_ttl": "720h"}, 200, "If-Match", headers.Get("ETag"))
							owner.request("POST", path+"/activations", map[string]any{"revision": saved["revision"]}, 201, "If-Match", headers.Get("ETag"), "Idempotency-Key", "initial")
						}
						if stage == 1 || stage == 3 {
							if change == "origin" {
								_, headers := owner.request("GET", path+"/configuration", nil, 200)
								status := 422
								if stage == 3 {
									status = 200
								}
								owner.request("PUT", path+"/configuration", map[string]any{"google_web_client_id": "app-client", "frontend_origins": []string{nextOrigin}, "api_base_url": "http://localhost:9694", "local_development": true, "session_ttl": "15m", "refresh_ttl": "720h"}, status, "If-Match", headers.Get("ETag"))
							} else {
								_, headers := owner.request("GET", path, nil, 200)
								status := 422
								if stage == 3 {
									status = 200
								}
								owner.request("PATCH", path, map[string]any{"state": "suspended"}, status, "If-Match", headers.Get("ETag"))
							}
						}
						application := owner
						application.origin = previousOrigin
						application.tenant = id
						if stage < 3 {
							application.login("app-user", "app-client")
							current, _ := owner.request("GET", path, nil, 200)
							if current["state"] != "active" || current["active_revision"] != float64(2) {
								t.Fatalf("rejected mutation changed runtime: %v", current)
							}
						} else {
							_, headers := application.request("POST", "/auth/nonce", nil, 403)
							if headers.Get("Access-Control-Allow-Origin") != "" {
								t.Fatal("removed origin retained CORS access")
							}
							if change == "origin" {
								application.origin = nextOrigin
								application.login("app-user", "app-client")
							}
						}
						return http.ErrServerClosed
					})
					defer restore()
					command := &cobra.Command{}
					command.SetContext(context.WithValue(context.Background(), appConfigContextKey, config))
					if err := runServer(command, nil); err != nil {
						t.Fatalf("restart stage %d: %v", stage, err)
					}
				}()
				if stage == 0 {
					config.Server.CORSAllowedOrigins = []string{console.TenantOrigins[0], previousOrigin}
				}
				if stage == 2 {
					config.Server.CORSAllowedOrigins = console.TenantOrigins
				}
			}
		})
	}
}

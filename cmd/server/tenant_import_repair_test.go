package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/spf13/cobra"
	"github.com/tyemirov/tauth/deployment/migrations"
	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/controlplane"
	"github.com/tyemirov/tauth/internal/tenants"
	"github.com/tyemirov/tauth/internal/testconfig"
)

func TestConsoleRepairedImportAuthenticatesIsolatedTenants(t *testing.T) {
	ctx := context.Background()
	config := testconfig.Prepare(t, appconfig.ApplicationConfig{Server: appconfig.ServerSettings{EnableCORS: true, EnableTenantHeaderOverride: true}})
	store, err := controlplane.OpenExisting(ctx, config.Server.DatabaseURL, config.Server.TenantEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := store.OwnerForSubject(ctx, appconfig.DefaultJWTIssuer, "fixture-owner")
	if err != nil {
		t.Fatal(err)
	}
	console, err := store.Console(ctx)
	if err != nil {
		t.Fatal(err)
	}
	config.Server.CORSAllowedOrigins = []string{console.TenantOrigins[0]}
	document := tenants.FileDocument{}
	for _, id := range []string{"first-local", "second-local"} {
		document.Tenants = append(document.Tenants, tenants.FileTenant{ID: id, TenantOrigins: []string{"https://shared.example.com"}, JWTSigningKey: "existing-key-" + id, GoogleWebClientID: id + "-client", SessionCookieName: id + "_session", RefreshCookieName: id + "_refresh", SessionTTL: "15m", RefreshTTL: "720h", RequireTenantHeader: true})
	}
	if _, err := migrations.Apply(ctx, config.Server.DatabaseURL, config.Server.TenantEncryptionKey, "original", owner.ID, document); err != nil {
		t.Fatal(err)
	}
	db, err := authkit.OpenControlDatabase(ctx, config.Server.DatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Table("tenants").Where("owner_account_id = ?", owner.ID).Updates(map[string]any{"state": "draft", "active_revision": nil}).Error; err != nil {
		t.Fatal(err)
	}
	for _, file := range document.Tenants {
		file.SessionCookieName = "app_session"
		file.RefreshCookieName = "app_refresh"
		file.RequireTenantHeader = false
		data, _ := json.Marshal(file)
		ref, _ := controlplane.NewSecretReference(file.ID, "configuration-1", "configuration")
		if err := store.SaveSecret(ctx, ref, data); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := migrations.RepairImport(ctx, config.Server.DatabaseURL, config.Server.TenantEncryptionKey, "original", "repair", owner.ID, document); err != nil {
		t.Fatal(err)
	}
	restoreValidator := withGoogleValidatorBuilderStub(func(context.Context) (authkit.GoogleTokenValidator, error) { return consoleGoogleValidator{}, nil })
	defer restoreValidator()
	restore := withServeHTTPStub(func(server *http.Server) error {
		listener := httptest.NewTLSServer(server.Handler)
		defer listener.Close()
		client := listener.Client()
		client.Jar, _ = cookiejar.New(nil)
		app := consoleHTTP{t: t, client: client, base: listener.URL, origin: "https://shared.example.com"}
		app.request("POST", "/auth/nonce", nil, 404)
		users := map[string]any{}
		for _, file := range document.Tenants {
			app.tenant = file.ID
			app.login(file.ID, file.GoogleWebClientID)
			me, _ := app.request("GET", "/me", nil, 200)
			users[file.ID] = me["user_id"]
			if users[file.ID] == nil {
				t.Fatal("profile missing")
			}
		}
		if users["first-local"] == users["second-local"] {
			t.Fatal("identities were shared")
		}
		for _, file := range document.Tenants {
			app.tenant = file.ID
			app.request("POST", "/auth/refresh", nil, 204)
			me, _ := app.request("GET", "/me", nil, 200)
			if me["user_id"] != users[file.ID] {
				t.Fatal("cookie isolation failed")
			}
		}
		app.tenant = "first-local"
		app.request("POST", "/auth/logout", nil, 204)
		app.request("GET", "/me", nil, 401)
		app.tenant = "second-local"
		app.request("GET", "/me", nil, 200)
		app.origin = "https://unregistered.example.com"
		app.request("POST", "/auth/nonce", nil, 403)
		return http.ErrServerClosed
	})
	defer restore()
	command := &cobra.Command{}
	command.SetContext(context.WithValue(ctx, appConfigContextKey, config))
	if err := runServer(command, nil); err != nil {
		t.Fatal(err)
	}
}

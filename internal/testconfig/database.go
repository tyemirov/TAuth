// Package testconfig provisions deterministic database-backed service fixtures.
package testconfig

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/controlplane"
	"github.com/tyemirov/tauth/internal/tenants"
	"gopkg.in/yaml.v3"
)

const ConsoleOrigin = "https://console.fixture.invalid"

// Prepare imports fixture tenants and returns canonical service configuration.
func Prepare(t testing.TB, source appconfig.ApplicationConfig) *appconfig.ApplicationConfig {
	t.Helper()
	if source.Server.DatabaseURL == "" {
		source.Server.DatabaseURL = "sqlite://" + filepath.Join(t.TempDir(), "tauth.db")
	}
	suffix := fmt.Sprintf("%x", sha256.Sum256([]byte(source.Server.DatabaseURL)))[:12]
	source.Server.TenantEncryptionKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	store, err := controlplane.Open(context.Background(), source.Server.DatabaseURL, source.Server.TenantEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	console := tenants.FileTenant{ID: controlplane.ConsoleTenantID, DisplayName: "Console fixture", TenantOrigins: []string{ConsoleOrigin}, GoogleWebClientID: "console-client", JWTSigningKey: "fixture-console-key", SessionCookieName: "tauth_console_session", RefreshCookieName: "tauth_console_refresh", SessionTTL: "15m", RefreshTTL: "720h", AccountManagement: tenants.FileAccountManagement{Enabled: true, EmailDelivery: tenants.FileEmailDelivery{ServerAddress: "localhost:50051", APIKey: "fixture", EmailVerificationURL: ConsoleOrigin + "/verify", PasswordResetURL: ConsoleOrigin + "/reset", PasswordLinkURL: ConsoleOrigin + "/link", ConnectionTimeoutSeconds: 1, OperationTimeoutSeconds: 1}}}
	console.TenantOrigins = []string{"https://console-" + suffix + ".fixture.invalid"}
	console.JWTSigningKey = "fixture-console-key-" + suffix
	if err := store.Bootstrap(context.Background(), console); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Provision(context.Background(), appconfig.DefaultJWTIssuer, "fixture-owner", controlplane.InitialOwnerEmail, "Fixture owner"); err != nil {
		t.Fatal(err)
	}
	if len(source.Tenants) > 0 {
		document, err := tenants.ResolveDocument(source.TenantDocument())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Import(context.Background(), "fixture-import", document); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	source.Tenants = nil
	return &source
}

// ServiceYAML imports source fixtures and emits service-only YAML.
func ServiceYAML(t testing.TB, payload string) string {
	t.Helper()
	source, err := appconfig.ParseImportSource([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	data, err := yaml.Marshal(Prepare(t, *source))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

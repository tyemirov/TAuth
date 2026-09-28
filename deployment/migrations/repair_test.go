package migrations_test

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/tyemirov/tauth/deployment/migrations"
	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/controlplane"
	"github.com/tyemirov/tauth/internal/tenants"
	"github.com/tyemirov/tauth/internal/testconfig"
)

func TestRepairInactiveImport(t *testing.T) {
	ctx := context.Background()
	config := testconfig.Prepare(t, appconfig.ApplicationConfig{})
	store, err := controlplane.OpenExisting(ctx, config.Server.DatabaseURL, config.Server.TenantEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	owner, err := store.OwnerForSubject(ctx, appconfig.DefaultJWTIssuer, "fixture-owner")
	if err != nil {
		t.Fatal(err)
	}
	document := tenants.FileDocument{}
	for _, id := range []string{"first-local", "second-local"} {
		document.Tenants = append(document.Tenants, tenants.FileTenant{ID: id, DisplayName: id, TenantOrigins: []string{"http://localhost:8000"}, JWTSigningKey: "existing-key-" + id, GoogleWebClientID: "client", SessionCookieName: id + "_session", RefreshCookieName: id + "_refresh", SessionTTL: "15m", RefreshTTL: "720h", RequireTenantHeader: true, AllowInsecureHTTP: true})
	}
	if _, err := migrations.Apply(ctx, config.Server.DatabaseURL, config.Server.TenantEncryptionKey, "original-import", owner.ID, document); err != nil {
		t.Fatal(err)
	}
	db, err := authkit.OpenControlDatabase(ctx, config.Server.DatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	// Reproduce the persisted result of the withdrawn inactive import path.
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
	write := func(name string, value any) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), name)
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := json.NewEncoder(f).Encode(value); err != nil {
			t.Fatal(err)
		}
		return p
	}
	service := write("service.json", map[string]any{"server": map[string]string{"database_url": config.Server.DatabaseURL, "tenant_encryption_key": config.Server.TenantEncryptionKey}})
	snapshot := write("corrected.json", document)
	run := func(path, ownerID string) error {
		cmd := migrations.NewCommand()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs([]string{"--config", service, "repair-import", "--snapshot", path, "--import-id", "original-import", "--repair-id", "repair-import", "--owner-id", ownerID})
		return cmd.Execute()
	}
	if err := run(snapshot, "wrong-owner"); err == nil {
		t.Fatal("wrong owner accepted")
	}
	invalid := document
	invalid.Tenants = append([]tenants.FileTenant(nil), document.Tenants...)
	invalid.Tenants[1].SessionCookieName = invalid.Tenants[0].SessionCookieName
	if err := run(write("invalid.json", invalid), owner.ID); err == nil {
		t.Fatal("conflicting repair accepted")
	}
	before, err := store.ApplicationTenants(ctx)
	if err != nil || len(before.Tenants) != 0 {
		t.Fatal("failed repair changed active tenants", err)
	}
	if err := db.Table("tenants").Where("id = ?", "second-local").Update("state", "suspended").Error; err != nil {
		t.Fatal(err)
	}
	if err := run(snapshot, owner.ID); err == nil {
		t.Fatal("edited tenant accepted")
	}
	var failedRevisions int64
	if err := db.Table("tenant_configurations").Where("revision = ?", 2).Count(&failedRevisions).Error; err != nil {
		t.Fatal(err)
	}
	if failedRevisions != 0 {
		t.Fatal("failed repair left partial revisions")
	}
	if err := db.Table("tenants").Where("id = ?", "second-local").Update("state", "draft").Error; err != nil {
		t.Fatal(err)
	}
	altered := document
	altered.Tenants = append([]tenants.FileTenant(nil), document.Tenants...)
	altered.Tenants[0].JWTSigningKey = "replacement-key"
	if err := run(write("altered-key.json", altered), owner.ID); err == nil {
		t.Fatal("unrelated key replacement accepted")
	}
	inactive := migrations.NewCommand()
	inactive.SetOut(io.Discard)
	inactive.SetErr(io.Discard)
	inactive.SetArgs([]string{"--config", service, "--snapshot", snapshot, "--state", "draft", "--owner-id", owner.ID, "--import-id", "another-import"})
	if err := inactive.Execute(); err == nil {
		t.Fatal("inactive import output remains available")
	}
	for i := 0; i < 2; i++ {
		if err := run(snapshot, owner.ID); err != nil {
			t.Fatal(err)
		}
	}
	active, err := store.ApplicationTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(active.Tenants) != 2 {
		t.Fatal("repair did not activate both tenants")
	}
	for _, file := range active.Tenants {
		if !file.RequireTenantHeader || file.JWTSigningKey != "existing-key-"+file.ID {
			t.Fatal("repair lost configuration")
		}
	}
	var count int64
	if err := db.Table("tenant_configurations").Where("revision = ?", 2).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatal("repair retry created duplicate revisions")
	}
	changed := document
	changed.Tenants = append([]tenants.FileTenant(nil), document.Tenants...)
	changed.Tenants[0].SessionTTL = "20m"
	if err := run(write("changed.json", changed), owner.ID); err == nil {
		t.Fatal("changed retry accepted")
	}
}

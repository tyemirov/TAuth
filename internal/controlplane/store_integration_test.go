package controlplane_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/controlplane"
	"github.com/tyemirov/tauth/internal/tenants"
	"github.com/tyemirov/tauth/internal/testconfig"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestImportRollbackPreservesExistingData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "migration.db")
	config := testconfig.Prepare(t, appconfig.ApplicationConfig{Server: appconfig.ServerSettings{DatabaseURL: "sqlite://" + path}})
	store, err := controlplane.OpenExisting(context.Background(), config.Server.DatabaseURL, config.Server.TenantEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	owner, err := store.OwnerForSubject(context.Background(), appconfig.DefaultJWTIssuer, "fixture-owner")
	if err != nil {
		t.Fatal(err)
	}
	db, err := gorm.Open(sqlite.Open(path+"?_pragma=foreign_keys(1)"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := db.Exec("INSERT INTO tenants(id,owner_account_id,name,state) VALUES(?,?,'Existing','draft')", "zz-conflict", owner.ID).Error; err != nil {
		t.Fatal(err)
	}
	tenant := func(id string) tenants.FileTenant {
		return tenants.FileTenant{ID: id, DisplayName: id, TenantOrigins: []string{"https://" + id + ".example.com"}, GoogleWebClientID: id + "-google", JWTSigningKey: id + "-secret", SessionCookieName: id + "-session", RefreshCookieName: id + "-refresh", SessionTTL: "15m", RefreshTTL: "720h"}
	}
	document := tenants.FileDocument{Tenants: []tenants.FileTenant{tenant("first-import"), tenant("zz-conflict")}}
	if _, err := store.Import(context.Background(), "rollback", document); err == nil {
		t.Fatal("conflicting import accepted")
	}
	var count int64
	if err := db.Raw("SELECT COUNT(*) FROM tenants WHERE id = ?", "first-import").Scan(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("failed import left a partial tenant")
	}
	if err := db.Raw("SELECT COUNT(*) FROM tenant_imports WHERE id = ?", "rollback").Scan(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("failed import left a receipt")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Import(cancelled, "cancelled", tenants.FileDocument{Tenants: []tenants.FileTenant{tenant("first-import")}}); err == nil {
		t.Fatal("cancelled import succeeded")
	}
}

func TestOwnershipDatabaseConstraints(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owners.db")
	store, err := controlplane.Open(context.Background(), "sqlite://"+path, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	db, err := gorm.Open(sqlite.Open(path+"?_pragma=foreign_keys(1)"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	accept := func(query string) {
		t.Helper()
		if err := db.Exec(query).Error; err != nil {
			t.Fatal(err)
		}
	}
	reject := func(query string) {
		t.Helper()
		if err := db.Exec(query).Error; err == nil {
			t.Fatalf("database accepted invalid relationship: %s", query)
		}
	}
	accept(`INSERT INTO owner_accounts(id,display_name,contact_email,state) VALUES('owner','Owner','owner@example.com','active')`)
	accept(`INSERT INTO tenants(id,owner_account_id,name,state) VALUES('first','owner','First','draft')`)
	accept(`INSERT INTO tenants(id,owner_account_id,name,state) VALUES('second','owner','Second','draft')`)
	ref, err := controlplane.NewSecretReference("first", "session-key", "session")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSecret(context.Background(), ref, []byte("private-signing-key")); err != nil {
		t.Fatal(err)
	}
	secret, err := store.LoadSecret(context.Background(), ref)
	if err != nil || string(secret) != "private-signing-key" {
		t.Fatalf("secret round trip failed: %v", err)
	}
	var ciphertext []byte
	if err := db.Raw("SELECT encrypted_value FROM tenant_secrets WHERE id = ?", "session-key").Row().Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("private-signing-key")) {
		t.Fatal("plaintext secret in database")
	}
	accept(`INSERT INTO tenant_secrets(id,tenant_id,purpose,encrypted_value,encryption_key_id) SELECT id,'second',purpose,encrypted_value,encryption_key_id FROM tenant_secrets WHERE id='session-key'`)
	otherRef, err := controlplane.NewSecretReference("second", "session-key", "session")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSecret(context.Background(), otherRef); err == nil {
		t.Fatal("ciphertext accepted for a different tenant")
	}
	reject(`INSERT INTO tenants(id,name,state) VALUES('orphan','Orphan','draft')`)
	reject(`INSERT INTO tenants(id,owner_account_id,name,state) VALUES('missing','absent','Missing','draft')`)
	reject(`DELETE FROM owner_accounts WHERE id='owner'`)
	accept(`INSERT INTO tenant_configurations(tenant_id,revision,configuration) VALUES('first',1,'{}')`)
	accept(`INSERT INTO tenant_configurations(tenant_id,revision,configuration) VALUES('second',1,'{}')`)
	accept(`INSERT INTO tenant_secrets(id,tenant_id,purpose,encrypted_value,encryption_key_id) VALUES('key','first','session','ciphertext','service')`)
	accept(`INSERT INTO tenant_providers(tenant_id,revision,provider_type,public_settings,secret_id) VALUES('first',1,'google','{}','key')`)
	reject(`INSERT INTO tenant_providers(tenant_id,revision,provider_type,public_settings,secret_id) VALUES('second',1,'google','{}','key')`)
	reject(`INSERT INTO tenant_origins(tenant_id,revision,origin,provenance) VALUES('first',2,'https://app.example.com','import')`)
}

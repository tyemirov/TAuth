package migrations_test

import (
	"context"
	"github.com/tyemirov/tauth/deployment/migrations"
	"github.com/tyemirov/tauth/internal/authkit"
	"path/filepath"
	"testing"
)

func TestAppHierarchyMigrationPreservesTenantData(t *testing.T) {
	ctx := context.Background()
	url := "sqlite://" + filepath.Join(t.TempDir(), "hierarchy.db")
	db, err := authkit.OpenControlDatabase(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := db.DB()
	defer raw.Close()
	statements := []string{
		`CREATE TABLE owner_accounts(id TEXT PRIMARY KEY)`,
		`INSERT INTO owner_accounts VALUES('owner')`,
		`CREATE TABLE tenants(id TEXT PRIMARY KEY,owner_account_id TEXT NOT NULL REFERENCES owner_accounts(id),name TEXT NOT NULL,active_revision BIGINT,state TEXT NOT NULL)`,
		`INSERT INTO tenants VALUES('kamu','owner','Kamu',2,'active'),('kamu-local','owner','Kamu Local',2,'active')`,
		`CREATE TABLE provisioning_credentials(id TEXT PRIMARY KEY,owner_account_id TEXT NOT NULL REFERENCES owner_accounts(id),tenant_ids TEXT NOT NULL,digest TEXT NOT NULL,revoked_at TIMESTAMP)`,
		`INSERT INTO provisioning_credentials VALUES('gateway','owner','["kamu"]','private-hash',NULL)`,
		`CREATE TABLE sessions(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL REFERENCES tenants(id),secret TEXT NOT NULL)`,
		`INSERT INTO sessions VALUES('session','kamu','unchanged-session')`,
	}
	for _, statement := range statements {
		if err := db.Exec(statement).Error; err != nil {
			t.Fatal(err)
		}
	}
	mapping := migrations.AppHierarchy{Apps: []migrations.AppGroup{{ID: "kamu-app", Name: "Kamu", TenantIDs: []string{"kamu", "kamu-local"}}}, Credentials: map[string]string{"gateway": "kamu-app"}}
	incomplete := migrations.AppHierarchy{Apps: []migrations.AppGroup{{ID: "kamu-app", Name: "Kamu", TenantIDs: []string{"kamu"}}}, Credentials: mapping.Credentials}
	if err := migrations.ApplyAppHierarchy(ctx, url, incomplete); err == nil {
		t.Fatal("incomplete grouping accepted")
	}
	if db.Migrator().HasColumn("tenants", "app_id") {
		t.Fatal("failed migration changed schema")
	}
	for i := 0; i < 2; i++ {
		if err := migrations.ApplyAppHierarchy(ctx, url, mapping); err != nil {
			t.Fatal(err)
		}
	}
	var count int64
	db.Table("tenants").Where("app_id = ? AND active_revision = 2 AND state = ?", "kamu-app", "active").Count(&count)
	if count != 2 {
		t.Fatal("tenant data changed")
	}
	var secret string
	db.Table("sessions").Select("secret").Scan(&secret)
	if secret != "unchanged-session" {
		t.Fatal("session data changed")
	}
	if err := db.Exec(`UPDATE tenants SET app_id='absent' WHERE id='kamu'`).Error; err == nil {
		t.Fatal("missing App accepted")
	}
	if err := db.Exec(`UPDATE tenants SET app_id=NULL WHERE id='kamu'`).Error; err == nil {
		t.Fatal("empty App accepted")
	}
	if err := db.Exec(`DELETE FROM tenants WHERE id='kamu'`).Error; err == nil {
		t.Fatal("session foreign key lost")
	}
	mapping.Apps[0].Name = "Different"
	if err := migrations.ApplyAppHierarchy(ctx, url, mapping); err == nil {
		t.Fatal("changed migration accepted")
	}
}

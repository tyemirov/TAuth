package migrations_test

import (
	"context"
	"encoding/json"
	"github.com/tyemirov/tauth/deployment/migrations"
	"github.com/tyemirov/tauth/internal/authkit"
	"path/filepath"
	"testing"
)

func TestAppHierarchyMigrationWithoutTenants(t *testing.T) {
	for _, test := range []struct {
		name, owner, credentialApp string
		valid                      bool
	}{
		{"active and revoked credentials", "owner", "active-app", true},
		{"missing owner", "", "active-app", false},
		{"unknown owner", "absent", "active-app", false},
		{"cross-owner credential", "owner", "revoked-app", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			url := "sqlite://" + filepath.Join(t.TempDir(), "empty-apps.db")
			db, err := authkit.OpenControlDatabase(ctx, url)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := db.DB()
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			for _, statement := range []string{
				`CREATE TABLE owner_accounts(id TEXT PRIMARY KEY)`,
				`INSERT INTO owner_accounts VALUES('owner'),('other')`,
				`CREATE TABLE tenants(id TEXT PRIMARY KEY,owner_account_id TEXT NOT NULL REFERENCES owner_accounts(id))`,
				`CREATE TABLE provisioning_credentials(id TEXT PRIMARY KEY,owner_account_id TEXT NOT NULL REFERENCES owner_accounts(id),tenant_ids TEXT NOT NULL,digest TEXT NOT NULL,revoked_at TIMESTAMP)`,
				`INSERT INTO provisioning_credentials VALUES('active','owner','[]','active-hash',NULL),('revoked','other','[]','revoked-hash','2026-09-01 00:00:00')`,
			} {
				if err := db.Exec(statement).Error; err != nil {
					t.Fatal(err)
				}
			}
			// Decode the deployment input through its public JSON contract.
			encoded, err := json.Marshal(map[string]any{
				"apps": []map[string]any{
					{"id": "active-app", "name": "Active App", "owner_account_id": test.owner, "tenant_ids": []string{}},
					{"id": "revoked-app", "name": "Revoked App", "owner_account_id": "other", "tenant_ids": []string{}},
				},
				"credentials": map[string]string{"active": test.credentialApp, "revoked": "revoked-app"},
			})
			if err != nil {
				t.Fatal(err)
			}
			var mapping migrations.AppHierarchy
			if err := json.Unmarshal(encoded, &mapping); err != nil {
				t.Fatal(err)
			}
			err = migrations.ApplyAppHierarchy(ctx, url, mapping)
			if !test.valid {
				if err == nil {
					t.Fatal("invalid owner assignment accepted")
				}
				if db.Migrator().HasTable("apps") || db.Migrator().HasColumn("provisioning_credentials", "app_id") {
					t.Fatal("rejected mapping changed schema")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := migrations.ApplyAppHierarchy(ctx, url, mapping); err != nil {
				t.Fatalf("repeat: %v", err)
			}
			var count int64
			if err := db.Table("tenants").Count(&count).Error; err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatal("migration fabricated tenants")
			}
			for _, condition := range []string{
				`id='active' AND app_id='active-app' AND owner_account_id='owner' AND tenant_ids='[]' AND digest='active-hash' AND revoked_at IS NULL`,
				`id='revoked' AND app_id='revoked-app' AND owner_account_id='other' AND tenant_ids='[]' AND digest='revoked-hash' AND revoked_at='2026-09-01 00:00:00'`,
			} {
				if err := db.Table("provisioning_credentials").Where(condition).Count(&count).Error; err != nil {
					t.Fatal(err)
				}
				if count != 1 {
					t.Fatal("credential data changed")
				}
			}
			if err := db.Exec(`UPDATE provisioning_credentials SET app_id='revoked-app' WHERE id='active'`).Error; err == nil {
				t.Fatal("cross-owner App accepted")
			}
		})
	}
}

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
		`INSERT INTO owner_accounts VALUES('owner'),('other')`,
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
	wrongOwner := migrations.AppHierarchy{Apps: []migrations.AppGroup{{ID: "kamu-app", Name: "Kamu", OwnerAccountID: "other", TenantIDs: []string{"kamu", "kamu-local"}}}, Credentials: mapping.Credentials}
	if err := migrations.ApplyAppHierarchy(ctx, url, wrongOwner); err == nil {
		t.Fatal("explicit owner mismatch accepted")
	}
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

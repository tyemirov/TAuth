package migrations

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tyemirov/tauth/internal/authkit"
	"gorm.io/gorm"
)

// AppGroup describes an App and its existing tenant assignments.
type AppGroup struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	OwnerAccountID string   `json:"owner_account_id,omitempty"`
	TenantIDs      []string `json:"tenant_ids"`
}

// AppHierarchy is a deployment input. The service never reads this mapping.
type AppHierarchy struct {
	Apps        []AppGroup        `json:"apps"`
	Credentials map[string]string `json:"credentials"`
}
type hierarchyReceipt struct {
	ID     string `gorm:"primaryKey"`
	Digest string
}

func (hierarchyReceipt) TableName() string { return "app_hierarchy_migrations" }

// ApplyAppHierarchy assigns all existing tenants and credentials in one transaction.
// Stop the service before this bounded schema migration.
func ApplyAppHierarchy(ctx context.Context, databaseURL string, mapping AppHierarchy) error {
	encoded, err := json.Marshal(mapping)
	if err != nil {
		return err
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(encoded))
	db, err := authkit.OpenControlDatabase(ctx, databaseURL)
	if err != nil {
		return err
	}
	raw, err := db.DB()
	if err != nil {
		return err
	}
	defer raw.Close()
	// SQLite table replacement requires foreign keys disabled outside the transaction.
	// This private connection is closed after the migration; all references are checked before commit.
	raw.SetMaxOpenConns(1)
	if db.Dialector.Name() == "sqlite" {
		if err := db.Exec("PRAGMA foreign_keys = OFF").Error; err != nil {
			return err
		}
	}
	err = db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.AutoMigrate(&hierarchyReceipt{}); err != nil {
			return err
		}
		var receipt hierarchyReceipt
		err := tx.First(&receipt, "id = ?", "account-app-tenant").Error
		if err == nil {
			if receipt.Digest != digest {
				return errors.New("migration.hierarchy_receipt_conflict")
			}
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if tx.Migrator().HasColumn("tenants", "app_id") {
			return errors.New("migration.hierarchy_already_present")
		}
		type existing struct {
			ID, OwnerAccountID, TenantIDs string
			RevokedAt                     *time.Time
		}
		var tenants, credentials []existing
		if err := tx.Table("tenants").Find(&tenants).Error; err != nil {
			return err
		}
		if err := tx.Table("provisioning_credentials").Find(&credentials).Error; err != nil {
			return err
		}
		owners := map[string]string{}
		for _, row := range tenants {
			owners[row.ID] = row.OwnerAccountID
		}
		assignments, appOwners := map[string]string{}, map[string]string{}
		var ownerIDs []string
		if err := tx.Table("owner_accounts").Pluck("id", &ownerIDs).Error; err != nil {
			return err
		}
		accounts := make(map[string]bool, len(ownerIDs))
		for _, id := range ownerIDs {
			accounts[id] = true
		}
		for _, app := range mapping.Apps {
			if strings.TrimSpace(app.ID) == "" || len(app.ID) > 128 || strings.TrimSpace(app.Name) == "" || len(app.Name) > 120 || appOwners[app.ID] != "" {
				return errors.New("migration.app_group_invalid")
			}
			owner := app.OwnerAccountID
			if len(app.TenantIDs) > 0 {
				tenantOwner := owners[app.TenantIDs[0]]
				if tenantOwner == "" {
					return errors.New("migration.tenant_missing")
				}
				if owner == "" {
					owner = tenantOwner
				}
			}
			if !accounts[owner] {
				return errors.New("migration.app_owner_invalid")
			}
			for _, id := range app.TenantIDs {
				if owners[id] != owner || assignments[id] != "" {
					return errors.New("migration.app_membership_invalid")
				}
				assignments[id] = app.ID
			}
			appOwners[app.ID] = owner
		}
		if len(assignments) != len(tenants) || len(mapping.Credentials) != len(credentials) {
			return errors.New("migration.hierarchy_incomplete")
		}
		for _, credential := range credentials {
			appID := mapping.Credentials[credential.ID]
			if appOwners[appID] != credential.OwnerAccountID {
				return errors.New("migration.credential_app_invalid")
			}
			if credential.RevokedAt != nil {
				continue
			}
			var ids []string
			if err := json.Unmarshal([]byte(credential.TenantIDs), &ids); err != nil {
				return err
			}
			for _, id := range ids {
				if assignments[id] != appID {
					return errors.New("migration.credential_spans_apps")
				}
			}
		}
		if err := tx.Exec(`CREATE TABLE apps (id TEXT PRIMARY KEY, owner_account_id TEXT NOT NULL REFERENCES owner_accounts(id) ON DELETE RESTRICT, name TEXT NOT NULL, version BIGINT NOT NULL DEFAULT 1, UNIQUE(id,owner_account_id))`).Error; err != nil {
			return err
		}
		for _, app := range mapping.Apps {
			if err := tx.Table("apps").Create(map[string]any{"id": app.ID, "name": app.Name, "owner_account_id": appOwners[app.ID], "version": 1}).Error; err != nil {
				return err
			}
		}
		for _, table := range []string{"tenants", "provisioning_credentials"} {
			bindings := assignments
			if table == "provisioning_credentials" {
				bindings = mapping.Credentials
			}
			if err := addAppMembership(tx, table, bindings); err != nil {
				return err
			}
		}
		// Old POST receipts contain the previous response shape and cannot be replayed after cutover.
		if tx.Migrator().HasTable("management_receipts") {
			if err := tx.Exec("DELETE FROM management_receipts").Error; err != nil {
				return err
			}
		}
		if tx.Dialector.Name() == "sqlite" {
			var failures []map[string]any
			if err := tx.Raw("PRAGMA foreign_key_check").Scan(&failures).Error; err != nil {
				return err
			}
			if len(failures) > 0 {
				return errors.New("migration.hierarchy_foreign_key_failed")
			}
		}
		return tx.Create(&hierarchyReceipt{ID: "account-app-tenant", Digest: digest}).Error
	})
	if err != nil {
		return fmt.Errorf("migration.app_hierarchy: %w", err)
	}
	return nil
}

func addAppMembership(tx *gorm.DB, table string, bindings map[string]string) error {
	var original string
	var dependent []struct{ SQL string }
	var columns []string
	if tx.Dialector.Name() == "sqlite" {
		if err := tx.Raw("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&original).Error; err != nil {
			return err
		}
		if err := tx.Raw("SELECT sql FROM sqlite_master WHERE tbl_name=? AND type IN ('index','trigger') AND sql IS NOT NULL", table).Scan(&dependent).Error; err != nil {
			return err
		}
		types, err := tx.Migrator().ColumnTypes(table)
		if err != nil {
			return err
		}
		for _, column := range types {
			columns = append(columns, `"`+column.Name()+`"`)
		}
	}
	if err := tx.Exec("ALTER TABLE " + table + " ADD COLUMN app_id TEXT").Error; err != nil {
		return err
	}
	for id, appID := range bindings {
		if err := tx.Table(table).Where("id = ?", id).Update("app_id", appID).Error; err != nil {
			return err
		}
	}
	constraint := "FOREIGN KEY(app_id,owner_account_id) REFERENCES apps(id,owner_account_id) ON DELETE RESTRICT"
	if tx.Dialector.Name() == "postgres" {
		if err := tx.Exec("ALTER TABLE " + table + " ALTER COLUMN app_id SET NOT NULL").Error; err != nil {
			return err
		}
		return tx.Exec("ALTER TABLE " + table + " ADD " + constraint).Error
	}
	start, end := strings.Index(original, "("), strings.LastIndex(original, ")")
	if start < 0 || end < start {
		return errors.New("migration.table_definition_invalid")
	}
	temporary := table + "_app_migration"
	definition := "CREATE TABLE " + temporary + " (app_id TEXT NOT NULL," + original[start+1:end] + "," + constraint + ")"
	if err := tx.Exec(definition).Error; err != nil {
		return err
	}
	fields := strings.Join(append(columns, "app_id"), ",")
	if err := tx.Exec("INSERT INTO " + temporary + " (" + fields + ") SELECT " + fields + " FROM " + table).Error; err != nil {
		return err
	}
	if err := tx.Exec("DROP TABLE " + table).Error; err != nil {
		return err
	}
	if err := tx.Exec("ALTER TABLE " + temporary + " RENAME TO " + table).Error; err != nil {
		return err
	}
	for _, item := range dependent {
		if err := tx.Exec(item.SQL).Error; err != nil {
			return err
		}
	}
	return nil
}

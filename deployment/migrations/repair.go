package migrations

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/controlplane"
	"github.com/tyemirov/tauth/internal/tenants"
	"gorm.io/gorm"
)

// RepairReceipt records one bounded correction of an inactive import.
type RepairReceipt struct {
	ID             string    `json:"id" gorm:"primaryKey"`
	ImportID       string    `json:"import_id"`
	OwnerAccountID string    `json:"owner_account_id"`
	SourceDigest   string    `json:"source_digest"`
	TenantIDs      string    `json:"tenant_ids"`
	CompletedAt    time.Time `json:"completed_at"`
}

func (RepairReceipt) TableName() string { return "tenant_import_repairs" }

// RepairImport applies an explicit cookie and tenant-header correction to an inactive import.
// All database writers must remain stopped for this deployment operation.
func RepairImport(ctx context.Context, databaseURL, encodedKey, importID, repairID, ownerID string, document tenants.FileDocument) (RepairReceipt, error) {
	var receipt RepairReceipt
	if strings.TrimSpace(importID) == "" || strings.TrimSpace(repairID) == "" || strings.TrimSpace(ownerID) == "" || len(repairID) > 128 {
		return receipt, errors.New("migration.identifier_required")
	}
	if len(document.Tenants) == 0 {
		return receipt, errors.New("migration.source_empty")
	}
	if _, err := tenants.LoadResolvedConfig(document); err != nil {
		return receipt, err
	}
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil || len(key) != 32 {
		return receipt, errors.New("migration.encryption_key_invalid")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return receipt, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return receipt, err
	}
	keyID := fmt.Sprintf("%x", sha256.Sum256(key))
	sort.Slice(document.Tenants, func(i, j int) bool { return document.Tenants[i].ID < document.Tenants[j].ID })
	encoded, err := json.Marshal(document)
	if err != nil {
		return receipt, err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(encoded)
	digest := fmt.Sprintf("%x", mac.Sum(nil))
	store, err := controlplane.OpenExisting(ctx, databaseURL, encodedKey)
	if err != nil {
		return receipt, err
	}
	defer store.Close()
	db, err := authkit.OpenControlDatabase(ctx, databaseURL)
	if err != nil {
		return receipt, err
	}
	raw, err := db.DB()
	if err != nil {
		return receipt, err
	}
	defer raw.Close()
	err = db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.AutoMigrate(&RepairReceipt{}); err != nil {
			return err
		}
		err := tx.First(&receipt, "id = ?", repairID).Error
		if err == nil {
			if receipt.ImportID != importID || receipt.OwnerAccountID != ownerID || receipt.SourceDigest != digest {
				return errors.New("migration.repair_receipt_conflict")
			}
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		var imported Receipt
		if err := tx.First(&imported, "id = ? AND owner_account_id = ?", importID, ownerID).Error; err != nil {
			return fmt.Errorf("migration.import_required: %w", err)
		}
		var owner controlplane.Owner
		if err := tx.First(&owner, "id = ? AND state = ?", ownerID, "active").Error; err != nil {
			return fmt.Errorf("migration.owner_required: %w", err)
		}
		ids := make([]string, 0, len(document.Tenants))
		for _, file := range document.Tenants {
			ids = append(ids, file.ID)
		}
		var importedIDs []string
		if err := json.Unmarshal([]byte(imported.TenantIDs), &importedIDs); err != nil {
			return err
		}
		sort.Strings(importedIDs)
		if !reflect.DeepEqual(ids, importedIDs) {
			return errors.New("migration.import_membership_changed")
		}
		existing, err := store.ApplicationTenants(ctx)
		if err != nil {
			return err
		}
		console, err := store.Console(ctx)
		if err != nil {
			return err
		}
		combined := tenants.FileDocument{Tenants: append(append(existing.Tenants, console), document.Tenants...)}
		runtime, err := tenants.LoadResolvedConfig(combined)
		if err != nil {
			return err
		}
		for _, tenant := range runtime.Tenants() {
			for _, origin := range tenant.Origins() {
				if runtime.OriginIsAmbiguous(origin) && !tenant.RequireTenantHeader() {
					return fmt.Errorf("migration.shared_origin_requires_tenant_header: %s", tenant.ID())
				}
			}
		}
		for _, file := range document.Tenants {
			var row struct {
				ID, State, OwnerAccountID string
				ActiveRevision            *int64
				Version                   int64
			}
			if err := tx.Table("tenants").Where("id = ?", file.ID).Take(&row).Error; err != nil {
				return err
			}
			var latest int64
			if err := tx.Table("tenant_configurations").Where("tenant_id = ?", file.ID).Select("MAX(revision)").Scan(&latest).Error; err != nil {
				return err
			}
			if row.State != "draft" || row.ActiveRevision != nil || row.OwnerAccountID != ownerID || latest != 1 {
				return fmt.Errorf("migration.import_was_edited: %s", file.ID)
			}
			ref, err := controlplane.NewSecretReference(file.ID, "configuration-1", "configuration")
			if err != nil {
				return err
			}
			originalBytes, err := store.LoadSecret(ctx, ref)
			if err != nil {
				return err
			}
			var original tenants.FileTenant
			if err := json.Unmarshal(originalBytes, &original); err != nil {
				return err
			}
			if original.RequireTenantHeader && !file.RequireTenantHeader {
				return fmt.Errorf("migration.header_policy_weakened: %s", file.ID)
			}
			original.SessionCookieName = file.SessionCookieName
			original.RefreshCookieName = file.RefreshCookieName
			original.RequireTenantHeader = file.RequireTenantHeader
			if !reflect.DeepEqual(original, file) {
				return fmt.Errorf("migration.unrelated_configuration_change: %s", file.ID)
			}
			data, err := json.Marshal(file)
			if err != nil {
				return err
			}
			binding, _ := json.Marshal([]string{file.ID, "configuration-2", "configuration", keyID})
			nonce := make([]byte, aead.NonceSize())
			if _, err := rand.Read(nonce); err != nil {
				return err
			}
			if err := tx.Table("tenant_secrets").Create(map[string]any{"id": "configuration-2", "tenant_id": file.ID, "purpose": "configuration", "encrypted_value": aead.Seal(nonce, nonce, data, binding), "encryption_key_id": keyID}).Error; err != nil {
				return err
			}
			local := false
			for _, origin := range file.TenantOrigins {
				address, _ := url.Parse(origin)
				host := address.Hostname()
				if host == "localhost" || host == "127.0.0.1" || host == "::1" {
					local = true
				}
			}

			if err := tx.Table("tenant_configurations").Create(map[string]any{"tenant_id": file.ID, "revision": 2, "configuration": `{"secret_id":"configuration-2"}`, "local_development": local}).Error; err != nil {
				return err
			}
			for _, origin := range file.TenantOrigins {
				if err := tx.Table("tenant_origins").Create(map[string]any{"tenant_id": file.ID, "revision": 2, "origin": origin, "provenance": "operator-approved-import"}).Error; err != nil {
					return err
				}
			}
			if err := tx.Table("tenants").Where("id = ?", file.ID).Updates(map[string]any{"state": "active", "active_revision": 2, "version": row.Version + 1}).Error; err != nil {
				return err
			}
		}
		idsJSON, _ := json.Marshal(ids)
		receipt = RepairReceipt{ID: repairID, ImportID: importID, OwnerAccountID: ownerID, SourceDigest: digest, TenantIDs: string(idsJSON), CompletedAt: time.Now().UTC()}
		return tx.Create(&receipt).Error
	})
	if err != nil {
		return RepairReceipt{}, fmt.Errorf("migration.repair: %w", err)
	}
	return receipt, nil
}

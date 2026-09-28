// Package migrations contains deployment-only data changes. The service does not import it.
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
	"sort"
	"strings"
	"time"

	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/controlplane"
	"github.com/tyemirov/tauth/internal/tenants"
	"gorm.io/gorm"
)

// Receipt identifies a completed deployment transaction without recording secrets.
type Receipt struct {
	ID             string    `json:"id" gorm:"primaryKey"`
	SourceDigest   string    `json:"source_digest" gorm:"not null;uniqueIndex"`
	OwnerAccountID string    `json:"owner_account_id" gorm:"not null"`
	TenantIDs      string    `json:"tenant_ids" gorm:"not null"`
	CompletedAt    time.Time `json:"completed_at"`
}

func (Receipt) TableName() string { return "tenant_imports" }

// Apply moves a frozen tenant source into the current schema in one GORM transaction.
// The destination is an ordinary owner created through verified console enrollment.
func Apply(ctx context.Context, databaseURL, encodedKey, id, ownerID string, document tenants.FileDocument) (Receipt, error) {

	if strings.TrimSpace(id) == "" || len(id) > 128 || strings.TrimSpace(ownerID) == "" {
		return Receipt{}, errors.New("migration.identifier_required")
	}
	if len(document.Tenants) == 0 {
		return Receipt{}, errors.New("migration.source_empty")
	}
	if _, err := tenants.LoadResolvedConfig(document); err != nil {
		return Receipt{}, err
	}
	for _, tenant := range document.Tenants {
		if tenant.ID == controlplane.ConsoleTenantID {
			return Receipt{}, errors.New("migration.console_reserved")
		}
	}
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil || len(key) != 32 {
		return Receipt{}, errors.New("migration.encryption_key_invalid")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Receipt{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Receipt{}, err
	}
	keyID := fmt.Sprintf("%x", sha256.Sum256(key))
	snapshot, err := controlplane.OpenExisting(ctx, databaseURL, encodedKey)
	if err != nil {
		return Receipt{}, err
	}
	defer snapshot.Close()
	existing, err := snapshot.ApplicationTenants(ctx)
	if err != nil {
		return Receipt{}, err
	}
	console, err := snapshot.Console(ctx)
	if err != nil {
		return Receipt{}, err
	}
	sort.Slice(document.Tenants, func(i, j int) bool { return document.Tenants[i].ID < document.Tenants[j].ID })
	encoded, err := json.Marshal(document)
	if err != nil {
		return Receipt{}, err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("active\x00"))
	_, _ = mac.Write(encoded)
	digest := fmt.Sprintf("%x", mac.Sum(nil))
	db, err := authkit.OpenControlDatabase(ctx, databaseURL)
	if err != nil {
		return Receipt{}, err
	}
	raw, err := db.DB()
	if err != nil {
		return Receipt{}, err
	}
	defer raw.Close()
	var receipt Receipt
	err = db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// A receipt is deployment state. Normal service startup never creates this table.
		if err := tx.AutoMigrate(&Receipt{}); err != nil {
			return err
		}
		var owner controlplane.Owner
		if err := tx.First(&owner, "id = ? AND state = ?", ownerID, "active").Error; err != nil {
			return fmt.Errorf("migration.owner_required: %w", err)
		}
		err := tx.First(&receipt, "id = ?", id).Error
		if err == nil {
			if receipt.SourceDigest != digest || receipt.OwnerAccountID != ownerID {
				return errors.New("migration.receipt_conflict")
			}
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		all := append(append(existing.Tenants, console), document.Tenants...)
		if _, err := tenants.LoadResolvedConfig(tenants.FileDocument{Tenants: all}); err != nil {
			return err
		}
		ids := make([]string, 0, len(document.Tenants))
		for _, file := range document.Tenants {
			if err := tx.Table("tenants").Create(map[string]any{"id": file.ID, "owner_account_id": ownerID, "name": file.DisplayName, "state": "draft"}).Error; err != nil {
				return fmt.Errorf("migration.tenant id=%s: %w", file.ID, err)
			}
			data, err := json.Marshal(file)
			if err != nil {
				return err
			}
			binding, _ := json.Marshal([]string{file.ID, "configuration-1", "configuration", keyID})
			nonce := make([]byte, aead.NonceSize())
			if _, err := rand.Read(nonce); err != nil {
				return err
			}
			encrypted := aead.Seal(nonce, nonce, data, binding)
			if err := tx.Table("tenant_secrets").Create(map[string]any{"id": "configuration-1", "tenant_id": file.ID, "purpose": "configuration", "encrypted_value": encrypted, "encryption_key_id": keyID}).Error; err != nil {
				return err
			}
			if err := tx.Table("tenant_configurations").Create(map[string]any{"tenant_id": file.ID, "revision": 1, "configuration": `{"secret_id":"configuration-1"}`}).Error; err != nil {
				return err
			}
			for _, origin := range file.TenantOrigins {
				if err := tx.Table("tenant_origins").Create(map[string]any{"tenant_id": file.ID, "revision": 1, "origin": origin, "provenance": "operator-approved-import"}).Error; err != nil {
					return err
				}
			}
			if err := tx.Table("tenants").Where("id = ?", file.ID).Updates(map[string]any{"state": "active", "active_revision": 1}).Error; err != nil {
				return err
			}
			ids = append(ids, file.ID)
		}
		if err := removeInitialOwner(tx); err != nil {
			return err
		}
		idsJSON, _ := json.Marshal(ids)
		receipt = Receipt{ID: id, SourceDigest: digest, OwnerAccountID: ownerID, TenantIDs: string(idsJSON), CompletedAt: time.Now().UTC()}
		return tx.Create(&receipt).Error
	})
	if err != nil {
		return Receipt{}, fmt.Errorf("migration.apply: %w", err)
	}
	return receipt, nil
}

// RemoveInitialOwner removes the obsolete schema field during deployment, including empty installations.
func RemoveInitialOwner(ctx context.Context, databaseURL string) error {
	db, err := authkit.OpenControlDatabase(ctx, databaseURL)
	if err != nil {
		return err
	}
	raw, err := db.DB()
	if err != nil {
		return err
	}
	defer raw.Close()
	return db.WithContext(ctx).Transaction(removeInitialOwner)
}

type obsoleteBootstrap struct {
	ID             string `gorm:"primaryKey"`
	Configuration  []byte
	Digest         string
	InitialOwnerID *string
}

func (obsoleteBootstrap) TableName() string { return "console_bootstraps" }

func removeInitialOwner(tx *gorm.DB) error {
	migrator := tx.Migrator()
	if !migrator.HasColumn("console_bootstraps", "initial_owner_id") {
		return nil
	}
	if migrator.HasConstraint("console_bootstraps", "fk_console_bootstraps_initial_owner") {
		if err := migrator.DropConstraint("console_bootstraps", "fk_console_bootstraps_initial_owner"); err != nil {
			return fmt.Errorf("migration.drop_initial_owner_constraint: %w", err)
		}
	}
	if err := migrator.DropColumn(&obsoleteBootstrap{}, "initial_owner_id"); err != nil {
		return fmt.Errorf("migration.drop_initial_owner_column: %w", err)
	}
	if migrator.HasColumn("console_bootstraps", "initial_owner_id") {
		return errors.New("migration.initial_owner_column_remains")
	}
	return nil
}

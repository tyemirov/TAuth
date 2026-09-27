package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/tyemirov/tauth/internal/tenants"
	"gorm.io/gorm"
)

const configurationPurpose = "configuration"

type tenantRecord struct {
	ID                string `json:"id"`
	OwnerAccountID    string `json:"-"`
	Name              string `json:"name"`
	Environment       string `json:"environment"`
	Version           int64  `json:"version" gorm:"default:1"`
	State             string `json:"state"`
	ActiveRevision    *int64 `json:"active_revision"`
	SuspensionPending bool   `json:"-"`
}

func (tenantRecord) TableName() string { return "tenants" }

// ImportReceipt records an atomic migration without secret values.
type ImportReceipt struct {
	ID             string    `json:"id" gorm:"primaryKey"`
	SourceDigest   string    `json:"source_digest"`
	OwnerAccountID string    `json:"owner_account_id"`
	TenantIDs      string    `json:"tenant_ids"`
	CompletedAt    time.Time `json:"completed_at"`
}

func (ImportReceipt) TableName() string { return "tenant_imports" }

type configurationRecord struct {
	TenantID            string
	Revision            int64
	Configuration       string
	APIBaseURL          string
	LocalDevelopment    bool
	OperatorIntegration bool
}

func (configurationRecord) TableName() string { return "tenant_configurations" }

type configurationReference struct {
	SecretID string `json:"secret_id"`
}

// Import installs effective application configuration under the verified initial owner.
func (store *Store) Import(ctx context.Context, id string, document tenants.FileDocument) (ImportReceipt, error) {
	if strings.TrimSpace(id) == "" || len(id) > 128 {
		return ImportReceipt{}, errors.New("management.import_id_invalid")
	}
	if len(document.Tenants) == 0 {
		return ImportReceipt{}, errors.New("management.import_empty")
	}
	if _, err := tenants.LoadResolvedConfig(document); err != nil {
		return ImportReceipt{}, err
	}
	for _, tenant := range document.Tenants {
		if tenant.ID == ConsoleTenantID {
			return ImportReceipt{}, errors.New("management.console_reserved")
		}
	}
	sort.Slice(document.Tenants, func(left, right int) bool { return document.Tenants[left].ID < document.Tenants[right].ID })
	encoded, err := json.Marshal(document)
	if err != nil {
		return ImportReceipt{}, fmt.Errorf("management.encode_import: %w", err)
	}
	digestMAC := hmac.New(sha256.New, store.digestKey)
	_, _ = digestMAC.Write(encoded)
	digest := fmt.Sprintf("%x", digestMAC.Sum(nil))
	var receipt ImportReceipt
	err = store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&consoleBootstrap{}).Where("id = ?", ConsoleTenantID).Update("id", ConsoleTenantID).Error; err != nil {
			return err
		}
		var bootstrap consoleBootstrap
		if err := tx.First(&bootstrap, "id = ?", ConsoleTenantID).Error; err != nil {
			return err
		}
		if bootstrap.InitialOwnerID == nil {
			return errors.New("management.initial_owner_required")
		}
		err := tx.First(&receipt, "id = ?", id).Error
		if err == nil {
			if receipt.SourceDigest != digest || receipt.OwnerAccountID != *bootstrap.InitialOwnerID {
				return errors.New("management.import_conflict")
			}
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		local := &Store{db: tx, cipher: store.cipher, keyID: store.keyID, digestKey: store.digestKey}
		existing, err := local.ApplicationTenants(ctx)
		if err != nil {
			return err
		}
		console, err := local.Console(ctx)
		if err != nil {
			return err
		}
		all := append(append(existing.Tenants, console), document.Tenants...)
		if _, err := tenants.LoadResolvedConfig(tenants.FileDocument{Tenants: all}); err != nil {
			return err
		}
		ids := make([]string, 0, len(document.Tenants))
		for _, file := range document.Tenants {
			record := tenantRecord{ID: file.ID, OwnerAccountID: *bootstrap.InitialOwnerID, Name: file.DisplayName, State: "draft"}
			if err := tx.Create(&record).Error; err != nil {
				return fmt.Errorf("management.import_tenant id=%s: %w", file.ID, err)
			}
			if err := local.saveConfiguration(ctx, file, 1, "operator-approved-import"); err != nil {
				return err
			}
			if err := tx.Model(&record).Updates(map[string]any{"state": "active", "active_revision": 1}).Error; err != nil {
				return err
			}
			ids = append(ids, file.ID)
		}
		idsJSON, err := json.Marshal(ids)
		if err != nil {
			return err
		}
		receipt = ImportReceipt{ID: id, SourceDigest: digest, OwnerAccountID: *bootstrap.InitialOwnerID, TenantIDs: string(idsJSON), CompletedAt: time.Now().UTC()}
		return tx.Create(&receipt).Error
	})
	if err != nil {
		return ImportReceipt{}, fmt.Errorf("management.import: %w", err)
	}
	return receipt, nil
}

func (store *Store) saveConfiguration(ctx context.Context, file tenants.FileTenant, revision int64, provenance string) error {
	secretID := fmt.Sprintf("configuration-%d", revision)
	ref, err := NewSecretReference(file.ID, secretID, configurationPurpose)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(file)
	if err != nil {
		return err
	}
	if err := store.SaveSecret(ctx, ref, encoded); err != nil {
		return err
	}
	reference, err := json.Marshal(configurationReference{SecretID: secretID})
	if err != nil {
		return err
	}
	if err := store.db.WithContext(ctx).Create(&configurationRecord{TenantID: file.ID, Revision: revision, Configuration: string(reference)}).Error; err != nil {
		return err
	}
	for _, origin := range file.TenantOrigins {
		if err := store.db.WithContext(ctx).Exec("INSERT INTO tenant_origins (tenant_id, revision, origin, provenance) VALUES (?, ?, ?, ?)", file.ID, revision, origin, provenance).Error; err != nil {
			return err
		}
	}
	return nil
}

// ApplicationTenants returns only committed active database revisions.
func (store *Store) ApplicationTenants(ctx context.Context) (tenants.FileDocument, error) {
	var records []configurationRecord
	err := store.db.WithContext(ctx).Table("tenant_configurations AS configuration").Select("configuration.*").Joins("JOIN tenants ON tenants.id = configuration.tenant_id AND tenants.active_revision = configuration.revision").Where("tenants.state = ?", "active").Order("configuration.tenant_id").Scan(&records).Error
	if err != nil {
		return tenants.FileDocument{}, fmt.Errorf("management.read_active_configurations: %w", err)
	}
	document := tenants.FileDocument{Tenants: make([]tenants.FileTenant, 0, len(records))}
	for _, record := range records {
		var reference configurationReference
		if err := json.Unmarshal([]byte(record.Configuration), &reference); err != nil {
			return document, fmt.Errorf("management.decode_configuration_reference: %w", err)
		}
		ref, err := NewSecretReference(record.TenantID, reference.SecretID, configurationPurpose)
		if err != nil {
			return document, err
		}
		encoded, err := store.LoadSecret(ctx, ref)
		if err != nil {
			return document, err
		}
		var file tenants.FileTenant
		if err := json.Unmarshal(encoded, &file); err != nil {
			return document, fmt.Errorf("management.decode_configuration: %w", err)
		}
		if file.ID != record.TenantID {
			return document, errors.New("management.configuration_tenant_mismatch")
		}
		document.Tenants = append(document.Tenants, file)
	}
	return document, nil
}

// RuntimeTenants validates the complete active snapshot from persistent storage.
func (store *Store) RuntimeTenants(ctx context.Context) (tenants.Config, error) {
	document, err := store.ApplicationTenants(ctx)
	if err != nil {
		return tenants.Config{}, err
	}
	console, err := store.Console(ctx)
	if err != nil {
		return tenants.Config{}, err
	}
	document.Tenants = append(document.Tenants, console)
	return tenants.LoadResolvedConfig(document)
}

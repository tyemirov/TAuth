package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/tyemirov/tauth/internal/tenants"
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

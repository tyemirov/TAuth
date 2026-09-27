package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm/clause"
)

// SecretReference binds a secret to its tenant, identifier, and purpose.
type SecretReference struct{ tenantID, id, purpose string }

// NewSecretReference validates a reference at the storage boundary.
func NewSecretReference(tenantID, id, purpose string) (SecretReference, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(id) == "" || strings.TrimSpace(purpose) == "" {
		return SecretReference{}, errors.New("management.secret_reference_invalid")
	}
	return SecretReference{tenantID: tenantID, id: id, purpose: purpose}, nil
}

type secretRecord struct {
	ID              string
	TenantID        string
	Purpose         string
	EncryptedValue  []byte
	EncryptionKeyID string
}

func (secretRecord) TableName() string { return "tenant_secrets" }

func (ref SecretReference) binding(keyID string) string {
	value, _ := json.Marshal([]string{ref.tenantID, ref.id, ref.purpose, keyID})
	return string(value)
}

// SaveSecret stores one authenticated ciphertext with tenant-bound associated data.
func (store *Store) SaveSecret(ctx context.Context, ref SecretReference, value []byte) error {
	record := secretRecord{ID: ref.id, TenantID: ref.tenantID, Purpose: ref.purpose, EncryptionKeyID: store.keyID, EncryptedValue: store.seal(value, ref.binding(store.keyID))}
	if err := store.db.WithContext(ctx).Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "tenant_id"}, {Name: "id"}}, DoUpdates: clause.AssignmentColumns([]string{"purpose", "encrypted_value", "encryption_key_id"})}).Create(&record).Error; err != nil {
		return fmt.Errorf("management.save_secret tenant=%s id=%s: %w", ref.tenantID, ref.id, err)
	}
	return nil
}

// LoadSecret authenticates and decrypts one exact tenant secret reference.
func (store *Store) LoadSecret(ctx context.Context, ref SecretReference) ([]byte, error) {
	var record secretRecord
	if err := store.db.WithContext(ctx).First(&record, "tenant_id = ? AND id = ? AND purpose = ?", ref.tenantID, ref.id, ref.purpose).Error; err != nil {
		return nil, fmt.Errorf("management.load_secret tenant=%s id=%s: %w", ref.tenantID, ref.id, err)
	}
	if record.EncryptionKeyID != store.keyID {
		return nil, errors.New("management.encryption_key_mismatch")
	}
	return store.unseal(record.EncryptedValue, ref.binding(record.EncryptionKeyID))
}

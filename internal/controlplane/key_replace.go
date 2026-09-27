package controlplane

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/tyemirov/tauth/internal/tenants"
	"gorm.io/gorm"
)

// KeyReplacement records the draft created by an offline operator cutover.
type KeyReplacement struct {
	TenantID string `json:"tenant_id"`
	Revision int64  `json:"revision"`
	State    string `json:"state"`
}

// ReplaceSessionKey creates one current draft while the tenant is suspended.
// The caller must stop the service and install the same key in each validator.
func (store *Store) ReplaceSessionKey(ctx context.Context, owner, id string, expected int64, encoded string) (KeyReplacement, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) < 32 || len(key) > 1024 || !utf8.Valid(key) || strings.TrimSpace(string(key)) != string(key) {
		return KeyReplacement{}, errors.New("management.replacement_key_invalid")
	}
	if id == ConsoleTenantID || owner == "" || expected < 1 {
		return KeyReplacement{}, errors.New("management.replacement_subject_invalid")
	}
	result := KeyReplacement{TenantID: id, State: "suspended"}
	err = store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&consoleBootstrap{}).Where("id = ?", ConsoleTenantID).Update("id", ConsoleTenantID).Error; err != nil {
			return err
		}
		local := store.local(tx)
		tenant, err := local.tenant(ctx, owner, id)
		if err != nil {
			return err
		}
		if tenant.State != "suspended" || tenant.SuspensionPending {
			return errors.New("management.completed_suspension_required")
		}
		file, record, err := local.configuration(ctx, id, 0)
		if err != nil {
			return err
		}
		if record.Revision != expected {
			return failure(412, "revision_conflict")
		}
		if file.JWTSigningKey == string(key) {
			return errors.New("management.replacement_key_unchanged")
		}
		file.JWTSigningKey = string(key)
		if _, err := tenants.LoadResolvedConfig(tenants.FileDocument{Tenants: []tenants.FileTenant{file}}); err != nil {
			return err
		}
		result.Revision = record.Revision + 1
		if err := local.saveConfiguration(ctx, file, result.Revision, "operator-key-replacement"); err != nil {
			return err
		}
		if err := tx.Model(&configurationRecord{}).Where("tenant_id = ? AND revision = ?", id, result.Revision).Updates(map[string]any{"api_base_url": record.APIBaseURL, "local_development": record.LocalDevelopment, "operator_integration": record.OperatorIntegration}).Error; err != nil {
			return err
		}
		return local.audit(ctx, owner, id, "session-key.replaced", "succeeded", result.Revision)
	})
	if err != nil {
		return KeyReplacement{}, fmt.Errorf("management.replace_session_key tenant=%s: %w", id, err)
	}
	return result, nil
}

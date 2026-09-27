package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"gorm.io/gorm"
)

var googleWebClientPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+\.apps\.googleusercontent\.com$`)

// ReplaceConsoleGoogleClient replaces only the console's Google audience.
// The operator must stop the service before replacement and restart it afterward.
func (store *Store) ReplaceConsoleGoogleClient(ctx context.Context, expected, replacement string) error {
	if expected == "" || strings.TrimSpace(expected) != expected || !googleWebClientPattern.MatchString(replacement) {
		return errors.New("management.console_client_invalid")
	}
	if expected == replacement {
		return errors.New("management.console_client_unchanged")
	}
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Serialize changes to the singleton before reading its current value.
		if err := tx.Model(&consoleBootstrap{}).Where("id = ?", ConsoleTenantID).Update("id", ConsoleTenantID).Error; err != nil {
			return err
		}
		file, err := store.local(tx).Console(ctx)
		if err != nil {
			return err
		}
		if file.GoogleWebClientID != expected {
			return errors.New("management.console_client_conflict")
		}
		file.GoogleWebClientID = replacement
		data, err := json.Marshal(file)
		if err != nil {
			return fmt.Errorf("management.encode_console: %w", err)
		}
		return tx.Model(&consoleBootstrap{}).Where("id = ?", ConsoleTenantID).Updates(map[string]any{
			"configuration": store.seal(data, ConsoleTenantID),
			"digest":        fmt.Sprintf("%x", sha256.Sum256(data)),
		}).Error
	})
	if err != nil {
		return fmt.Errorf("management.replace_console_google_client tenant=%s: %w", ConsoleTenantID, err)
	}
	return nil
}

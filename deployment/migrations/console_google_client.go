package migrations

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/controlplane"
	"gorm.io/gorm"
)

// ConsoleGoogleClientID identifies the independent console client migration.
const ConsoleGoogleClientID = "20261005-console-google-client"

// ConsoleGoogleClientPlan binds one console origin to an exact client replacement.
type ConsoleGoogleClientPlan struct {
	ExpectedClientID string `json:"expected_client_id"`
	ClientID         string `json:"client_id"`
	ConsoleOrigin    string `json:"console_origin"`
}

// LoadConsoleGoogleClientPlan validates the sealed public migration input.
func LoadConsoleGoogleClientPlan(path string) (ConsoleGoogleClientPlan, error) {
	var plan ConsoleGoogleClientPlan
	file, err := os.Open(path)
	if err != nil {
		return plan, fmt.Errorf("console_client.read_plan: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&plan); err != nil {
		return plan, fmt.Errorf("console_client.decode_plan: %w", err)
	}
	var trailing any
	if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return plan, errors.New("console_client.plan_trailing_data")
	}
	origin, err := url.Parse(plan.ConsoleOrigin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || plan.ExpectedClientID == "" || strings.TrimSpace(plan.ExpectedClientID) != plan.ExpectedClientID || plan.ExpectedClientID == plan.ClientID || !regexp.MustCompile(`^[A-Za-z0-9_-]+\.apps\.googleusercontent\.com$`).MatchString(plan.ClientID) {
		return plan, errors.New("console_client.plan_invalid")
	}
	return plan, nil
}

func consoleClientDigests(plan ConsoleGoogleClientPlan, key []byte) (string, string) {
	payload, _ := json.Marshal(plan)
	return fmt.Sprintf("%x", sha256.Sum256(payload)), fmt.Sprintf("%x", sha256.Sum256(key))
}

func newConsoleGoogleClientCommand() *cobra.Command {
	var databaseURL, keyFile, planFile string
	var status bool
	command := &cobra.Command{Use: "console-google-client", Short: "Apply the console Google client migration once", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		plan, err := LoadConsoleGoogleClientPlan(planFile)
		if err != nil {
			return err
		}
		encoded, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("console_client.read_key: %w", err)
		}
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
		if err != nil || len(key) != 32 {
			return errors.New("console_client.encryption_key_invalid")
		}
		receipt, completed, err := readConsoleClientReceipt(command.Context(), databaseURL, plan, key)
		if err != nil {
			return err
		}
		if !status && !completed {
			receipt, err = applyConsoleClient(command.Context(), databaseURL, plan, key)
			if err != nil {
				return fmt.Errorf("console_client.apply: %w", err)
			}
			completed = true
		}
		return json.NewEncoder(command.OutOrStdout()).Encode(struct {
			ID          string    `json:"id"`
			Completed   bool      `json:"completed"`
			CompletedAt time.Time `json:"completed_at"`
		}{ConsoleGoogleClientID, completed, receipt.CompletedAt})
	}}
	command.Flags().StringVar(&databaseURL, "database", "", "Stopped deployment database URL")
	command.Flags().StringVar(&keyFile, "key-file", "", "Persistent encryption key file")
	command.Flags().StringVar(&planFile, "plan", "", "Sealed console client plan")
	command.Flags().BoolVar(&status, "status", false, "Read the completion receipt")
	return command
}

func readConsoleClientReceipt(ctx context.Context, databaseURL string, plan ConsoleGoogleClientPlan, key []byte) (cutoverReceipt, bool, error) {
	var receipt cutoverReceipt
	path := strings.TrimPrefix(databaseURL, "sqlite://")
	if !strings.HasPrefix(databaseURL, "sqlite://") || !filepath.IsAbs(path) || strings.ContainsAny(path, "?#") {
		return receipt, false, errors.New("console_client.sqlite_database_required")
	}
	if _, err := os.Stat(path); err != nil {
		return receipt, false, fmt.Errorf("console_client.database_absent: %w", err)
	}
	db, err := authkit.OpenControlDatabase(ctx, databaseURL+"?mode=ro")
	if err != nil {
		return receipt, false, err
	}
	raw, err := db.DB()
	if err != nil {
		return receipt, false, err
	}
	defer raw.Close()
	if !db.Migrator().HasTable(receipt.TableName()) {
		return receipt, false, nil
	}
	err = db.First(&receipt, "id = ?", ConsoleGoogleClientID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return receipt, false, nil
	}
	if err != nil {
		return receipt, false, err
	}
	digest, keyID := consoleClientDigests(plan, key)
	if receipt.PlanDigest != digest || receipt.KeyID != keyID {
		return receipt, false, errors.New("console_client.receipt_conflict")
	}
	return receipt, true, nil
}

func applyConsoleClient(ctx context.Context, databaseURL string, plan ConsoleGoogleClientPlan, key []byte) (cutoverReceipt, error) {
	var receipt cutoverReceipt
	original := strings.TrimPrefix(databaseURL, "sqlite://")
	lock, err := os.Create(original + "." + ConsoleGoogleClientID + ".lock")
	if err != nil {
		return receipt, err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return receipt, fmt.Errorf("console_client.already_running: %w", err)
	}
	recorded, completed, err := readConsoleClientReceipt(ctx, databaseURL, plan, key)
	if err != nil {
		return receipt, err
	}
	if completed {
		return recorded, nil
	}
	encodedKey := base64.StdEncoding.EncodeToString(key)
	store, err := controlplane.OpenExisting(ctx, databaseURL+"?mode=ro", encodedKey)
	if err != nil {
		return receipt, err
	}
	console, err := store.Console(ctx)
	closeErr := store.Close()
	if err != nil {
		return receipt, err
	}
	if closeErr != nil {
		return receipt, closeErr
	}
	if len(console.TenantOrigins) != 1 || console.TenantOrigins[0] != plan.ConsoleOrigin || console.GoogleWebClientID != plan.ExpectedClientID {
		return receipt, errors.New("console_client.configuration_conflict")
	}
	db, err := authkit.OpenControlDatabase(ctx, databaseURL)
	if err != nil {
		return receipt, err
	}
	raw, err := db.DB()
	if err != nil {
		return receipt, err
	}
	var checkpoint struct{ Busy, Log, Checkpointed int }
	if err = db.Raw("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&checkpoint).Error; err != nil {
		raw.Close()
		return receipt, err
	}
	if checkpoint.Busy != 0 {
		raw.Close()
		return receipt, errors.New("console_client.database_busy")
	}
	backupFile, err := os.CreateTemp(filepath.Dir(original), filepath.Base(original)+"."+ConsoleGoogleClientID+"-before-*.db")
	if err != nil {
		raw.Close()
		return receipt, err
	}
	backup := backupFile.Name()
	if err = backupFile.Close(); err != nil {
		raw.Close()
		return receipt, err
	}
	if err = os.Remove(backup); err != nil {
		raw.Close()
		return receipt, err
	}
	err = db.Exec("VACUUM INTO ?", backup).Error
	closeErr = raw.Close()
	if err != nil {
		return receipt, err
	}
	if closeErr != nil {
		return receipt, closeErr
	}
	candidate := original + "." + ConsoleGoogleClientID + "-candidate.db"
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err = os.Remove(candidate + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return receipt, err
		}
	}
	if err = copyCutoverDatabase(backup, candidate); err != nil {
		return receipt, err
	}
	candidateURL := "sqlite://" + candidate
	store, err = controlplane.OpenExisting(ctx, candidateURL, encodedKey)
	if err != nil {
		return receipt, err
	}
	err = store.ReplaceConsoleGoogleClient(ctx, plan.ExpectedClientID, plan.ClientID)
	closeErr = store.Close()
	if err != nil {
		return receipt, err
	}
	if closeErr != nil {
		return receipt, closeErr
	}
	db, err = authkit.OpenControlDatabase(ctx, candidateURL, &cutoverReceipt{})
	if err != nil {
		return receipt, err
	}
	raw, err = db.DB()
	if err != nil {
		return receipt, err
	}
	digest, keyID := consoleClientDigests(plan, key)
	receipt = cutoverReceipt{ID: ConsoleGoogleClientID, PlanDigest: digest, KeyID: keyID, CompletedAt: time.Now().UTC()}
	err = db.Create(&receipt).Error
	if err == nil {
		err = db.Raw("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&checkpoint).Error
		if err == nil && checkpoint.Busy != 0 {
			err = errors.New("console_client.candidate_busy")
		}
	}
	closeErr = raw.Close()
	if err != nil {
		return receipt, err
	}
	if closeErr != nil {
		return receipt, closeErr
	}
	file, err := os.Open(candidate)
	if err != nil {
		return receipt, err
	}
	err = file.Sync()
	closeErr = file.Close()
	if err != nil {
		return receipt, err
	}
	if closeErr != nil {
		return receipt, closeErr
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err = os.Remove(original + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return receipt, err
		}
	}
	if err = os.Rename(candidate, original); err != nil {
		return receipt, err
	}
	directory, err := os.Open(filepath.Dir(original))
	if err != nil {
		return receipt, err
	}
	err = directory.Sync()
	closeErr = directory.Close()
	if err != nil {
		return receipt, err
	}
	return receipt, closeErr
}

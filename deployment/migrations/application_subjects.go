package migrations

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/tyemirov/tauth/internal/authkit"
	"gorm.io/gorm"
)

// ApplicationSubjectsID identifies the immutable public subject migration.
const ApplicationSubjectsID = "20261006-application-subjects"

// ApplicationSubjectsPlan binds the public subject schema to its migration.
type ApplicationSubjectsPlan struct {
	ID     string `json:"id"`
	Schema string `json:"schema"`
}

// LoadApplicationSubjectsPlan validates the sealed public migration input.
func LoadApplicationSubjectsPlan(path string) (ApplicationSubjectsPlan, error) {
	var plan ApplicationSubjectsPlan
	file, err := os.Open(path)
	if err != nil {
		return plan, fmt.Errorf("application_subjects.read_plan: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&plan); err != nil {
		return plan, fmt.Errorf("application_subjects.decode_plan: %w", err)
	}
	var trailing any
	if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return plan, errors.New("application_subjects.plan_trailing_data")
	}
	if plan.ID != ApplicationSubjectsID || plan.Schema != "application-subjects" {
		return plan, errors.New("application_subjects.plan_invalid")
	}
	return plan, nil
}

func applicationSubjectsDigests(plan ApplicationSubjectsPlan, key []byte) (string, string) {
	payload, _ := json.Marshal(plan)
	return fmt.Sprintf("%x", sha256.Sum256(payload)), fmt.Sprintf("%x", sha256.Sum256(key))
}

func newApplicationSubjectsCommand() *cobra.Command {
	var databaseURL, keyFile, planFile string
	var status bool
	command := &cobra.Command{Use: "application-subjects", Short: "Apply the public application subject migration once", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		plan, err := LoadApplicationSubjectsPlan(planFile)
		if err != nil {
			return err
		}
		encoded, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("application_subjects.read_key: %w", err)
		}
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
		if err != nil || len(key) != 32 {
			return errors.New("application_subjects.encryption_key_invalid")
		}
		receipt, completed, err := readApplicationSubjectsReceipt(command.Context(), databaseURL, plan, key)
		if err != nil {
			return err
		}
		if !status && !completed {
			receipt, err = applyApplicationSubjects(command.Context(), databaseURL, plan, key)
			if err != nil {
				return fmt.Errorf("application_subjects.apply: %w", err)
			}
			completed = true
		}
		return json.NewEncoder(command.OutOrStdout()).Encode(struct {
			ID          string    `json:"id"`
			Completed   bool      `json:"completed"`
			CompletedAt time.Time `json:"completed_at"`
		}{ApplicationSubjectsID, completed, receipt.CompletedAt})
	}}
	command.Flags().StringVar(&databaseURL, "database", "", "Stopped deployment database URL")
	command.Flags().StringVar(&keyFile, "key-file", "", "Persistent encryption key file")
	command.Flags().StringVar(&planFile, "plan", "", "Sealed application subject plan")
	command.Flags().BoolVar(&status, "status", false, "Read the completion receipt")
	return command
}

func readApplicationSubjectsReceipt(ctx context.Context, databaseURL string, plan ApplicationSubjectsPlan, key []byte) (cutoverReceipt, bool, error) {
	var receipt cutoverReceipt
	path := strings.TrimPrefix(databaseURL, "sqlite://")
	if !strings.HasPrefix(databaseURL, "sqlite://") || !filepath.IsAbs(path) || strings.ContainsAny(path, "?#") {
		return receipt, false, errors.New("application_subjects.sqlite_database_required")
	}
	if _, err := os.Stat(path); err != nil {
		return receipt, false, fmt.Errorf("application_subjects.database_absent: %w", err)
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
	err = db.First(&receipt, "id = ?", ApplicationSubjectsID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return receipt, false, nil
	}
	if err != nil {
		return receipt, false, err
	}
	digest, keyID := applicationSubjectsDigests(plan, key)
	if receipt.PlanDigest != digest || receipt.KeyID != keyID {
		return receipt, false, errors.New("application_subjects.receipt_conflict")
	}
	return receipt, true, nil
}

func applyApplicationSubjects(ctx context.Context, databaseURL string, plan ApplicationSubjectsPlan, key []byte) (receipt cutoverReceipt, migrationErr error) {
	original := strings.TrimPrefix(databaseURL, "sqlite://")
	lock, err := os.Create(original + "." + ApplicationSubjectsID + ".lock")
	if err != nil {
		return receipt, err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return receipt, fmt.Errorf("application_subjects.already_running: %w", err)
	}
	recorded, completed, err := readApplicationSubjectsReceipt(ctx, databaseURL, plan, key)
	if err != nil {
		return receipt, err
	}
	if completed {
		return recorded, nil
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
		return receipt, errors.New("application_subjects.database_busy")
	}
	backupFile, err := os.CreateTemp(filepath.Dir(original), filepath.Base(original)+"."+ApplicationSubjectsID+"-before-*.db")
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
	closeErr := raw.Close()
	if err != nil {
		return receipt, err
	}
	if closeErr != nil {
		return receipt, closeErr
	}
	candidate := original + "." + ApplicationSubjectsID + "-candidate.db"
	defer func() {
		for _, suffix := range []string{"", "-wal", "-shm"} {
			if cleanupErr := os.Remove(candidate + suffix); cleanupErr != nil && !errors.Is(cleanupErr, os.ErrNotExist) {
				migrationErr = errors.Join(migrationErr, fmt.Errorf("application_subjects.cleanup_candidate: %w", cleanupErr))
			}
		}
	}()
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err = os.Remove(candidate + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return receipt, err
		}
	}
	if err = copyCutoverDatabase(backup, candidate); err != nil {
		return receipt, err
	}
	candidateURL := "sqlite://" + candidate
	db, err = authkit.OpenControlDatabase(ctx, candidateURL)
	if err != nil {
		return receipt, err
	}
	raw, err = db.DB()
	if err != nil {
		return receipt, err
	}
	digest, keyID := applicationSubjectsDigests(plan, key)
	receipt = cutoverReceipt{ID: ApplicationSubjectsID, PlanDigest: digest, KeyID: keyID, CompletedAt: time.Now().UTC()}
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := authkit.MigrateApplicationSubjects(ctx, tx); err != nil {
			return err
		}
		if err := tx.AutoMigrate(&cutoverReceipt{}); err != nil {
			return err
		}
		return tx.Create(&receipt).Error
	})
	if err == nil {
		err = db.Raw("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&checkpoint).Error
		if err == nil && checkpoint.Busy != 0 {
			err = errors.New("application_subjects.candidate_busy")
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

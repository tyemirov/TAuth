package migrations

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
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
	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/controlplane"
	"github.com/tyemirov/tauth/internal/tenants"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

// CutoverID identifies the immutable production configuration transfer.
const CutoverID = "20260930-tenant-console"

// CutoverApp retains the exact Gateway contribution and its destination App.
type CutoverApp struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	TenantIDs         []string `json:"tenant_ids"`
	ContributionOwner string   `json:"contribution_owner"`
	ContributionID    string   `json:"contribution_id"`
}

// CutoverPlan is public deployment policy, not a service configuration.
type CutoverPlan struct {
	OwnerEmails         []string     `json:"owner_emails"`
	ConsoleOrigin       string       `json:"console_origin"`
	ConsoleSourceTenant string       `json:"console_source_tenant"`
	ManagementURL       string       `json:"management_url"`
	Apps                []CutoverApp `json:"apps"`
}

type cutoverReceipt struct {
	ID          string `gorm:"primaryKey"`
	PlanDigest  string
	KeyID       string
	CompletedAt time.Time
}

func (cutoverReceipt) TableName() string { return "deployment_migrations" }

// CredentialMap derives stable App credentials from the persistent server secret.
// Tokens are delivered privately to Gateway and stored only as digests in the database.
func (plan CutoverPlan) CredentialMap(key []byte) map[string]map[string]string {
	result := map[string]map[string]string{}
	for _, app := range plan.Apps {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte(CutoverID + "\x00credential\x00" + app.ID))
		token := "tauthp_" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if result[app.ContributionOwner] == nil {
			result[app.ContributionOwner] = map[string]string{}
		}
		result[app.ContributionOwner][app.ContributionID] = token
	}
	return result
}

// LoadCutoverPlan validates the timestamped migration input once at its file boundary.
func LoadCutoverPlan(path string) (CutoverPlan, error) {
	var plan CutoverPlan
	file, err := os.Open(path)
	if err != nil {
		return plan, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&plan); err != nil {
		return plan, err
	}
	if len(plan.OwnerEmails) == 0 || plan.ConsoleOrigin == "" || plan.ConsoleSourceTenant == "" || plan.ManagementURL == "" || len(plan.Apps) == 0 {
		return plan, errors.New("cutover.plan_incomplete")
	}
	ids, bindings, tenantIDs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, app := range plan.Apps {
		binding := app.ContributionOwner + "/" + app.ContributionID
		if app.ID == "" || app.Name == "" || len(app.TenantIDs) == 0 || app.ContributionOwner == "" || app.ContributionID == "" || ids[app.ID] || bindings[binding] {
			return plan, errors.New("cutover.app_invalid")
		}
		ids[app.ID], bindings[binding] = true, true
		for _, id := range app.TenantIDs {
			if id == "" || tenantIDs[id] {
				return plan, errors.New("cutover.tenant_assignment_invalid")
			}
			tenantIDs[id] = true
		}
	}
	return plan, nil
}

func newCutoverCommand() *cobra.Command {
	var databaseURL, keyFile, planFile, sourceFile, environmentFile string
	var status bool
	command := &cobra.Command{Use: "cutover", Short: "Apply the timestamped deployment cutover once", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		plan, err := LoadCutoverPlan(planFile)
		if err != nil {
			return err
		}
		encoded, err := os.ReadFile(keyFile)
		if err != nil {
			return err
		}
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
		if err != nil || len(key) != 32 {
			return errors.New("cutover.encryption_key_invalid")
		}
		receipt, completed, err := readCutoverReceipt(command.Context(), databaseURL, plan, key)
		if err != nil {
			return err
		}
		if !status && !completed {
			receipt, err = applyCutover(command.Context(), databaseURL, plan, key, sourceFile, environmentFile)
			if err != nil {
				return err
			}
			completed = true
		}
		return json.NewEncoder(command.OutOrStdout()).Encode(struct {
			ID          string    `json:"id"`
			Completed   bool      `json:"completed"`
			CompletedAt time.Time `json:"completed_at"`
		}{CutoverID, completed, receipt.CompletedAt})
	}}
	command.Flags().StringVar(&databaseURL, "database", "", "Stopped deployment database URL")
	command.Flags().StringVar(&keyFile, "key-file", "", "Private persistent encryption key file")
	command.Flags().StringVar(&planFile, "plan", "", "Timestamped public cutover plan")
	command.Flags().StringVar(&sourceFile, "source", "", "Captured native tenant configuration")
	command.Flags().StringVar(&environmentFile, "environment", "", "Captured container environment JSON")
	command.Flags().BoolVar(&status, "status", false, "Read the completion receipt without changing data")
	return command
}

func cutoverDigests(plan CutoverPlan, key []byte) (string, string) {
	encoded, _ := json.Marshal(plan)
	return fmt.Sprintf("%x", sha256.Sum256(encoded)), fmt.Sprintf("%x", sha256.Sum256(key))
}

func readCutoverReceipt(ctx context.Context, databaseURL string, plan CutoverPlan, key []byte) (cutoverReceipt, bool, error) {
	var receipt cutoverReceipt
	// This bounded migration targets the deployed SQLite volume. Never create a missing source database.
	path := strings.TrimPrefix(databaseURL, "sqlite://")
	if !strings.HasPrefix(databaseURL, "sqlite://") || !filepath.IsAbs(path) {
		return receipt, false, errors.New("cutover.sqlite_database_required")
	}
	if _, err := os.Stat(path); err != nil {
		return receipt, false, fmt.Errorf("cutover.database_absent: %w", err)
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
	err = db.First(&receipt, "id = ?", CutoverID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return receipt, false, nil
	}
	if err != nil {
		return receipt, false, err
	}
	digest, keyID := cutoverDigests(plan, key)
	if receipt.PlanDigest != digest || receipt.KeyID != keyID {
		return receipt, false, errors.New("cutover.receipt_conflict")
	}
	return receipt, true, nil
}

func applyCutover(ctx context.Context, databaseURL string, plan CutoverPlan, key []byte, sourceFile, environmentFile string) (cutoverReceipt, error) {
	var receipt cutoverReceipt
	lock, err := os.Create(strings.TrimPrefix(databaseURL, "sqlite://") + ".20260930.lock")
	if err != nil {
		return receipt, err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return receipt, fmt.Errorf("cutover.already_running: %w", err)
	}
	recorded, completed, err := readCutoverReceipt(ctx, databaseURL, plan, key)
	if err != nil {
		return receipt, err
	}
	if completed {
		return recorded, nil
	}
	if environmentFile != "" {
		payload, err := os.ReadFile(environmentFile)
		if err != nil {
			return receipt, err
		}
		var environment []string
		if err = json.Unmarshal(payload, &environment); err != nil {
			return receipt, err
		}
		for _, entry := range environment {
			name, value, ok := strings.Cut(entry, "=")
			if !ok {
				return receipt, errors.New("cutover.environment_invalid")
			}
			if err = os.Setenv(name, value); err != nil {
				return receipt, err
			}
		}
	}
	payload, err := os.ReadFile(sourceFile)
	if err != nil {
		return receipt, err
	}
	// Delete the obsolete persisted field in this bounded migration, before the canonical strict loader.
	var captured map[string]any
	if err = yaml.Unmarshal(payload, &captured); err != nil {
		return receipt, err
	}
	if entries, ok := captured["tenants"].([]any); ok {
		for _, entry := range entries {
			if tenant, ok := entry.(map[string]any); ok {
				if account, ok := tenant["account_management"].(map[string]any); ok {
					delete(account, "return_challenge_tokens")
				}
			}
		}
	}
	payload, err = yaml.Marshal(captured)
	if err != nil {
		return receipt, err
	}
	source, err := appconfig.ParseImportSource(payload)
	if err != nil {
		return receipt, err
	}
	document, err := tenants.ResolveDocument(source.TenantDocument())
	if err != nil {
		return receipt, err
	}
	byID := map[string]tenants.FileTenant{}
	for _, tenant := range document.Tenants {
		byID[tenant.ID] = tenant
	}
	// The source defines the inventory. The plan grants credentials only to known assignments.
	assigned, appIDs := map[string]bool{}, map[string]bool{}
	var imports, credentialApps []CutoverApp
	for _, app := range plan.Apps {
		appIDs[app.ID] = true
		present := app
		present.TenantIDs = nil
		for _, id := range app.TenantIDs {
			assigned[id] = true
			if _, ok := byID[id]; ok {
				present.TenantIDs = append(present.TenantIDs, id)
			}
		}
		if len(present.TenantIDs) > 0 {
			imports = append(imports, present)
			credentialApps = append(credentialApps, present)
		}
	}
	for _, tenant := range document.Tenants {
		if assigned[tenant.ID] {
			continue
		}
		id := "imported-" + tenant.ID
		if appIDs[id] {
			return receipt, fmt.Errorf("cutover.imported_app_conflict: %s", id)
		}
		name := strings.TrimSpace(tenant.DisplayName)
		if name == "" {
			name = tenant.ID
		}
		imports = append(imports, CutoverApp{ID: id, Name: name, TenantIDs: []string{tenant.ID}})
	}
	consoleSource, ok := byID[plan.ConsoleSourceTenant]
	if !ok || consoleSource.GoogleWebClientID == "" {
		return receipt, errors.New("cutover.console_client_absent")
	}
	original := strings.TrimPrefix(databaseURL, "sqlite://")
	backup := original + ".20260930-before.db"
	staging := original + ".20260930-staging.db"
	db, err := authkit.OpenControlDatabase(ctx, databaseURL)
	if err != nil {
		return receipt, err
	}
	raw, err := db.DB()
	if err != nil {
		return receipt, err
	}
	type identity struct{ ProviderID, UserEmail, UserDisplayName string }
	var identities []identity
	err = db.Raw("SELECT DISTINCT i.provider_id, a.user_email, a.user_display_name FROM account_identities i JOIN accounts a ON a.tenant_id=i.tenant_id AND a.account_id=i.account_id WHERE i.provider='google' AND a.account_state='active' AND a.user_email IN ?", plan.OwnerEmails).Scan(&identities).Error
	if err != nil {
		_ = raw.Close()
		return receipt, err
	}
	subjects := map[string]bool{}
	for _, identity := range identities {
		subjects[identity.ProviderID] = true
	}
	if len(subjects) != 1 || subjects[""] {
		_ = raw.Close()
		return receipt, errors.New("cutover.verified_owner_ambiguous")
	}
	var checkpoint struct{ Busy, Log, Checkpointed int }
	if err = db.Raw("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&checkpoint).Error; err != nil {
		_ = raw.Close()
		return receipt, fmt.Errorf("cutover.checkpoint_failed: %w", err)
	}
	if checkpoint.Busy != 0 {
		_ = raw.Close()
		return receipt, errors.New("cutover.checkpoint_busy")
	}
	// An interrupted attempt can be followed by new source writes. Never reuse a stale backup as the next candidate.
	if _, statErr := os.Stat(backup); statErr == nil {
		file, createErr := os.CreateTemp(filepath.Dir(original), filepath.Base(original)+".20260930-before-*.db")
		if createErr != nil {
			_ = raw.Close()
			return receipt, createErr
		}
		backup = file.Name()
		if err = file.Close(); err != nil {
			_ = raw.Close()
			return receipt, err
		}
		if err = os.Remove(backup); err != nil {
			_ = raw.Close()
			return receipt, err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		_ = raw.Close()
		return receipt, statErr
	}
	err = db.Exec("VACUUM INTO ?", backup).Error
	closeErr := raw.Close()
	if err != nil {
		return receipt, err
	}
	if closeErr != nil {
		return receipt, closeErr
	}
	// An interrupted process can leave candidate sidecars. Discard them with the abandoned candidate before a fresh copy.
	for _, suffix := range []string{"-wal", "-shm"} {
		if err = os.Remove(staging + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return receipt, err
		}
	}
	if err = copyCutoverDatabase(backup, staging); err != nil {
		return receipt, err
	}
	// All changes occur in the private candidate. A failure leaves the deployment database unchanged.
	stageURL := "sqlite://" + staging
	encodedKey := base64.StdEncoding.EncodeToString(key)
	store, err := controlplane.Open(ctx, stageURL, encodedKey)
	if err != nil {
		return receipt, err
	}
	consoleMac := hmac.New(sha256.New, key)
	_, _ = consoleMac.Write([]byte(CutoverID + "\x00console-session"))
	console := tenants.FileTenant{ID: controlplane.ConsoleTenantID, DisplayName: "TAuth console", TenantOrigins: []string{plan.ConsoleOrigin}, GoogleWebClientID: consoleSource.GoogleWebClientID, JWTSigningKey: base64.RawURLEncoding.EncodeToString(consoleMac.Sum(nil)), SessionCookieName: "tauth_console_session", RefreshCookieName: "tauth_console_refresh", SessionTTL: "15m", RefreshTTL: "720h", AccountManagement: tenants.FileAccountManagement{Enabled: true, EmailDelivery: tenants.FileEmailDelivery{ServerAddress: "127.0.0.1:8090", APIKey: "console-unused-email", ConnectionTimeoutSeconds: 1, OperationTimeoutSeconds: 1, EmailVerificationURL: plan.ConsoleOrigin + "/app/verify", PasswordResetURL: plan.ConsoleOrigin + "/app/reset", PasswordLinkURL: plan.ConsoleOrigin + "/app/link"}}}
	err = store.Bootstrap(ctx, console)
	if err != nil {
		_ = store.Close()
		return receipt, err
	}
	stageDB, err := authkit.OpenControlDatabase(ctx, stageURL)
	if err != nil {
		_ = store.Close()
		return receipt, err
	}
	stageRaw, err := stageDB.DB()
	if err != nil {
		_ = store.Close()
		return receipt, err
	}
	ownerIdentity := identities[0]
	accountBytes := make([]byte, 16)
	if _, err = rand.Read(accountBytes); err != nil {
		_ = store.Close()
		_ = stageRaw.Close()
		return receipt, err
	}
	accountID := base64.RawURLEncoding.EncodeToString(accountBytes)
	now := time.Now().UTC()
	err = stageDB.Transaction(func(tx *gorm.DB) error {
		account := map[string]any{"tenant_id": controlplane.ConsoleTenantID, "account_id": accountID, "user_email": ownerIdentity.UserEmail, "user_display_name": ownerIdentity.UserDisplayName, "user_avatar_url": "", "account_state": "active", "user_roles": "[]", "created_at_unix": now.Unix(), "last_updated_unix": now.Unix()}
		// This timestamped import can precede the application subject migration on an existing database.
		if tx.Migrator().HasColumn("accounts", "user_id") {
			account["user_id"] = accountID
		}
		if err := tx.Table("accounts").Create(account).Error; err != nil {
			return err
		}
		return tx.Table("account_identities").Create(map[string]any{"tenant_id": controlplane.ConsoleTenantID, "provider": "google", "provider_id": ownerIdentity.ProviderID, "account_id": accountID, "created_at_unix": now.Unix(), "last_updated_unix": now.Unix()}).Error
	})
	if err != nil {
		_ = store.Close()
		_ = stageRaw.Close()
		return receipt, err
	}
	owner, _, err := store.Provision(ctx, appconfig.DefaultJWTIssuer, accountID, ownerIdentity.UserEmail, ownerIdentity.UserDisplayName)
	closeErr = store.Close()
	if err != nil {
		_ = stageRaw.Close()
		return receipt, err
	}
	if closeErr != nil {
		_ = stageRaw.Close()
		return receipt, closeErr
	}
	for _, app := range imports {
		subset := tenants.FileDocument{}
		for _, id := range app.TenantIDs {
			subset.Tenants = append(subset.Tenants, byID[id])
		}
		if _, err = Apply(ctx, stageURL, encodedKey, CutoverID+"-"+app.ID, owner.ID, app.ID, app.Name, subset); err != nil {
			_ = stageRaw.Close()
			return receipt, err
		}
	}
	credentials := plan.CredentialMap(key)
	err = stageDB.Transaction(func(tx *gorm.DB) error {
		for _, app := range credentialApps {
			token := credentials[app.ContributionOwner][app.ContributionID]
			mac := hmac.New(sha256.New, key)
			_, _ = mac.Write([]byte(token))
			operations, _ := json.Marshal([]string{"read", "configure", "activate", "suspend", "proofs"})
			ids, _ := json.Marshal(app.TenantIDs)
			if err := tx.Table("provisioning_credentials").Create(map[string]any{"id": CutoverID + "-" + app.ID, "app_id": app.ID, "owner_account_id": owner.ID, "name": "Gateway deployment", "operations": string(operations), "tenant_ids": string(ids), "allow_create": false, "digest": fmt.Sprintf("%x", mac.Sum(nil)), "created_at": now}).Error; err != nil {
				return err
			}
		}
		if err := tx.AutoMigrate(&cutoverReceipt{}); err != nil {
			return err
		}
		digest, keyID := cutoverDigests(plan, key)
		receipt = cutoverReceipt{ID: CutoverID, PlanDigest: digest, KeyID: keyID, CompletedAt: now}
		return tx.Create(&receipt).Error
	})
	closeErr = stageRaw.Close()
	if err != nil {
		return receipt, err
	}
	if closeErr != nil {
		return receipt, closeErr
	}
	candidate, err := os.Open(staging)
	if err != nil {
		return receipt, err
	}
	err = candidate.Sync()
	closeErr = candidate.Close()
	if err != nil {
		return receipt, err
	}
	if closeErr != nil {
		return receipt, closeErr
	}
	// SQLite source writers are stopped by deployment. Remove checkpointed sidecars before replacement.
	for _, suffix := range []string{"-wal", "-shm"} {
		if err = os.Remove(original + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return receipt, err
		}
	}
	if err = os.Rename(staging, original); err != nil {
		return receipt, fmt.Errorf("cutover.commit_database: %w", err)
	}
	directory, err := os.Open(filepath.Dir(original))
	if err != nil {
		return receipt, fmt.Errorf("cutover.commit_sync: database replaced: %w", err)
	}
	err = directory.Sync()
	closeErr = directory.Close()
	if err != nil {
		return receipt, fmt.Errorf("cutover.commit_sync: database replaced: %w", err)
	}
	if closeErr != nil {
		return receipt, fmt.Errorf("cutover.commit_sync: database replaced: %w", closeErr)
	}
	return receipt, nil
}

func copyCutoverDatabase(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.Create(destination)
	if err != nil {
		return err
	}
	_, err = io.Copy(output, input)
	if err == nil {
		err = output.Sync()
	}
	closeErr := output.Close()
	if err != nil {
		return err
	}
	return closeErr
}

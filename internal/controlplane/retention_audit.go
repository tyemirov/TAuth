package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/tenants"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

const (
	retentionRequestSchema = "tauth.retention.request.v1"
	retentionFrameSchema   = "tauth.retention.frame.v1"
	retentionResultSchema  = "tauth.retention.result.v1"
)

// RetentionAuditBinding identifies the native service and one lease acquisition.
// The collector verifies container, storage, and image facts independently.
type RetentionAuditBinding struct {
	HandoffID             string `json:"handoff_id"`
	CandidateDigest       string `json:"candidate_digest"`
	AcquisitionID         string `json:"acquisition_id"`
	ContainerID           string `json:"container_id"`
	ImageID               string `json:"image_id"`
	ConfigDigest          string `json:"config_digest"`
	DatabaseURL           string `json:"database_url"`
	StorageSource         string `json:"storage_source"`
	StorageTarget         string `json:"storage_target"`
	AuditorArtifactDigest string `json:"auditor_artifact_digest"`
}

// RetentionAuditRequest is the closed private audit input.
type RetentionAuditRequest struct {
	Schema        string                `json:"schema"`
	Operation     string                `json:"operation"`
	ServiceConfig string                `json:"service_config"`
	DatabasePath  string                `json:"database_path"`
	Binding       RetentionAuditBinding `json:"binding"`
	Baseline      *RetentionAuditFrame  `json:"baseline,omitempty"`
	NativeMounts  []RetentionAuditMount `json:"native_mounts,omitempty"`
}

// RetentionAuditMount is an actual native mount supplied by the collector.
type RetentionAuditMount struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

// RetentionAuditResolution translates the configured database through its mount.
type RetentionAuditResolution struct {
	DatabaseURL           string `json:"database_url"`
	DatabasePath          string `json:"database_path"`
	StorageSource         string `json:"storage_source"`
	StorageTarget         string `json:"storage_target"`
	ConfigDigest          string `json:"config_digest"`
	AuditorArtifactDigest string `json:"auditor_artifact_digest"`
}

// RetentionAuditFrame contains private opaque evidence, never a public receipt.
type RetentionAuditFrame struct {
	Schema       string                `json:"schema"`
	Binding      RetentionAuditBinding `json:"binding"`
	CapturedUnix int64                 `json:"captured_unix"`
	SchemaDigest string                `json:"schema_digest"`
	Tables       []RetentionAuditTable `json:"tables"`
	Seal         string                `json:"seal"`
}

// RetentionAuditTable covers every observed row of one service-owned table.
type RetentionAuditTable struct {
	Name string              `json:"name"`
	Rows []RetentionAuditRow `json:"rows"`
}

// RetentionAuditRow uses keyed opaque identities and private semantic metadata.
type RetentionAuditRow struct {
	ID      string                 `json:"id"`
	Digest  string                 `json:"digest"`
	Stable  string                 `json:"stable"`
	Expires int64                  `json:"expires_unix,omitempty"`
	Session *retentionAuditSession `json:"session,omitempty"`
}

type retentionAuditSession struct {
	Group    string `json:"group"`
	Previous string `json:"previous,omitempty"`
	Family   string `json:"family,omitempty"`
	Issued   int64  `json:"issued_unix"`
	Revoked  int64  `json:"revoked_unix"`
	Rotated  int64  `json:"rotated_unix"`
	Status   string `json:"status"`
}

// RetentionAuditResult binds a current frame to the verified private baseline.
type RetentionAuditResult struct {
	Schema         string                    `json:"schema"`
	Operation      string                    `json:"operation"`
	Status         string                    `json:"status"`
	Capture        *RetentionAuditFrame      `json:"capture,omitempty"`
	CaptureDigest  string                    `json:"capture_digest,omitempty"`
	Resolution     *RetentionAuditResolution `json:"resolution,omitempty"`
	BaselineDigest string                    `json:"baseline_digest,omitempty"`
	Proof          string                    `json:"proof"`
}

type retentionTablePolicy struct {
	expiry    string
	session   bool
	revocable bool
}

// Unknown tables fail closed. Transient rows still have complete private evidence.
var retentionTables = map[string]retentionTablePolicy{
	"owner_accounts": {}, "owner_login_bindings": {}, "console_bootstraps": {},
	"apps": {}, "provisioning_credentials": {}, "management_receipts": {},
	"tenants": {}, "tenant_configurations": {}, "tenant_secrets": {},
	"tenant_origins": {}, "tenant_providers": {}, "tenant_audit_events": {},
	"tenant_origin_proofs": {}, "tenant_origin_verifications": {},
	"tenant_activations": {}, "provisioning_bindings": {},
	"tenant_reauthentications": {}, "tenant_key_exports": {}, "tenant_setup_checks": {},
	"accounts": {}, "account_identities": {}, "user_profiles": {}, "password_credentials": {},
	"account_challenges": {expiry: "expires_unix"}, "account_erasures": {},
	"account_erasure_providers": {}, "apple_grants": {}, "apple_event_receipts": {}, "apple_erasure_subjects": {},
	"github_credentials": {}, "github_login_transactions": {expiry: "expires_at_unix"},
	"refresh_tokens":     {expiry: "expires_unix", session: true},
	"nonce_tokens":       {expiry: "expires_unix"},
	"auth_abuse_budgets": {expiry: "expires_unix"}, "auth_abuse_budget_lock": {},
	"auth_password_failures": {expiry: "expires_unix_nano"}, "auth_transient_capacity_locks": {},
	"oauth_authorization_requests": {expiry: "expires_at_unix"},
	"oauth_authorization_codes":    {expiry: "expires_at_unix"},
	"oauth_consents":               {expiry: "expires_at_unix", revocable: true},
	"oauth_refresh_tokens":         {expiry: "expires_at_unix", session: true}, "oauth_capacity_lock": {},
	"schema_migrations": {}, "tenant_imports": {}, "tenant_import_repairs": {},
	"deployment_migrations": {}, "app_hierarchy_migrations": {},
}

var retentionDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var retentionContainerPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var retentionHandoffPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
var retentionEnvironmentPattern = regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*`)

// AuditRetention captures or verifies service-owned data without SQL mutations.
func AuditRetention(ctx context.Context, request RetentionAuditRequest) (result RetentionAuditResult, auditErr error) {
	if err := validateRetentionRequest(request); err != nil {
		return result, err
	}
	configuration, err := os.ReadFile(request.ServiceConfig)
	if err != nil {
		return result, errors.New("retention.config_binding_invalid")
	}
	executable, err := os.Executable()
	if err != nil {
		return result, errors.New("retention.artifact_unavailable")
	}
	artifact, err := os.ReadFile(executable)
	if err != nil {
		return result, errors.New("retention.artifact_binding_invalid")
	}
	var tree yaml.Node
	if yaml.Unmarshal(configuration, &tree) != nil || retentionHasEnvironment(&tree) {
		return result, errors.New("retention.configuration_invalid")
	}
	config, err := appconfig.ParseConfig(configuration)
	if err != nil {
		return result, errors.New("retention.configuration_invalid")
	}
	decodedKey, err := base64.StdEncoding.DecodeString(config.Server.TenantEncryptionKey)
	if err != nil || len(decodedKey) != 32 {
		return result, errors.New("retention.configuration_invalid")
	}
	key := retentionMAC(decodedKey, []byte("tauth.retention.audit-key.v1"))
	if request.Operation == "resolve-binding" {
		resolution, err := resolveRetentionBinding(config.Server.DatabaseURL, request.NativeMounts)
		if err != nil {
			return result, err
		}
		resolution.ConfigDigest, resolution.AuditorArtifactDigest = retentionSHA(configuration), retentionSHA(artifact)
		result = RetentionAuditResult{Schema: retentionResultSchema, Operation: request.Operation, Status: "resolved", Resolution: &resolution}
		result.Proof = retentionSign(key, result)
		return result, nil
	}
	if retentionSHA(configuration) != request.Binding.ConfigDigest {
		return result, errors.New("retention.config_binding_invalid")
	}
	if retentionSHA(artifact) != request.Binding.AuditorArtifactDigest {
		return result, errors.New("retention.artifact_binding_invalid")
	}
	if config.Server.DatabaseURL != request.Binding.DatabaseURL {
		return result, errors.New("retention.configuration_invalid")
	}
	store, err := OpenExisting(ctx, "sqlite://"+request.DatabasePath+"?mode=ro", config.Server.TenantEncryptionKey)
	if err != nil {
		return result, errors.New("retention.database_unavailable")
	}
	defer func() {
		if err := store.Close(); err != nil {
			result = RetentionAuditResult{}
			auditErr = errors.Join(auditErr, errors.New("retention.database_close_failed"))
		}
	}()
	if request.Baseline != nil {
		baseline := *request.Baseline
		seal := baseline.Seal
		baseline.Seal = ""
		if baseline.Schema != retentionFrameSchema || !hmac.Equal([]byte(seal), []byte(retentionSign(key, baseline))) {
			return result, errors.New("retention.baseline_invalid")
		}
		priorBinding, currentBinding := baseline.Binding, request.Binding
		priorBinding.AcquisitionID, currentBinding.AcquisitionID = "", ""
		if priorBinding != currentBinding {
			return result, errors.New("retention.binding_changed")
		}
	}
	frame, err := store.captureRetention(ctx, request.Binding, key)
	if err != nil {
		return result, err
	}
	result = RetentionAuditResult{Schema: retentionResultSchema, Operation: request.Operation, Status: "captured", Capture: &frame}
	encodedFrame, err := json.Marshal(frame)
	if err != nil {
		return RetentionAuditResult{}, errors.New("retention.capture_encoding_failed")
	}
	result.CaptureDigest = retentionSHA(encodedFrame)
	if request.Baseline != nil {
		if err := compareRetention(*request.Baseline, frame); err != nil {
			return RetentionAuditResult{}, err
		}
		result.Status = "retained"
		encoded, _ := json.Marshal(request.Baseline)
		result.BaselineDigest = retentionSHA(encoded)
	}
	result.Proof = retentionSign(key, result)
	return result, nil
}

func validateRetentionRequest(request RetentionAuditRequest) error {
	binding := request.Binding
	if request.Schema == retentionRequestSchema && request.Operation == "resolve-binding" && filepath.IsAbs(request.ServiceConfig) && request.DatabasePath == "" && binding == (RetentionAuditBinding{}) && request.Baseline == nil && len(request.NativeMounts) > 0 {
		for _, mount := range request.NativeMounts {
			if !filepath.IsAbs(mount.Source) || !filepath.IsAbs(mount.Target) {
				return errors.New("retention.request_invalid")
			}
		}
		return nil
	}
	if request.Schema != retentionRequestSchema || (request.Operation != "capture" && request.Operation != "verify") || (request.Operation == "verify") != (request.Baseline != nil) || !filepath.IsAbs(request.ServiceConfig) || !filepath.IsAbs(request.DatabasePath) || !filepath.IsAbs(binding.StorageSource) || !filepath.IsAbs(binding.StorageTarget) || !retentionHandoffPattern.MatchString(binding.HandoffID) || strings.TrimSpace(binding.AcquisitionID) == "" || !retentionContainerPattern.MatchString(binding.ContainerID) {
		return errors.New("retention.request_invalid")
	}
	if len(request.NativeMounts) != 0 {
		return errors.New("retention.request_invalid")
	}
	for _, digest := range []string{binding.CandidateDigest, binding.ImageID, binding.ConfigDigest, binding.AuditorArtifactDigest} {
		if !retentionDigestPattern.MatchString(digest) {
			return errors.New("retention.request_invalid")
		}
	}
	parsed, err := url.Parse(binding.DatabaseURL)
	if err != nil || parsed.Scheme != "sqlite" || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" || !filepath.IsAbs(parsed.Path) {
		return errors.New("retention.database_binding_invalid")
	}
	relative, err := filepath.Rel(binding.StorageTarget, parsed.Path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.Join(binding.StorageSource, relative) != request.DatabasePath || strings.ContainsAny(request.DatabasePath, "?#") {
		return errors.New("retention.database_binding_invalid")
	}
	return nil
}

func retentionHasEnvironment(node *yaml.Node) bool {
	if node.Kind == yaml.ScalarNode && retentionEnvironmentPattern.MatchString(node.Value) {
		return true
	}
	for _, child := range node.Content {
		if retentionHasEnvironment(child) {
			return true
		}
	}
	return false
}

func resolveRetentionBinding(databaseURL string, mounts []RetentionAuditMount) (RetentionAuditResolution, error) {
	resolution := RetentionAuditResolution{DatabaseURL: databaseURL}
	parsed, err := url.Parse(databaseURL)
	if err != nil || parsed.Scheme != "sqlite" || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" || !filepath.IsAbs(parsed.Path) {
		return resolution, errors.New("retention.database_binding_invalid")
	}
	selected := -1
	for _, mount := range mounts {
		relative, err := filepath.Rel(mount.Target, parsed.Path)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			continue
		}
		length := len(filepath.Clean(mount.Target))
		if length == selected {
			return resolution, errors.New("retention.database_binding_ambiguous")
		}
		if length > selected {
			selected = length
			resolution.StorageSource, resolution.StorageTarget = mount.Source, mount.Target
			resolution.DatabasePath = filepath.Join(mount.Source, relative)
		}
	}
	if selected < 0 {
		return resolution, errors.New("retention.database_binding_invalid")
	}
	return resolution, nil
}

func retentionSHA(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func retentionMAC(key, value []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(value)
	return mac.Sum(nil)
}
func retentionSign(key []byte, value any) string {
	encoded, _ := json.Marshal(value)
	return "hmac-sha256:" + hex.EncodeToString(retentionMAC(key, encoded))
}

func (store *Store) captureRetention(ctx context.Context, binding RetentionAuditBinding, key []byte) (RetentionAuditFrame, error) {
	frame := RetentionAuditFrame{Schema: retentionFrameSchema, Binding: binding, CapturedUnix: time.Now().UTC().Unix(), Tables: []RetentionAuditTable{}}
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var schema []struct {
			Type  string
			Name  string
			Table string `gorm:"column:tbl_name"`
			SQL   string
		}
		if err := tx.Raw("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").Scan(&schema).Error; err != nil {
			return errors.New("retention.database_read_failed")
		}
		frame.SchemaDigest = retentionSign(key, schema)
		snapshot := &Store{db: tx, cipher: store.cipher, keyID: store.keyID, digestKey: store.digestKey}
		for _, item := range schema {
			if item.Type != "table" {
				continue
			}
			policy, known := retentionTables[item.Name]
			if !known {
				return errors.New("retention.schema_unclassified")
			}
			table, err := captureRetentionTable(tx, item.Name, policy, key)
			if err != nil {
				return err
			}
			frame.Tables = append(frame.Tables, table)
		}
		if err := snapshot.validateRetentionConfigurations(ctx); err != nil {
			return errors.New("retention.configuration_invalid")
		}
		return nil
	}, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return RetentionAuditFrame{}, err
	}
	if err := validateRetentionLineage(frame); err != nil {
		return RetentionAuditFrame{}, err
	}
	frame.Seal = retentionSign(key, frame)
	return frame, nil
}

func (store *Store) validateRetentionConfigurations(ctx context.Context) error {
	if _, err := store.RuntimeTenants(ctx); err != nil {
		return err
	}
	var secrets []secretRecord
	if err := store.db.Find(&secrets).Error; err != nil {
		return err
	}
	for _, secret := range secrets {
		ref, err := NewSecretReference(secret.TenantID, secret.ID, secret.Purpose)
		if err != nil {
			return err
		}
		if _, err := store.LoadSecret(ctx, ref); err != nil {
			return err
		}
	}
	var records []configurationRecord
	if err := store.db.Find(&records).Error; err != nil {
		return err
	}
	for _, record := range records {
		var reference configurationReference
		if err := json.Unmarshal([]byte(record.Configuration), &reference); err != nil {
			return err
		}
		ref, err := NewSecretReference(record.TenantID, reference.SecretID, configurationPurpose)
		if err != nil {
			return err
		}
		data, err := store.LoadSecret(ctx, ref)
		if err != nil {
			return err
		}
		var tenant tenants.FileTenant
		if err := json.Unmarshal(data, &tenant); err != nil {
			return err
		}
		if tenant.ID != record.TenantID {
			return errors.New("retention.tenant_binding_invalid")
		}
		if _, err := tenants.LoadResolvedConfig(tenants.FileDocument{Tenants: []tenants.FileTenant{tenant}}); err != nil {
			return err
		}
	}
	return nil
}

func captureRetentionTable(database *gorm.DB, name string, policy retentionTablePolicy, key []byte) (RetentionAuditTable, error) {
	table := RetentionAuditTable{Name: name, Rows: []RetentionAuditRow{}}
	var columns []struct {
		Name string
		PK   int
	}
	if err := database.Raw("PRAGMA table_info(\"" + name + "\")").Scan(&columns).Error; err != nil {
		return table, errors.New("retention.database_read_failed")
	}
	var records []map[string]any
	if err := database.Table(name).Find(&records).Error; err != nil {
		return table, errors.New("retention.database_read_failed")
	}
	for _, record := range records {
		identity := map[string]any{}
		for _, column := range columns {
			if column.PK > 0 {
				identity[column.Name] = record[column.Name]
			}
		}
		if len(identity) == 0 {
			return table, errors.New("retention.schema_unclassified")
		}
		row := RetentionAuditRow{ID: retentionRowID(key, name, identity), Digest: retentionSign(key, record)}
		if policy.expiry != "" {
			row.Expires = retentionInteger(record[policy.expiry])
			if policy.expiry == "expires_unix_nano" {
				row.Expires /= int64(time.Second)
			}
		}
		stable := make(map[string]any, len(record))
		for field, value := range record {
			stable[field] = value
		}
		if policy.session || policy.revocable {
			for _, field := range []string{"revoked_at_unix", "rotated_at_unix", "status"} {
				delete(stable, field)
			}
			session := &retentionAuditSession{Group: retentionSign(key, []any{name, record["tenant_id"], record["user_id"]}), Issued: retentionInteger(record["issued_at_unix"]), Revoked: retentionInteger(record["revoked_at_unix"]), Rotated: retentionInteger(record["rotated_at_unix"]), Status: "active"}
			if policy.revocable {
				session.Issued = retentionInteger(record["created_at_unix"])
				if session.Revoked > 0 {
					session.Status = "revoked"
				}
			} else if name == "refresh_tokens" {
				if previous, _ := record["previous_token_id"].(string); previous != "" {
					session.Previous = retentionRowID(key, name, map[string]any{"token_id": previous})
				}
				if session.Revoked > 0 {
					session.Status = "revoked"
				}
			} else {
				session.Status, _ = record["status"].(string)
				session.Family = retentionSign(key, []any{record["family_id"], record["consent_id"], record["client_id"], record["resource"], record["scope"], record["disclosure_policy"]})
			}
			row.Session = session
		}
		row.Stable = retentionSign(key, stable)
		table.Rows = append(table.Rows, row)
	}
	sort.Slice(table.Rows, func(left, right int) bool { return table.Rows[left].ID < table.Rows[right].ID })
	return table, nil
}

func retentionRowID(key []byte, table string, primary map[string]any) string {
	return retentionSign(key, []any{table, primary})
}
func retentionInteger(value any) int64 {
	switch value := value.(type) {
	case int64:
		return value
	case int:
		return int64(value)
	default:
		return 0
	}
}

func validateRetentionLineage(frame RetentionAuditFrame) error {
	for _, table := range frame.Tables {
		if !retentionTables[table.Name].session {
			continue
		}
		rows := make(map[string]RetentionAuditRow, len(table.Rows))
		for _, row := range table.Rows {
			rows[row.ID] = row
		}
		for _, row := range table.Rows {
			session := row.Session
			if session == nil || (session.Status != "active" && session.Status != "rotated" && session.Status != "revoked") {
				return errors.New("retention.session_lineage_invalid")
			}
			if session.Previous != "" {
				parent, exists := rows[session.Previous]
				if !exists || parent.Session == nil || parent.Session.Group != session.Group || parent.Session.Revoked == 0 || parent.Session.Issued > session.Issued || parent.ID == row.ID {
					return errors.New("retention.session_lineage_invalid")
				}
				seen := map[string]bool{row.ID: true}
				for ancestor := parent; ; {
					if seen[ancestor.ID] {
						return errors.New("retention.session_lineage_invalid")
					}
					seen[ancestor.ID] = true
					if ancestor.Session.Previous == "" {
						break
					}
					ancestor, exists = rows[ancestor.Session.Previous]
					if !exists || ancestor.Session == nil {
						return errors.New("retention.session_lineage_invalid")
					}
				}
			}
			if session.Status == "rotated" {
				found := false
				for _, successor := range table.Rows {
					if successor.ID != row.ID && successor.Session.Status != "rotated" && successor.Session.Group == session.Group && successor.Session.Family == session.Family && successor.Session.Issued >= session.Rotated && successor.Session.Issued >= session.Issued {
						found = true
						break
					}
				}
				if !found {
					return errors.New("retention.session_lineage_invalid")
				}
			}
		}
	}
	return nil
}

func compareRetention(before, after RetentionAuditFrame) error {
	if before.CapturedUnix > after.CapturedUnix || before.SchemaDigest != after.SchemaDigest {
		return errors.New("retention.changed_during_window")
	}
	current := map[string]map[string]RetentionAuditRow{}
	for _, table := range after.Tables {
		rows := map[string]RetentionAuditRow{}
		for _, row := range table.Rows {
			rows[row.ID] = row
		}
		current[table.Name] = rows
	}
	for _, table := range before.Tables {
		policy, known := retentionTables[table.Name]
		if !known {
			return errors.New("retention.baseline_invalid")
		}
		for _, prior := range table.Rows {
			row, exists := current[table.Name][prior.ID]
			if !exists {
				if prior.Expires > 0 && prior.Expires <= after.CapturedUnix {
					continue
				}
				if policy.session {
					return errors.New("retention.active_session_missing")
				}
				return errors.New("retention.data_missing")
			}
			if row.Digest == prior.Digest {
				continue
			}
			if (policy.session || policy.revocable) && row.Stable == prior.Stable && prior.Session != nil && row.Session != nil && row.Session.Revoked >= prior.Session.Revoked && row.Session.Rotated >= prior.Session.Rotated {
				changedAt := row.Session.Revoked
				if row.Session.Rotated > changedAt {
					changedAt = row.Session.Rotated
				}
				if changedAt >= before.CapturedUnix && changedAt <= after.CapturedUnix && !reflect.DeepEqual(row.Session, prior.Session) && row.Session.Status != "active" {
					continue
				}
			}
			return errors.New("retention.changed_during_window")
		}
	}
	return nil
}

package retentionaudit_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/oauthserver"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

func TestPublicRetentionAuditCLI(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "tauth-retention-audit")
	build := exec.CommandContext(t.Context(), "make", "build-retention-audit", "RETENTION_AUDIT_OUTPUT="+binary)
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build public retention audit: %v\n%s", err, output)
	}
	fixture := filepath.Join(t.TempDir(), "tauth-test-fixture")
	build = exec.CommandContext(t.Context(), "make", "build-test-fixture", "TEST_FIXTURE_OUTPUT="+fixture)
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fixture: %v\n%s", err, output)
	}
	for _, scenario := range []string{"unchanged", "append", "fresh-acquisition", "missing-account", "changed-key", "missing-configuration", "missing-active-session", "expired-session", "rotation", "broken-rotation", "oauth-rotation", "oauth-broken-rotation", "oauth-revocation", "changed-profile", "unknown-table", "tampered-baseline", "wrong-binding", "uncommitted-write"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			input := map[string]any{"schema": "tauth.test-fixture.v1", "test_only": true, "app_id": "retention-app", "server": map[string]any{"listen_addr": ":8081"}, "tenant": map[string]any{"id": "retention-tenant", "display_name": "Retention tenant", "origin": "http://localhost:32123", "google_web_client_id": "fixture-web.apps.googleusercontent.com", "google_native_client_id": "fixture-native.apps.googleusercontent.com", "jwt_signing_key": "synthetic-retention-signing-key", "session_cookie_name": "retention_session", "refresh_cookie_name": "retention_refresh", "session_ttl": "8h", "refresh_ttl": "720h", "nonce_ttl": "10m"}}
			input["accounts"] = map[string]any{"active": map[string]any{"subject": "fixture-active", "email": "active@example.com", "display_name": "Active", "avatar_url": "https://example.com/avatar.png", "state": "active"}, "disabled": map[string]any{"subject": "fixture-disabled", "email": "disabled@example.com", "display_name": "Disabled", "avatar_url": "https://example.com/avatar.png", "state": "disabled"}}
			inputPath := filepath.Join(directory, "input.json")
			writeJSON(t, inputPath, input)
			prepared := filepath.Join(directory, "prepared")
			command := exec.CommandContext(t.Context(), fixture, "--input", inputPath, "--output-dir", prepared)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("prepare account fixture: %v\n%s", err, output)
			}
			var receipt struct {
				Accounts map[string]struct {
					UserID string `json:"user_id"`
				} `json:"accounts"`
			}
			readJSON(t, filepath.Join(prepared, "receipt.json"), &receipt)
			databasePath := filepath.Join(prepared, "tauth.db")
			databaseURL := "sqlite://" + databasePath
			refresh, err := authkit.NewDatabaseRefreshTokenStore(t.Context(), databaseURL)
			if err != nil {
				t.Fatal(err)
			}
			var oauth *oauthserver.DatabaseStore
			var oauthToken string
			if strings.HasPrefix(scenario, "oauth-") {
				oauth, err = oauthserver.NewDatabaseStore(t.Context(), databaseURL)
				if err != nil {
					t.Fatal(err)
				}
				now := time.Now().Unix()
				consent, err := oauth.SaveConsent(t.Context(), oauthserver.Consent{ConsentKey: oauthserver.ConsentKey{TenantID: "retention-tenant", UserID: receipt.Accounts["active"].UserID, ClientID: "https://client.example.com", Resource: "https://api.example.com", Scope: "read"}, CreatedAtUnix: now, ExpiresAtUnix: now + 3600})
				if err != nil {
					t.Fatal(err)
				}
				oauthToken, err = oauth.IssueRefreshToken(t.Context(), oauthserver.RefreshGrant{TenantID: "retention-tenant", UserID: receipt.Accounts["active"].UserID, ConsentID: consent.ID, ClientID: "https://client.example.com", Resource: "https://api.example.com", Scope: "read", ExpiresAtUnix: now + 3600}, now)
				if err != nil {
					t.Fatal(err)
				}
			}
			tokenID, _, err := refresh.Issue(t.Context(), "retention-tenant", receipt.Accounts["active"].UserID, time.Now().Add(time.Hour).Unix(), "")
			if err != nil {
				t.Fatal(err)
			}
			database, err := authkit.OpenControlDatabase(t.Context(), databaseURL)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := database.DB()
			t.Cleanup(func() { _ = raw.Close() })
			if scenario == "expired-session" {
				execute(t, database, "UPDATE refresh_tokens SET expires_unix=? WHERE token_id=?", time.Now().Add(-time.Hour).Unix(), tokenID)
			}
			configPath := filepath.Join(prepared, "service.yaml")
			config, _ := os.ReadFile(configPath)
			artifact, _ := os.ReadFile(binary)
			binding := map[string]any{"handoff_id": "retained-authority", "candidate_digest": digest([]byte("candidate")), "acquisition_id": "retention-acquisition", "container_id": strings.Repeat("1", 64), "image_id": "sha256:" + strings.Repeat("2", 64), "config_digest": digest(config), "database_url": "sqlite:///tauth-fixture/tauth.db", "storage_source": prepared, "storage_target": "/tauth-fixture", "auditor_artifact_digest": digest(artifact)}
			request := map[string]any{"schema": "tauth.retention.request.v1", "operation": "capture", "service_config": configPath, "database_path": databasePath, "binding": binding}
			resolution := invoke(t, binary, map[string]any{"schema": "tauth.retention.request.v1", "operation": "resolve-binding", "service_config": configPath, "native_mounts": []map[string]string{{"source": directory, "target": "/"}, {"source": prepared, "target": "/tauth-fixture"}}}, "resolved")
			resolved := resolution["resolution"].(map[string]any)
			if _, present := resolution["capture_digest"]; present {
				t.Fatal("binding resolution must not claim a database capture")
			}
			if resolved["database_path"] != databasePath || resolved["database_url"] != binding["database_url"] || resolved["storage_source"] != prepared || resolved["config_digest"] != binding["config_digest"] || resolved["auditor_artifact_digest"] != binding["auditor_artifact_digest"] {
				t.Fatal("service-owned native binding resolution differs")
			}
			before := logicalSnapshot(t, database)
			captured := invoke(t, binary, request, "captured")
			if logicalSnapshot(t, database) != before {
				t.Fatal("capture mutated database")
			}
			frame := captured["capture"].(map[string]any)
			if captured["capture_digest"] == nil || captured["capture_digest"] == "" {
				t.Fatal("capture lacks its native frame digest")
			}
			if scenario == "unchanged" {
				request["unknown_field"] = true
				invoke(t, binary, request, "retention.request_invalid")
				delete(request, "unknown_field")
				binding["auditor_artifact_digest"] = digest([]byte("wrong-artifact"))
				invoke(t, binary, request, "retention.artifact_binding_invalid")
				binding["auditor_artifact_digest"] = digest(artifact)
				request["database_path"] = filepath.Join(directory, "other.db")
				invoke(t, binary, request, "retention.database_binding_invalid")
				request["database_path"] = databasePath
				invoke(t, binary, map[string]any{"schema": "tauth.retention.request.v1", "operation": "resolve-binding", "service_config": configPath, "native_mounts": []map[string]string{{"source": directory, "target": "/tauth-fixture"}, {"source": prepared, "target": "/tauth-fixture"}}}, "retention.database_binding_ambiguous")
				var service map[string]any
				if err := yaml.Unmarshal(config, &service); err != nil {
					t.Fatal(err)
				}
				key := service["server"].(map[string]any)["tenant_encryption_key"].(string)
				t.Setenv("TAUTH_AUDIT_TEST_KEY", key)
				writeBytes(t, configPath, bytes.Replace(config, []byte(key), []byte("${TAUTH_AUDIT_TEST_KEY}"), 1))
				invoke(t, binary, request, "retention.configuration_invalid")
				writeBytes(t, configPath, config)
			}
			encoded, _ := json.Marshal(captured)
			for _, secret := range []string{"active@example.com", "disabled@example.com", "synthetic-retention-signing-key", receipt.Accounts["active"].UserID} {
				if bytes.Contains(encoded, []byte(secret)) {
					t.Fatal("audit exposed private record values")
				}
			}
			expected := "retained"
			switch scenario {
			case "fresh-acquisition":
				binding["acquisition_id"] = "next-acquisition"
			case "missing-account":
				execute(t, database, "DELETE FROM accounts WHERE user_id=?", receipt.Accounts["active"].UserID)
				expected = "retention.data_missing"
			case "changed-key":
				execute(t, database, "UPDATE tenant_secrets SET encryption_key_id='changed'")
				expected = "retention.configuration_invalid"
			case "missing-configuration":
				execute(t, database, "DELETE FROM tenant_secrets WHERE tenant_id='retention-tenant'")
				expected = "retention.configuration_invalid"
			case "missing-active-session":
				execute(t, database, "DELETE FROM refresh_tokens WHERE token_id=?", tokenID)
				expected = "retention.active_session_missing"
			case "expired-session":
				execute(t, database, "DELETE FROM refresh_tokens WHERE token_id=?", tokenID)
			case "rotation":
				if _, _, err := refresh.Issue(t.Context(), "retention-tenant", receipt.Accounts["active"].UserID, time.Now().Add(time.Hour).Unix(), tokenID); err != nil {
					t.Fatal(err)
				}
			case "broken-rotation":
				if _, _, err := refresh.Issue(t.Context(), "retention-tenant", receipt.Accounts["active"].UserID, time.Now().Add(time.Hour).Unix(), tokenID); err != nil {
					t.Fatal(err)
				}
				execute(t, database, "UPDATE refresh_tokens SET previous_token_id='absent-parent' WHERE previous_token_id=?", tokenID)
				expected = "retention.session_lineage_invalid"
			case "oauth-rotation", "oauth-broken-rotation":
				if _, _, err := oauth.RotateRefreshToken(t.Context(), oauthToken, "https://client.example.com", "https://api.example.com", "read", time.Now().Unix(), func(context.Context, string, string) error { return nil }); err != nil {
					t.Fatal(err)
				}
				if scenario == "oauth-broken-rotation" {
					execute(t, database, "UPDATE oauth_refresh_tokens SET family_id='other-family' WHERE status='active'")
					expected = "retention.session_lineage_invalid"
				}
			case "oauth-revocation":
				if err := oauth.RevokeRefreshToken(t.Context(), oauthToken, "https://client.example.com", time.Now().Unix()); err != nil {
					t.Fatal(err)
				}
			case "changed-profile":
				execute(t, database, "UPDATE accounts SET user_display_name='Changed' WHERE user_id=?", receipt.Accounts["active"].UserID)
				expected = "retention.changed_during_window"
			case "unknown-table":
				execute(t, database, "CREATE TABLE unclassified_data(id TEXT PRIMARY KEY)")
				expected = "retention.schema_unclassified"
			case "tampered-baseline":
				frame["captured_unix"] = float64(1)
				expected = "retention.baseline_invalid"
			case "wrong-binding":
				binding["candidate_digest"] = digest([]byte("other-candidate"))
				expected = "retention.binding_changed"
			case "append":
				execute(t, database, "INSERT INTO tenant_audit_events(id,actor_account_id,operation,result) SELECT 'added-event',id,'read','accepted' FROM owner_accounts LIMIT 1")
			case "uncommitted-write":
				transaction := database.Begin()
				if transaction.Error != nil {
					t.Fatal(transaction.Error)
				}
				execute(t, transaction, "UPDATE accounts SET user_display_name='Uncommitted' WHERE user_id=?", receipt.Accounts["active"].UserID)
				defer transaction.Rollback()
			}
			request["operation"], request["baseline"] = "verify", frame
			before = logicalSnapshot(t, database)
			verified := invoke(t, binary, request, expected)
			if logicalSnapshot(t, database) != before {
				t.Fatal("verification mutated database")
			}
			if expected == "retained" && (verified["baseline_digest"] == "" || verified["proof"] == "") {
				t.Fatal("verification lacks bound private proof")
			}
			if expected == "retained" {
				if verified["baseline_digest"] != captured["capture_digest"] {
					t.Fatal("verification does not bind the original native capture digest")
				}
				request["baseline"] = verified["capture"]
				repeated := invoke(t, binary, request, "retained")
				if verified["capture_digest"] == nil || repeated["baseline_digest"] != verified["capture_digest"] {
					t.Fatal("verification frame cannot serve as the next native baseline")
				}
				if logicalSnapshot(t, database) != before {
					t.Fatal("repeated verification mutated database")
				}
			}
		})
	}
}

func digest(content []byte) string {
	value := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(value[:])
}
func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(file).Encode(value); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeBytes(t *testing.T, path string, value []byte) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(value); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
func readJSON(t *testing.T, path string, value any) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(content, value); err != nil {
		t.Fatal(err)
	}
}
func execute(t *testing.T, database *gorm.DB, statement string, args ...any) {
	t.Helper()
	if err := database.Exec(statement, args...).Error; err != nil {
		t.Fatal(err)
	}
}
func invoke(t *testing.T, binary string, request any, expected string) map[string]any {
	t.Helper()
	content, _ := json.Marshal(request)
	command := exec.CommandContext(t.Context(), binary)
	command.Stdin = bytes.NewReader(content)
	output, err := command.CombinedOutput()
	if expected != "captured" && expected != "retained" && expected != "resolved" {
		if err == nil || !bytes.Contains(output, []byte(expected)) {
			t.Fatalf("expected %s: %v\n%s", expected, err, output)
		}
		return nil
	}
	if err != nil {
		t.Fatalf("public audit %s: %v\n%s", expected, err, output)
	}
	var result map[string]any
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatal(err)
	}
	if result["status"] != expected {
		t.Fatalf("expected %s: %s", expected, output)
	}
	return result
}
func logicalSnapshot(t *testing.T, database *gorm.DB) string {
	t.Helper()
	var tables []string
	if err := database.Raw("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").Scan(&tables).Error; err != nil {
		t.Fatal(err)
	}
	var result strings.Builder
	for _, table := range tables {
		var rows []map[string]any
		if err := database.Table(table).Find(&rows).Error; err != nil {
			t.Fatal(err)
		}
		content, err := json.Marshal(rows)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&result, "%s:%s\n", table, content)
	}
	return result.String()
}

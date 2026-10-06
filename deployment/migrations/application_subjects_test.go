package migrations_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyemirov/tauth/deployment/migrations"
	"github.com/tyemirov/tauth/internal/authkit"
)

func TestApplicationSubjectsMigrationCLI(t *testing.T) {
	for _, scenario := range []string{"complete", "conflict", "interrupted"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			database := filepath.Join(root, "tauth.db")
			key := filepath.Join(root, "key")
			plan := filepath.Join(root, "plan.json")
			save := func(path string, payload []byte) {
				t.Helper()
				file, err := os.Create(path)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = file.Write(payload); err != nil {
					t.Fatal(err)
				}
				if err = file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			save(key, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))))
			planBytes := []byte(`{"id":"20261006-application-subjects","schema":"application-subjects"}`)
			save(plan, planBytes)
			db, err := authkit.OpenControlDatabase(context.Background(), "sqlite://"+database)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := db.DB()
			if err != nil {
				t.Fatal(err)
			}
			statements := []string{
				`CREATE TABLE accounts (tenant_id TEXT NOT NULL,account_id TEXT NOT NULL,user_email TEXT NOT NULL,user_display_name TEXT NOT NULL,display_name_override TEXT,user_avatar_url TEXT NOT NULL,account_state TEXT NOT NULL,user_roles TEXT NOT NULL,created_at_unix INTEGER NOT NULL,last_updated_unix INTEGER NOT NULL,PRIMARY KEY(tenant_id,account_id))`,
				`CREATE TABLE account_identities (tenant_id TEXT NOT NULL,provider TEXT NOT NULL,provider_id TEXT NOT NULL,account_id TEXT NOT NULL,created_at_unix INTEGER NOT NULL,last_updated_unix INTEGER NOT NULL,PRIMARY KEY(tenant_id,provider,provider_id))`,
				`CREATE TABLE user_profiles (tenant_id TEXT NOT NULL,user_id TEXT NOT NULL,user_email TEXT NOT NULL,user_display_name TEXT NOT NULL,user_avatar_url TEXT NOT NULL,user_roles TEXT NOT NULL,created_at_unix INTEGER NOT NULL,last_updated_unix INTEGER NOT NULL,PRIMARY KEY(tenant_id,user_id))`,
				`CREATE TABLE deployment_migrations (id TEXT PRIMARY KEY,plan_digest TEXT,key_id TEXT,completed_at datetime)`,
				`INSERT INTO deployment_migrations VALUES ('20260930-tenant-console','retained-plan','retained-key','2026-09-30T00:00:00Z')`,
				`CREATE TABLE retained_settings (id TEXT PRIMARY KEY,value TEXT NOT NULL)`,
				`INSERT INTO retained_settings VALUES ('session-key','existing-key'),('tenant-settings','existing-settings')`,
				`INSERT INTO accounts VALUES ('parent','AAAAAAAAAAAAAAAAAAAAAA','owner@example.com','Managed','Parent chosen name','','disabled','["parent"]',1,2)`,
				`INSERT INTO account_identities VALUES ('parent','google','managed','AAAAAAAAAAAAAAAAAAAAAA',1,2)`,
				`INSERT INTO user_profiles VALUES ('parent','AAAAAAAAAAAAAAAAAAAAAA','owner@example.com','Managed','','["parent"]',1,2)`,
				`INSERT INTO user_profiles VALUES ('parent','google:unmanaged','second@example.com','Unmanaged','','["parent"]',1,2)`,
			}
			if scenario == "conflict" {
				statements = append(statements, `INSERT INTO user_profiles VALUES ('parent','google:managed','owner@example.com','Conflicting issued subject','','[]',1,2)`)
			}
			if scenario == "interrupted" {
				statements = append(statements, `CREATE TRIGGER reject_application_receipt BEFORE INSERT ON deployment_migrations WHEN NEW.id='20261006-application-subjects' BEGIN SELECT RAISE(ABORT, 'injected receipt failure'); END`)
			}
			for _, statement := range statements {
				if err = db.Exec(statement).Error; err != nil {
					t.Fatal(err)
				}
			}
			if err = raw.Close(); err != nil {
				t.Fatal(err)
			}
			run := func(extra ...string) ([]byte, error) {
				command := migrations.NewCommand()
				var out bytes.Buffer
				command.SetOut(&out)
				command.SetErr(&out)
				command.SetArgs(append([]string{"application-subjects", "--database", "sqlite://" + database, "--key-file", key, "--plan", plan}, extra...))
				err := command.Execute()
				return out.Bytes(), err
			}
			before, err := os.ReadFile(database)
			if err != nil {
				t.Fatal(err)
			}
			output, err := run("--status")
			if err != nil {
				t.Fatal(err)
			}
			var status struct {
				Completed bool `json:"completed"`
			}
			if err = json.Unmarshal(output, &status); err != nil || status.Completed {
				t.Fatal("pending status", string(output), err)
			}
			unchanged, err := os.ReadFile(database)
			if err != nil || !bytes.Equal(before, unchanged) {
				t.Fatal("status wrote database", err)
			}
			_, err = run()
			if scenario != "complete" {
				if err == nil {
					t.Fatal("rejected scenario completed")
				}
				unchanged, readErr := os.ReadFile(database)
				if readErr != nil || !bytes.Equal(before, unchanged) {
					t.Fatal("failed migration changed source", readErr)
				}
				output, statusErr := run("--status")
				if statusErr != nil || json.Unmarshal(output, &status) != nil || status.Completed {
					t.Fatal("failure recorded completion", string(output), statusErr)
				}
				leftovers, _ := filepath.Glob(database + ".20261006-application-subjects-candidate*")
				if len(leftovers) != 0 {
					t.Fatal("candidate preserved", leftovers)
				}
				if scenario == "conflict" {
					return
				}
				db, err = authkit.OpenControlDatabase(context.Background(), "sqlite://"+database)
				if err != nil {
					t.Fatal(err)
				}
				if err = db.Exec("DROP TRIGGER reject_application_receipt").Error; err != nil {
					t.Fatal(err)
				}
				raw, _ = db.DB()
				raw.Close()
				_, err = run()
			}
			if err != nil {
				t.Fatal(err)
			}
			db, err = authkit.OpenControlDatabase(context.Background(), "sqlite://"+database+"?mode=ro")
			if err != nil {
				t.Fatal(err)
			}
			raw, _ = db.DB()
			var rows []struct {
				AccountID, UserID, AccountState, UserRoles string
				DisplayNameOverride                        string
			}
			if err = db.Table("accounts").Order("user_id").Find(&rows).Error; err != nil {
				t.Fatal(err)
			}
			if len(rows) != 2 || rows[0].AccountID != "AAAAAAAAAAAAAAAAAAAAAA" || rows[0].UserID != "AAAAAAAAAAAAAAAAAAAAAA" || rows[0].AccountState != "disabled" || rows[0].DisplayNameOverride != "Parent chosen name" || rows[0].UserRoles != `["parent"]` || rows[1].UserID != "google:unmanaged" || rows[1].AccountID == rows[1].UserID {
				t.Fatal("subject or managed state changed", rows)
			}
			var preserved []struct{ ID, Value string }
			db.Table("retained_settings").Order("id").Find(&preserved)
			if len(preserved) != 2 || preserved[0].Value != "existing-key" || preserved[1].Value != "existing-settings" {
				t.Fatal("settings changed", preserved)
			}
			var receipt struct{ PlanDigest, KeyID string }
			db.Table("deployment_migrations").Where("id=?", "20260930-tenant-console").Take(&receipt)
			if receipt.PlanDigest != "retained-plan" || receipt.KeyID != "retained-key" {
				t.Fatal("old receipt changed", receipt)
			}
			raw.Close()
			committed, _ := os.ReadFile(database)
			if _, err = run(); err != nil {
				t.Fatal(err)
			}
			unchanged, _ = os.ReadFile(database)
			if !bytes.Equal(committed, unchanged) {
				t.Fatal("repeat changed database")
			}
			save(plan, []byte(`{"id":"20261006-application-subjects","schema":"changed"}`))
			if _, err = run("--status"); err == nil {
				t.Fatal("changed plan accepted")
			}
			save(plan, planBytes)
			save(key, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))))
			if _, err = run("--status"); err == nil || !strings.Contains(err.Error(), "receipt_conflict") {
				t.Fatal("changed key accepted", err)
			}
		})
	}
}

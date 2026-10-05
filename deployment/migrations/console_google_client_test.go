package migrations_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tyemirov/tauth/deployment/migrations"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/controlplane"
)

func TestConsoleGoogleClientMigrationCLI(t *testing.T) {
	for _, scenario := range []string{"complete", "wrong-client", "wrong-origin", "interrupted", "already-replaced"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("TAUTH_AUTOMATIC_DEPLOYMENT_ROOT", root)
			TestAutomaticDeploymentFixture(t)
			database := filepath.Join(root, "tauth.db")
			key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
			run := func(name, plan string, extra ...string) error {
				command := migrations.NewCommand()
				command.SetOut(&bytes.Buffer{})
				command.SetErr(&bytes.Buffer{})
				command.SetArgs(append([]string{name, "--database", "sqlite://" + database, "--key-file", filepath.Join(root, "key"), "--plan", plan}, extra...))
				return command.Execute()
			}
			if err := run("cutover", filepath.Join(root, "plan.json"), "--source", filepath.Join(root, "source.yaml")); err != nil {
				t.Fatal(err)
			}
			read := func() any {
				store, err := controlplane.OpenExisting(context.Background(), "sqlite://"+database, key)
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close()
				file, err := store.Console(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				return file
			}
			before := read()
			beforeJSON, _ := json.Marshal(before)
			db, err := authkit.OpenControlDatabase(context.Background(), "sqlite://"+database)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := db.DB()
			snapshot := func() map[string][]map[string]any {
				result := map[string][]map[string]any{}
				var tables []string
				if err := db.Raw("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != 'console_bootstraps' ORDER BY name").Scan(&tables).Error; err != nil {
					t.Fatal(err)
				}
				for _, table := range tables {
					if db.Migrator().HasTable(table) {
						var rows []map[string]any
						if err := db.Table(table).Find(&rows).Error; err != nil {
							t.Fatal(err)
						}
						result[table] = rows
					}
				}
				return result
			}
			preserved := snapshot()
			raw.Close()
			expected := "existing-google-client"
			origin := "https://console.example.com"
			replacement := "corrected-console.apps.googleusercontent.com"
			if scenario == "wrong-client" {
				expected = "another-client"
			}
			if scenario == "wrong-origin" {
				origin = "https://unrelated.example.com"
			}
			if scenario == "already-replaced" {
				store, e := controlplane.OpenExisting(context.Background(), "sqlite://"+database, key)
				if e != nil {
					t.Fatal(e)
				}
				if e = store.ReplaceConsoleGoogleClient(context.Background(), expected, replacement); e != nil {
					t.Fatal(e)
				}
				store.Close()
			}
			plan := filepath.Join(root, "console-plan.json")
			payload, _ := json.Marshal(map[string]string{"expected_client_id": expected, "client_id": replacement, "console_origin": origin})
			file, err := os.Create(plan)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = file.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err = file.Close(); err != nil {
				t.Fatal(err)
			}
			if scenario == "interrupted" {
				db, e := authkit.OpenControlDatabase(context.Background(), "sqlite://"+database)
				if e != nil {
					t.Fatal(e)
				}
				if e = db.Exec("CREATE TRIGGER reject_console_receipt BEFORE INSERT ON deployment_migrations WHEN NEW.id='20261005-console-google-client' BEGIN SELECT RAISE(ABORT, 'injected receipt failure'); END").Error; e != nil {
					t.Fatal(e)
				}
				r, _ := db.DB()
				r.Close()
			}
			attemptBytes, err := os.ReadFile(database)
			if err != nil {
				t.Fatal(err)
			}
			err = run("console-google-client", plan)
			if scenario == "wrong-client" || scenario == "wrong-origin" || scenario == "already-replaced" {
				if err == nil || !strings.Contains(err.Error(), "conflict") {
					t.Fatalf("expected conflict: %v", err)
				}
				if scenario != "already-replaced" && !reflect.DeepEqual(before, read()) {
					t.Fatal("conflict changed console")
				}
				unchanged, readErr := os.ReadFile(database)
				if readErr != nil || !bytes.Equal(attemptBytes, unchanged) {
					t.Fatal("rejection changed live database", readErr)
				}
				return
			}
			if scenario == "interrupted" {
				if err == nil || !strings.Contains(err.Error(), "injected receipt failure") {
					t.Fatalf("expected injected failure: %v", err)
				}
				if !reflect.DeepEqual(before, read()) {
					t.Fatal("failed candidate changed live console")
				}
				unchanged, readErr := os.ReadFile(database)
				if readErr != nil || !bytes.Equal(attemptBytes, unchanged) {
					t.Fatal("interruption changed live database", readErr)
				}
				db, e := authkit.OpenControlDatabase(context.Background(), "sqlite://"+database)
				if e != nil {
					t.Fatal(e)
				}
				if e = db.Exec("DROP TRIGGER reject_console_receipt").Error; e != nil {
					t.Fatal(e)
				}
				r, _ := db.DB()
				r.Close()
				err = run("console-google-client", plan)
			}
			if err != nil {
				t.Fatal(err)
			}
			afterJSON, _ := json.Marshal(read())
			expectedJSON := bytes.Replace(beforeJSON, []byte("existing-google-client"), []byte(replacement), 1)
			if !bytes.Equal(afterJSON, expectedJSON) {
				t.Fatalf("console differs beyond client: %s", afterJSON)
			}
			db, err = authkit.OpenControlDatabase(context.Background(), "sqlite://"+database)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ = db.DB()
			defer raw.Close()
			after := snapshot()
			newReceipts := after["deployment_migrations"]
			var old []map[string]any
			for _, row := range newReceipts {
				if row["id"] != "20261005-console-google-client" {
					old = append(old, row)
				}
			}
			after["deployment_migrations"] = old
			if !reflect.DeepEqual(preserved, after) {
				t.Fatal("migration changed retained accounts, tenants, Apps, bindings, or original receipt")
			}
			if err = run("console-google-client", plan); err != nil {
				t.Fatal(err)
			}
			if err = run("console-google-client", plan, "--status"); err != nil {
				t.Fatal(err)
			}

			changedPlan := bytes.Replace(payload, []byte(replacement), []byte("another-console.apps.googleusercontent.com"), 1)
			file, err = os.Create(plan)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = file.Write(changedPlan); err != nil {
				t.Fatal(err)
			}
			if err = file.Close(); err != nil {
				t.Fatal(err)
			}
			if err = run("console-google-client", plan, "--status"); err == nil || !strings.Contains(err.Error(), "receipt_conflict") {
				t.Fatal("changed plan accepted completed receipt", err)
			}
			file, err = os.Create(plan)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = file.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err = file.Close(); err != nil {
				t.Fatal(err)
			}
			file, err = os.Create(filepath.Join(root, "key"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = file.WriteString(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))); err != nil {
				t.Fatal(err)
			}
			if err = file.Close(); err != nil {
				t.Fatal(err)
			}
			if err = run("console-google-client", plan, "--status"); err == nil || !strings.Contains(err.Error(), "receipt_conflict") {
				t.Fatal("changed key accepted completed receipt", err)
			}
		})
	}
}

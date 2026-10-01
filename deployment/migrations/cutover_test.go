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
	"time"

	"github.com/tyemirov/tauth/deployment/migrations"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/controlplane"
)

func TestAutomaticCutoverCLI(t *testing.T) {
	root := t.TempDir()
	database := filepath.Join(root, "tauth.db")
	users, err := authkit.NewDatabaseUserStore(context.Background(), "sqlite://"+database)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := users.UpsertGoogleAccount(context.Background(), "product", authkit.GoogleAccountIdentity{Subject: "123456789", UserEmail: "owner@example.com", DisplayName: "Owner"})
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "source.yaml")
	payload := "server:\n  database_url: sqlite:///data/tauth.db\ntenants:\n  - id: product\n    display_name: Product\n    tenant_origins: [https://console.example.com]\n    google_web_client_id: existing-google-client\n    jwt_signing_key: existing-client-key\n    session_cookie_name: product_session\n    refresh_cookie_name: product_refresh\n    session_ttl: 15m\n    refresh_ttl: 720h\n    account_management:\n      return_challenge_tokens: false\n"
	write := func(path string, value []byte) {
		t.Helper()
		f, e := os.Create(path)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write(value); e != nil {
			t.Fatal(e)
		}
		if e = f.Close(); e != nil {
			t.Fatal(e)
		}
	}
	write(source, []byte(payload))
	keyFile := filepath.Join(root, "key")
	write(keyFile, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))))
	plan := map[string]any{"owner_emails": []string{"owner@example.com"}, "console_origin": "https://console.example.com", "console_source_tenant": "product", "management_url": "https://auth.example.com", "apps": []map[string]any{{"id": "product", "name": "Product", "tenant_ids": []string{"product"}, "contribution_owner": "product", "contribution_id": "authentication"}}}
	encoded, _ := json.Marshal(plan)
	planFile := filepath.Join(root, "plan.json")
	write(planFile, encoded)
	run := func(args ...string) (map[string]any, error) {
		cmd := migrations.NewCommand()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(append([]string{"cutover", "--database", "sqlite://" + database, "--key-file", keyFile, "--plan", planFile}, args...))
		e := cmd.Execute()
		var result map[string]any
		if e == nil {
			e = json.Unmarshal(out.Bytes(), &result)
		}
		return result, e
	}
	before, err := run("--status")
	if err != nil {
		t.Fatal(err)
	}
	if before["completed"] != false {
		t.Fatal("unexpected receipt")
	}
	if _, err = run("--source", source); err != nil {
		t.Fatal(err)
	}
	first, err := run("--status")
	if err != nil {
		t.Fatal(err)
	}
	if first["completed"] != true {
		t.Fatal("missing receipt")
	}
	store, err := controlplane.OpenExisting(context.Background(), "sqlite://"+database, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	tenants, err := store.ApplicationTenants(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tenants.Tenants) != 1 || tenants.Tenants[0].JWTSigningKey != "existing-client-key" {
		t.Fatal("client key changed")
	}
	if _, err = os.Stat(database + ".20260930-before.db"); err != nil {
		t.Fatal("missing backup", err)
	}
	// A repeat needs no obsolete source and never reimports an edited tenant.
	if err = os.Remove(source); err != nil {
		t.Fatal(err)
	}
	again, err := run("--source", source)
	if err != nil {
		t.Fatal(err)
	}
	if again["completed_at"] != first["completed_at"] {
		t.Fatal("migration executed again")
	}
	accounts, err := authkit.NewDatabaseUserStore(context.Background(), "sqlite://"+database)
	if err != nil {
		t.Fatal(err)
	}
	restored, found, err := accounts.AuthenticateGoogleAccount(context.Background(), "product", authkit.GoogleAccountIdentity{Subject: "123456789", UserEmail: "owner@example.com"})
	if err != nil || !found || restored.AccountID != profile.AccountID {
		t.Fatal("existing account changed", err)
	}
	write(keyFile, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))))
	if _, err = run("--status"); err == nil {
		t.Fatal("replacement key accepted")
	}
}

func TestAutomaticCutoverRollbackAndFreshRetry(t *testing.T) {
	root := t.TempDir()
	database := filepath.Join(root, "tauth.db")
	databaseURL := "sqlite://" + database
	users, err := authkit.NewDatabaseUserStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = users.UpsertGoogleAccount(context.Background(), "one", authkit.GoogleAccountIdentity{Subject: "verified-owner", UserEmail: "owner@example.com", DisplayName: "Owner"}); err != nil {
		t.Fatal(err)
	}
	db, err := authkit.OpenControlDatabase(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err = db.Exec("PRAGMA journal_mode=WAL").Error; err != nil {
		t.Fatal(err)
	}
	write := func(name string, payload []byte) string {
		t.Helper()
		path := filepath.Join(root, name)
		f, e := os.Create(path)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write(payload); e != nil {
			t.Fatal(e)
		}
		if e = f.Close(); e != nil {
			t.Fatal(e)
		}
		return path
	}
	key := write("key", []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))))
	prepared, err := controlplane.Open(context.Background(), databaseURL, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if err = prepared.Close(); err != nil {
		t.Fatal(err)
	}
	// Inject a database write failure while keeping the real CLI and migration transactions.
	if err = db.Exec("CREATE TRIGGER cutover_injected_failure BEFORE INSERT ON apps WHEN NEW.id='two' BEGIN SELECT RAISE(ABORT,'injected database write failure'); END").Error; err != nil {
		t.Fatal(err)
	}
	plan := map[string]any{"owner_emails": []string{"owner@example.com"}, "console_origin": "https://console.example.com", "console_source_tenant": "one", "management_url": "https://auth.example.com", "apps": []map[string]any{{"id": "one", "name": "One", "tenant_ids": []string{"one"}, "contribution_owner": "one", "contribution_id": "authentication"}, {"id": "two", "name": "Two", "tenant_ids": []string{"two"}, "contribution_owner": "two", "contribution_id": "authentication"}}}
	payload, _ := json.Marshal(plan)
	planFile := write("plan.json", payload)
	source := `tenants:
  - id: one
    display_name: One
    tenant_origins: [https://one.example.com]
    google_web_client_id: existing-client
    jwt_signing_key: existing-key-one
    session_cookie_name: common_session
    refresh_cookie_name: common_refresh
    cookie_domain: example.com
    session_ttl: 15m
    refresh_ttl: 720h
  - id: two
    display_name: Two
    tenant_origins: [https://two.example.com]
    google_web_client_id: existing-client
    jwt_signing_key: existing-key-two
    session_cookie_name: common_session
    refresh_cookie_name: common_refresh
    cookie_domain: example.com
    session_ttl: 15m
    refresh_ttl: 720h
`
	second := strings.LastIndex(source, "session_cookie_name: common_session")
	source = source[:second] + strings.ReplaceAll(source[second:], "common_", "second_")
	sourceFile := write("source.yaml", []byte(source))
	run := func() error {
		command := migrations.NewCommand()
		var output bytes.Buffer
		command.SetOut(&output)
		command.SetErr(&output)
		command.SetArgs([]string{"cutover", "--database", databaseURL, "--key-file", key, "--plan", planFile, "--source", sourceFile})
		return command.Execute()
	}
	if err = run(); err == nil {
		t.Fatal("injected database write failure ignored")
	}
	var originalTenants int64
	if err = db.Table("tenants").Count(&originalTenants).Error; err != nil {
		t.Fatal(err)
	}
	if originalTenants != 0 {
		t.Fatal("failed migration changed the original database")
	}
	candidate, err := authkit.OpenControlDatabase(context.Background(), "sqlite://"+database+".20260930-staging.db")
	if err != nil {
		t.Fatal(err)
	}
	candidateRaw, err := candidate.DB()
	if err != nil {
		t.Fatal(err)
	}
	var partial int64
	if err = candidate.Table("tenants").Count(&partial).Error; err != nil {
		t.Fatal(err)
	}
	if err = candidateRaw.Close(); err != nil {
		t.Fatal(err)
	}
	if partial != 1 {
		t.Fatal("failure did not exercise a partially migrated candidate")
	}
	// Simulate source writes after an interrupted deployment. The retry must preserve this new account.
	newProfile, err := users.UpsertGoogleAccount(context.Background(), "one", authkit.GoogleAccountIdentity{Subject: "new-user", UserEmail: "new@example.com", DisplayName: "New"})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Exec("DROP TRIGGER cutover_injected_failure").Error; err != nil {
		t.Fatal(err)
	}
	if err = run(); err != nil {
		t.Fatal(err)
	}
	restored, err := authkit.NewDatabaseUserStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	profile, found, err := restored.AuthenticateGoogleAccount(context.Background(), "one", authkit.GoogleAccountIdentity{Subject: "new-user", UserEmail: "new@example.com"})
	if err != nil || !found || profile.AccountID != newProfile.AccountID {
		t.Fatal("retry lost a newly committed source account", err)
	}
}

func TestAutomaticDeploymentFixture(t *testing.T) {
	root := os.Getenv("TAUTH_AUTOMATIC_DEPLOYMENT_ROOT")
	if root == "" {
		t.Skip("container deployment fixture")
	}
	database := filepath.Join(root, "tauth.db")
	users, err := authkit.NewDatabaseUserStore(context.Background(), "sqlite://"+database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = users.UpsertGoogleAccount(context.Background(), "product", authkit.GoogleAccountIdentity{Subject: "verified-google-subject", UserEmail: "owner@example.com", DisplayName: "Owner"}); err != nil {
		t.Fatal(err)
	}
	user, roles, err := users.UpsertGoogleUser(context.Background(), "product", "verified-google-subject", "owner@example.com", "Owner", "")
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := authkit.MintAppJWT(authkit.NewSystemClock(), "product", user, "owner@example.com", "Owner", "", roles, "tauth", []byte("existing-client-key"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	save := func(name string, payload []byte) {
		t.Helper()
		file, e := os.Create(filepath.Join(root, name))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = file.Write(payload); e != nil {
			t.Fatal(e)
		}
		if e = file.Close(); e != nil {
			t.Fatal(e)
		}
	}
	save("session-token", []byte(token))
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	save("key", []byte(key))
	plan := map[string]any{"owner_emails": []string{"owner@example.com"}, "console_origin": "https://console.example.com", "console_source_tenant": "product", "management_url": "https://auth.example.com", "apps": []map[string]any{{"id": "product", "name": "Product", "tenant_ids": []string{"product"}, "contribution_owner": "product", "contribution_id": "authentication"}}}
	payload, _ := json.Marshal(plan)
	save("plan.json", payload)
	cutoverPlan, err := migrations.LoadCutoverPlan(filepath.Join(root, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	save("gateway-token", []byte(cutoverPlan.CredentialMap(bytes.Repeat([]byte{7}, 32))["product"]["authentication"]))
	save("source.yaml", []byte("server:\n  database_url: sqlite:///data/tauth.db\ntenants:\n  - id: product\n    display_name: Product\n    tenant_origins: [https://console.example.com]\n    google_web_client_id: existing-google-client\n    jwt_signing_key: existing-client-key\n    session_cookie_name: product_session\n    refresh_cookie_name: product_refresh\n    session_ttl: 15m\n    refresh_ttl: 720h\n"))
	save("service.yaml", []byte("server:\n  listen_addr: ':8080'\n  database_url: sqlite:///data/tauth.db\n  tenant_encryption_key: "+key+"\n  enable_cors: true\n  cors_allowed_origins: [https://accounts.google.com]\n  cors_allowed_origin_exceptions: [https://accounts.google.com]\n  enable_tenant_header_override: true\n"))
}

func TestAutomaticProductionSnapshotCutover(t *testing.T) {
	evidence := os.Getenv("TAUTH_CUTOVER_REHEARSAL_ROOT")
	if evidence == "" {
		t.Skip("private production-copy qualification")
	}
	sourceRoot := os.Getenv("TAUTH_CUTOVER_CAPTURE_ROOT")
	copyFile := func(from, to string) {
		t.Helper()
		payload, e := os.ReadFile(from)
		if e != nil {
			t.Fatal(e)
		}
		f, e := os.Create(to)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write(payload); e != nil {
			t.Fatal(e)
		}
		if e = f.Close(); e != nil {
			t.Fatal(e)
		}
	}
	database := filepath.Join(evidence, "working.db")
	copyFile(filepath.Join(sourceRoot, "snapshot.db"), database)
	var captured struct {
		Config string   `json:"config"`
		Env    []string `json:"env"`
	}
	payload, err := os.ReadFile(filepath.Join(sourceRoot, "production-inputs.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(payload, &captured); err != nil {
		t.Fatal(err)
	}
	save := func(name string, value []byte) string {
		t.Helper()
		path := filepath.Join(evidence, name)
		f, e := os.Create(path)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write(value); e != nil {
			t.Fatal(e)
		}
		if e = f.Close(); e != nil {
			t.Fatal(e)
		}
		return path
	}
	source := save("source.yaml", []byte(captured.Config))
	encoded, _ := json.Marshal(captured.Env)
	environment := save("environment.json", encoded)
	key := save("key", []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{27}, 32))))
	command := migrations.NewCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"cutover", "--database", "sqlite://" + database, "--key-file", key, "--plan", "20260930-tenant-console.json", "--source", source, "--environment", environment})
	if err = command.Execute(); err != nil {
		t.Fatal(err)
	}
	store, err := controlplane.OpenExisting(context.Background(), "sqlite://"+database, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{27}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	actual, err := store.ApplicationTenants(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Use the original capture's canonical tenant loader, with the bounded obsolete-field deletion already applied by migration.
	var receipt map[string]any
	if err = json.Unmarshal(output.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt["completed"] != true || len(actual.Tenants) != 20 {
		t.Fatal("incomplete production migration")
	}
	payload, _ = json.Marshal(actual)
	save("migrated-tenants.json", payload)
	again := migrations.NewCommand()
	var retry bytes.Buffer
	again.SetOut(&retry)
	again.SetArgs([]string{"cutover", "--database", "sqlite://" + database, "--key-file", key, "--plan", "20260930-tenant-console.json", "--status"})
	if err = again.Execute(); err != nil {
		t.Fatal(err)
	}
	var repeated map[string]any
	if err = json.Unmarshal(retry.Bytes(), &repeated); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(receipt, repeated) {
		t.Fatal("migration repeat changed receipt")
	}
	save("receipt.json", retry.Bytes())
}

package migrations_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/tyemirov/tauth/deployment/migrations"
	"github.com/tyemirov/tauth/internal/tenants"
)

func TestFreezeEffectiveSource(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source.yaml")
	file, err := os.Create(source)
	if err != nil {
		t.Fatal(err)
	}
	_, err = file.WriteString(`tenants:
  - id: frozen
    display_name: Frozen
    tenant_origins: [http://localhost:8100]
    google_web_client_id: ${MIGRATION_GOOGLE_CLIENT}
    jwt_signing_key: ${MIGRATION_SESSION_KEY}
    session_cookie_name: frozen_session
    refresh_cookie_name: frozen_refresh
    session_ttl: 15m
    refresh_ttl: 720h
    cookie_domain: ${MIGRATION_COOKIE_DOMAIN}
`)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MIGRATION_COOKIE_DOMAIN", "")
	t.Setenv("MIGRATION_GOOGLE_CLIENT", "frozen-client")
	t.Setenv("MIGRATION_SESSION_KEY", "literal-key$preserved")
	command := migrations.NewCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetArgs([]string{"freeze-source", "--source", source})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	var document tenants.FileDocument
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Tenants) != 1 || document.Tenants[0].JWTSigningKey != "literal-key$preserved" || document.Tenants[0].GoogleWebClientID != "frozen-client" {
		t.Fatal("effective source changed")
	}
}

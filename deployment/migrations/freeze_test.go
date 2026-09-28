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

func TestFreezeDeploymentContribution(t *testing.T) {
	source := filepath.Join(t.TempDir(), "contribution.json")
	contribution := map[string]any{
		"owner": "example", "id": "authentication", "kind": "tauth_tenant",
		"desired": map[string]any{"kind": "tauth_tenant", "id": "authentication", "capability": "tauth.tenants", "version": 1, "tenant": map[string]any{
			"id": "example", "display_name": "Example", "origins": []string{"https://example.com"},
			"google_web_client_id": map[string]string{"resource": "private", "output": "client"}, "jwt_signing_key": map[string]string{"resource": "private", "output": "key"},
			"cookie": map[string]string{"domain": "example.com", "session_name": "example_session", "refresh_name": "example_refresh"}}},
		"outputs": map[string]any{"google-web-client-id": map[string]string{"value": "example.apps.googleusercontent.com"}, "jwt-signing-key": map[string]string{"value": "literal-${UNEXPANDED}-key"}},
	}
	encoded, err := json.Marshal(contribution)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(encoded); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	command := migrations.NewCommand()
	command.SetOut(&output)
	command.SetArgs([]string{"freeze-contribution", "--source", source})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	var document tenants.FileDocument
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Tenants) != 1 || document.Tenants[0].JWTSigningKey != "literal-${UNEXPANDED}-key" || document.Tenants[0].ID != "example" || document.Tenants[0].SessionTTL != "15m" {
		t.Fatal("canonical contribution values changed")
	}
	delete(contribution["outputs"].(map[string]any), "jwt-signing-key")
	encoded, err = json.Marshal(contribution)
	if err != nil {
		t.Fatal(err)
	}
	file, err = os.Create(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(encoded); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	command = migrations.NewCommand()
	command.SetOut(&output)
	command.SetArgs([]string{"freeze-contribution", "--source", source})
	if err := command.Execute(); err == nil {
		t.Fatal("incomplete contribution accepted")
	}
	if output.Len() != 0 {
		t.Fatal("failed conversion emitted a partial snapshot")
	}
}

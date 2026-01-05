package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctorCommandHelp(testingHandle *testing.T) {
	rootCommand := newRootCommand()
	var stdout bytes.Buffer
	rootCommand.SetOut(&stdout)
	rootCommand.SetArgs([]string{"doctor", "--help"})
	if err := rootCommand.Execute(); err != nil {
		testingHandle.Fatalf("expected no error, got %v", err)
	}
	output := stdout.String()
	if !strings.Contains(output, "Validate one or more TAuth configuration files") {
		testingHandle.Fatalf("expected help output to contain description, got %s", output)
	}
	if !strings.Contains(output, "--cross-validate") {
		testingHandle.Fatalf("expected help output to contain cross-validate flag")
	}
	if !strings.Contains(output, "--json") {
		testingHandle.Fatalf("expected help output to contain json flag")
	}
}

func TestDoctorCommandValidatesValidConfig(testingHandle *testing.T) {
	tempDir := testingHandle.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	writeDoctorTestConfig(testingHandle, configPath, validDoctorConfigYAML)

	rootCommand := newRootCommand()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	rootCommand.SetOut(&stdout)
	rootCommand.SetErr(&stderr)
	rootCommand.SetArgs([]string{"doctor", configPath})

	if err := rootCommand.Execute(); err != nil {
		testingHandle.Fatalf("expected no error, got %v", err)
	}
	output := stdout.String()
	if !strings.Contains(output, "VALID") {
		testingHandle.Fatalf("expected output to contain VALID, got %s", output)
	}
}

func TestDoctorCommandJSONOutput(testingHandle *testing.T) {
	tempDir := testingHandle.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	writeDoctorTestConfig(testingHandle, configPath, validDoctorConfigYAML)

	rootCommand := newRootCommand()
	var stdout bytes.Buffer
	rootCommand.SetOut(&stdout)
	rootCommand.SetArgs([]string{"doctor", "--json", configPath})

	if err := rootCommand.Execute(); err != nil {
		testingHandle.Fatalf("expected no error, got %v", err)
	}
	output := stdout.String()
	if !strings.Contains(output, `"schema_version"`) {
		testingHandle.Fatalf("expected JSON output, got %s", output)
	}
	if !strings.Contains(output, `"tauth.doctor.v1"`) {
		testingHandle.Fatalf("expected schema version in JSON output, got %s", output)
	}
}

func TestDoctorCommandFailsOnInvalidConfig(testingHandle *testing.T) {
	tempDir := testingHandle.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	writeDoctorTestConfig(testingHandle, configPath, invalidDoctorConfigYAML)

	rootCommand := newRootCommand()
	var stdout bytes.Buffer
	rootCommand.SetOut(&stdout)
	rootCommand.SetArgs([]string{"doctor", configPath})

	err := rootCommand.Execute()
	if err == nil {
		testingHandle.Fatalf("expected error for invalid config")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		testingHandle.Fatalf("expected validation failed error, got %v", err)
	}
}

func TestDoctorCommandMultipleConfigs(testingHandle *testing.T) {
	tempDir := testingHandle.TempDir()
	config1Path := filepath.Join(tempDir, "config1.yaml")
	config2Path := filepath.Join(tempDir, "config2.yaml")
	writeDoctorTestConfig(testingHandle, config1Path, validDoctorConfigYAML)
	writeDoctorTestConfig(testingHandle, config2Path, validDoctorConfig2YAML)

	rootCommand := newRootCommand()
	var stdout bytes.Buffer
	rootCommand.SetOut(&stdout)
	rootCommand.SetArgs([]string{"doctor", "--cross-validate", config1Path, config2Path})

	if err := rootCommand.Execute(); err != nil {
		testingHandle.Fatalf("expected no error, got %v", err)
	}
	output := stdout.String()
	if !strings.Contains(output, "Cross-Config Validation") {
		testingHandle.Fatalf("expected cross-config validation output, got %s", output)
	}
}

func writeDoctorTestConfig(testingHandle *testing.T, path string, content string) {
	testingHandle.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		testingHandle.Fatalf("write config: %v", err)
	}
}

const validDoctorConfigYAML = `
server:
  listen_addr: ":8082"
  enable_cors: false

tenants:
  - id: demo
    display_name: Demo Tenant
    tenant_origins:
      - http://localhost:8000
    google_web_client_id: demo-client.apps.googleusercontent.com
    jwt_signing_key: demo-signing-key-at-least-32-chars
    session_cookie_name: app_session_demo
    refresh_cookie_name: app_refresh_demo
    session_ttl: 30m
    refresh_ttl: 720h
    nonce_ttl: 5m
    allow_insecure_http: true
`

const validDoctorConfig2YAML = `
server:
  listen_addr: ":8083"
  enable_cors: false

tenants:
  - id: other
    display_name: Other Tenant
    tenant_origins:
      - http://localhost:9000
    google_web_client_id: other-client.apps.googleusercontent.com
    jwt_signing_key: other-signing-key-at-least-32-chars
    session_cookie_name: app_session_other
    refresh_cookie_name: app_refresh_other
    session_ttl: 30m
    refresh_ttl: 720h
    nonce_ttl: 5m
    allow_insecure_http: true
`

const invalidDoctorConfigYAML = `
server:
  listen_addr: ":8082"

tenants:
  - id: invalid
    display_name: Invalid Tenant
`

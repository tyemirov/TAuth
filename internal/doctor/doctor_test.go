package doctor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRunValidatesValidConfig(testingHandle *testing.T) {
	tempDir := testingHandle.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	writeTestConfig(testingHandle, configPath, validConfigYAML)

	report, err := Run(context.Background(), Options{
		ConfigPaths: []string{configPath},
	})
	if err != nil {
		testingHandle.Fatalf("expected no error, got %v", err)
	}
	if report.Summary.TotalConfigs != 1 {
		testingHandle.Fatalf("expected 1 config, got %d", report.Summary.TotalConfigs)
	}
	if report.Summary.ValidConfigs != 1 {
		testingHandle.Fatalf("expected 1 valid config, got %d", report.Summary.ValidConfigs)
	}
	if report.Summary.InvalidConfigs != 0 {
		testingHandle.Fatalf("expected 0 invalid configs, got %d", report.Summary.InvalidConfigs)
	}
	if len(report.Diagnostics[0].TenantIDs) != 1 {
		testingHandle.Fatalf("expected 1 tenant, got %d", len(report.Diagnostics[0].TenantIDs))
	}
	if report.Diagnostics[0].TenantIDs[0] != "demo" {
		testingHandle.Fatalf("expected tenant id 'demo', got %s", report.Diagnostics[0].TenantIDs[0])
	}
}

func TestRunValidatesInvalidConfig(testingHandle *testing.T) {
	tempDir := testingHandle.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	writeTestConfig(testingHandle, configPath, invalidConfigYAML)

	report, err := Run(context.Background(), Options{
		ConfigPaths: []string{configPath},
	})
	if err != nil {
		testingHandle.Fatalf("expected no error for run, got %v", err)
	}
	if report.Summary.ValidConfigs != 0 {
		testingHandle.Fatalf("expected 0 valid configs, got %d", report.Summary.ValidConfigs)
	}
	if report.Summary.InvalidConfigs != 1 {
		testingHandle.Fatalf("expected 1 invalid config, got %d", report.Summary.InvalidConfigs)
	}
	if len(report.Diagnostics[0].Errors) == 0 {
		testingHandle.Fatalf("expected errors in diagnostic")
	}
}

func TestRunValidatesMissingFile(testingHandle *testing.T) {
	report, err := Run(context.Background(), Options{
		ConfigPaths: []string{"/nonexistent/config.yaml"},
	})
	if err != nil {
		testingHandle.Fatalf("expected no error for run, got %v", err)
	}
	if report.Summary.InvalidConfigs != 1 {
		testingHandle.Fatalf("expected 1 invalid config, got %d", report.Summary.InvalidConfigs)
	}
	if !report.Diagnostics[0].Valid {
		found := false
		for _, diagErr := range report.Diagnostics[0].Errors {
			if diagErr != "" {
				found = true
				break
			}
		}
		if !found {
			testingHandle.Fatalf("expected error message for missing file")
		}
	}
}

func TestRunValidatesMultipleConfigs(testingHandle *testing.T) {
	tempDir := testingHandle.TempDir()
	config1Path := filepath.Join(tempDir, "config1.yaml")
	config2Path := filepath.Join(tempDir, "config2.yaml")
	writeTestConfig(testingHandle, config1Path, validConfigYAML)
	writeTestConfig(testingHandle, config2Path, validConfig2YAML)

	report, err := Run(context.Background(), Options{
		ConfigPaths:          []string{config1Path, config2Path},
		ValidateCrossConfigs: true,
	})
	if err != nil {
		testingHandle.Fatalf("expected no error, got %v", err)
	}
	if report.Summary.TotalConfigs != 2 {
		testingHandle.Fatalf("expected 2 configs, got %d", report.Summary.TotalConfigs)
	}
	if report.Summary.ValidConfigs != 2 {
		testingHandle.Fatalf("expected 2 valid configs, got %d", report.Summary.ValidConfigs)
	}
	if !report.CrossValidation.Performed {
		testingHandle.Fatalf("expected cross validation to be performed")
	}
}

func TestRunDetectsCrossConfigOriginConflict(testingHandle *testing.T) {
	tempDir := testingHandle.TempDir()
	config1Path := filepath.Join(tempDir, "config1.yaml")
	config2Path := filepath.Join(tempDir, "config2.yaml")
	writeTestConfig(testingHandle, config1Path, validConfigYAML)
	writeTestConfig(testingHandle, config2Path, conflictingOriginConfigYAML)

	report, err := Run(context.Background(), Options{
		ConfigPaths:          []string{config1Path, config2Path},
		ValidateCrossConfigs: true,
	})
	if err != nil {
		testingHandle.Fatalf("expected no error, got %v", err)
	}
	if len(report.CrossValidation.Errors) == 0 {
		testingHandle.Fatalf("expected cross-config errors for conflicting origins")
	}
}

func TestRunReturnsErrorWithNoConfigs(testingHandle *testing.T) {
	_, err := Run(context.Background(), Options{
		ConfigPaths: []string{},
	})
	if err == nil {
		testingHandle.Fatalf("expected error for no config paths")
	}
}

func TestFormatReportProducesValidJSON(testingHandle *testing.T) {
	tempDir := testingHandle.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	writeTestConfig(testingHandle, configPath, validConfigYAML)

	report, err := Run(context.Background(), Options{
		ConfigPaths: []string{configPath},
	})
	if err != nil {
		testingHandle.Fatalf("expected no error, got %v", err)
	}

	jsonOutput, formatErr := FormatReport(report)
	if formatErr != nil {
		testingHandle.Fatalf("expected no format error, got %v", formatErr)
	}
	if len(jsonOutput) == 0 {
		testingHandle.Fatalf("expected non-empty JSON output")
	}
}

func TestFormatSummaryProducesReadableOutput(testingHandle *testing.T) {
	tempDir := testingHandle.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	writeTestConfig(testingHandle, configPath, validConfigYAML)

	report, err := Run(context.Background(), Options{
		ConfigPaths: []string{configPath},
	})
	if err != nil {
		testingHandle.Fatalf("expected no error, got %v", err)
	}

	summary := FormatSummary(report)
	if summary == "" {
		testingHandle.Fatalf("expected non-empty summary")
	}
	if !contains(summary, "TAuth Doctor Report") {
		testingHandle.Fatalf("expected summary to contain header")
	}
	if !contains(summary, "VALID") {
		testingHandle.Fatalf("expected summary to contain VALID status")
	}
}

func TestWarningForInsecureHTTP(testingHandle *testing.T) {
	tempDir := testingHandle.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	writeTestConfig(testingHandle, configPath, validConfigYAML)

	report, err := Run(context.Background(), Options{
		ConfigPaths: []string{configPath},
	})
	if err != nil {
		testingHandle.Fatalf("expected no error, got %v", err)
	}

	foundWarning := false
	for _, warn := range report.Diagnostics[0].Warnings {
		if contains(warn, "allow_insecure_http") {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		testingHandle.Fatalf("expected warning for allow_insecure_http")
	}
}

func writeTestConfig(testingHandle *testing.T, path string, content string) {
	testingHandle.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		testingHandle.Fatalf("write config: %v", err)
	}
}

func contains(haystack string, needle string) bool {
	return len(haystack) > 0 && len(needle) > 0 && (haystack == needle || len(haystack) > len(needle) && (haystack[:len(needle)] == needle || contains(haystack[1:], needle)))
}

const validConfigYAML = `
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

const validConfig2YAML = `
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

const conflictingOriginConfigYAML = `
server:
  listen_addr: ":8083"
  enable_cors: false

tenants:
  - id: conflicting
    display_name: Conflicting Tenant
    tenant_origins:
      - http://localhost:8000
    google_web_client_id: conflicting-client.apps.googleusercontent.com
    jwt_signing_key: conflicting-signing-key-at-least
    session_cookie_name: app_session_conflict
    refresh_cookie_name: app_refresh_conflict
    session_ttl: 30m
    refresh_ttl: 720h
    nonce_ttl: 5m
    allow_insecure_http: true
`

const invalidConfigYAML = `
server:
  listen_addr: ":8082"

tenants:
  - id: invalid
    display_name: Invalid Tenant
`

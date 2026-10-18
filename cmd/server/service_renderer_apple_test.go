package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyemirov/tauth/internal/deploymentconfig"
	"github.com/tyemirov/tauth/internal/tenants"
)

func TestConsoleRendererOptionalAppleNotifications(t *testing.T) {
	const audienceField = "notification_audience"
	const configuredAudience = "com.example.browser-demo.primary"
	for _, resourceKind := range []string{"tauth_tenant", "tauth_github_tenant"} {
		t.Run(resourceKind, func(t *testing.T) {
			for _, scenario := range []struct {
				name             string
				appleSettings    map[string]any
				expectedAudience string
				expectedError    string
			}{
				{name: "omitted", appleSettings: map[string]any{}},
				{name: "empty", appleSettings: map[string]any{audienceField: ""}},
				{name: "configured", appleSettings: map[string]any{audienceField: configuredAudience}, expectedAudience: configuredAudience},
				{name: "unknown field", appleSettings: map[string]any{"unexpected_notification_setting": true}, expectedError: `unknown field "unexpected_notification_setting"`},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					request, contribution := appleNotificationDeploymentFixture(t, resourceKind, scenario.appleSettings)
					command := newRootCommand()
					command.SilenceUsage = true
					var output bytes.Buffer
					command.SetIn(bytes.NewReader(request))
					command.SetOut(&output)
					command.SetErr(&bytes.Buffer{})
					command.SetArgs([]string{"render-deployment-config"})
					renderErr := command.Execute()
					projection, projectionErr := deploymentconfig.ResolveContribution(contribution)
					if scenario.expectedError != "" {
						for _, actualError := range []error{renderErr, projectionErr} {
							if actualError == nil || !strings.Contains(actualError.Error(), scenario.expectedError) {
								t.Fatalf("expected %q, got %v", scenario.expectedError, actualError)
							}
						}
						if output.Len() != 0 {
							t.Fatal("invalid request emitted service configuration")
						}
						return
					}
					if renderErr != nil {
						t.Fatalf("render deployment config: %v", renderErr)
					}
					if projectionErr != nil {
						t.Fatalf("resolve provisioning contribution: %v", projectionErr)
					}
					configuration, err := tenants.LoadResolvedConfig(tenants.FileDocument{Tenants: []tenants.FileTenant{projection.Tenant}})
					if err != nil {
						t.Fatal(err)
					}
					apple := configuration.Tenants()[0].AppleOAuth()
					if !apple.Enabled() || apple.ClientID() != "com.example.browser-demo.web" {
						t.Fatal("notification settings changed Apple login configuration")
					}
					if actual := apple.NotificationAudience(); actual != scenario.expectedAudience {
						t.Fatalf("notification audience = %q, want %q", actual, scenario.expectedAudience)
					}
					configPath := filepath.Join(t.TempDir(), "service.yml")
					configFile, err := os.Create(configPath)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := configFile.Write(output.Bytes()); err != nil {
						configFile.Close()
						t.Fatal(err)
					}
					if err := configFile.Close(); err != nil {
						t.Fatal(err)
					}
					validate := newRootCommand()
					validate.SetOut(&bytes.Buffer{})
					validate.SetArgs([]string{"validate-service-config", configPath})
					if err := validate.Execute(); err != nil {
						t.Fatalf("validate rendered service config: %v", err)
					}
				})
			}
		})
	}
}

func appleNotificationDeploymentFixture(t *testing.T, resourceKind string, appleSettings map[string]any) ([]byte, []byte) {
	t.Helper()
	payload, err := os.ReadFile("../../tests/fixtures/deployment-config/browser-demo.json")
	if err != nil {
		t.Fatal(err)
	}
	var request struct {
		SchemaVersion int              `json:"schema_version"`
		Contributions []map[string]any `json:"contributions"`
	}
	if err := json.Unmarshal(payload, &request); err != nil {
		t.Fatal(err)
	}
	contribution := request.Contributions[1]
	contribution["kind"] = resourceKind
	desired := contribution["desired"].(map[string]any)
	desired["kind"] = resourceKind
	tenant := desired["tenant"].(map[string]any)
	apple := tenant["apple_oauth"].(map[string]any)
	delete(apple, "native_client_ids")
	delete(tenant, "google_native_clients")
	for name, value := range appleSettings {
		apple[name] = value
	}
	if resourceKind == "tauth_github_tenant" {
		tenant["github_oauth"] = map[string]any{
			"enabled":       true,
			"client_id":     map[string]string{"resource": "private", "output": "github-client-id"},
			"client_secret": map[string]string{"resource": "private", "output": "github-client-secret"},
			"redirect_uri":  "https://auth.example.invalid/auth/github/callback",
			"scopes":        []string{"read:user", "user:email"},
		}
		outputs := contribution["outputs"].(map[string]any)
		outputs["github-client-id"] = map[string]string{"value": "fixture-github-client"}
		outputs["github-client-secret"] = map[string]string{"value": "fixture-github-secret"}
	}
	requestPayload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	contributionPayload, err := json.Marshal(contribution)
	if err != nil {
		t.Fatal(err)
	}
	return requestPayload, contributionPayload
}

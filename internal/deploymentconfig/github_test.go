package deploymentconfig

import (
	"strings"
	"testing"

	"github.com/tyemirov/tauth/internal/tenants"
	"gopkg.in/yaml.v3"
)

func TestGitHubOnlyDeploymentRendering(t *testing.T) {
	payload, err := Render(strings.NewReader(githubDeploymentInput))
	if err != nil {
		t.Fatalf("GitHub-only rendering: %v", err)
	}
	var document tenants.FileDocument
	if err := yaml.Unmarshal(payload, &document); err != nil {
		t.Fatal(err)
	}
	config, err := tenants.LoadConfigFromDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	if !config.Tenants()[0].GitHubOAuth().Enabled() || config.Tenants()[0].GoogleWebClientID() != "" {
		t.Fatal("GitHub-only capability lost")
	}
}

const githubDeploymentInput = `{"schema_version":1,"contributions":[{"owner":"sample","id":"github","kind":"tauth_tenant","desired":{"kind":"tauth_tenant","id":"github","capability":"authentication","version":1,"tenant":{"id":"github","display_name":"GitHub","origins":["https://app.example.com"],"github_oauth":{"enabled":true,"client_id":{"resource":"identity","output":"id"},"client_secret":{"resource":"identity","output":"secret"},"redirect_uri":"https://auth.example.com/auth/github/callback","scopes":["read:user","user:email"]},"jwt_signing_key":{"resource":"key","output":"secret"},"cookie":{"domain":"","session_name":"github_session","refresh_name":"github_refresh"}}},"outputs":{"github-client-id":{"value":"github-client"},"github-client-secret":{"value":"test-secret"},"jwt-signing-key":{"value":"test-signing-key"}}}]}`

func TestGitHubDisabledDeploymentRendering(t *testing.T) {
	input := strings.Replace(githubDeploymentInput, `"github_oauth":{"enabled":true,"client_id":{"resource":"identity","output":"id"},"client_secret":{"resource":"identity","output":"secret"},"redirect_uri":"https://auth.example.com/auth/github/callback","scopes":["read:user","user:email"]}`, `"github_oauth":{"enabled":false},"password_auth":{"enabled":true}`, 1)
	input = strings.Replace(input, `"github-client-id":{"value":"github-client"},"github-client-secret":{"value":"test-secret"},`, "", 1)
	if _, err := Render(strings.NewReader(input)); err != nil {
		t.Fatalf("disabled GitHub provider required credentials: %v", err)
	}
}

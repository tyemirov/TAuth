package tenants

import (
	"os"
	"strings"
	"testing"
)

func TestGitHubOnlyConfig(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "github-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_, err = file.WriteString(githubOnlyConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(file.Name()); err != nil {
		t.Fatalf("GitHub-only startup config: %v", err)
	}
}

const githubOnlyConfig = `tenants:
  - id: github
    display_name: GitHub
    tenant_origins: [https://app.example.com]
    github_oauth:
      enabled: true
      client_id: github-client
      client_secret: test-secret
      redirect_uri: https://auth.example.com/auth/github/callback
      scopes: [read:user, user:email]
    jwt_signing_key: test-signing-key
    session_cookie_name: github_session
    refresh_cookie_name: github_refresh
    session_ttl: 30m
    refresh_ttl: 720h
`

func TestGitHubConfigurationRejectsInvalidProvider(t *testing.T) {
	for _, scenario := range []struct{ name, old, replacement string }{
		{"disabled", "enabled: true", "enabled: false"},
		{"missing enabled", "enabled: true", ""},
		{"missing client", "client_id: github-client", "client_id: ''"},
		{"missing secret", "client_secret: test-secret", "client_secret: ''"},
		{"insecure callback", "https://auth.example.com", "http://auth.example.com"},
		{"callback path", "/auth/github/callback", "/callback"},
		{"callback query", "/auth/github/callback", "/auth/github/callback?next=evil"},
		{"callback fragment", "/auth/github/callback", "/auth/github/callback#fragment"},
		{"callback credentials", "https://auth.example.com", "https://user@auth.example.com"},
		{"repository scope", "scopes: [read:user, user:email]", "scopes: [read:user, user:email, repo]"},
		{"offline scope", "scopes: [read:user, user:email]", "scopes: [read:user, user:email, offline_access]"},
		{"partial scope", "scopes: [read:user, user:email]", "scopes: [read:user]"},
		{"provider endpoint", "scopes: [read:user, user:email]", "token_endpoint: https://foreign.example/token"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			file, err := os.CreateTemp(t.TempDir(), "github-*.yaml")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteString(strings.Replace(githubOnlyConfig, scenario.old, scenario.replacement, 1)); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfig(file.Name()); err == nil {
				t.Fatal("invalid GitHub configuration accepted")
			}
		})
	}
}

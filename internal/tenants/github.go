package tenants

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
)

const (
	// GitHubProvider is the canonical GitHub.com identity provider.
	GitHubProvider = "github"
	// GitHubStartPath starts the GitHub authorization protocol.
	GitHubStartPath = "/auth/github/start"
	// GitHubCallbackPath receives the GitHub authorization response.
	GitHubCallbackPath = "/auth/github/callback"
	// GitHubIdentityScope is the closed GitHub OAuth App permission set.
	GitHubIdentityScope = "read:user user:email"
)

// GitHubOAuth contains validated GitHub.com identity settings.
type GitHubOAuth struct {
	enabled      bool
	clientID     string
	clientSecret string
	redirectURI  string
}

// FileGitHubOAuth is the native GitHub provider configuration.
type FileGitHubOAuth struct {
	Enabled      yamlBool `json:"enabled" yaml:"enabled"`
	ClientID     string   `json:"client_id" yaml:"client_id"`
	ClientSecret string   `json:"client_secret" yaml:"client_secret"`
	RedirectURI  string   `json:"redirect_uri" yaml:"redirect_uri"`
	Scopes       []string `json:"scopes" yaml:"scopes"`
}

// GitHubOAuth returns the tenant's GitHub provider.
func (tenant Tenant) GitHubOAuth() GitHubOAuth { return tenant.githubOAuth }

// Enabled reports whether GitHub login is available.
func (config GitHubOAuth) Enabled() bool { return config.enabled }

// ClientID returns the dedicated OAuth App identifier.
func (config GitHubOAuth) ClientID() string { return config.clientID }

// ClientSecret returns the server-side OAuth App secret.
func (config GitHubOAuth) ClientSecret() string { return config.clientSecret }

// RedirectURI returns the exact configured callback.
func (config GitHubOAuth) RedirectURI() string { return config.redirectURI }

func parseGitHubOAuth(raw FileGitHubOAuth, tenantID TenantID) (GitHubOAuth, error) {
	invalid := func() (GitHubOAuth, error) {
		return GitHubOAuth{}, fmt.Errorf("%w: tenant.invalid_github_oauth tenant=%s", ErrInvalidTenantConfig, tenantID)
	}
	if !bool(raw.Enabled) {
		if raw.ClientID != "" || raw.ClientSecret != "" || raw.RedirectURI != "" || len(raw.Scopes) != 0 {
			return invalid()
		}
		return GitHubOAuth{}, nil
	}
	callback, err := url.Parse(raw.RedirectURI)
	if strings.TrimSpace(raw.ClientID) == "" || raw.ClientID != strings.TrimSpace(raw.ClientID) || strings.TrimSpace(raw.ClientSecret) == "" ||
		err != nil || callback.Scheme != "https" || callback.Hostname() == "" || callback.User != nil || callback.RawQuery != "" || callback.ForceQuery || callback.Fragment != "" || callback.Path != GitHubCallbackPath || callback.RawPath != "" {
		return invalid()
	}
	if len(raw.Scopes) != 0 {
		scopes := slices.Clone(raw.Scopes)
		slices.Sort(scopes)
		if !slices.Equal(scopes, strings.Fields(GitHubIdentityScope)) {
			return invalid()
		}
	}
	return GitHubOAuth{enabled: true, clientID: raw.ClientID, clientSecret: raw.ClientSecret, redirectURI: raw.RedirectURI}, nil
}

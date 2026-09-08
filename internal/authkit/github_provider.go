package authkit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/tyemirov/tauth/internal/tenants"
)

const (
	githubAuthorizationEndpoint = "https://github.com/login/oauth/authorize"
	githubTokenEndpoint         = "https://github.com/login/oauth/access_token"
	githubUserEndpoint          = "https://api.github.com/user"
	githubEmailsEndpoint        = "https://api.github.com/user/emails?per_page=100"
	githubProviderDeadline      = 10 * time.Second
	githubMaximumResponseBytes  = 64 * 1024
)

var (
	ErrGitHubProviderRejected = errors.New("github_provider_rejected")
	ErrGitHubEmailMissing     = errors.New("github_verified_email_required")
)

// GitHubProvider retrieves verified identities from fixed GitHub.com endpoints.
type GitHubProvider struct {
	client                *http.Client
	authorizationEndpoint string
}

// NewGitHubProvider accepts an HTTP transport for local protocol qualification.
// Production uses http.DefaultTransport. Provider URLs are not configuration inputs.
func NewGitHubProvider(transport http.RoundTripper) *GitHubProvider {
	return &GitHubProvider{authorizationEndpoint: githubAuthorizationEndpoint, client: &http.Client{Transport: transport, Timeout: githubProviderDeadline,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (provider *GitHubProvider) identity(ctx context.Context, config tenants.GitHubOAuth, transaction githubTransaction, code string) (AccountProviderIdentity, error) {
	ctx, cancel := context.WithTimeout(ctx, githubProviderDeadline)
	defer cancel()
	form := url.Values{"client_id": {transaction.ClientID}, "client_secret": {config.ClientSecret()}, "code": {code}, "redirect_uri": {transaction.RedirectURI}, "code_verifier": {transaction.Verifier}}
	tokenRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, githubTokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return AccountProviderIdentity{}, ErrGitHubProviderRejected
	}
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
		Error       string `json:"error"`
	}
	if err := provider.read(tokenRequest, &token); err != nil {
		return AccountProviderIdentity{}, err
	}
	scopes := strings.FieldsFunc(token.Scope, func(char rune) bool { return char == ',' || char == ' ' })
	slices.Sort(scopes)
	if token.AccessToken == "" || strings.ContainsAny(token.AccessToken, "\r\n\t ") || token.TokenType != "bearer" || token.Error != "" || !slices.Equal(scopes, strings.Fields(tenants.GitHubIdentityScope)) {
		return AccountProviderIdentity{}, ErrGitHubProviderRejected
	}
	var user struct {
		ID        json.RawMessage `json:"id"`
		Login     string          `json:"login"`
		Name      string          `json:"name"`
		AvatarURL string          `json:"avatar_url"`
	}
	if err := provider.get(ctx, githubUserEndpoint, token.AccessToken, &user); err != nil {
		return AccountProviderIdentity{}, err
	}
	identifier, idErr := strconv.ParseUint(string(user.ID), 10, 64)
	if idErr != nil || identifier == 0 || strconv.FormatUint(identifier, 10) != string(user.ID) || strings.TrimSpace(user.Login) == "" {
		return AccountProviderIdentity{}, ErrGitHubProviderRejected
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := provider.get(ctx, githubEmailsEndpoint, token.AccessToken, &emails); err != nil {
		return AccountProviderIdentity{}, err
	}
	primaryCount := 0
	email := ""
	for _, candidate := range emails {
		if !candidate.Primary {
			continue
		}
		primaryCount++
		if !candidate.Verified {
			return AccountProviderIdentity{}, ErrGitHubEmailMissing
		}
		email, err = normalizePasswordEmail(candidate.Email)
		if err != nil {
			return AccountProviderIdentity{}, ErrGitHubEmailMissing
		}
	}
	if primaryCount != 1 {
		return AccountProviderIdentity{}, ErrGitHubEmailMissing
	}
	return AccountProviderIdentity{Provider: accountProviderGitHub, Subject: string(user.ID), UserEmail: email, DisplayName: user.Name, AvatarURL: user.AvatarURL}, nil
}

func (provider *GitHubProvider) get(ctx context.Context, endpoint, token string, destination any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ErrGitHubProviderRejected
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	return provider.read(request, destination)
}

func (provider *GitHubProvider) read(request *http.Request, destination any) error {
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "TAuth")
	response, err := provider.client.Do(request)
	if err != nil {
		return ErrGitHubProviderRejected
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ErrGitHubProviderRejected
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, githubMaximumResponseBytes+1))
	if err != nil || len(body) > githubMaximumResponseBytes || json.Unmarshal(body, destination) != nil || githubJSONValue(json.NewDecoder(bytes.NewReader(body))) != nil {
		return ErrGitHubProviderRejected
	}
	return nil
}

// GitHub responses may contain additional API fields, but duplicate names cannot
// establish an unambiguous identity or verification result.
func githubJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return ErrGitHubProviderRejected
	}
	switch token {
	case json.Delim('{'):
		fields := make(map[string]struct{})
		for decoder.More() {
			name, err := decoder.Token()
			if err != nil {
				return ErrGitHubProviderRejected
			}
			key, ok := name.(string)
			if !ok {
				return ErrGitHubProviderRejected
			}
			if _, exists := fields[key]; exists {
				return ErrGitHubProviderRejected
			}
			fields[key] = struct{}{}
			if err := githubJSONValue(decoder); err != nil {
				return err
			}
		}
		if close, err := decoder.Token(); err != nil || close != json.Delim('}') {
			return ErrGitHubProviderRejected
		}
	case json.Delim('['):
		for decoder.More() {
			if err := githubJSONValue(decoder); err != nil {
				return err
			}
		}
		if close, err := decoder.Token(); err != nil || close != json.Delim(']') {
			return ErrGitHubProviderRejected
		}
	}
	return nil
}

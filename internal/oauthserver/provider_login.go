package oauthserver

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/pkg/oauthvalidator"
)

// GitHubAuthorization resolves the same unconsumed request before and after GitHub login.
func (server *Server) GitHubAuthorization(ctx context.Context, tenantID, requestToken string) (string, error) {
	pending, err := server.store.GetAuthorizationRequest(ctx, requestToken, server.now().Unix())
	if err != nil {
		return "", err
	}
	if pending.TenantID != tenantID {
		return "", ErrAuthorizationRequestInvalid
	}
	policy, resource, err := server.registry.ResolveResource(pending.Resource)
	if err != nil || policy.TenantID != tenantID {
		return "", ErrAuthorizationRequestInvalid
	}
	client, err := server.resolveClient(ctx, policy, pending.ClientID)
	if err != nil || !redirectMatches(client, pending.RedirectURI) {
		return "", ErrAuthorizationRequestInvalid
	}
	if _, _, err := validateRequestedScopes(resource, client, pending.Scope); err != nil {
		return "", ErrAuthorizationRequestInvalid
	}
	return issuerPageURL(server.config.ConsentEndpoint(), requestToken), nil
}

func requiredIdentityProviders(resource Resource, scope string) []string {
	required := make(map[string]struct{})
	for _, identifier := range strings.Fields(scope) {
		for _, provider := range resource.Scopes[identifier].IdentityProviders {
			required[provider] = struct{}{}
		}
	}
	providers := make([]string, 0, len(required))
	for provider := range required {
		providers = append(providers, provider)
	}
	sort.Strings(providers)
	return providers
}

func (server *Server) grantedIdentities(ctx context.Context, tenantID, userID string, resource Resource, scope string) (oauthvalidator.ProviderIdentities, error) {
	return server.browserSessions.ProviderIdentities(ctx, tenantID, userID, requiredIdentityProviders(resource, scope))
}

func (server *Server) writeIdentityGrantError(response http.ResponseWriter, err error) {
	if errors.Is(err, authkit.ErrRequiredIdentityMissing) {
		writeOAuthError(response, http.StatusBadRequest, "invalid_grant")
		return
	}
	writeOAuthError(response, http.StatusInternalServerError, "server_error")
}

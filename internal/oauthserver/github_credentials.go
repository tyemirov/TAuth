package oauthserver

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/tenants"
)

const githubCredentialsPath = "/oauth/github-credentials"

func (server *Server) requireGitHubCredential(response http.ResponseWriter, request *http.Request, pending AuthorizationRequest, requestToken, userID string) bool {
	_, resource, err := server.registry.ResolveResource(pending.Resource)
	if err != nil {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return false
	}
	if resource.GitHubCredentialsKey == "" {
		return true
	}
	_, err = server.browserSessions.GitHubCredential(request.Context(), pending.TenantID, userID)
	if err == nil {
		return true
	}
	if errors.Is(err, authkit.ErrGitHubCredentialMissing) || errors.Is(err, authkit.ErrRequiredIdentityMissing) {
		destination := tenants.GitHubStartPath + "?" + url.Values{"tenant_id": {pending.TenantID}, "operation": {"oauth"}, "oauth_request": {requestToken}}.Encode()
		http.Redirect(response, request, destination, http.StatusSeeOther)
		return false
	}
	writeOAuthError(response, http.StatusInternalServerError, "server_error")
	return false
}

func (server *Server) handleGitHubCredentials(response http.ResponseWriter, request *http.Request) {
	var payload struct {
		SubjectToken string `json:"subject_token"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, maximumOAuthFormBytes))
	decoder.DisallowUnknownFields()
	if request.Header.Get("Content-Type") != "application/json" || decoder.Decode(&payload) != nil || decoder.Decode(new(any)) != io.EOF {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	claims, err := server.signer.ParseAccessToken(payload.SubjectToken, server.now())
	if err != nil || len(claims.Audience) != 1 || claims.Subject == "" {
		writeOAuthError(response, http.StatusUnauthorized, "invalid_token")
		return
	}
	policy, resource, err := server.registry.ResolveResource(claims.Audience[0])
	suppliedKey, present := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer ")
	expectedDigest := sha256.Sum256([]byte(resource.GitHubCredentialsKey))
	suppliedDigest := sha256.Sum256([]byte(suppliedKey))
	if err != nil || policy.TenantID != claims.TenantID || resource.GitHubCredentialsKey == "" || !present || subtle.ConstantTimeCompare(expectedDigest[:], suppliedDigest[:]) != 1 {
		writeOAuthError(response, http.StatusUnauthorized, "invalid_client")
		return
	}
	client, err := server.resolveClient(request.Context(), policy, claims.ClientID)
	if err != nil {
		writeOAuthError(response, http.StatusForbidden, "invalid_grant")
		return
	}
	if _, _, err := validateRequestedScopes(resource, client, claims.Scope); err != nil {
		writeOAuthError(response, http.StatusForbidden, "invalid_grant")
		return
	}
	consent, found, err := server.store.FindConsent(request.Context(), ConsentKey{TenantID: claims.TenantID, UserID: claims.Subject, ClientID: claims.ClientID, Resource: resource.Identifier, Scope: claims.Scope, DisclosurePolicy: identityDisclosurePolicy(resource, claims.Scope)}, server.now().Unix())
	if err != nil {
		writeOAuthError(response, http.StatusInternalServerError, "server_error")
		return
	}
	if !found || consent.ID != claims.GrantID {
		writeOAuthError(response, http.StatusForbidden, "invalid_grant")
		return
	}
	if err := server.requireActiveUser(request.Context(), claims.TenantID, claims.Subject); err != nil {
		if errors.Is(err, errInactiveUser) {
			writeOAuthError(response, http.StatusForbidden, "invalid_grant")
		} else {
			writeOAuthError(response, http.StatusInternalServerError, "server_error")
		}
		return
	}
	credential, err := server.browserSessions.GitHubCredential(request.Context(), claims.TenantID, claims.Subject)
	if errors.Is(err, authkit.ErrGitHubCredentialMissing) || errors.Is(err, authkit.ErrRequiredIdentityMissing) {
		writeOAuthError(response, http.StatusForbidden, "github_authorization_required")
		return
	}
	if err != nil {
		writeOAuthError(response, http.StatusInternalServerError, "server_error")
		return
	}
	if len(claims.ProviderIdentities) != 1 || claims.ProviderIdentities[0].Provider != "github" || claims.ProviderIdentities[0].ProviderID != credential.GitHubID {
		writeOAuthError(response, http.StatusForbidden, "invalid_grant")
		return
	}
	writePrivateJSON(response, http.StatusOK, credential)
}

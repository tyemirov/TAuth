package oauthserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/appconfig"
)

const authorizationServerMetadataPath = "/.well-known/oauth-authorization-server"

const (
	maximumOAuthParameterBytes = 2048
	maximumOAuthFormBytes      = 16 * 1024
)

// BrowserSessions connects issuer-owned browser pages to normal TAuth sessions.
type BrowserSessions interface {
	Resolve(request *http.Request, tenantID string) (string, error)
	LoginMethods(tenantID string) (passwordEnabled bool, googleWebClientID string, err error)
	IssueGoogleNonce(ctx context.Context, tenantID string) (string, error)
	LoginPassword(ctx context.Context, response http.ResponseWriter, request *http.Request, tenantID string, email string, password string) (accepted bool, err error)
	LoginGoogle(ctx context.Context, response http.ResponseWriter, request *http.Request, tenantID string, googleIDToken string, nonceToken string) (accepted bool, err error)
}

// Server implements one OAuth 2.1 authorization issuer across tenant resources.
type Server struct {
	config           appconfig.OAuthServerConfig
	registry         Registry
	store            Store
	signer           *Signer
	metadataResolver MetadataClientResolver
	browserSessions  BrowserSessions
	now              func() time.Time
}

// NewServer constructs the authorization server from validated dependencies.
func NewServer(
	config appconfig.OAuthServerConfig,
	registry Registry,
	store Store,
	signer *Signer,
	metadataResolver MetadataClientResolver,
	browserSessions BrowserSessions,
) (*Server, error) {
	if !config.Enabled() || store == nil || signer == nil || metadataResolver == nil || browserSessions == nil {
		return nil, fmt.Errorf("oauth.server.invalid_dependencies")
	}
	return &Server{
		config: config, registry: registry, store: store, signer: signer,
		metadataResolver: metadataResolver, browserSessions: browserSessions,
		now: func() time.Time { return time.Now().UTC() },
	}, nil
}

// Mount registers discovery, key, browser, token, and revocation endpoints.
func (server *Server) Mount(router gin.IRouter) error {
	paths := []struct {
		method  string
		address string
		handler http.HandlerFunc
	}{
		{http.MethodGet, authorizationServerMetadataPath, server.handleMetadata},
		{http.MethodGet, endpointPath(server.config.JWKSURI()), server.handleJWKS},
		{http.MethodGet, endpointPath(server.config.AuthorizationEndpoint()), server.handleAuthorize},
		{http.MethodPost, endpointPath(server.config.TokenEndpoint()), server.handleToken},
		{http.MethodPost, endpointPath(server.config.RevocationEndpoint()), server.handleRevocation},
		{http.MethodGet, endpointPath(server.config.LoginEndpoint()), server.handleLogin},
		{http.MethodPost, endpointPath(server.config.LoginEndpoint()), server.handleLogin},
		{http.MethodGet, endpointPath(server.config.ConsentEndpoint()), server.handleConsent},
		{http.MethodPost, endpointPath(server.config.ConsentEndpoint()), server.handleConsent},
	}
	for _, route := range paths {
		if route.address == "" {
			return fmt.Errorf("oauth.server.invalid_endpoint_path")
		}
		router.Handle(route.method, route.address, gin.WrapF(route.handler))
	}
	return nil
}

func (server *Server) handleMetadata(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writePublicJSON(response, http.StatusOK, map[string]any{
		"issuer":                                         server.config.Issuer(),
		"authorization_endpoint":                         server.config.AuthorizationEndpoint(),
		"token_endpoint":                                 server.config.TokenEndpoint(),
		"revocation_endpoint":                            server.config.RevocationEndpoint(),
		"jwks_uri":                                       server.config.JWKSURI(),
		"scopes_supported":                               server.registry.SupportedScopes(),
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"revocation_endpoint_auth_methods_supported":     []string{"none"},
		"code_challenge_methods_supported":               []string{"S256"},
		"client_id_metadata_document_supported":          true,
		"resource_parameter_supported":                   true,
		"authorization_response_iss_parameter_supported": true,
	})
}

func (server *Server) handleJWKS(response http.ResponseWriter, request *http.Request) {
	writePublicJSON(response, http.StatusOK, server.signer.JWKS())
}

func (server *Server) handleAuthorize(response http.ResponseWriter, request *http.Request) {
	values := request.URL.Query()
	responseType, responseTypeOK := singleValue(values, "response_type")
	clientID, clientIDOK := singleValue(values, "client_id")
	redirectURI, redirectOK := singleValue(values, "redirect_uri")
	resourceID, resourceOK := singleValue(values, "resource")
	rawScope, scopeOK := singleValue(values, "scope")
	state, stateOK := singleValue(values, "state")
	challenge, challengeOK := singleValue(values, "code_challenge")
	challengeMethod, methodOK := singleValue(values, "code_challenge_method")
	if !responseTypeOK || responseType == "" {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if responseType != "code" {
		writeOAuthError(response, http.StatusBadRequest, "unsupported_response_type")
		return
	}
	if !clientIDOK || !redirectOK || !resourceOK || !scopeOK || !stateOK || state == "" || !challengeOK || !methodOK || challengeMethod != "S256" || validatePKCEChallenge(challenge) != nil ||
		len(clientID) > maximumOAuthParameterBytes || len(redirectURI) > maximumOAuthParameterBytes || len(resourceID) > maximumOAuthParameterBytes || len(rawScope) > maximumOAuthParameterBytes || len(state) > maximumOAuthParameterBytes {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	policy, resource, resourceErr := server.registry.ResolveResource(resourceID)
	if resourceErr != nil {
		writeOAuthError(response, http.StatusBadRequest, "invalid_target")
		return
	}
	client, clientErr := server.resolveClient(request.Context(), policy, clientID)
	if clientErr != nil {
		writeOAuthError(response, http.StatusBadRequest, "unauthorized_client")
		return
	}
	if !redirectMatches(client, redirectURI) {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	_, normalizedScope, validateScopeErr := validateRequestedScopes(resource, client, rawScope)
	if validateScopeErr != nil {
		server.redirectAuthorizationError(response, redirectURI, state, "invalid_scope")
		return
	}
	redirectURL, parseRedirectErr := url.Parse(redirectURI)
	if parseRedirectErr != nil {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	now := server.now().UTC()
	pending := AuthorizationRequest{
		TenantID: policy.TenantID, ClientID: client.ID, ClientName: client.DisplayName,
		ClientSource: client.Source, RedirectURI: redirectURI, RedirectHost: redirectURL.Host,
		Resource: resource.Identifier, ResourceName: resource.DisplayName, Scope: normalizedScope,
		State: state, CodeChallenge: challenge, CreatedAtUnix: now.Unix(),
		ExpiresAtUnix: now.Add(server.config.AuthorizationRequestTTL()).Unix(),
	}
	requestToken, createErr := server.store.CreateAuthorizationRequest(request.Context(), pending)
	if createErr != nil {
		writeOAuthError(response, http.StatusInternalServerError, "server_error")
		return
	}
	userID, sessionErr := server.browserSessions.Resolve(request, policy.TenantID)
	if sessionErr != nil {
		redirectIssuerPage(response, server.config.LoginEndpoint(), requestToken)
		return
	}
	consent, consentExists, consentErr := server.store.FindConsent(request.Context(), pending.consentKey(userID), now.Unix())
	if consentErr != nil {
		writeOAuthError(response, http.StatusInternalServerError, "server_error")
		return
	}
	if consentExists {
		server.consumeAndIssueCodeAndRedirect(response, request, requestToken, pending, userID, consent.ID)
		return
	}
	redirectIssuerPage(response, server.config.ConsentEndpoint(), requestToken)
}

func (server *Server) handleLogin(response http.ResponseWriter, request *http.Request) {
	loginProvider := ""
	if request.Method == http.MethodPost {
		var formOK bool
		loginProvider, formOK = server.parseBrowserLoginForm(response, request)
		if !formOK {
			return
		}
	}
	pending, requestToken, ok := server.pendingBrowserRequest(response, request)
	if !ok {
		return
	}
	if _, resolveErr := server.browserSessions.Resolve(request, pending.TenantID); resolveErr == nil {
		redirectIssuerPage(response, server.config.ConsentEndpoint(), requestToken)
		return
	}
	if request.Method == http.MethodGet {
		server.writeLoginPage(response, request, pending, requestToken, http.StatusOK, "")
		return
	}
	passwordEnabled, googleClientID, methodsErr := server.browserSessions.LoginMethods(pending.TenantID)
	if methodsErr != nil {
		writeOAuthError(response, http.StatusInternalServerError, "server_error")
		return
	}
	loginAccepted := false
	var loginErr error
	switch loginProvider {
	case "password":
		if !passwordEnabled {
			break
		}
		loginAccepted, loginErr = server.browserSessions.LoginPassword(request.Context(), response, request, pending.TenantID, request.PostForm.Get("email"), request.PostForm.Get("password"))
	case "google":
		if googleClientID == "" {
			break
		}
		loginAccepted, loginErr = server.browserSessions.LoginGoogle(request.Context(), response, request, pending.TenantID, request.PostForm.Get("google_id_token"), request.PostForm.Get("nonce_token"))
	}
	if loginErr != nil {
		writeOAuthError(response, http.StatusInternalServerError, "server_error")
		return
	}
	if !loginAccepted {
		server.writeLoginPage(response, request, pending, requestToken, http.StatusUnauthorized, "Authentication was not accepted.")
		return
	}
	if loginProvider == "google" && strings.Contains(request.Header.Get("Accept"), "application/json") {
		writePrivateJSON(response, http.StatusOK, map[string]string{"next": issuerPageURL(server.config.ConsentEndpoint(), requestToken)})
		return
	}
	redirectIssuerPage(response, server.config.ConsentEndpoint(), requestToken)
}

func (server *Server) handleConsent(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodPost && !server.parseBrowserForm(response, request, []string{"request", "decision"}, "") {
		return
	}
	pending, requestToken, ok := server.pendingBrowserRequest(response, request)
	if !ok {
		return
	}
	userID, sessionErr := server.browserSessions.Resolve(request, pending.TenantID)
	if sessionErr != nil {
		redirectIssuerPage(response, server.config.LoginEndpoint(), requestToken)
		return
	}
	policy, resource, resourceErr := server.registry.ResolveResource(pending.Resource)
	if resourceErr != nil || policy.TenantID != pending.TenantID {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if request.Method == http.MethodGet {
		writeBrowserPage(response, consentPage, consentPageDataFor(pending, resource, requestToken))
		return
	}
	decision := request.PostForm.Get("decision")
	if decision == "deny" {
		if _, consumeErr := server.store.ConsumeAuthorizationRequest(request.Context(), requestToken, server.now().UTC().Unix()); consumeErr != nil {
			writeAuthorizationRequestStoreError(response, consumeErr)
			return
		}
		server.redirectAuthorizationError(response, pending.RedirectURI, pending.State, "access_denied")
		return
	}
	if decision != "approve" {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	now := server.now().UTC()
	consumed, consumeErr := server.store.ConsumeAuthorizationRequest(request.Context(), requestToken, now.Unix())
	if consumeErr != nil || consumed != pending {
		if consumeErr != nil {
			writeAuthorizationRequestStoreError(response, consumeErr)
		} else {
			writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		}
		return
	}
	consent, saveErr := server.store.SaveConsent(request.Context(), Consent{
		ConsentKey: pending.consentKey(userID), CreatedAtUnix: now.Unix(),
		ExpiresAtUnix: now.Add(policy.ConsentTTL).Unix(),
	})
	if saveErr != nil {
		writeOAuthError(response, http.StatusInternalServerError, "server_error")
		return
	}
	server.issueCodeAndRedirect(response, request, pending, userID, consent.ID, now)
}

func (server *Server) handleToken(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Pragma", "no-cache")
	if !validFormRequest(request) || request.Header.Get("Authorization") != "" || parseBoundedForm(response, request) != nil {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	grantType, grantTypeOK := boundedSingleFormValue(request.PostForm, "grant_type", "")
	if !grantTypeOK {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	switch grantType {
	case "authorization_code":
		if !definedFormParametersValid(request.PostForm, []string{"grant_type", "code", "client_id", "resource", "code_verifier"}, nil, "") {
			writeOAuthError(response, http.StatusBadRequest, "invalid_request")
			return
		}
		server.exchangeAuthorizationCode(response, request)
	case "refresh_token":
		if !definedFormParametersValid(request.PostForm, []string{"grant_type", "refresh_token", "client_id", "resource"}, []string{"scope"}, "") {
			writeOAuthError(response, http.StatusBadRequest, "invalid_request")
			return
		}
		server.exchangeRefreshToken(response, request)
	default:
		writeOAuthError(response, http.StatusBadRequest, "unsupported_grant_type")
	}
}

func (server *Server) exchangeAuthorizationCode(response http.ResponseWriter, request *http.Request) {
	clientID := request.PostForm.Get("client_id")
	resourceID := request.PostForm.Get("resource")
	policy, resource, resourceErr := server.registry.ResolveResource(resourceID)
	if resourceErr != nil {
		writeOAuthError(response, http.StatusBadRequest, "invalid_target")
		return
	}
	client, clientErr := server.resolveTokenClient(policy, clientID)
	if clientErr != nil {
		writeOAuthError(response, http.StatusBadRequest, "invalid_grant")
		return
	}
	now := server.now().UTC()
	grant, redeemErr := server.store.RedeemAuthorizationCode(request.Context(), request.PostForm.Get("code"), CodeExchange{
		ClientID: clientID, Resource: resourceID,
		CodeVerifier: request.PostForm.Get("code_verifier"), NowUnix: now.Unix(),
	})
	if redeemErr != nil {
		if errors.Is(redeemErr, ErrAuthorizationCodeInvalid) {
			writeOAuthError(response, http.StatusBadRequest, "invalid_grant")
		} else {
			writeOAuthError(response, http.StatusInternalServerError, "server_error")
		}
		return
	}
	if policyErr := server.enforceCurrentGrantPolicy(request.Context(), policy, resource, client, grant.TenantID, grant.ConsentID, grant.Scope, now.Unix()); policyErr != nil {
		if errors.Is(policyErr, ErrInvalidScope) {
			writeOAuthError(response, http.StatusBadRequest, "invalid_grant")
		} else {
			writeOAuthError(response, http.StatusInternalServerError, "server_error")
		}
		return
	}
	refreshGrant := RefreshGrant{
		ConsentID: grant.ConsentID, TenantID: grant.TenantID, UserID: grant.UserID,
		ClientID: grant.ClientID, Resource: grant.Resource, Scope: grant.Scope,
		ExpiresAtUnix: now.Add(policy.RefreshTokenTTL).Unix(),
	}
	refreshToken, refreshErr := server.store.IssueRefreshToken(request.Context(), refreshGrant)
	if refreshErr != nil {
		writeOAuthError(response, http.StatusInternalServerError, "server_error")
		return
	}
	server.writeTokenResponse(response, refreshGrant, refreshToken, policy.AccessTokenTTL, now)
}

func (server *Server) exchangeRefreshToken(response http.ResponseWriter, request *http.Request) {
	clientID := request.PostForm.Get("client_id")
	resourceID := request.PostForm.Get("resource")
	requestedScope, scopeOK := normalizeScopeParameter(request.PostForm.Get("scope"))
	if !scopeOK {
		writeOAuthError(response, http.StatusBadRequest, "invalid_scope")
		return
	}
	policy, resource, resourceErr := server.registry.ResolveResource(resourceID)
	if resourceErr != nil {
		writeOAuthError(response, http.StatusBadRequest, "invalid_target")
		return
	}
	client, clientErr := server.resolveTokenClient(policy, clientID)
	if clientErr != nil {
		writeOAuthError(response, http.StatusBadRequest, "invalid_grant")
		return
	}
	now := server.now().UTC()
	grant, rotatedToken, rotateErr := server.store.RotateRefreshToken(request.Context(), request.PostForm.Get("refresh_token"), clientID, resourceID, requestedScope, now.Unix())
	if rotateErr != nil {
		if errors.Is(rotateErr, ErrRefreshTokenScope) {
			writeOAuthError(response, http.StatusBadRequest, "invalid_scope")
		} else if errors.Is(rotateErr, ErrRefreshTokenInvalid) || errors.Is(rotateErr, ErrRefreshTokenReuse) {
			writeOAuthError(response, http.StatusBadRequest, "invalid_grant")
		} else {
			writeOAuthError(response, http.StatusInternalServerError, "server_error")
		}
		return
	}
	if policyErr := server.enforceCurrentGrantPolicy(request.Context(), policy, resource, client, grant.TenantID, grant.ConsentID, grant.Scope, now.Unix()); policyErr != nil {
		if errors.Is(policyErr, ErrInvalidScope) {
			writeOAuthError(response, http.StatusBadRequest, "invalid_grant")
		} else {
			writeOAuthError(response, http.StatusInternalServerError, "server_error")
		}
		return
	}
	server.writeTokenResponse(response, grant, rotatedToken, policy.AccessTokenTTL, now)
}

func (server *Server) writeTokenResponse(response http.ResponseWriter, grant RefreshGrant, refreshToken string, ttl time.Duration, now time.Time) {
	accessToken, expiresAt, mintErr := server.signer.MintAccessToken(grant, now, ttl)
	if mintErr != nil {
		writeOAuthError(response, http.StatusInternalServerError, "server_error")
		return
	}
	writePrivateJSON(response, http.StatusOK, map[string]any{
		"access_token": accessToken, "token_type": "Bearer",
		"expires_in": int64(expiresAt.Sub(now).Seconds()), "scope": grant.Scope, "refresh_token": refreshToken,
	})
}

func (server *Server) handleRevocation(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	if !validFormRequest(request) || request.Header.Get("Authorization") != "" || parseBoundedForm(response, request) != nil {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if !definedFormParametersValid(request.PostForm, []string{"token", "client_id"}, []string{"token_type_hint"}, "") {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	token := request.PostForm.Get("token")
	clientID := request.PostForm.Get("client_id")
	now := server.now().UTC()
	var revokeErr error
	if claims, parseErr := server.signer.ParseAccessToken(token, now); parseErr == nil && claims.ClientID == clientID {
		revokeErr = server.store.RevokeConsent(request.Context(), claims.GrantID, now.Unix())
	} else {
		revokeErr = server.store.RevokeRefreshToken(request.Context(), token, clientID, now.Unix())
	}
	if revokeErr != nil {
		writeOAuthError(response, http.StatusInternalServerError, "server_error")
		return
	}
	response.WriteHeader(http.StatusOK)
}

func (server *Server) resolveClient(ctx context.Context, policy TenantPolicy, clientID string) (Client, error) {
	if client, exists := server.registry.ResolveExplicitClient(policy.TenantID, clientID); exists {
		return client, nil
	}
	if !policy.AllowClientMetadataDocuments {
		return Client{}, ErrUnknownClient
	}
	client, resolveErr := server.metadataResolver.Resolve(ctx, clientID)
	if resolveErr != nil {
		return Client{}, ErrUnknownClient
	}
	return client, nil
}

func (server *Server) resolveTokenClient(policy TenantPolicy, clientID string) (Client, error) {
	if client, exists := server.registry.ResolveExplicitClient(policy.TenantID, clientID); exists {
		return client, nil
	}
	if !policy.AllowClientMetadataDocuments {
		return Client{}, ErrUnknownClient
	}
	if _, validationErr := validateClientIdentifierURL(clientID); validationErr != nil {
		return Client{}, ErrUnknownClient
	}
	return Client{ID: clientID, Source: clientSourceMetadata}, nil
}

func (server *Server) enforceCurrentGrantPolicy(ctx context.Context, policy TenantPolicy, resource Resource, client Client, tenantID string, consentID string, scope string, nowUnix int64) error {
	if tenantID != policy.TenantID {
		return ErrInvalidScope
	}
	if _, _, scopeErr := validateRequestedScopes(resource, client, scope); scopeErr == nil {
		return nil
	}
	if revokeErr := server.store.RevokeConsent(ctx, consentID, nowUnix); revokeErr != nil {
		return fmt.Errorf("oauth.grant.revoke: %w", revokeErr)
	}
	return ErrInvalidScope
}

func (server *Server) pendingBrowserRequest(response http.ResponseWriter, request *http.Request) (AuthorizationRequest, string, bool) {
	requestToken, requestTokenOK := singleValue(request.URL.Query(), "request")
	if request.Method == http.MethodPost {
		requestToken = request.PostForm.Get("request")
		requestTokenOK = true
	}
	if !requestTokenOK || len(requestToken) > maximumOAuthParameterBytes {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return AuthorizationRequest{}, "", false
	}
	pending, pendingErr := server.store.GetAuthorizationRequest(request.Context(), requestToken, server.now().Unix())
	if pendingErr != nil {
		writeAuthorizationRequestStoreError(response, pendingErr)
		return AuthorizationRequest{}, "", false
	}
	return pending, requestToken, true
}

func (server *Server) consumeAndIssueCodeAndRedirect(response http.ResponseWriter, request *http.Request, requestToken string, pending AuthorizationRequest, userID string, consentID string) {
	now := server.now().UTC()
	consumed, consumeErr := server.store.ConsumeAuthorizationRequest(request.Context(), requestToken, now.Unix())
	if consumeErr != nil || consumed != pending {
		if consumeErr != nil {
			writeAuthorizationRequestStoreError(response, consumeErr)
		} else {
			writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		}
		return
	}
	server.issueCodeAndRedirect(response, request, pending, userID, consentID, now)
}

func (server *Server) issueCodeAndRedirect(response http.ResponseWriter, request *http.Request, pending AuthorizationRequest, userID string, consentID string, now time.Time) {
	code, issueErr := server.store.IssueAuthorizationCode(request.Context(), AuthorizationGrant{
		ConsentID: consentID, TenantID: pending.TenantID, UserID: userID,
		ClientID: pending.ClientID, RedirectURI: pending.RedirectURI, Resource: pending.Resource,
		Scope: pending.Scope, CodeChallenge: pending.CodeChallenge,
		ExpiresAtUnix: now.Add(server.config.AuthorizationCodeTTL()).Unix(),
	})
	if issueErr != nil {
		writeOAuthError(response, http.StatusInternalServerError, "server_error")
		return
	}
	redirectWithParameters(response, pending.RedirectURI, map[string]string{"code": code, "iss": server.config.Issuer(), "state": pending.State})
}

func writeAuthorizationRequestStoreError(response http.ResponseWriter, storeErr error) {
	if errors.Is(storeErr, ErrAuthorizationRequestInvalid) {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	writeOAuthError(response, http.StatusInternalServerError, "server_error")
}

func (request AuthorizationRequest) consentKey(userID string) ConsentKey {
	return ConsentKey{TenantID: request.TenantID, UserID: userID, ClientID: request.ClientID, Resource: request.Resource, Scope: request.Scope}
}

func endpointPath(address string) string {
	parsed, parseErr := url.Parse(address)
	if parseErr != nil {
		return ""
	}
	return parsed.EscapedPath()
}

func singleValue(values url.Values, name string) (string, bool) {
	entries, exists := values[name]
	return firstSingle(entries, exists)
}

func firstSingle(entries []string, exists bool) (string, bool) {
	returnValue := ""
	if !exists || len(entries) != 1 {
		return returnValue, false
	}
	return entries[0], strings.TrimSpace(entries[0]) == entries[0] && entries[0] != ""
}

func validFormRequest(request *http.Request) bool {
	mediaType, _, parseErr := mime.ParseMediaType(request.Header.Get("Content-Type"))
	return parseErr == nil && mediaType == "application/x-www-form-urlencoded"
}

func parseBoundedForm(response http.ResponseWriter, request *http.Request) error {
	request.Body = http.MaxBytesReader(response, request.Body, maximumOAuthFormBytes)
	return request.ParseForm()
}

func (server *Server) parseBrowserForm(response http.ResponseWriter, request *http.Request, fields []string, untrimmedField string) bool {
	if !validFormRequest(request) || request.Header.Get("Authorization") != "" || !requestOriginMatchesIssuer(request, server.config.Issuer()) || parseBoundedForm(response, request) != nil || len(request.PostForm) != len(fields) || !definedFormParametersValid(request.PostForm, fields, nil, untrimmedField) {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

func (server *Server) parseBrowserLoginForm(response http.ResponseWriter, request *http.Request) (string, bool) {
	if !validFormRequest(request) || request.Header.Get("Authorization") != "" || !requestOriginMatchesIssuer(request, server.config.Issuer()) || parseBoundedForm(response, request) != nil {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return "", false
	}
	provider, providerOK := boundedSingleFormValue(request.PostForm, "provider", "")
	fields := []string{}
	untrimmedField := ""
	switch provider {
	case "password":
		fields = []string{"request", "provider", "email", "password"}
		untrimmedField = "password"
	case "google":
		fields = []string{"request", "provider", "google_id_token", "nonce_token"}
	default:
		providerOK = false
	}
	if !providerOK || len(request.PostForm) != len(fields) || !definedFormParametersValid(request.PostForm, fields, nil, untrimmedField) {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return "", false
	}
	return provider, true
}

func requestOriginMatchesIssuer(request *http.Request, issuer string) bool {
	originURL, originErr := url.Parse(request.Header.Get("Origin"))
	issuerURL, issuerErr := url.Parse(issuer)
	if originErr != nil || issuerErr != nil || originURL.Path != "" || originURL.RawQuery != "" || originURL.Fragment != "" || originURL.User != nil {
		return false
	}
	return originURL.Scheme == issuerURL.Scheme && strings.EqualFold(originURL.Host, issuerURL.Host)
}

func definedFormParametersValid(values url.Values, required []string, optional []string, untrimmedField string) bool {
	for _, name := range required {
		if _, ok := boundedSingleFormValue(values, name, untrimmedField); !ok {
			return false
		}
	}
	for _, name := range optional {
		if entries, exists := values[name]; exists {
			if len(entries) == 1 && entries[0] == "" {
				continue
			}
			if _, ok := boundedSingleFormValue(url.Values{name: entries}, name, untrimmedField); !ok {
				return false
			}
		}
	}
	return true
}

func boundedSingleFormValue(values url.Values, name string, untrimmedField string) (string, bool) {
	entries, exists := values[name]
	if !exists || len(entries) != 1 || entries[0] == "" || len(entries[0]) > maximumOAuthParameterBytes {
		return "", false
	}
	if name != untrimmedField && strings.TrimSpace(entries[0]) != entries[0] {
		return "", false
	}
	return entries[0], true
}

func normalizeScopeParameter(raw string) (string, bool) {
	if raw == "" {
		return "", true
	}
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return "", false
	}
	seen := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		if _, duplicate := seen[field]; duplicate {
			return "", false
		}
		seen[field] = struct{}{}
	}
	sort.Strings(fields)
	return strings.Join(fields, " "), true
}

func redirectIssuerPage(response http.ResponseWriter, endpoint string, requestToken string) {
	redirectWithParameters(response, endpoint, map[string]string{"request": requestToken})
}

func issuerPageURL(endpoint string, requestToken string) string {
	parsed, parseErr := url.Parse(endpoint)
	if parseErr != nil {
		return ""
	}
	query := parsed.Query()
	query.Set("request", requestToken)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func (server *Server) redirectAuthorizationError(response http.ResponseWriter, redirectURI string, state string, code string) {
	redirectWithParameters(response, redirectURI, map[string]string{"error": code, "iss": server.config.Issuer(), "state": state})
}

func redirectWithParameters(response http.ResponseWriter, address string, parameters map[string]string) {
	parsed, parseErr := url.Parse(address)
	if parseErr != nil {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	query := parsed.Query()
	keys := make([]string, 0, len(parameters))
	for key := range parameters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		query.Set(key, parameters[key])
	}
	parsed.RawQuery = query.Encode()
	response.Header().Set("Location", parsed.String())
	response.WriteHeader(http.StatusSeeOther)
}

func writeOAuthError(response http.ResponseWriter, status int, code string) {
	writePrivateJSON(response, status, map[string]string{"error": code})
}

func writePublicJSON(response http.ResponseWriter, status int, payload any) {
	response.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(response, status, payload)
}

func writePrivateJSON(response http.ResponseWriter, status int, payload any) {
	response.Header().Set("Cache-Control", "no-store")
	writeJSON(response, status, payload)
}

func writeJSON(response http.ResponseWriter, status int, payload any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(payload)
}

type loginPageData struct {
	RequestToken   string
	ClientName     string
	ResourceName   string
	ErrorMessage   string
	PasswordLogin  bool
	GoogleClientID string
	GoogleNonce    string
	ScriptNonce    string
}

type consentScopeData struct {
	Name        string
	Description string
}

type consentPageData struct {
	RequestToken string
	ClientName   string
	ClientID     string
	ResourceName string
	RedirectHost string
	Loopback     bool
	Scopes       []consentScopeData
}

func consentPageDataFor(pending AuthorizationRequest, resource Resource, requestToken string) consentPageData {
	parsedRedirect, _ := url.Parse(pending.RedirectURI)
	scopeData := make([]consentScopeData, 0)
	for _, scopeID := range strings.Fields(pending.Scope) {
		scope := resource.Scopes[scopeID]
		scopeData = append(scopeData, consentScopeData{Name: scope.DisplayName, Description: scope.Description})
	}
	return consentPageData{
		RequestToken: requestToken, ClientName: pending.ClientName, ClientID: pending.ClientID,
		ResourceName: pending.ResourceName, RedirectHost: pending.RedirectHost,
		Loopback: parsedRedirect != nil && (parsedRedirect.Hostname() == "localhost" || strings.HasPrefix(parsedRedirect.Hostname(), "127.")),
		Scopes:   scopeData,
	}
}

func writeBrowserPage(response http.ResponseWriter, page *template.Template, data any) {
	writeBrowserPageStatus(response, http.StatusOK, page, data)
}

func writeBrowserPageStatus(response http.ResponseWriter, status int, page *template.Template, data any) {
	writeBrowserPageStatusWithScript(response, status, page, data, "")
}

func writeBrowserPageStatusWithScript(response http.ResponseWriter, status int, page *template.Template, data any, scriptNonce string) {
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	contentSecurityPolicy := "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
	if scriptNonce != "" {
		contentSecurityPolicy += "; script-src 'nonce-" + scriptNonce + "' https://accounts.google.com; frame-src https://accounts.google.com; connect-src 'self' https://accounts.google.com"
	}
	response.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	response.Header().Set("Referrer-Policy", "origin")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(status)
	_ = page.Execute(response, data)
}

func (server *Server) writeLoginPage(response http.ResponseWriter, request *http.Request, pending AuthorizationRequest, requestToken string, status int, errorMessage string) {
	passwordLogin, googleClientID, methodsErr := server.browserSessions.LoginMethods(pending.TenantID)
	if methodsErr != nil || (!passwordLogin && googleClientID == "") {
		writeOAuthError(response, http.StatusInternalServerError, "server_error")
		return
	}
	data := loginPageData{
		RequestToken: requestToken, ClientName: pending.ClientName, ResourceName: pending.ResourceName,
		ErrorMessage: errorMessage, PasswordLogin: passwordLogin, GoogleClientID: googleClientID,
	}
	if googleClientID != "" {
		googleNonce, nonceErr := server.browserSessions.IssueGoogleNonce(request.Context(), pending.TenantID)
		scriptNonce, _, scriptNonceErr := newOpaqueToken("browser_script_nonce")
		if nonceErr != nil || scriptNonceErr != nil {
			writeOAuthError(response, http.StatusInternalServerError, "server_error")
			return
		}
		data.GoogleNonce = googleNonce
		data.ScriptNonce = scriptNonce
	}
	writeBrowserPageStatusWithScript(response, status, loginPage, data, data.ScriptNonce)
}

var loginPage = template.Must(template.New("login").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Log in to TAuth</title><style>{{template "style"}}</style>{{if .GoogleClientID}}<script src="https://accounts.google.com/gsi/client" async defer></script>{{end}}</head><body data-request-token="{{.RequestToken}}" data-google-client-id="{{.GoogleClientID}}" data-google-nonce="{{.GoogleNonce}}"><main><h1>Log in</h1><p><strong>{{.ClientName}}</strong> is requesting access to {{.ResourceName}}.</p>{{if .ErrorMessage}}<p role="alert" class="error">{{.ErrorMessage}}</p>{{end}}{{if .GoogleClientID}}<div id="google-login"></div><p id="google-error" role="alert" class="error" hidden>Google authentication was not accepted.</p><script nonce="{{.ScriptNonce}}">window.addEventListener("load",function(){var root=document.body;var error=document.getElementById("google-error");if(!window.google||!google.accounts||!google.accounts.id){error.hidden=false;return;}google.accounts.id.initialize({client_id:root.dataset.googleClientId,nonce:root.dataset.googleNonce,callback:async function(result){try{var response=await fetch(window.location.href,{method:"POST",credentials:"same-origin",headers:{"Accept":"application/json","Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({request:root.dataset.requestToken,provider:"google",google_id_token:result.credential,nonce_token:root.dataset.googleNonce})});if(!response.ok){throw new Error("login rejected");}var payload=await response.json();if(!payload.next){throw new Error("login continuation missing");}window.location.assign(payload.next);}catch(_failure){error.hidden=false;}}});google.accounts.id.renderButton(document.getElementById("google-login"),{theme:"outline",size:"large",width:320});});</script>{{end}}{{if and .GoogleClientID .PasswordLogin}}<p class="separator">or</p>{{end}}{{if .PasswordLogin}}<form method="post"><input type="hidden" name="request" value="{{.RequestToken}}"><input type="hidden" name="provider" value="password"><label>Email<input name="email" type="email" required autocomplete="username"></label><label>Password<input name="password" type="password" required autocomplete="current-password"></label><button type="submit">Continue</button></form>{{end}}</main></body></html>{{define "style"}}:root{color-scheme:dark}body{margin:0;background:#111;color:#eee;font:16px system-ui}main{max-width:30rem;margin:10vh auto;padding:2rem;background:#1b1b1b;border:1px solid #444;border-radius:12px}label{display:block;margin:1rem 0}input,button{box-sizing:border-box;width:100%;padding:.75rem;margin-top:.35rem;background:#242424;color:#fff;border:1px solid #666;border-radius:6px}button{background:#2765d7;border:0;font-weight:700}.error{color:#ff9b9b}.separator{text-align:center;color:#aaa}#google-login{display:flex;justify-content:center;margin:1.25rem 0}{{end}}`))

var consentPage = template.Must(template.New("consent").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Authorize access</title><style>{{template "style"}}</style></head><body><main><h1>Authorize access</h1><p><strong>{{.ClientName}}</strong> wants to access <strong>{{.ResourceName}}</strong>.</p><p class="meta">Client: {{.ClientID}}<br>Return host: {{.RedirectHost}}</p>{{if .Loopback}}<p role="note" class="warning">This client returns to an application on this device.</p>{{end}}<h2>Permissions</h2><ul>{{range .Scopes}}<li><strong>{{.Name}}</strong><br><span>{{.Description}}</span></li>{{end}}</ul><form method="post"><input type="hidden" name="request" value="{{.RequestToken}}"><div class="actions"><button name="decision" value="deny" class="secondary">Deny</button><button name="decision" value="approve">Approve</button></div></form></main></body></html>{{define "style"}}:root{color-scheme:dark}body{margin:0;background:#111;color:#eee;font:16px system-ui}main{max-width:36rem;margin:8vh auto;padding:2rem;background:#1b1b1b;border:1px solid #444;border-radius:12px}.meta{color:#aaa;overflow-wrap:anywhere}.warning{padding:.75rem;background:#392f12;border:1px solid #7b6321}li{margin:.8rem 0}li span{color:#bbb}.actions{display:flex;gap:.75rem;margin-top:1.5rem}button{flex:1;padding:.75rem;background:#2765d7;color:#fff;border:0;border-radius:6px;font-weight:700}.secondary{background:#333;border:1px solid #666}{{end}}`))

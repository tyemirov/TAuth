package tenants

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	errorCodeOAuthDisabled             = "tenant.oauth_disabled"
	errorCodeOAuthInvalidAccessTTL     = "tenant.oauth_invalid_access_token_ttl"
	errorCodeOAuthInvalidRefreshTTL    = "tenant.oauth_invalid_refresh_token_ttl"
	errorCodeOAuthInvalidConsentTTL    = "tenant.oauth_invalid_consent_ttl"
	errorCodeOAuthMissingResource      = "tenant.oauth_missing_resource"
	errorCodeOAuthInvalidResource      = "tenant.oauth_invalid_resource"
	errorCodeOAuthDuplicateResource    = "tenant.oauth_duplicate_resource"
	errorCodeOAuthInvalidScope         = "tenant.oauth_invalid_scope"
	errorCodeOAuthDuplicateScope       = "tenant.oauth_duplicate_scope"
	errorCodeOAuthMissingClient        = "tenant.oauth_missing_client"
	errorCodeOAuthMissingBrowserAuth   = "tenant.oauth_missing_browser_auth"
	errorCodeOAuthInvalidClient        = "tenant.oauth_invalid_client"
	errorCodeOAuthDuplicateClient      = "tenant.oauth_duplicate_client"
	errorCodeOAuthInvalidRedirectURI   = "tenant.oauth_invalid_redirect_uri"
	errorCodeOAuthDuplicateRedirectURI = "tenant.oauth_duplicate_redirect_uri"
	errorCodeOAuthInvalidLoopbackPorts = "tenant.oauth_invalid_loopback_ports"
	errorCodeOAuthInvalidClientGrant   = "tenant.oauth_invalid_client_grant"
	maximumOAuthAccessTokenTTL         = 15 * time.Minute
	maximumOAuthRefreshTokenTTL        = 90 * 24 * time.Hour
	maximumOAuthConsentTTL             = 365 * 24 * time.Hour
	minimumOAuthAccessTokenTTL         = 30 * time.Second
	minimumOAuthRefreshTokenTTL        = time.Minute
	minimumOAuthConsentTTL             = time.Minute
	oauthApplicationTypeWeb            = "web"
	oauthApplicationTypeNative         = "native"
)

var oauthClientIDRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]{2,127}$`)

// OAuthAuthorization is one tenant's validated resource authorization policy.
type OAuthAuthorization struct {
	enabled                      bool
	accessTokenTTL               time.Duration
	refreshTokenTTL              time.Duration
	consentTTL                   time.Duration
	allowClientMetadataDocuments bool
	resources                    []OAuthResource
	clients                      []OAuthClient
}

// OAuthResource is one protected-resource identifier and its permitted scopes.
type OAuthResource struct {
	identifier  string
	displayName string
	scopes      []OAuthScope
}

// OAuthScope is one resource permission displayed during consent.
type OAuthScope struct {
	identifier  string
	displayName string
	description string
}

// OAuthClient is one explicitly registered public client.
type OAuthClient struct {
	id                  string
	displayName         string
	applicationType     string
	redirectURIs        []string
	loopbackPortMinimum int
	loopbackPortMaximum int
	grants              []OAuthClientGrant
}

// OAuthClientGrant limits one explicit client to a resource and scope set.
type OAuthClientGrant struct {
	resource string
	scopes   []string
}

// FileOAuthAuthorization represents a raw tenant OAuth block.
type FileOAuthAuthorization struct {
	Enabled                      yamlBool            `json:"enabled" yaml:"enabled"`
	AccessTokenTTL               string              `json:"access_token_ttl" yaml:"access_token_ttl"`
	RefreshTokenTTL              string              `json:"refresh_token_ttl" yaml:"refresh_token_ttl"`
	ConsentTTL                   string              `json:"consent_ttl" yaml:"consent_ttl"`
	AllowClientMetadataDocuments yamlBool            `json:"allow_client_metadata_documents" yaml:"allow_client_metadata_documents"`
	Resources                    []FileOAuthResource `json:"resources" yaml:"resources"`
	Clients                      []FileOAuthClient   `json:"clients" yaml:"clients"`
}

// FileOAuthResource represents one raw protected resource.
type FileOAuthResource struct {
	Identifier  string           `json:"identifier" yaml:"identifier"`
	DisplayName string           `json:"display_name" yaml:"display_name"`
	Scopes      []FileOAuthScope `json:"scopes" yaml:"scopes"`
}

// FileOAuthScope represents one raw resource scope.
type FileOAuthScope struct {
	Identifier  string `json:"identifier" yaml:"identifier"`
	DisplayName string `json:"display_name" yaml:"display_name"`
	Description string `json:"description" yaml:"description"`
}

// FileOAuthClient represents one raw explicitly registered public client.
type FileOAuthClient struct {
	ID                string                     `json:"id" yaml:"id"`
	DisplayName       string                     `json:"display_name" yaml:"display_name"`
	ApplicationType   string                     `json:"application_type" yaml:"application_type"`
	RedirectURIs      []string                   `json:"redirect_uris" yaml:"redirect_uris"`
	LoopbackPortRange FileOAuthLoopbackPortRange `json:"loopback_port_range" yaml:"loopback_port_range"`
	Grants            []FileOAuthClientGrant     `json:"grants" yaml:"grants"`
}

// FileOAuthLoopbackPortRange bounds native loopback redirect ports.
type FileOAuthLoopbackPortRange struct {
	Minimum int `json:"minimum" yaml:"minimum"`
	Maximum int `json:"maximum" yaml:"maximum"`
}

// FileOAuthClientGrant represents one raw client resource grant.
type FileOAuthClientGrant struct {
	Resource string   `json:"resource" yaml:"resource"`
	Scopes   []string `json:"scopes" yaml:"scopes"`
}

// Enabled reports whether the tenant accepts OAuth grants.
func (authorization OAuthAuthorization) Enabled() bool { return authorization.enabled }

// AccessTokenTTL returns the access-token lifetime.
func (authorization OAuthAuthorization) AccessTokenTTL() time.Duration {
	return authorization.accessTokenTTL
}

// RefreshTokenTTL returns the absolute refresh-family lifetime.
func (authorization OAuthAuthorization) RefreshTokenTTL() time.Duration {
	return authorization.refreshTokenTTL
}

// ConsentTTL returns the repeat-consent lifetime.
func (authorization OAuthAuthorization) ConsentTTL() time.Duration { return authorization.consentTTL }

// AllowClientMetadataDocuments reports whether the tenant accepts valid Client ID Metadata Documents.
func (authorization OAuthAuthorization) AllowClientMetadataDocuments() bool {
	return authorization.allowClientMetadataDocuments
}

// Resources returns a copy of the tenant resource declarations.
func (authorization OAuthAuthorization) Resources() []OAuthResource {
	resources := make([]OAuthResource, len(authorization.resources))
	for index, resource := range authorization.resources {
		resources[index] = resource.clone()
	}
	return resources
}

// Clients returns a copy of the explicit public clients.
func (authorization OAuthAuthorization) Clients() []OAuthClient {
	clients := make([]OAuthClient, len(authorization.clients))
	for index, client := range authorization.clients {
		clients[index] = client.clone()
	}
	return clients
}

// Identifier returns the exact RFC 8707 resource identifier.
func (resource OAuthResource) Identifier() string { return resource.identifier }

// DisplayName returns the resource name shown during consent.
func (resource OAuthResource) DisplayName() string { return resource.displayName }

// Scopes returns the resource's permitted scopes.
func (resource OAuthResource) Scopes() []OAuthScope {
	scopes := make([]OAuthScope, len(resource.scopes))
	copy(scopes, resource.scopes)
	return scopes
}

// Identifier returns the exact OAuth scope value.
func (scope OAuthScope) Identifier() string { return scope.identifier }

// DisplayName returns the scope name shown during consent.
func (scope OAuthScope) DisplayName() string { return scope.displayName }

// Description returns the scope description shown during consent.
func (scope OAuthScope) Description() string { return scope.description }

// ID returns the exact explicit client identifier.
func (client OAuthClient) ID() string { return client.id }

// DisplayName returns the client name shown during consent.
func (client OAuthClient) DisplayName() string { return client.displayName }

// ApplicationType returns web or native.
func (client OAuthClient) ApplicationType() string { return client.applicationType }

// RedirectURIs returns the client's exact registered redirect values.
func (client OAuthClient) RedirectURIs() []string {
	return append([]string(nil), client.redirectURIs...)
}

// LoopbackPortMinimum returns the optional native port lower bound.
func (client OAuthClient) LoopbackPortMinimum() int { return client.loopbackPortMinimum }

// LoopbackPortMaximum returns the optional native port upper bound.
func (client OAuthClient) LoopbackPortMaximum() int { return client.loopbackPortMaximum }

// Grants returns the client's permitted resources and scopes.
func (client OAuthClient) Grants() []OAuthClientGrant {
	grants := make([]OAuthClientGrant, len(client.grants))
	for index, grant := range client.grants {
		grants[index] = OAuthClientGrant{resource: grant.resource, scopes: append([]string(nil), grant.scopes...)}
	}
	return grants
}

// Resource returns the permitted resource identifier.
func (grant OAuthClientGrant) Resource() string { return grant.resource }

// Scopes returns the client's permitted scope values for the resource.
func (grant OAuthClientGrant) Scopes() []string { return append([]string(nil), grant.scopes...) }

func (authorization OAuthAuthorization) clone() OAuthAuthorization {
	authorization.resources = authorization.Resources()
	authorization.clients = authorization.Clients()
	return authorization
}

func (resource OAuthResource) clone() OAuthResource {
	resource.scopes = resource.Scopes()
	return resource
}

func (client OAuthClient) clone() OAuthClient {
	client.redirectURIs = client.RedirectURIs()
	client.grants = client.Grants()
	return client
}

func parseOAuthAuthorization(raw FileOAuthAuthorization, tenantID TenantID, allowInsecureHTTP bool) (OAuthAuthorization, error) {
	if !bool(raw.Enabled) {
		if fileOAuthAuthorizationHasValues(raw) {
			return OAuthAuthorization{}, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeOAuthDisabled, tenantID)
		}
		return OAuthAuthorization{}, nil
	}
	accessTokenTTL, accessErr := parseOAuthTenantTTL(raw.AccessTokenTTL, minimumOAuthAccessTokenTTL, maximumOAuthAccessTokenTTL)
	if accessErr != nil {
		return OAuthAuthorization{}, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeOAuthInvalidAccessTTL, tenantID)
	}
	refreshTokenTTL, refreshErr := parseOAuthTenantTTL(raw.RefreshTokenTTL, minimumOAuthRefreshTokenTTL, maximumOAuthRefreshTokenTTL)
	if refreshErr != nil {
		return OAuthAuthorization{}, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeOAuthInvalidRefreshTTL, tenantID)
	}
	consentTTL, consentErr := parseOAuthTenantTTL(raw.ConsentTTL, minimumOAuthConsentTTL, maximumOAuthConsentTTL)
	if consentErr != nil {
		return OAuthAuthorization{}, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeOAuthInvalidConsentTTL, tenantID)
	}
	resources, resourceIndex, resourcesErr := parseOAuthResources(raw.Resources, tenantID, allowInsecureHTTP)
	if resourcesErr != nil {
		return OAuthAuthorization{}, resourcesErr
	}
	clients, clientsErr := parseOAuthClients(raw.Clients, tenantID, resourceIndex)
	if clientsErr != nil {
		return OAuthAuthorization{}, clientsErr
	}
	if len(clients) == 0 && !bool(raw.AllowClientMetadataDocuments) {
		return OAuthAuthorization{}, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeOAuthMissingClient, tenantID)
	}
	return OAuthAuthorization{
		enabled:                      true,
		accessTokenTTL:               accessTokenTTL,
		refreshTokenTTL:              refreshTokenTTL,
		consentTTL:                   consentTTL,
		allowClientMetadataDocuments: bool(raw.AllowClientMetadataDocuments),
		resources:                    resources,
		clients:                      clients,
	}, nil
}

func parseOAuthTenantTTL(raw string, minimum time.Duration, maximum time.Duration) (time.Duration, error) {
	duration, durationErr := time.ParseDuration(strings.TrimSpace(raw))
	if durationErr != nil || duration < minimum || duration > maximum {
		return 0, fmt.Errorf("duration must be between %s and %s", minimum, maximum)
	}
	return duration, nil
}

func parseOAuthResources(rawResources []FileOAuthResource, tenantID TenantID, allowInsecureHTTP bool) ([]OAuthResource, map[string]map[string]struct{}, error) {
	if len(rawResources) == 0 {
		return nil, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeOAuthMissingResource, tenantID)
	}
	resources := make([]OAuthResource, 0, len(rawResources))
	resourceIndex := make(map[string]map[string]struct{}, len(rawResources))
	for _, rawResource := range rawResources {
		identifier, identifierErr := normalizeOAuthResourceIdentifier(rawResource.Identifier, allowInsecureHTTP)
		if identifierErr != nil {
			return nil, nil, fmt.Errorf("%w: %s tenant=%s resource=%s", ErrInvalidTenantConfig, errorCodeOAuthInvalidResource, tenantID, strings.TrimSpace(rawResource.Identifier))
		}
		if _, exists := resourceIndex[identifier]; exists {
			return nil, nil, fmt.Errorf("%w: %s tenant=%s resource=%s", ErrInvalidTenantConfig, errorCodeOAuthDuplicateResource, tenantID, identifier)
		}
		displayName := strings.TrimSpace(rawResource.DisplayName)
		if displayName == "" {
			return nil, nil, fmt.Errorf("%w: %s tenant=%s resource=%s", ErrInvalidTenantConfig, errorCodeOAuthInvalidResource, tenantID, identifier)
		}
		scopes, scopeIndex, scopeErr := parseOAuthScopes(rawResource.Scopes, tenantID, identifier)
		if scopeErr != nil {
			return nil, nil, scopeErr
		}
		resourceIndex[identifier] = scopeIndex
		resources = append(resources, OAuthResource{identifier: identifier, displayName: displayName, scopes: scopes})
	}
	sort.Slice(resources, func(left, right int) bool { return resources[left].identifier < resources[right].identifier })
	return resources, resourceIndex, nil
}

func parseOAuthScopes(rawScopes []FileOAuthScope, tenantID TenantID, resource string) ([]OAuthScope, map[string]struct{}, error) {
	if len(rawScopes) == 0 {
		return nil, nil, fmt.Errorf("%w: %s tenant=%s resource=%s", ErrInvalidTenantConfig, errorCodeOAuthInvalidScope, tenantID, resource)
	}
	scopes := make([]OAuthScope, 0, len(rawScopes))
	index := make(map[string]struct{}, len(rawScopes))
	for _, rawScope := range rawScopes {
		identifier := strings.TrimSpace(rawScope.Identifier)
		if !validOAuthScopeToken(identifier) || strings.TrimSpace(rawScope.DisplayName) == "" || strings.TrimSpace(rawScope.Description) == "" {
			return nil, nil, fmt.Errorf("%w: %s tenant=%s resource=%s scope=%s", ErrInvalidTenantConfig, errorCodeOAuthInvalidScope, tenantID, resource, identifier)
		}
		if _, exists := index[identifier]; exists {
			return nil, nil, fmt.Errorf("%w: %s tenant=%s resource=%s scope=%s", ErrInvalidTenantConfig, errorCodeOAuthDuplicateScope, tenantID, resource, identifier)
		}
		index[identifier] = struct{}{}
		scopes = append(scopes, OAuthScope{identifier: identifier, displayName: strings.TrimSpace(rawScope.DisplayName), description: strings.TrimSpace(rawScope.Description)})
	}
	sort.Slice(scopes, func(left, right int) bool { return scopes[left].identifier < scopes[right].identifier })
	return scopes, index, nil
}

func validOAuthScopeToken(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range []byte(value) {
		if character == 0x21 || (character >= 0x23 && character <= 0x5b) || (character >= 0x5d && character <= 0x7e) {
			continue
		}
		return false
	}
	return true
}

func parseOAuthClients(rawClients []FileOAuthClient, tenantID TenantID, resources map[string]map[string]struct{}) ([]OAuthClient, error) {
	clients := make([]OAuthClient, 0, len(rawClients))
	seenClients := make(map[string]struct{}, len(rawClients))
	for _, rawClient := range rawClients {
		clientID := strings.TrimSpace(rawClient.ID)
		if !oauthClientIDRegex.MatchString(clientID) || strings.TrimSpace(rawClient.DisplayName) == "" {
			return nil, fmt.Errorf("%w: %s tenant=%s client_id=%s", ErrInvalidTenantConfig, errorCodeOAuthInvalidClient, tenantID, clientID)
		}
		if _, exists := seenClients[clientID]; exists {
			return nil, fmt.Errorf("%w: %s tenant=%s client_id=%s", ErrInvalidTenantConfig, errorCodeOAuthDuplicateClient, tenantID, clientID)
		}
		seenClients[clientID] = struct{}{}
		applicationType := strings.ToLower(strings.TrimSpace(rawClient.ApplicationType))
		if applicationType != oauthApplicationTypeWeb && applicationType != oauthApplicationTypeNative {
			return nil, fmt.Errorf("%w: %s tenant=%s client_id=%s", ErrInvalidTenantConfig, errorCodeOAuthInvalidClient, tenantID, clientID)
		}
		redirectURIs, redirectErr := parseOAuthRedirectURIs(rawClient.RedirectURIs, tenantID, clientID, applicationType)
		if redirectErr != nil {
			return nil, redirectErr
		}
		minimumPort, maximumPort, portErr := parseOAuthLoopbackPorts(rawClient.LoopbackPortRange, redirectURIs, applicationType)
		if portErr != nil {
			return nil, fmt.Errorf("%w: %s tenant=%s client_id=%s", ErrInvalidTenantConfig, errorCodeOAuthInvalidLoopbackPorts, tenantID, clientID)
		}
		grants, grantsErr := parseOAuthClientGrants(rawClient.Grants, tenantID, clientID, resources)
		if grantsErr != nil {
			return nil, grantsErr
		}
		clients = append(clients, OAuthClient{
			id: clientID, displayName: strings.TrimSpace(rawClient.DisplayName), applicationType: applicationType,
			redirectURIs: redirectURIs, loopbackPortMinimum: minimumPort, loopbackPortMaximum: maximumPort, grants: grants,
		})
	}
	sort.Slice(clients, func(left, right int) bool { return clients[left].id < clients[right].id })
	return clients, nil
}

func parseOAuthRedirectURIs(rawURIs []string, tenantID TenantID, clientID string, applicationType string) ([]string, error) {
	if len(rawURIs) == 0 {
		return nil, fmt.Errorf("%w: %s tenant=%s client_id=%s", ErrInvalidTenantConfig, errorCodeOAuthInvalidRedirectURI, tenantID, clientID)
	}
	redirectURIs := make([]string, 0, len(rawURIs))
	seen := make(map[string]struct{}, len(rawURIs))
	for _, rawURI := range rawURIs {
		redirectURI, redirectErr := normalizeOAuthRedirectURI(rawURI, applicationType)
		if redirectErr != nil {
			return nil, fmt.Errorf("%w: %s tenant=%s client_id=%s redirect_uri=%s", ErrInvalidTenantConfig, errorCodeOAuthInvalidRedirectURI, tenantID, clientID, strings.TrimSpace(rawURI))
		}
		if _, exists := seen[redirectURI]; exists {
			return nil, fmt.Errorf("%w: %s tenant=%s client_id=%s redirect_uri=%s", ErrInvalidTenantConfig, errorCodeOAuthDuplicateRedirectURI, tenantID, clientID, redirectURI)
		}
		seen[redirectURI] = struct{}{}
		redirectURIs = append(redirectURIs, redirectURI)
	}
	sort.Strings(redirectURIs)
	return redirectURIs, nil
}

func normalizeOAuthRedirectURI(raw string, applicationType string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	parsed, parseErr := url.Parse(trimmed)
	if parseErr != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", fmt.Errorf("invalid redirect URI")
	}
	if parsed.Scheme == "https" {
		return trimmed, nil
	}
	if applicationType == oauthApplicationTypeNative && parsed.Scheme == "http" && isOAuthLoopbackHost(parsed.Hostname()) {
		return trimmed, nil
	}
	return "", fmt.Errorf("HTTPS or native loopback HTTP is required")
}

func parseOAuthLoopbackPorts(raw FileOAuthLoopbackPortRange, redirectURIs []string, applicationType string) (int, int, error) {
	if raw.Minimum == 0 && raw.Maximum == 0 {
		return 0, 0, nil
	}
	if applicationType != oauthApplicationTypeNative || raw.Minimum < 1024 || raw.Maximum > 65535 || raw.Minimum > raw.Maximum {
		return 0, 0, fmt.Errorf("invalid loopback range")
	}
	foundLoopback := false
	for _, redirectURI := range redirectURIs {
		parsed, _ := url.Parse(redirectURI)
		if parsed.Scheme != "http" || !isOAuthLoopbackHost(parsed.Hostname()) {
			continue
		}
		if parsed.Port() != "" {
			return 0, 0, fmt.Errorf("registered loopback URI must omit the port")
		}
		foundLoopback = true
	}
	if !foundLoopback {
		return 0, 0, fmt.Errorf("loopback redirect is required")
	}
	return raw.Minimum, raw.Maximum, nil
}

func parseOAuthClientGrants(rawGrants []FileOAuthClientGrant, tenantID TenantID, clientID string, resources map[string]map[string]struct{}) ([]OAuthClientGrant, error) {
	if len(rawGrants) == 0 {
		return nil, fmt.Errorf("%w: %s tenant=%s client_id=%s", ErrInvalidTenantConfig, errorCodeOAuthInvalidClientGrant, tenantID, clientID)
	}
	grants := make([]OAuthClientGrant, 0, len(rawGrants))
	seenResources := make(map[string]struct{}, len(rawGrants))
	for _, rawGrant := range rawGrants {
		resource := strings.TrimSpace(rawGrant.Resource)
		resourceScopes, exists := resources[resource]
		if !exists || len(rawGrant.Scopes) == 0 {
			return nil, fmt.Errorf("%w: %s tenant=%s client_id=%s resource=%s", ErrInvalidTenantConfig, errorCodeOAuthInvalidClientGrant, tenantID, clientID, resource)
		}
		if _, duplicate := seenResources[resource]; duplicate {
			return nil, fmt.Errorf("%w: %s tenant=%s client_id=%s resource=%s", ErrInvalidTenantConfig, errorCodeOAuthInvalidClientGrant, tenantID, clientID, resource)
		}
		seenResources[resource] = struct{}{}
		scopes := make([]string, 0, len(rawGrant.Scopes))
		seenScopes := make(map[string]struct{}, len(rawGrant.Scopes))
		for _, rawScope := range rawGrant.Scopes {
			scope := strings.TrimSpace(rawScope)
			if _, permitted := resourceScopes[scope]; !permitted {
				return nil, fmt.Errorf("%w: %s tenant=%s client_id=%s resource=%s scope=%s", ErrInvalidTenantConfig, errorCodeOAuthInvalidClientGrant, tenantID, clientID, resource, scope)
			}
			if _, duplicate := seenScopes[scope]; duplicate {
				return nil, fmt.Errorf("%w: %s tenant=%s client_id=%s resource=%s scope=%s", ErrInvalidTenantConfig, errorCodeOAuthInvalidClientGrant, tenantID, clientID, resource, scope)
			}
			seenScopes[scope] = struct{}{}
			scopes = append(scopes, scope)
		}
		sort.Strings(scopes)
		grants = append(grants, OAuthClientGrant{resource: resource, scopes: scopes})
	}
	sort.Slice(grants, func(left, right int) bool { return grants[left].resource < grants[right].resource })
	return grants, nil
}

func normalizeOAuthResourceIdentifier(raw string, allowInsecureHTTP bool) (string, error) {
	trimmed := strings.TrimSpace(raw)
	parsed, parseErr := url.Parse(trimmed)
	if parseErr != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", fmt.Errorf("invalid resource identifier")
	}
	if parsed.Scheme == "https" {
		return trimmed, nil
	}
	if allowInsecureHTTP && parsed.Scheme == "http" && isOAuthLoopbackHost(parsed.Hostname()) {
		return trimmed, nil
	}
	return "", fmt.Errorf("resource identifier must use HTTPS")
}

func isOAuthLoopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSpace(host), "localhost") {
		return true
	}
	ipAddress := net.ParseIP(strings.TrimSpace(host))
	return ipAddress != nil && ipAddress.IsLoopback()
}

func fileOAuthAuthorizationHasValues(raw FileOAuthAuthorization) bool {
	return strings.TrimSpace(raw.AccessTokenTTL) != "" || strings.TrimSpace(raw.RefreshTokenTTL) != "" ||
		strings.TrimSpace(raw.ConsentTTL) != "" || bool(raw.AllowClientMetadataDocuments) ||
		len(raw.Resources) != 0 || len(raw.Clients) != 0
}

func expandFileOAuthAuthorizationEnv(raw FileOAuthAuthorization) FileOAuthAuthorization {
	raw.AccessTokenTTL = os.ExpandEnv(raw.AccessTokenTTL)
	raw.RefreshTokenTTL = os.ExpandEnv(raw.RefreshTokenTTL)
	raw.ConsentTTL = os.ExpandEnv(raw.ConsentTTL)
	for resourceIndex := range raw.Resources {
		resource := &raw.Resources[resourceIndex]
		resource.Identifier = os.ExpandEnv(resource.Identifier)
		resource.DisplayName = os.ExpandEnv(resource.DisplayName)
		for scopeIndex := range resource.Scopes {
			resource.Scopes[scopeIndex].Identifier = os.ExpandEnv(resource.Scopes[scopeIndex].Identifier)
			resource.Scopes[scopeIndex].DisplayName = os.ExpandEnv(resource.Scopes[scopeIndex].DisplayName)
			resource.Scopes[scopeIndex].Description = os.ExpandEnv(resource.Scopes[scopeIndex].Description)
		}
	}
	for clientIndex := range raw.Clients {
		client := &raw.Clients[clientIndex]
		client.ID = os.ExpandEnv(client.ID)
		client.DisplayName = os.ExpandEnv(client.DisplayName)
		client.ApplicationType = os.ExpandEnv(client.ApplicationType)
		client.RedirectURIs = expandEnvSlice(client.RedirectURIs)
		for grantIndex := range client.Grants {
			client.Grants[grantIndex].Resource = os.ExpandEnv(client.Grants[grantIndex].Resource)
			client.Grants[grantIndex].Scopes = expandEnvSlice(client.Grants[grantIndex].Scopes)
		}
	}
	return raw
}

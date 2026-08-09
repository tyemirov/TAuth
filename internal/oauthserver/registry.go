package oauthserver

import (
	"errors"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/tyemirov/tauth/internal/tenants"
)

var (
	ErrUnknownResource = errors.New("oauth.unknown_resource")
	ErrUnknownClient   = errors.New("oauth.unknown_client")
	ErrInvalidScope    = errors.New("oauth.invalid_scope")
	ErrInvalidRedirect = errors.New("oauth.invalid_redirect_uri")
)

// Registry resolves OAuth resources and explicit clients without browser origin state.
type Registry struct {
	resources map[string]TenantPolicy
	tenants   map[string]TenantPolicy
}

// NewRegistry builds an issuer-level registry from validated tenant declarations.
func NewRegistry(config tenants.Config) (Registry, error) {
	registry := Registry{
		resources: make(map[string]TenantPolicy),
		tenants:   make(map[string]TenantPolicy),
	}
	for _, tenant := range config.Tenants() {
		authorization := tenant.OAuthAuthorization()
		if !authorization.Enabled() {
			continue
		}
		policy := TenantPolicy{
			TenantID:                     string(tenant.ID()),
			AccessTokenTTL:               authorization.AccessTokenTTL(),
			RefreshTokenTTL:              authorization.RefreshTokenTTL(),
			ConsentTTL:                   authorization.ConsentTTL(),
			AllowClientMetadataDocuments: authorization.AllowClientMetadataDocuments(),
			Resources:                    make(map[string]Resource),
			Clients:                      make(map[string]Client),
		}
		for _, configuredResource := range authorization.Resources() {
			resource := Resource{
				Identifier:  configuredResource.Identifier(),
				DisplayName: configuredResource.DisplayName(),
				Scopes:      make(map[string]Scope),
			}
			for _, configuredScope := range configuredResource.Scopes() {
				resource.Scopes[configuredScope.Identifier()] = Scope{
					Identifier: configuredScope.Identifier(), DisplayName: configuredScope.DisplayName(), Description: configuredScope.Description(),
				}
			}
			policy.Resources[resource.Identifier] = resource
		}
		for _, configuredClient := range authorization.Clients() {
			redirectURIs := configuredClient.RedirectURIs()
			client := Client{
				ID:                  configuredClient.ID(),
				DisplayName:         configuredClient.DisplayName(),
				ApplicationType:     configuredClient.ApplicationType(),
				RedirectURIs:        redirectURIs,
				Source:              clientSourceRegistered,
				LoopbackPortMinimum: configuredClient.LoopbackPortMinimum(),
				LoopbackPortMaximum: configuredClient.LoopbackPortMaximum(),
				grants:              make(map[string]map[string]struct{}),
			}
			for _, grant := range configuredClient.Grants() {
				client.grants[grant.Resource()] = scopeLookup(grant.Scopes())
			}
			policy.Clients[client.ID] = client
		}
		registry.tenants[policy.TenantID] = policy
		for resourceID := range policy.Resources {
			registry.resources[resourceID] = policy
		}
	}
	return registry, nil
}

// ResolveResource resolves the exact RFC 8707 resource identifier.
func (registry Registry) ResolveResource(resourceID string) (TenantPolicy, Resource, error) {
	policy, exists := registry.resources[strings.TrimSpace(resourceID)]
	if !exists {
		return TenantPolicy{}, Resource{}, ErrUnknownResource
	}
	resource := policy.Resources[strings.TrimSpace(resourceID)]
	return policy, resource, nil
}

// ResolveExplicitClient resolves one preregistered public client for a tenant.
func (registry Registry) ResolveExplicitClient(tenantID string, clientID string) (Client, bool) {
	policy, exists := registry.tenants[strings.TrimSpace(tenantID)]
	if !exists {
		return Client{}, false
	}
	client, exists := policy.Clients[strings.TrimSpace(clientID)]
	return client, exists
}

// SupportedScopes returns the sorted issuer-wide scope set for discovery.
func (registry Registry) SupportedScopes() []string {
	set := make(map[string]struct{})
	for _, policy := range registry.tenants {
		for _, resource := range policy.Resources {
			for scope := range resource.Scopes {
				set[scope] = struct{}{}
			}
		}
	}
	values := make([]string, 0, len(set))
	for scope := range set {
		values = append(values, scope)
	}
	sort.Strings(values)
	return values
}

func validateRequestedScopes(resource Resource, client Client, rawScope string) ([]string, string, error) {
	fields := strings.Fields(rawScope)
	if len(fields) == 0 {
		return nil, "", ErrInvalidScope
	}
	seen := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		if _, duplicate := seen[field]; duplicate {
			return nil, "", ErrInvalidScope
		}
		if _, exists := resource.Scopes[field]; !exists {
			return nil, "", ErrInvalidScope
		}
		seen[field] = struct{}{}
	}
	sort.Strings(fields)
	if !client.permits(resource.Identifier, fields) {
		return nil, "", ErrInvalidScope
	}
	return fields, strings.Join(fields, " "), nil
}

func redirectMatches(client Client, requestedURI string) bool {
	if client.Source == clientSourceRegistered {
		for _, registeredURI := range client.RedirectURIs {
			if registeredURI == requestedURI {
				return true
			}
			if client.LoopbackPortMinimum != 0 && loopbackRedirectMatches(registeredURI, requestedURI, client.LoopbackPortMinimum, client.LoopbackPortMaximum) {
				return true
			}
		}
		return false
	}
	for _, registeredURI := range client.RedirectURIs {
		if registeredURI == requestedURI {
			return true
		}
	}
	return false
}

func loopbackRedirectMatches(registeredURI string, requestedURI string, minimum int, maximum int) bool {
	registered, registeredErr := url.Parse(registeredURI)
	requested, requestedErr := url.Parse(requestedURI)
	if registeredErr != nil || requestedErr != nil || registered.User != nil || requested.User != nil || registered.Fragment != "" || requested.Fragment != "" || registered.Port() != "" || requested.Port() == "" {
		return false
	}
	port, portErr := parsePort(requested.Port())
	if portErr != nil || port < minimum || port > maximum {
		return false
	}
	return registered.Scheme == requested.Scheme && strings.EqualFold(registered.Hostname(), requested.Hostname()) &&
		registered.EscapedPath() == requested.EscapedPath() && registered.RawQuery == requested.RawQuery
}

func parsePort(value string) (int, error) {
	port, parseErr := strconv.Atoi(value)
	if parseErr != nil || port < 1 || port > 65535 {
		return 0, ErrInvalidRedirect
	}
	return port, nil
}

func scopeLookup(scopes []string) map[string]struct{} {
	lookup := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		lookup[scope] = struct{}{}
	}
	return lookup
}

package oauthserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tyemirov/tauth/internal/appconfig"
)

var ErrClientMetadataInvalid = errors.New("oauth.client_metadata_invalid")

const maximumClientMetadataCacheEntries = 256

type clientMetadataDocument struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	ApplicationType         string   `json:"application_type"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

type cachedMetadataClient struct {
	client    Client
	expiresAt time.Time
}

// MetadataClientResolver resolves and validates an HTTPS Client ID Metadata Document.
type MetadataClientResolver interface {
	Resolve(ctx context.Context, clientID string) (Client, error)
}

// ClientMetadataResolver applies HTTPS, DNS, size, redirect, document, and cache constraints.
type ClientMetadataResolver struct {
	policy   appconfig.ClientMetadataPolicy
	resolver *net.Resolver
	mu       sync.Mutex
	cache    map[string]cachedMetadataClient
	now      func() time.Time
}

// NewClientMetadataResolver creates a production metadata resolver.
func NewClientMetadataResolver(policy appconfig.ClientMetadataPolicy) *ClientMetadataResolver {
	return &ClientMetadataResolver{
		policy: policy, resolver: net.DefaultResolver, cache: make(map[string]cachedMetadataClient), now: func() time.Time { return time.Now().UTC() },
	}
}

// Resolve returns one validated public client and caches only valid documents.
func (resolver *ClientMetadataResolver) Resolve(ctx context.Context, clientID string) (Client, error) {
	clientURL, validationErr := validateClientIdentifierURL(clientID)
	if validationErr != nil {
		return Client{}, validationErr
	}
	now := resolver.now().UTC()
	resolver.mu.Lock()
	cached, exists := resolver.cache[clientID]
	if exists && cached.expiresAt.After(now) {
		resolver.mu.Unlock()
		return cloneClient(cached.client), nil
	}
	delete(resolver.cache, clientID)
	resolver.mu.Unlock()

	requestContext, cancel := context.WithTimeout(ctx, resolver.policy.RequestTimeout())
	defer cancel()
	httpClient, clientErr := resolver.secureHTTPClient(requestContext, clientURL)
	if clientErr != nil {
		return Client{}, clientErr
	}
	request, requestErr := http.NewRequestWithContext(requestContext, http.MethodGet, clientID, nil)
	if requestErr != nil {
		return Client{}, fmt.Errorf("%w: request", ErrClientMetadataInvalid)
	}
	request.Header.Set("Accept", "application/json")
	response, responseErr := httpClient.Do(request)
	if responseErr != nil {
		return Client{}, fmt.Errorf("%w: fetch", ErrClientMetadataInvalid)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return Client{}, fmt.Errorf("%w: status", ErrClientMetadataInvalid)
	}
	if response.ContentLength > resolver.policy.MaximumBytes() {
		return Client{}, fmt.Errorf("%w: size", ErrClientMetadataInvalid)
	}
	if !validJSONContentType(response.Header.Get("Content-Type")) {
		return Client{}, fmt.Errorf("%w: content_type", ErrClientMetadataInvalid)
	}
	limitedBody := io.LimitReader(response.Body, resolver.policy.MaximumBytes()+1)
	payload, readErr := io.ReadAll(limitedBody)
	if readErr != nil || int64(len(payload)) > resolver.policy.MaximumBytes() {
		return Client{}, fmt.Errorf("%w: size", ErrClientMetadataInvalid)
	}
	client, documentErr := parseClientMetadataDocument(clientID, payload)
	if documentErr != nil {
		return Client{}, documentErr
	}
	cacheTTL, cacheable := metadataCacheTTL(response.Header, now, resolver.policy)
	if cacheable {
		resolver.cacheClient(clientID, client, now, cacheTTL)
	}
	return client, nil
}

func (resolver *ClientMetadataResolver) cacheClient(clientID string, client Client, now time.Time, ttl time.Duration) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	for cachedClientID, cached := range resolver.cache {
		if !cached.expiresAt.After(now) {
			delete(resolver.cache, cachedClientID)
		}
	}
	if _, exists := resolver.cache[clientID]; !exists && len(resolver.cache) >= maximumClientMetadataCacheEntries {
		oldestClientID := ""
		var oldestExpiry time.Time
		for cachedClientID, cached := range resolver.cache {
			if oldestClientID == "" || cached.expiresAt.Before(oldestExpiry) || (cached.expiresAt.Equal(oldestExpiry) && cachedClientID < oldestClientID) {
				oldestClientID = cachedClientID
				oldestExpiry = cached.expiresAt
			}
		}
		delete(resolver.cache, oldestClientID)
	}
	resolver.cache[clientID] = cachedMetadataClient{client: cloneClient(client), expiresAt: now.Add(ttl)}
}

func (resolver *ClientMetadataResolver) secureHTTPClient(ctx context.Context, clientURL *url.URL) (*http.Client, error) {
	addresses, lookupErr := resolver.resolver.LookupNetIP(ctx, "ip", clientURL.Hostname())
	if lookupErr != nil || len(addresses) == 0 {
		return nil, fmt.Errorf("%w: dns", ErrClientMetadataInvalid)
	}
	for _, address := range addresses {
		if specialUseAddress(address) {
			return nil, fmt.Errorf("%w: network_address", ErrClientMetadataInvalid)
		}
	}
	port := clientURL.Port()
	if port == "" {
		port = "443"
	}
	selectedAddress := addresses[0]
	dialer := &net.Dialer{Timeout: resolver.policy.RequestTimeout()}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(dialContext context.Context, network string, address string) (net.Conn, error) {
			return dialer.DialContext(dialContext, network, net.JoinHostPort(selectedAddress.String(), port))
		},
		TLSHandshakeTimeout: resolver.policy.RequestTimeout(),
		DisableKeepAlives:   true,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   resolver.policy.RequestTimeout(),
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func validateClientIdentifierURL(clientID string) (*url.URL, error) {
	if strings.TrimSpace(clientID) != clientID || clientID == "" || len(clientID) > 2048 {
		return nil, fmt.Errorf("%w: client_id", ErrClientMetadataInvalid)
	}
	parsed, parseErr := url.Parse(clientID)
	if parseErr != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Path == "" {
		return nil, fmt.Errorf("%w: client_id", ErrClientMetadataInvalid)
	}
	if parsed.RawQuery != "" || parsed.Path == "/" {
		return nil, fmt.Errorf("%w: client_id", ErrClientMetadataInvalid)
	}
	for _, segment := range strings.Split(parsed.EscapedPath(), "/") {
		decodedSegment, decodeErr := url.PathUnescape(segment)
		if decodeErr != nil || decodedSegment == "." || decodedSegment == ".." || strings.ContainsAny(decodedSegment, "/\\") {
			return nil, fmt.Errorf("%w: client_id", ErrClientMetadataInvalid)
		}
	}
	if literalAddress, parseAddressErr := netip.ParseAddr(parsed.Hostname()); parseAddressErr == nil && specialUseAddress(literalAddress) {
		return nil, fmt.Errorf("%w: network_address", ErrClientMetadataInvalid)
	}
	return parsed, nil
}

func parseClientMetadataDocument(clientID string, payload []byte) (Client, error) {
	var document clientMetadataDocument
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	if decodeErr := decoder.Decode(&document); decodeErr != nil {
		return Client{}, fmt.Errorf("%w: json", ErrClientMetadataInvalid)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Client{}, fmt.Errorf("%w: json", ErrClientMetadataInvalid)
	}
	if document.ClientID != clientID || strings.TrimSpace(document.ClientName) == "" || document.TokenEndpointAuthMethod != "none" {
		return Client{}, fmt.Errorf("%w: contract", ErrClientMetadataInvalid)
	}
	if !validMetadataGrantTypes(document.GrantTypes) || !exactStringSet(document.ResponseTypes, []string{"code"}) {
		return Client{}, fmt.Errorf("%w: grant", ErrClientMetadataInvalid)
	}
	applicationType := strings.ToLower(strings.TrimSpace(document.ApplicationType))
	if applicationType == "" {
		applicationType = "web"
	}
	if applicationType != "web" && applicationType != "native" {
		return Client{}, fmt.Errorf("%w: application_type", ErrClientMetadataInvalid)
	}
	redirectURIs, redirectErr := validateMetadataRedirectURIs(document.RedirectURIs, applicationType)
	if redirectErr != nil {
		return Client{}, redirectErr
	}
	return Client{
		ID: clientID, DisplayName: strings.TrimSpace(document.ClientName), ApplicationType: applicationType,
		RedirectURIs: redirectURIs, Source: clientSourceMetadata,
	}, nil
}

func validateMetadataRedirectURIs(rawURIs []string, applicationType string) ([]string, error) {
	if len(rawURIs) == 0 {
		return nil, fmt.Errorf("%w: redirect_uri", ErrClientMetadataInvalid)
	}
	redirectURIs := make([]string, 0, len(rawURIs))
	seen := make(map[string]struct{}, len(rawURIs))
	for _, rawURI := range rawURIs {
		if strings.TrimSpace(rawURI) != rawURI || rawURI == "" {
			return nil, fmt.Errorf("%w: redirect_uri", ErrClientMetadataInvalid)
		}
		parsed, parseErr := url.Parse(rawURI)
		if parseErr != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return nil, fmt.Errorf("%w: redirect_uri", ErrClientMetadataInvalid)
		}
		validHTTPS := parsed.Scheme == "https"
		validLoopback := applicationType == "native" && parsed.Scheme == "http" && metadataLoopbackHost(parsed.Hostname())
		if !validHTTPS && !validLoopback {
			return nil, fmt.Errorf("%w: redirect_uri", ErrClientMetadataInvalid)
		}
		if _, duplicate := seen[rawURI]; duplicate {
			return nil, fmt.Errorf("%w: redirect_uri", ErrClientMetadataInvalid)
		}
		seen[rawURI] = struct{}{}
		redirectURIs = append(redirectURIs, rawURI)
	}
	return redirectURIs, nil
}

func metadataLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address, addressErr := netip.ParseAddr(host)
	return addressErr == nil && address.IsLoopback()
}

func exactStringSet(actual []string, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range expected {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

func validMetadataGrantTypes(grantTypes []string) bool {
	if len(grantTypes) < 1 || len(grantTypes) > 2 {
		return false
	}
	seen := make(map[string]struct{}, len(grantTypes))
	for _, grantType := range grantTypes {
		if grantType != "authorization_code" && grantType != "refresh_token" {
			return false
		}
		if _, duplicate := seen[grantType]; duplicate {
			return false
		}
		seen[grantType] = struct{}{}
	}
	_, hasAuthorizationCode := seen["authorization_code"]
	return hasAuthorizationCode
}

func validJSONContentType(value string) bool {
	mediaType, _, parseErr := mime.ParseMediaType(value)
	if parseErr != nil {
		return false
	}
	return mediaType == "application/json" || (strings.HasPrefix(mediaType, "application/") && strings.HasSuffix(mediaType, "+json"))
}

func metadataCacheTTL(headers http.Header, now time.Time, policy appconfig.ClientMetadataPolicy) (time.Duration, bool) {
	cacheControl := strings.ToLower(headers.Get("Cache-Control"))
	directives := strings.Split(cacheControl, ",")
	for _, directive := range directives {
		trimmed := strings.TrimSpace(directive)
		if trimmed == "no-store" || trimmed == "no-cache" {
			return 0, false
		}
	}
	for _, directive := range directives {
		trimmed := strings.TrimSpace(directive)
		if strings.HasPrefix(trimmed, "max-age=") {
			seconds, parseErr := strconv.ParseInt(strings.TrimPrefix(trimmed, "max-age="), 10, 64)
			if parseErr == nil {
				return boundCacheTTL(time.Duration(seconds)*time.Second, policy), true
			}
		}
	}
	if expiresValue := strings.TrimSpace(headers.Get("Expires")); expiresValue != "" {
		if expiresAt, parseErr := http.ParseTime(expiresValue); parseErr == nil {
			return boundCacheTTL(expiresAt.Sub(now), policy), true
		}
	}
	return policy.MinimumCacheTTL(), true
}

func boundCacheTTL(value time.Duration, policy appconfig.ClientMetadataPolicy) time.Duration {
	if value < policy.MinimumCacheTTL() {
		return policy.MinimumCacheTTL()
	}
	if value > policy.MaximumCacheTTL() {
		return policy.MaximumCacheTTL()
	}
	return value
}

func cloneClient(client Client) Client {
	client.RedirectURIs = append([]string(nil), client.RedirectURIs...)
	return client
}

func specialUseAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return true
	}
	for _, prefix := range specialUsePrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

var specialUsePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
}

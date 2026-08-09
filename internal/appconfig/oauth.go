package appconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	ErrorCodeOAuthDisabled                = "config.oauth_disabled"
	ErrorCodeOAuthInvalidIssuer           = "config.oauth_invalid_issuer"
	ErrorCodeOAuthInvalidEndpoint         = "config.oauth_invalid_endpoint"
	ErrorCodeOAuthDuplicateEndpoint       = "config.oauth_duplicate_endpoint"
	ErrorCodeOAuthInvalidRequestTTL       = "config.oauth_invalid_request_ttl"
	ErrorCodeOAuthInvalidCodeTTL          = "config.oauth_invalid_code_ttl"
	ErrorCodeOAuthInvalidSigningKey       = "config.oauth_invalid_signing_key"
	ErrorCodeOAuthDuplicateSigningKey     = "config.oauth_duplicate_signing_key"
	ErrorCodeOAuthInvalidActiveSigningKey = "config.oauth_invalid_active_signing_key"
	ErrorCodeOAuthInvalidMetadataTimeout  = "config.oauth_invalid_metadata_timeout"
	ErrorCodeOAuthInvalidMetadataSize     = "config.oauth_invalid_metadata_size"
	ErrorCodeOAuthInvalidMetadataCache    = "config.oauth_invalid_metadata_cache"
	maximumOAuthAuthorizationRequestTTL   = 10 * time.Minute
	maximumOAuthAuthorizationCodeTTL      = 5 * time.Minute
	maximumOAuthMetadataResponseBytes     = 5 * 1024
	maximumOAuthMetadataRequestTimeout    = 10 * time.Second
	maximumOAuthMetadataCacheTTL          = 24 * time.Hour
	minimumOAuthMetadataResponseBytes     = 1024
	minimumOAuthMetadataRequestTimeout    = 100 * time.Millisecond
	minimumOAuthMetadataCacheTTL          = time.Second
	oauthSigningAlgorithmES256            = "ES256"
	oauthAuthorizationServerMetadataPath  = "/.well-known/oauth-authorization-server"
)

var reservedOAuthEndpointPaths = map[string]struct{}{
	oauthAuthorizationServerMetadataPath: {},
	"/health":                            {},
	"/me":                                {},
	"/api/me":                            {},
	"/auth/nonce":                        {},
	"/auth/session":                      {},
	"/auth/google":                       {},
	"/auth/google/native/config":         {},
	"/auth/google/native":                {},
	"/auth/apple/start":                  {},
	"/auth/apple/callback":               {},
	"/auth/password/login":               {},
	"/auth/password/signup":              {},
	"/auth/password/verify-email":        {},
	"/auth/password/reset/start":         {},
	"/auth/password/reset/complete":      {},
	"/auth/account/password/change":      {},
	"/auth/account/password/link/start":  {},
	"/auth/account/password/link/verify": {},
	"/auth/account/google/link":          {},
	"/auth/account/unlink":               {},
	"/auth/account/disable":              {},
	"/auth/refresh":                      {},
	"/auth/logout":                       {},
}

// FileOAuthSettings represents the raw OAuth authorization-server block.
type FileOAuthSettings struct {
	Enabled                 YamlBool                 `yaml:"enabled"`
	AllowInsecureHTTP       YamlBool                 `yaml:"allow_insecure_http"`
	Issuer                  string                   `yaml:"issuer"`
	AuthorizationEndpoint   string                   `yaml:"authorization_endpoint"`
	TokenEndpoint           string                   `yaml:"token_endpoint"`
	RevocationEndpoint      string                   `yaml:"revocation_endpoint"`
	JWKSURI                 string                   `yaml:"jwks_uri"`
	LoginEndpoint           string                   `yaml:"login_endpoint"`
	ConsentEndpoint         string                   `yaml:"consent_endpoint"`
	AuthorizationRequestTTL string                   `yaml:"authorization_request_ttl"`
	AuthorizationCodeTTL    string                   `yaml:"authorization_code_ttl"`
	ActiveSigningKeyID      string                   `yaml:"active_signing_key_id"`
	SigningKeys             []FileOAuthSigningKey    `yaml:"signing_keys"`
	ClientMetadata          FileClientMetadataPolicy `yaml:"client_metadata"`
}

// FileOAuthSigningKey represents one operator-managed OAuth signing key.
type FileOAuthSigningKey struct {
	ID               string `yaml:"id"`
	PrivateKey       string `yaml:"private_key"`
	PrivateKeyBase64 string `yaml:"private_key_base64"`
	PublicKey        string `yaml:"public_key"`
	PublicKeyBase64  string `yaml:"public_key_base64"`
}

// FileClientMetadataPolicy represents bounded Client ID Metadata fetch settings.
type FileClientMetadataPolicy struct {
	RequestTimeout  string `yaml:"request_timeout"`
	MaximumBytes    int64  `yaml:"maximum_bytes"`
	MinimumCacheTTL string `yaml:"minimum_cache_ttl"`
	MaximumCacheTTL string `yaml:"maximum_cache_ttl"`
}

// OAuthServerConfig is the validated issuer-level OAuth configuration.
type OAuthServerConfig struct {
	enabled                 bool
	allowInsecureHTTP       bool
	issuer                  string
	authorizationEndpoint   string
	tokenEndpoint           string
	revocationEndpoint      string
	jwksURI                 string
	loginEndpoint           string
	consentEndpoint         string
	authorizationRequestTTL time.Duration
	authorizationCodeTTL    time.Duration
	activeSigningKeyID      string
	signingKeys             []OAuthSigningKey
	clientMetadata          ClientMetadataPolicy
}

// OAuthSigningKey is one validated P-256 key in the rotation set.
type OAuthSigningKey struct {
	id         string
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

// ClientMetadataPolicy bounds remote Client ID Metadata retrieval.
type ClientMetadataPolicy struct {
	requestTimeout  time.Duration
	maximumBytes    int64
	minimumCacheTTL time.Duration
	maximumCacheTTL time.Duration
}

// Enabled reports whether the OAuth authorization server is configured.
func (config OAuthServerConfig) Enabled() bool { return config.enabled }

// AllowInsecureHTTP reports whether loopback HTTP endpoints are permitted.
func (config OAuthServerConfig) AllowInsecureHTTP() bool { return config.allowInsecureHTTP }

// Issuer returns the canonical OAuth issuer.
func (config OAuthServerConfig) Issuer() string { return config.issuer }

// AuthorizationEndpoint returns the public authorization endpoint.
func (config OAuthServerConfig) AuthorizationEndpoint() string { return config.authorizationEndpoint }

// TokenEndpoint returns the public token endpoint.
func (config OAuthServerConfig) TokenEndpoint() string { return config.tokenEndpoint }

// RevocationEndpoint returns the public revocation endpoint.
func (config OAuthServerConfig) RevocationEndpoint() string { return config.revocationEndpoint }

// JWKSURI returns the public JSON Web Key Set endpoint.
func (config OAuthServerConfig) JWKSURI() string { return config.jwksURI }

// LoginEndpoint returns the TAuth-owned browser login endpoint.
func (config OAuthServerConfig) LoginEndpoint() string { return config.loginEndpoint }

// ConsentEndpoint returns the TAuth-owned browser consent endpoint.
func (config OAuthServerConfig) ConsentEndpoint() string { return config.consentEndpoint }

// AuthorizationRequestTTL returns the pending browser request lifetime.
func (config OAuthServerConfig) AuthorizationRequestTTL() time.Duration {
	return config.authorizationRequestTTL
}

// AuthorizationCodeTTL returns the authorization-code lifetime.
func (config OAuthServerConfig) AuthorizationCodeTTL() time.Duration {
	return config.authorizationCodeTTL
}

// ActiveSigningKeyID returns the key used for new access tokens.
func (config OAuthServerConfig) ActiveSigningKeyID() string { return config.activeSigningKeyID }

// SigningKeys returns a copy of the configured key rotation set.
func (config OAuthServerConfig) SigningKeys() []OAuthSigningKey {
	keys := make([]OAuthSigningKey, len(config.signingKeys))
	copy(keys, config.signingKeys)
	return keys
}

// ClientMetadata returns the bounded metadata retrieval policy.
func (config OAuthServerConfig) ClientMetadata() ClientMetadataPolicy { return config.clientMetadata }

// ID returns the public signing-key identifier.
func (key OAuthSigningKey) ID() string { return key.id }

// PrivateKey returns the validated P-256 private key.
func (key OAuthSigningKey) PrivateKey() *ecdsa.PrivateKey { return key.privateKey }

// PublicKey returns the P-256 verification key.
func (key OAuthSigningKey) PublicKey() *ecdsa.PublicKey { return key.publicKey }

// Algorithm returns the required JWS signing algorithm.
func (key OAuthSigningKey) Algorithm() string { return oauthSigningAlgorithmES256 }

// RequestTimeout returns the metadata HTTP request deadline.
func (policy ClientMetadataPolicy) RequestTimeout() time.Duration { return policy.requestTimeout }

// MaximumBytes returns the metadata response read limit.
func (policy ClientMetadataPolicy) MaximumBytes() int64 { return policy.maximumBytes }

// MinimumCacheTTL returns the lower cache lifetime bound.
func (policy ClientMetadataPolicy) MinimumCacheTTL() time.Duration { return policy.minimumCacheTTL }

// MaximumCacheTTL returns the upper cache lifetime bound.
func (policy ClientMetadataPolicy) MaximumCacheTTL() time.Duration { return policy.maximumCacheTTL }

func (config OAuthServerConfig) clone() OAuthServerConfig {
	config.signingKeys = config.SigningKeys()
	return config
}

func parseOAuthServerConfig(raw FileOAuthSettings) (OAuthServerConfig, error) {
	if !bool(raw.Enabled) {
		if oauthSettingsHaveValues(raw) {
			return OAuthServerConfig{}, fmt.Errorf("%s: enabled must be true when OAuth settings are present", ErrorCodeOAuthDisabled)
		}
		return OAuthServerConfig{}, nil
	}
	allowInsecureHTTP := bool(raw.AllowInsecureHTTP)
	issuer, issuerURL, issuerErr := parseOAuthIssuer(raw.Issuer, allowInsecureHTTP)
	if issuerErr != nil {
		return OAuthServerConfig{}, issuerErr
	}
	endpointInputs := []struct {
		name  string
		value string
	}{
		{name: "authorization", value: raw.AuthorizationEndpoint},
		{name: "token", value: raw.TokenEndpoint},
		{name: "revocation", value: raw.RevocationEndpoint},
		{name: "jwks", value: raw.JWKSURI},
		{name: "login", value: raw.LoginEndpoint},
		{name: "consent", value: raw.ConsentEndpoint},
	}
	endpoints := make(map[string]string, len(endpointInputs))
	seenEndpointPaths := make(map[string]string, len(endpointInputs))
	for _, input := range endpointInputs {
		endpoint, endpointErr := parseOAuthEndpoint(input.name, input.value, issuerURL)
		if endpointErr != nil {
			return OAuthServerConfig{}, endpointErr
		}
		parsedEndpoint, _ := url.Parse(endpoint)
		endpointPath := parsedEndpoint.EscapedPath()
		if _, reserved := reservedOAuthEndpointPaths[endpointPath]; reserved {
			return OAuthServerConfig{}, fmt.Errorf("%s: endpoint=%s conflicts_with=tauth_route", ErrorCodeOAuthDuplicateEndpoint, input.name)
		}
		if otherName, exists := seenEndpointPaths[endpointPath]; exists {
			return OAuthServerConfig{}, fmt.Errorf("%s: endpoint=%s conflicts_with=%s", ErrorCodeOAuthDuplicateEndpoint, input.name, otherName)
		}
		seenEndpointPaths[endpointPath] = input.name
		endpoints[input.name] = endpoint
	}
	requestTTL, requestTTLErr := parseBoundedDuration(raw.AuthorizationRequestTTL, maximumOAuthAuthorizationRequestTTL)
	if requestTTLErr != nil {
		return OAuthServerConfig{}, fmt.Errorf("%s: %w", ErrorCodeOAuthInvalidRequestTTL, requestTTLErr)
	}
	codeTTL, codeTTLErr := parseBoundedDuration(raw.AuthorizationCodeTTL, maximumOAuthAuthorizationCodeTTL)
	if codeTTLErr != nil {
		return OAuthServerConfig{}, fmt.Errorf("%s: %w", ErrorCodeOAuthInvalidCodeTTL, codeTTLErr)
	}
	signingKeys, signingKeyErr := parseOAuthSigningKeys(raw.SigningKeys)
	if signingKeyErr != nil {
		return OAuthServerConfig{}, signingKeyErr
	}
	activeSigningKeyID := strings.TrimSpace(raw.ActiveSigningKeyID)
	activeSigningKey, exists := signingKeys[activeSigningKeyID]
	if !exists || activeSigningKey.privateKey == nil {
		return OAuthServerConfig{}, fmt.Errorf("%s: key_id=%s", ErrorCodeOAuthInvalidActiveSigningKey, activeSigningKeyID)
	}
	orderedKeyIDs := make([]string, 0, len(signingKeys))
	for keyID := range signingKeys {
		orderedKeyIDs = append(orderedKeyIDs, keyID)
	}
	sort.Strings(orderedKeyIDs)
	orderedKeys := make([]OAuthSigningKey, 0, len(orderedKeyIDs))
	for _, keyID := range orderedKeyIDs {
		orderedKeys = append(orderedKeys, signingKeys[keyID])
	}
	metadataPolicy, metadataErr := parseClientMetadataPolicy(raw.ClientMetadata)
	if metadataErr != nil {
		return OAuthServerConfig{}, metadataErr
	}
	return OAuthServerConfig{
		enabled:                 true,
		allowInsecureHTTP:       allowInsecureHTTP,
		issuer:                  issuer,
		authorizationEndpoint:   endpoints["authorization"],
		tokenEndpoint:           endpoints["token"],
		revocationEndpoint:      endpoints["revocation"],
		jwksURI:                 endpoints["jwks"],
		loginEndpoint:           endpoints["login"],
		consentEndpoint:         endpoints["consent"],
		authorizationRequestTTL: requestTTL,
		authorizationCodeTTL:    codeTTL,
		activeSigningKeyID:      activeSigningKeyID,
		signingKeys:             orderedKeys,
		clientMetadata:          metadataPolicy,
	}, nil
}

func parseOAuthIssuer(raw string, allowInsecureHTTP bool) (string, *url.URL, error) {
	issuer := strings.TrimSuffix(strings.TrimSpace(raw), "/")
	parsed, parseErr := url.Parse(issuer)
	if parseErr != nil || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return "", nil, fmt.Errorf("%s: issuer=%s", ErrorCodeOAuthInvalidIssuer, issuer)
	}
	if parsed.Path != "" {
		return "", nil, fmt.Errorf("%s: issuer path must be empty", ErrorCodeOAuthInvalidIssuer)
	}
	if parsed.Scheme == "https" {
		return issuer, parsed, nil
	}
	if parsed.Scheme == "http" && allowInsecureHTTP && isLoopbackHostname(parsed.Hostname()) {
		return issuer, parsed, nil
	}
	return "", nil, fmt.Errorf("%s: issuer must use HTTPS", ErrorCodeOAuthInvalidIssuer)
}

func parseOAuthEndpoint(name string, raw string, issuer *url.URL) (string, error) {
	endpoint := strings.TrimSpace(raw)
	parsed, parseErr := url.Parse(endpoint)
	if parseErr != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%s: endpoint=%s", ErrorCodeOAuthInvalidEndpoint, name)
	}
	if parsed.Scheme != issuer.Scheme || !strings.EqualFold(parsed.Host, issuer.Host) || parsed.Path == "" || parsed.Path == "/" {
		return "", fmt.Errorf("%s: endpoint=%s must use the issuer origin and a non-root path", ErrorCodeOAuthInvalidEndpoint, name)
	}
	return endpoint, nil
}

func parseBoundedDuration(raw string, maximum time.Duration) (time.Duration, error) {
	value, parseErr := time.ParseDuration(strings.TrimSpace(raw))
	if parseErr != nil || value <= 0 || value > maximum {
		return 0, fmt.Errorf("duration must be positive and at most %s", maximum)
	}
	return value, nil
}

func parseOAuthSigningKeys(rawKeys []FileOAuthSigningKey) (map[string]OAuthSigningKey, error) {
	if len(rawKeys) == 0 {
		return nil, fmt.Errorf("%s: at least one signing key is required", ErrorCodeOAuthInvalidSigningKey)
	}
	keys := make(map[string]OAuthSigningKey, len(rawKeys))
	for _, rawKey := range rawKeys {
		keyID := strings.TrimSpace(rawKey.ID)
		if keyID == "" || strings.ContainsAny(keyID, " \t\r\n") {
			return nil, fmt.Errorf("%s: invalid key id", ErrorCodeOAuthInvalidSigningKey)
		}
		if _, exists := keys[keyID]; exists {
			return nil, fmt.Errorf("%s: key_id=%s", ErrorCodeOAuthDuplicateSigningKey, keyID)
		}
		privateKey, publicKey, keyErr := parseOAuthSigningKey(rawKey)
		if keyErr != nil {
			return nil, fmt.Errorf("%s: key_id=%s: %w", ErrorCodeOAuthInvalidSigningKey, keyID, keyErr)
		}
		keys[keyID] = OAuthSigningKey{id: keyID, privateKey: privateKey, publicKey: publicKey}
	}
	return keys, nil
}

func parseOAuthSigningKey(raw FileOAuthSigningKey) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateConfigured := strings.TrimSpace(raw.PrivateKey) != "" || strings.TrimSpace(raw.PrivateKeyBase64) != ""
	publicConfigured := strings.TrimSpace(raw.PublicKey) != "" || strings.TrimSpace(raw.PublicKeyBase64) != ""
	if privateConfigured == publicConfigured {
		return nil, nil, errors.New("provide one private or public key representation")
	}
	if privateConfigured {
		privateKey, privateKeyErr := parseOAuthPrivateKey(raw)
		if privateKeyErr != nil {
			return nil, nil, privateKeyErr
		}
		return privateKey, &privateKey.PublicKey, nil
	}
	publicKey, publicKeyErr := parseOAuthPublicKey(raw)
	if publicKeyErr != nil {
		return nil, nil, publicKeyErr
	}
	return nil, publicKey, nil
}

func parseOAuthPrivateKey(raw FileOAuthSigningKey) (*ecdsa.PrivateKey, error) {
	privateKeyPEM := strings.TrimSpace(raw.PrivateKey)
	privateKeyBase64 := strings.Join(strings.Fields(strings.TrimSpace(raw.PrivateKeyBase64)), "")
	if (privateKeyPEM == "") == (privateKeyBase64 == "") {
		return nil, errors.New("provide exactly one private key representation")
	}
	if privateKeyBase64 != "" {
		decoded, decodeErr := base64.StdEncoding.DecodeString(privateKeyBase64)
		if decodeErr != nil {
			return nil, errors.New("private_key_base64 is invalid")
		}
		privateKeyPEM = strings.TrimSpace(string(decoded))
	}
	block, remainder := pem.Decode([]byte(privateKeyPEM))
	if block == nil || block.Type != "PRIVATE KEY" || strings.TrimSpace(string(remainder)) != "" {
		return nil, errors.New("private key PEM is invalid")
	}
	parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
	if parseErr != nil {
		return nil, errors.New("private key must use PKCS8")
	}
	privateKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || privateKey.Curve != elliptic.P256() {
		return nil, errors.New("private key must use P-256")
	}
	return privateKey, nil
}

func parseOAuthPublicKey(raw FileOAuthSigningKey) (*ecdsa.PublicKey, error) {
	publicKeyPEM := strings.TrimSpace(raw.PublicKey)
	publicKeyBase64 := strings.Join(strings.Fields(strings.TrimSpace(raw.PublicKeyBase64)), "")
	if (publicKeyPEM == "") == (publicKeyBase64 == "") {
		return nil, errors.New("provide exactly one public key representation")
	}
	if publicKeyBase64 != "" {
		decoded, decodeErr := base64.StdEncoding.DecodeString(publicKeyBase64)
		if decodeErr != nil {
			return nil, errors.New("public_key_base64 is invalid")
		}
		publicKeyPEM = strings.TrimSpace(string(decoded))
	}
	block, remainder := pem.Decode([]byte(publicKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" || strings.TrimSpace(string(remainder)) != "" {
		return nil, errors.New("public key PEM is invalid")
	}
	parsed, parseErr := x509.ParsePKIXPublicKey(block.Bytes)
	if parseErr != nil {
		return nil, errors.New("public key must use PKIX")
	}
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return nil, errors.New("public key must use P-256")
	}
	return publicKey, nil
}

func parseClientMetadataPolicy(raw FileClientMetadataPolicy) (ClientMetadataPolicy, error) {
	requestTimeout, timeoutErr := time.ParseDuration(strings.TrimSpace(raw.RequestTimeout))
	if timeoutErr != nil || requestTimeout < minimumOAuthMetadataRequestTimeout || requestTimeout > maximumOAuthMetadataRequestTimeout {
		return ClientMetadataPolicy{}, fmt.Errorf("%s: request_timeout", ErrorCodeOAuthInvalidMetadataTimeout)
	}
	if raw.MaximumBytes < minimumOAuthMetadataResponseBytes || raw.MaximumBytes > maximumOAuthMetadataResponseBytes {
		return ClientMetadataPolicy{}, fmt.Errorf("%s: maximum_bytes must be between %d and %d", ErrorCodeOAuthInvalidMetadataSize, minimumOAuthMetadataResponseBytes, maximumOAuthMetadataResponseBytes)
	}
	minimumCacheTTL, minimumErr := time.ParseDuration(strings.TrimSpace(raw.MinimumCacheTTL))
	maximumCacheTTL, maximumErr := time.ParseDuration(strings.TrimSpace(raw.MaximumCacheTTL))
	if minimumErr != nil || maximumErr != nil || minimumCacheTTL < minimumOAuthMetadataCacheTTL || maximumCacheTTL > maximumOAuthMetadataCacheTTL || minimumCacheTTL > maximumCacheTTL {
		return ClientMetadataPolicy{}, fmt.Errorf("%s: cache TTL bounds are invalid", ErrorCodeOAuthInvalidMetadataCache)
	}
	return ClientMetadataPolicy{
		requestTimeout:  requestTimeout,
		maximumBytes:    raw.MaximumBytes,
		minimumCacheTTL: minimumCacheTTL,
		maximumCacheTTL: maximumCacheTTL,
	}, nil
}

func isLoopbackHostname(hostname string) bool {
	if strings.EqualFold(strings.TrimSpace(hostname), "localhost") {
		return true
	}
	ipAddress := net.ParseIP(strings.TrimSpace(hostname))
	return ipAddress != nil && ipAddress.IsLoopback()
}

func oauthSettingsHaveValues(raw FileOAuthSettings) bool {
	return bool(raw.AllowInsecureHTTP) || strings.TrimSpace(raw.Issuer) != "" ||
		strings.TrimSpace(raw.AuthorizationEndpoint) != "" || strings.TrimSpace(raw.TokenEndpoint) != "" ||
		strings.TrimSpace(raw.RevocationEndpoint) != "" || strings.TrimSpace(raw.JWKSURI) != "" ||
		strings.TrimSpace(raw.LoginEndpoint) != "" || strings.TrimSpace(raw.ConsentEndpoint) != "" ||
		strings.TrimSpace(raw.AuthorizationRequestTTL) != "" || strings.TrimSpace(raw.AuthorizationCodeTTL) != "" ||
		strings.TrimSpace(raw.ActiveSigningKeyID) != "" || len(raw.SigningKeys) != 0 ||
		strings.TrimSpace(raw.ClientMetadata.RequestTimeout) != "" || raw.ClientMetadata.MaximumBytes != 0 ||
		strings.TrimSpace(raw.ClientMetadata.MinimumCacheTTL) != "" || strings.TrimSpace(raw.ClientMetadata.MaximumCacheTTL) != ""
}

func expandOAuthSettingsEnv(raw FileOAuthSettings) FileOAuthSettings {
	raw.Issuer = os.ExpandEnv(raw.Issuer)
	raw.AuthorizationEndpoint = os.ExpandEnv(raw.AuthorizationEndpoint)
	raw.TokenEndpoint = os.ExpandEnv(raw.TokenEndpoint)
	raw.RevocationEndpoint = os.ExpandEnv(raw.RevocationEndpoint)
	raw.JWKSURI = os.ExpandEnv(raw.JWKSURI)
	raw.LoginEndpoint = os.ExpandEnv(raw.LoginEndpoint)
	raw.ConsentEndpoint = os.ExpandEnv(raw.ConsentEndpoint)
	raw.AuthorizationRequestTTL = os.ExpandEnv(raw.AuthorizationRequestTTL)
	raw.AuthorizationCodeTTL = os.ExpandEnv(raw.AuthorizationCodeTTL)
	raw.ActiveSigningKeyID = os.ExpandEnv(raw.ActiveSigningKeyID)
	for index := range raw.SigningKeys {
		raw.SigningKeys[index].ID = os.ExpandEnv(raw.SigningKeys[index].ID)
		raw.SigningKeys[index].PrivateKey = os.ExpandEnv(raw.SigningKeys[index].PrivateKey)
		raw.SigningKeys[index].PrivateKeyBase64 = os.ExpandEnv(raw.SigningKeys[index].PrivateKeyBase64)
		raw.SigningKeys[index].PublicKey = os.ExpandEnv(raw.SigningKeys[index].PublicKey)
		raw.SigningKeys[index].PublicKeyBase64 = os.ExpandEnv(raw.SigningKeys[index].PublicKeyBase64)
	}
	raw.ClientMetadata.RequestTimeout = os.ExpandEnv(raw.ClientMetadata.RequestTimeout)
	raw.ClientMetadata.MinimumCacheTTL = os.ExpandEnv(raw.ClientMetadata.MinimumCacheTTL)
	raw.ClientMetadata.MaximumCacheTTL = os.ExpandEnv(raw.ClientMetadata.MaximumCacheTTL)
	return raw
}

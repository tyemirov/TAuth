// Package oauthvalidator validates TAuth OAuth access tokens at protected resources.
package oauthvalidator

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrInvalidConfig means the protected-resource policy is incomplete.
	ErrInvalidConfig = errors.New("oauthvalidator.invalid_config")
	// ErrInvalidToken means the bearer token is missing, malformed, expired, or outside policy.
	ErrInvalidToken = errors.New("oauthvalidator.invalid_token")
)

// JWK is one public ES256 verification key.
type JWK struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Curve     string `json:"crv"`
	X         string `json:"x"`
	Y         string `json:"y"`
}

// JWKSet is one issuer verification-key document.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// Claims contains the validated TAuth resource-token claims.
type Claims struct {
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
	TenantID string `json:"tenant_id"`
	GrantID  string `json:"grant_id"`
	jwt.RegisteredClaims
}

// Config is the complete protected-resource validation policy.
type Config struct {
	Issuer         string
	Audience       string
	RequiredScopes []string
	JWKSURL        string
	JWKSet         JWKSet
	HTTPClient     *http.Client
	Clock          func() time.Time
}

// Validator verifies bearer access tokens against one issuer, audience, and scope set.
type Validator struct {
	issuer         string
	audience       string
	requiredScopes []string
	jwksURL        string
	httpClient     *http.Client
	clock          func() time.Time
	mu             sync.RWMutex
	keys           map[string]*ecdsa.PublicKey
	keysExpiresAt  time.Time
}

// New constructs a protected-resource validator.
func New(config Config) (*Validator, error) {
	issuer := strings.TrimSuffix(strings.TrimSpace(config.Issuer), "/")
	audience := strings.TrimSpace(config.Audience)
	if issuer == "" || audience == "" || (strings.TrimSpace(config.JWKSURL) == "" && len(config.JWKSet.Keys) == 0) {
		return nil, ErrInvalidConfig
	}
	requiredScopes := normalizeScopes(config.RequiredScopes)
	if len(requiredScopes) != len(config.RequiredScopes) {
		return nil, ErrInvalidConfig
	}
	clock := config.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	validator := &Validator{
		issuer: issuer, audience: audience, requiredScopes: requiredScopes,
		jwksURL: strings.TrimSpace(config.JWKSURL), httpClient: httpClient, clock: clock,
	}
	if len(config.JWKSet.Keys) != 0 {
		keys, keyErr := parseJWKSet(config.JWKSet)
		if keyErr != nil {
			return nil, keyErr
		}
		validator.keys = keys
		validator.keysExpiresAt = time.Unix(1<<62, 0)
	}
	return validator, nil
}

// ValidateRequest extracts and validates an Authorization bearer token.
func (validator *Validator) ValidateRequest(request *http.Request) (*Claims, error) {
	if request == nil {
		return nil, ErrInvalidToken
	}
	parts := strings.Fields(request.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, ErrInvalidToken
	}
	return validator.ValidateToken(request.Context(), parts[1])
}

// ValidateToken validates one compact JWT access token.
func (validator *Validator) ValidateToken(ctx context.Context, tokenValue string) (*Claims, error) {
	claims := &Claims{}
	parsed, parseErr := jwt.ParseWithClaims(tokenValue, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodES256 || token.Header["typ"] != "at+jwt" {
			return nil, ErrInvalidToken
		}
		keyID, ok := token.Header["kid"].(string)
		if !ok || strings.TrimSpace(keyID) == "" {
			return nil, ErrInvalidToken
		}
		return validator.verificationKey(ctx, keyID)
	},
		jwt.WithIssuer(validator.issuer),
		jwt.WithAudience(validator.audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		jwt.WithTimeFunc(func() time.Time { return validator.clock().UTC() }),
	)
	if parseErr != nil || !parsed.Valid || claims.IssuedAt == nil || len(claims.Audience) != 1 || claims.Audience[0] != validator.audience || strings.TrimSpace(claims.Subject) == "" || strings.TrimSpace(claims.ClientID) == "" || strings.TrimSpace(claims.TenantID) == "" || strings.TrimSpace(claims.GrantID) == "" || strings.TrimSpace(claims.Scope) == "" {
		return nil, ErrInvalidToken
	}
	if !containsScopes(claims.Scope, validator.requiredScopes) {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

func (validator *Validator) verificationKey(ctx context.Context, keyID string) (*ecdsa.PublicKey, error) {
	now := validator.clock().UTC()
	validator.mu.RLock()
	key := validator.keys[keyID]
	fresh := validator.keysExpiresAt.After(now)
	validator.mu.RUnlock()
	if key != nil && fresh {
		return key, nil
	}
	if validator.jwksURL == "" {
		return nil, ErrInvalidToken
	}
	if refreshErr := validator.refreshKeys(ctx, now); refreshErr != nil {
		return nil, ErrInvalidToken
	}
	validator.mu.RLock()
	key = validator.keys[keyID]
	validator.mu.RUnlock()
	if key == nil {
		return nil, ErrInvalidToken
	}
	return key, nil
}

func (validator *Validator) refreshKeys(ctx context.Context, now time.Time) error {
	request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, validator.jwksURL, nil)
	if requestErr != nil {
		return requestErr
	}
	request.Header.Set("Accept", "application/json")
	response, responseErr := validator.httpClient.Do(request)
	if responseErr != nil {
		return responseErr
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return ErrInvalidToken
	}
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if readErr != nil || len(payload) > 64*1024 {
		return ErrInvalidToken
	}
	var document JWKSet
	if decodeErr := json.Unmarshal(payload, &document); decodeErr != nil {
		return decodeErr
	}
	keys, keyErr := parseJWKSet(document)
	if keyErr != nil {
		return keyErr
	}
	validator.mu.Lock()
	validator.keys = keys
	validator.keysExpiresAt = now.Add(jwksCacheTTL(response.Header))
	validator.mu.Unlock()
	return nil
}

func parseJWKSet(document JWKSet) (map[string]*ecdsa.PublicKey, error) {
	if len(document.Keys) == 0 {
		return nil, ErrInvalidConfig
	}
	keys := make(map[string]*ecdsa.PublicKey, len(document.Keys))
	for _, jwk := range document.Keys {
		if jwk.KeyType != "EC" || jwk.Use != "sig" || jwk.Algorithm != "ES256" || jwk.Curve != "P-256" || strings.TrimSpace(jwk.KeyID) == "" {
			return nil, ErrInvalidConfig
		}
		if _, exists := keys[jwk.KeyID]; exists {
			return nil, ErrInvalidConfig
		}
		xBytes, xErr := base64.RawURLEncoding.DecodeString(jwk.X)
		yBytes, yErr := base64.RawURLEncoding.DecodeString(jwk.Y)
		if xErr != nil || yErr != nil || len(xBytes) != 32 || len(yBytes) != 32 {
			return nil, ErrInvalidConfig
		}
		encoded := make([]byte, 65)
		encoded[0] = 4
		copy(encoded[1:33], xBytes)
		copy(encoded[33:65], yBytes)
		publicKey, publicKeyErr := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encoded)
		if publicKeyErr != nil {
			return nil, ErrInvalidConfig
		}
		keys[jwk.KeyID] = publicKey
	}
	return keys, nil
}

func normalizeScopes(scopes []string) []string {
	result := make([]string, 0, len(scopes))
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if strings.TrimSpace(scope) != scope || scope == "" {
			return nil
		}
		if _, exists := seen[scope]; exists {
			return nil
		}
		seen[scope] = struct{}{}
		result = append(result, scope)
	}
	return result
}

func containsScopes(raw string, required []string) bool {
	granted := make(map[string]struct{})
	for _, scope := range strings.Fields(raw) {
		granted[scope] = struct{}{}
	}
	for _, scope := range required {
		if _, exists := granted[scope]; !exists {
			return false
		}
	}
	return true
}

func jwksCacheTTL(headers http.Header) time.Duration {
	for _, directive := range strings.Split(strings.ToLower(headers.Get("Cache-Control")), ",") {
		trimmed := strings.TrimSpace(directive)
		if strings.HasPrefix(trimmed, "max-age=") {
			var seconds int64
			if _, scanErr := fmt.Sscanf(strings.TrimPrefix(trimmed, "max-age="), "%d", &seconds); scanErr == nil && seconds >= 0 && seconds <= 3600 {
				return time.Duration(seconds) * time.Second
			}
		}
	}
	return 5 * time.Minute
}

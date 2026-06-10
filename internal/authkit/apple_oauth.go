package authkit

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tyemirov/tauth/internal/tenants"
)

const (
	appleIssuer                 = "https://appleid.apple.com"
	appleOAuthGrantTypeCode     = "authorization_code"
	appleOAuthResponseTypeCode  = "code"
	appleOAuthResponseModeForm  = "form_post"
	appleStateAudience          = "tauth.apple.oauth"
	appleStateTenantIDClaim     = "tenant_id"
	appleStateNonceClaim        = "nonce"
	appleStateReturnToClaim     = "return_to"
	appleDefaultClientSecretTTL = 5 * time.Minute
)

var configuredAppleOAuthHTTPClient *http.Client
var configuredAppleOAuthHTTPClientMutex sync.RWMutex

var (
	errAppleOAuthInvalidState = errors.New("auth.apple.invalid_state")
	errAppleOAuthReturnTo     = errors.New("auth.apple.invalid_return_to")
	errAppleOAuthToken        = errors.New("auth.apple.token")
	errAppleOAuthIDToken      = errors.New("auth.apple.id_token")
)

type appleOAuthState struct {
	TenantID string
	Nonce    string
	ReturnTo string
}

type appleTokenResponse struct {
	IDToken string `json:"id_token"`
}

type appleIdentity struct {
	Subject       string
	Email         string
	EmailVerified bool
	DisplayName   string
	Nonce         string
}

type appleJWKS struct {
	Keys []appleJWK `json:"keys"`
}

type appleJWK struct {
	KeyType   string `json:"kty"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Use       string `json:"use"`
	Modulus   string `json:"n"`
	Exponent  string `json:"e"`
}

// ProvideAppleOAuthHTTPClient injects the HTTP client used for Apple token and JWKS requests.
func ProvideAppleOAuthHTTPClient(client *http.Client) {
	configuredAppleOAuthHTTPClientMutex.Lock()
	defer configuredAppleOAuthHTTPClientMutex.Unlock()
	configuredAppleOAuthHTTPClient = client
}

func resolveAppleOAuthHTTPClient() *http.Client {
	configuredAppleOAuthHTTPClientMutex.RLock()
	client := configuredAppleOAuthHTTPClient
	configuredAppleOAuthHTTPClientMutex.RUnlock()
	if client != nil {
		return client
	}
	return http.DefaultClient
}

func buildAppleAuthorizationRedirect(config AppleOAuthConfig, state string, nonce string) (string, error) {
	authorizationURL, parseErr := url.Parse(strings.TrimSpace(config.AuthorizationEndpoint))
	if parseErr != nil {
		return "", fmt.Errorf("auth.apple.authorization_url: %w", parseErr)
	}
	query := authorizationURL.Query()
	query.Set("client_id", strings.TrimSpace(config.ClientID))
	query.Set("redirect_uri", strings.TrimSpace(config.RedirectURI))
	query.Set("response_type", appleOAuthResponseTypeCode)
	query.Set("response_mode", appleOAuthResponseModeForm)
	query.Set("scope", strings.Join(config.Scopes, " "))
	query.Set("state", state)
	query.Set("nonce", nonce)
	authorizationURL.RawQuery = query.Encode()
	return authorizationURL.String(), nil
}

func createAppleOAuthState(clock Clock, config ServerConfig, tenantID string, nonce string, returnTo string) (string, error) {
	now := clock.Now().UTC()
	claims := jwt.MapClaims{
		"iss":                   config.AppJWTIssuer,
		"aud":                   appleStateAudience,
		"iat":                   now.Unix(),
		"exp":                   now.Add(effectiveDuration(config.NonceTTL, 5*time.Minute)).Unix(),
		appleStateTenantIDClaim: strings.TrimSpace(tenantID),
		appleStateNonceClaim:    strings.TrimSpace(nonce),
	}
	trimmedReturnTo := strings.TrimSpace(returnTo)
	if trimmedReturnTo != "" {
		claims[appleStateReturnToClaim] = trimmedReturnTo
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, signErr := token.SignedString(config.AppJWTSigningKey)
	if signErr != nil {
		return "", fmt.Errorf("%w: sign: %w", errAppleOAuthInvalidState, signErr)
	}
	return signedToken, nil
}

func validateAppleOAuthState(registry TenantRegistry, state string) (ServerConfig, appleOAuthState, error) {
	trimmedState := strings.TrimSpace(state)
	if trimmedState == "" {
		return ServerConfig{}, appleOAuthState{}, fmt.Errorf("%w: missing", errAppleOAuthInvalidState)
	}
	unverifiedClaims := jwt.MapClaims{}
	_, _, parseErr := jwt.NewParser().ParseUnverified(trimmedState, unverifiedClaims)
	if parseErr != nil {
		return ServerConfig{}, appleOAuthState{}, fmt.Errorf("%w: parse_unverified: %w", errAppleOAuthInvalidState, parseErr)
	}
	tenantID := readStringMapClaim(unverifiedClaims, appleStateTenantIDClaim)
	config, exists := registry.ConfigByID(tenantID)
	if !exists {
		return ServerConfig{}, appleOAuthState{}, fmt.Errorf("%w: unknown_tenant", errAppleOAuthInvalidState)
	}
	verifiedClaims := jwt.MapClaims{}
	_, verifyErr := jwt.ParseWithClaims(trimmedState, verifiedClaims, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("%w: invalid_state_alg", errAppleOAuthInvalidState)
		}
		return config.AppJWTSigningKey, nil
	}, jwt.WithAudience(appleStateAudience), jwt.WithIssuer(config.AppJWTIssuer), jwt.WithExpirationRequired())
	if verifyErr != nil {
		return ServerConfig{}, appleOAuthState{}, fmt.Errorf("%w: verify: %w", errAppleOAuthInvalidState, verifyErr)
	}
	nonce := readStringMapClaim(verifiedClaims, appleStateNonceClaim)
	if strings.TrimSpace(nonce) == "" {
		return ServerConfig{}, appleOAuthState{}, fmt.Errorf("%w: missing_nonce", errAppleOAuthInvalidState)
	}
	returnTo := readStringMapClaim(verifiedClaims, appleStateReturnToClaim)
	if strings.TrimSpace(returnTo) != "" {
		validatedReturnTo, returnToErr := validateAppleOAuthReturnTo(config, returnTo)
		if returnToErr != nil {
			return ServerConfig{}, appleOAuthState{}, fmt.Errorf("%w: %w", errAppleOAuthInvalidState, returnToErr)
		}
		returnTo = validatedReturnTo
	}
	return config, appleOAuthState{TenantID: tenantID, Nonce: nonce, ReturnTo: returnTo}, nil
}

func validateAppleOAuthReturnTo(config ServerConfig, returnTo string) (string, error) {
	trimmedReturnTo := strings.TrimSpace(returnTo)
	if trimmedReturnTo == "" {
		return "", nil
	}
	parsedReturnTo, parseErr := url.Parse(trimmedReturnTo)
	if parseErr != nil {
		return "", fmt.Errorf("%w: parse: %w", errAppleOAuthReturnTo, parseErr)
	}
	if parsedReturnTo.Scheme == "" || parsedReturnTo.Host == "" {
		return "", fmt.Errorf("%w: absolute_url_required", errAppleOAuthReturnTo)
	}
	if parsedReturnTo.User != nil {
		return "", fmt.Errorf("%w: userinfo_forbidden", errAppleOAuthReturnTo)
	}
	returnToOrigin, originErr := normalizeAppleReturnOrigin(parsedReturnTo)
	if originErr != nil {
		return "", fmt.Errorf("%w: origin: %w", errAppleOAuthReturnTo, originErr)
	}
	for _, tenantOrigin := range config.TenantOrigins {
		normalizedTenantOrigin, normalizeErr := tenants.NormalizeOrigin(tenantOrigin)
		if normalizeErr != nil {
			return "", fmt.Errorf("%w: tenant_origin: %w", errAppleOAuthReturnTo, normalizeErr)
		}
		if normalizedTenantOrigin == returnToOrigin {
			return parsedReturnTo.String(), nil
		}
	}
	return "", fmt.Errorf("%w: origin_not_allowed", errAppleOAuthReturnTo)
}

func normalizeAppleReturnOrigin(parsedReturnTo *url.URL) (string, error) {
	return tenants.NormalizeOrigin((&url.URL{
		Scheme: parsedReturnTo.Scheme,
		Host:   parsedReturnTo.Host,
	}).String())
}

func exchangeAppleAuthorizationCode(ctx context.Context, client *http.Client, config AppleOAuthConfig, clock Clock, code string) (appleTokenResponse, error) {
	clientSecret, secretErr := buildAppleClientSecret(config, clock)
	if secretErr != nil {
		return appleTokenResponse{}, secretErr
	}
	form := url.Values{}
	form.Set("client_id", strings.TrimSpace(config.ClientID))
	form.Set("client_secret", clientSecret)
	form.Set("code", strings.TrimSpace(code))
	form.Set("grant_type", appleOAuthGrantTypeCode)
	form.Set("redirect_uri", strings.TrimSpace(config.RedirectURI))
	request, requestErr := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(config.TokenEndpoint), strings.NewReader(form.Encode()))
	if requestErr != nil {
		return appleTokenResponse{}, fmt.Errorf("%w: request: %w", errAppleOAuthToken, requestErr)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, responseErr := client.Do(request)
	if responseErr != nil {
		return appleTokenResponse{}, fmt.Errorf("%w: request_failed: %w", errAppleOAuthToken, responseErr)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return appleTokenResponse{}, fmt.Errorf("%w: status=%d", errAppleOAuthToken, response.StatusCode)
	}
	var payload appleTokenResponse
	if decodeErr := json.NewDecoder(response.Body).Decode(&payload); decodeErr != nil {
		return appleTokenResponse{}, fmt.Errorf("%w: decode: %w", errAppleOAuthToken, decodeErr)
	}
	if strings.TrimSpace(payload.IDToken) == "" {
		return appleTokenResponse{}, fmt.Errorf("%w: missing_id_token", errAppleOAuthToken)
	}
	return payload, nil
}

func buildAppleClientSecret(config AppleOAuthConfig, clock Clock) (string, error) {
	privateKey, keyErr := jwt.ParseECPrivateKeyFromPEM([]byte(config.PrivateKey))
	if keyErr != nil {
		return "", fmt.Errorf("%w: private_key: %w", errAppleOAuthToken, keyErr)
	}
	now := clock.Now().UTC()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": strings.TrimSpace(config.TeamID),
		"iat": now.Unix(),
		"exp": now.Add(appleDefaultClientSecretTTL).Unix(),
		"aud": appleIssuer,
		"sub": strings.TrimSpace(config.ClientID),
	})
	token.Header["kid"] = strings.TrimSpace(config.KeyID)
	signedToken, signErr := token.SignedString(privateKey)
	if signErr != nil {
		return "", fmt.Errorf("%w: client_secret: %w", errAppleOAuthToken, signErr)
	}
	return signedToken, nil
}

func validateAppleIDToken(ctx context.Context, client *http.Client, config AppleOAuthConfig, idToken string) (appleIdentity, error) {
	jwks, jwksErr := fetchAppleJWKS(ctx, client, config.JWKSURL)
	if jwksErr != nil {
		return appleIdentity{}, jwksErr
	}
	claims := jwt.MapClaims{}
	_, parseErr := jwt.ParseWithClaims(idToken, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, fmt.Errorf("%w: invalid_alg", errAppleOAuthIDToken)
		}
		keyID, ok := token.Header["kid"].(string)
		if !ok || strings.TrimSpace(keyID) == "" {
			return nil, fmt.Errorf("%w: missing_kid", errAppleOAuthIDToken)
		}
		publicKey, keyErr := jwks.publicKey(keyID)
		if keyErr != nil {
			return nil, keyErr
		}
		return publicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(appleIssuer), jwt.WithAudience(config.ClientID), jwt.WithExpirationRequired())
	if parseErr != nil {
		return appleIdentity{}, fmt.Errorf("%w: verify: %w", errAppleOAuthIDToken, parseErr)
	}
	return appleIdentity{
		Subject:       readStringMapClaim(claims, "sub"),
		Email:         strings.ToLower(readStringMapClaim(claims, "email")),
		EmailVerified: readBoolishMapClaim(claims, "email_verified"),
		DisplayName:   readStringMapClaim(claims, "name"),
		Nonce:         readStringMapClaim(claims, "nonce"),
	}, nil
}

func fetchAppleJWKS(ctx context.Context, client *http.Client, jwksURL string) (appleJWKS, error) {
	request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSpace(jwksURL), nil)
	if requestErr != nil {
		return appleJWKS{}, fmt.Errorf("%w: jwks_request: %w", errAppleOAuthIDToken, requestErr)
	}
	response, responseErr := client.Do(request)
	if responseErr != nil {
		return appleJWKS{}, fmt.Errorf("%w: jwks_request_failed: %w", errAppleOAuthIDToken, responseErr)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return appleJWKS{}, fmt.Errorf("%w: jwks_status=%d", errAppleOAuthIDToken, response.StatusCode)
	}
	var keys appleJWKS
	if decodeErr := json.NewDecoder(response.Body).Decode(&keys); decodeErr != nil {
		return appleJWKS{}, fmt.Errorf("%w: jwks_decode: %w", errAppleOAuthIDToken, decodeErr)
	}
	return keys, nil
}

func (keys appleJWKS) publicKey(keyID string) (*rsa.PublicKey, error) {
	for _, key := range keys.Keys {
		if key.KeyID != keyID {
			continue
		}
		if key.KeyType != "RSA" {
			return nil, fmt.Errorf("%w: jwk_not_rsa", errAppleOAuthIDToken)
		}
		modulusBytes, modulusErr := base64.RawURLEncoding.DecodeString(key.Modulus)
		if modulusErr != nil {
			return nil, fmt.Errorf("%w: jwk_modulus: %w", errAppleOAuthIDToken, modulusErr)
		}
		exponentBytes, exponentErr := base64.RawURLEncoding.DecodeString(key.Exponent)
		if exponentErr != nil {
			return nil, fmt.Errorf("%w: jwk_exponent: %w", errAppleOAuthIDToken, exponentErr)
		}
		exponent := new(big.Int).SetBytes(exponentBytes).Int64()
		if exponent <= 0 {
			return nil, fmt.Errorf("%w: jwk_exponent_invalid", errAppleOAuthIDToken)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(modulusBytes), E: int(exponent)}, nil
	}
	return nil, fmt.Errorf("%w: jwk_not_found", errAppleOAuthIDToken)
}

func readStringMapClaim(claims jwt.MapClaims, key string) string {
	value, _ := claims[key].(string)
	return strings.TrimSpace(value)
}

func readBoolishMapClaim(claims jwt.MapClaims, key string) bool {
	switch value := claims[key].(type) {
	case bool:
		return value
	case string:
		return strings.EqualFold(strings.TrimSpace(value), "true")
	default:
		return false
	}
}

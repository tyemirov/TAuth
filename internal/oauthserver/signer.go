package oauthserver

import (
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tyemirov/tauth/internal/appconfig"
)

const accessTokenType = "at+jwt"

var ErrInvalidAccessToken = errors.New("oauth.invalid_access_token")

// AccessTokenClaims is the complete first-party resource-token claim set.
type AccessTokenClaims struct {
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
	TenantID string `json:"tenant_id"`
	GrantID  string `json:"grant_id"`
	jwt.RegisteredClaims
}

// JWK is one public ES256 signing key.
type JWK struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Curve     string `json:"crv"`
	X         string `json:"x"`
	Y         string `json:"y"`
}

// JWKSet is the RFC 7517 public verification-key document.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// Signer mints ES256 access tokens and publishes the corresponding public keys.
type Signer struct {
	issuer      string
	activeKeyID string
	privateKeys map[string]*ecdsa.PrivateKey
	publicKeys  map[string]*ecdsa.PublicKey
	jwks        JWKSet
}

// NewSigner constructs the issuer key set from validated operator configuration.
func NewSigner(config appconfig.OAuthServerConfig) (*Signer, error) {
	if !config.Enabled() {
		return nil, fmt.Errorf("oauth.signer.disabled")
	}
	privateKeys := make(map[string]*ecdsa.PrivateKey)
	publicVerificationKeys := make(map[string]*ecdsa.PublicKey)
	publicKeys := make([]JWK, 0, len(config.SigningKeys()))
	for _, configuredKey := range config.SigningKeys() {
		privateKey := configuredKey.PrivateKey()
		publicKey := configuredKey.PublicKey()
		if publicKey == nil {
			return nil, fmt.Errorf("oauth.signer.public_key_missing key_id=%s", configuredKey.ID())
		}
		if privateKey != nil {
			privateKeys[configuredKey.ID()] = privateKey
		}
		publicVerificationKeys[configuredKey.ID()] = publicKey
		jwk, jwkErr := publicJWK(configuredKey.ID(), publicKey)
		if jwkErr != nil {
			return nil, fmt.Errorf("oauth.signer.public_key_invalid key_id=%s: %w", configuredKey.ID(), jwkErr)
		}
		publicKeys = append(publicKeys, jwk)
	}
	if privateKeys[config.ActiveSigningKeyID()] == nil {
		return nil, fmt.Errorf("oauth.signer.active_key_missing key_id=%s", config.ActiveSigningKeyID())
	}
	return &Signer{
		issuer: config.Issuer(), activeKeyID: config.ActiveSigningKeyID(),
		privateKeys: privateKeys, publicKeys: publicVerificationKeys, jwks: JWKSet{Keys: publicKeys},
	}, nil
}

// JWKS returns the public verification keys without private key material.
func (signer *Signer) JWKS() JWKSet {
	keys := make([]JWK, len(signer.jwks.Keys))
	copy(keys, signer.jwks.Keys)
	return JWKSet{Keys: keys}
}

// MintAccessToken creates one resource-bound JWT access token.
func (signer *Signer) MintAccessToken(grant RefreshGrant, issuedAt time.Time, ttl time.Duration) (string, time.Time, error) {
	if signer == nil || signer.privateKeys[signer.activeKeyID] == nil {
		return "", time.Time{}, fmt.Errorf("oauth.access_token.signer_uninitialized")
	}
	current := issuedAt.UTC()
	expiresAt := current.Add(ttl)
	tokenID, _, tokenIDErr := newOpaqueToken("access_token_id")
	if tokenIDErr != nil {
		return "", time.Time{}, tokenIDErr
	}
	claims := AccessTokenClaims{
		ClientID: grant.ClientID,
		Scope:    grant.Scope,
		TenantID: grant.TenantID,
		GrantID:  grant.ConsentID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    signer.issuer,
			Subject:   grant.UserID,
			Audience:  jwt.ClaimStrings{grant.Resource},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(current),
			ID:        tokenID,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = signer.activeKeyID
	token.Header["typ"] = accessTokenType
	signed, signErr := token.SignedString(signer.privateKeys[signer.activeKeyID])
	if signErr != nil {
		return "", time.Time{}, fmt.Errorf("oauth.access_token.sign: %w", signErr)
	}
	return signed, expiresAt, nil
}

// ParseAccessToken validates a token issued by this signer for revocation routing.
func (signer *Signer) ParseAccessToken(value string, now time.Time) (*AccessTokenClaims, error) {
	claims := &AccessTokenClaims{}
	parsed, parseErr := jwt.ParseWithClaims(value, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodES256 || token.Header["typ"] != accessTokenType {
			return nil, ErrInvalidAccessToken
		}
		keyID, ok := token.Header["kid"].(string)
		if !ok || strings.TrimSpace(keyID) == "" {
			return nil, ErrInvalidAccessToken
		}
		publicKey := signer.publicKeys[keyID]
		if publicKey == nil {
			return nil, ErrInvalidAccessToken
		}
		return publicKey, nil
	}, jwt.WithIssuer(signer.issuer), jwt.WithExpirationRequired(), jwt.WithTimeFunc(func() time.Time { return now.UTC() }), jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}))
	if parseErr != nil || !parsed.Valid || strings.TrimSpace(claims.GrantID) == "" || strings.TrimSpace(claims.ClientID) == "" {
		return nil, ErrInvalidAccessToken
	}
	return claims, nil
}

func publicJWK(keyID string, publicKey *ecdsa.PublicKey) (JWK, error) {
	encoded, encodeErr := publicKey.Bytes()
	if encodeErr != nil || len(encoded) != 65 || encoded[0] != 4 {
		return JWK{}, fmt.Errorf("invalid P-256 public key")
	}
	return JWK{
		KeyType: "EC", Use: "sig", KeyID: keyID, Algorithm: jwt.SigningMethodES256.Alg(), Curve: "P-256",
		X: base64.RawURLEncoding.EncodeToString(encoded[1:33]),
		Y: base64.RawURLEncoding.EncodeToString(encoded[33:65]),
	}, nil
}

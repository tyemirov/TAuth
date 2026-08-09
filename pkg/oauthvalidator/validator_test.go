package oauthvalidator

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestValidatorAcceptsOnlyExactResourcePolicy(t *testing.T) {
	now := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	privateKey, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if keyErr != nil {
		t.Fatalf("generate key: %v", keyErr)
	}
	keySet := testJWKSet(t, &privateKey.PublicKey, "active")
	validToken := signTestAccessToken(t, privateKey, "active", now, "https://issuer.example", "https://resource.example", "resource:read resource:write")
	otherPrivateKey, otherKeyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if otherKeyErr != nil {
		t.Fatalf("generate other key: %v", otherKeyErr)
	}
	validator := mustValidator(t, Config{
		Issuer: "https://issuer.example", Audience: "https://resource.example",
		RequiredScopes: []string{"resource:write"}, JWKSet: keySet, Clock: func() time.Time { return now },
	})
	claims, validateErr := validator.ValidateToken(context.Background(), validToken)
	if validateErr != nil || claims.Subject != "user-1" || claims.ClientID != "client-1" || claims.TenantID != "tenant-1" {
		t.Fatalf("validate token: claims=%#v err=%v", claims, validateErr)
	}
	request, requestErr := http.NewRequest(http.MethodGet, "https://resource.example", nil)
	if requestErr != nil {
		t.Fatalf("new request: %v", requestErr)
	}
	request.Header.Set("Authorization", "Bearer "+validToken)
	if _, requestValidationErr := validator.ValidateRequest(request); requestValidationErr != nil {
		t.Fatalf("validate request: %v", requestValidationErr)
	}
	missingIssuedAtToken := signTestClaims(t, privateKey, "active", Claims{
		ClientID: "client-1", Scope: "resource:write", TenantID: "tenant-1", GrantID: "consent-1",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "https://issuer.example", Subject: "user-1", Audience: jwt.ClaimStrings{"https://resource.example"},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
		},
	})
	multipleAudienceToken := signTestClaims(t, privateKey, "active", Claims{
		ClientID: "client-1", Scope: "resource:write", TenantID: "tenant-1", GrantID: "consent-1",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "https://issuer.example", Subject: "user-1", Audience: jwt.ClaimStrings{"https://resource.example", "https://other.example"},
			IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
		},
	})

	testCases := []struct {
		name      string
		config    Config
		token     string
		clockTime time.Time
	}{
		{name: "wrong issuer", config: Config{Issuer: "https://other.example", Audience: "https://resource.example", JWKSet: keySet}, token: validToken, clockTime: now},
		{name: "wrong audience", config: Config{Issuer: "https://issuer.example", Audience: "https://other.example", JWKSet: keySet}, token: validToken, clockTime: now},
		{name: "wrong scope", config: Config{Issuer: "https://issuer.example", Audience: "https://resource.example", RequiredScopes: []string{"resource:delete"}, JWKSet: keySet}, token: validToken, clockTime: now},
		{name: "expired", config: Config{Issuer: "https://issuer.example", Audience: "https://resource.example", JWKSet: keySet}, token: validToken, clockTime: now.Add(2 * time.Minute)},
		{name: "unknown signing key", config: Config{Issuer: "https://issuer.example", Audience: "https://resource.example", JWKSet: keySet}, token: signTestAccessToken(t, privateKey, "retired", now, "https://issuer.example", "https://resource.example", "resource:write"), clockTime: now},
		{name: "wrong signing key", config: Config{Issuer: "https://issuer.example", Audience: "https://resource.example", JWKSet: keySet}, token: signTestAccessToken(t, otherPrivateKey, "active", now, "https://issuer.example", "https://resource.example", "resource:write"), clockTime: now},
		{name: "missing issued at", config: Config{Issuer: "https://issuer.example", Audience: "https://resource.example", JWKSet: keySet}, token: missingIssuedAtToken, clockTime: now},
		{name: "multiple audiences", config: Config{Issuer: "https://issuer.example", Audience: "https://resource.example", JWKSet: keySet}, token: multipleAudienceToken, clockTime: now},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.config.Clock = func() time.Time { return testCase.clockTime }
			candidate := mustValidator(t, testCase.config)
			if _, candidateErr := candidate.ValidateToken(context.Background(), testCase.token); candidateErr != ErrInvalidToken {
				t.Fatalf("expected invalid token, got %v", candidateErr)
			}
		})
	}
}

func mustValidator(t *testing.T, config Config) *Validator {
	t.Helper()
	validator, validatorErr := New(config)
	if validatorErr != nil {
		t.Fatalf("new validator: %v", validatorErr)
	}
	return validator
}

func signTestAccessToken(t *testing.T, key *ecdsa.PrivateKey, keyID string, now time.Time, issuer string, audience string, scope string) string {
	t.Helper()
	claims := Claims{
		ClientID: "client-1", Scope: scope, TenantID: "tenant-1", GrantID: "consent-1",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: issuer, Subject: "user-1", Audience: jwt.ClaimStrings{audience},
			IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
		},
	}
	return signTestClaims(t, key, keyID, claims)
}

func signTestClaims(t *testing.T, key *ecdsa.PrivateKey, keyID string, claims Claims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = keyID
	token.Header["typ"] = "at+jwt"
	signed, signErr := token.SignedString(key)
	if signErr != nil {
		t.Fatalf("sign token: %v", signErr)
	}
	return signed
}

func testJWKSet(t *testing.T, key *ecdsa.PublicKey, keyID string) JWKSet {
	t.Helper()
	encoded, encodeErr := key.Bytes()
	if encodeErr != nil {
		t.Fatalf("encode public key: %v", encodeErr)
	}
	return JWKSet{Keys: []JWK{{
		KeyType: "EC", Use: "sig", KeyID: keyID, Algorithm: "ES256", Curve: "P-256",
		X: base64.RawURLEncoding.EncodeToString(encoded[1:33]),
		Y: base64.RawURLEncoding.EncodeToString(encoded[33:65]),
	}}}
}

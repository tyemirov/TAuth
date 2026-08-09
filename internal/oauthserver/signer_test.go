package oauthserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tyemirov/tauth/internal/appconfig"
)

func TestSignerUsesRetainedPublicKeyForRevocationRouting(t *testing.T) {
	activeKey := generateSignerTestKey(t)
	retiredKey := generateSignerTestKey(t)
	issuer := "http://127.0.0.1:9090"
	configDocument := fmt.Sprintf(`server:
  listen_addr: "127.0.0.1:9090"
oauth:
  enabled: true
  allow_insecure_http: true
  issuer: %q
  authorization_endpoint: %q
  token_endpoint: %q
  revocation_endpoint: %q
  jwks_uri: %q
  login_endpoint: %q
  consent_endpoint: %q
  authorization_request_ttl: "5m"
  authorization_code_ttl: "1m"
  active_signing_key_id: "active"
  signing_keys:
    - id: "active"
      private_key_base64: %q
    - id: "retired"
      public_key_base64: %q
  client_metadata:
    request_timeout: "1s"
    maximum_bytes: 5120
    minimum_cache_ttl: "1s"
    maximum_cache_ttl: "1h"
tenants: []
`, issuer, issuer+"/oauth/authorize", issuer+"/oauth/token", issuer+"/oauth/revoke", issuer+"/oauth/jwks", issuer+"/oauth/login", issuer+"/oauth/consent", signerTestPrivateKey(t, activeKey), signerTestPublicKey(t, &retiredKey.PublicKey))
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if writeErr := os.WriteFile(configPath, []byte(configDocument), 0o600); writeErr != nil {
		t.Fatalf("write config: %v", writeErr)
	}
	applicationConfig, loadErr := appconfig.LoadConfig(configPath)
	if loadErr != nil {
		t.Fatalf("load config: %v", loadErr)
	}
	signer, signerErr := NewSigner(applicationConfig.OAuthServer())
	if signerErr != nil {
		t.Fatalf("build signer: %v", signerErr)
	}
	if signer.privateKeys["retired"] != nil || signer.publicKeys["retired"] == nil {
		t.Fatal("retired key did not remain verification-only")
	}

	now := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	claims := AccessTokenClaims{
		ClientID: "client-one", Scope: "resource:use", TenantID: "tenant-one", GrantID: "grant-one",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: issuer, Subject: "user-one", Audience: jwt.ClaimStrings{"https://resource.example"},
			IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "retired"
	token.Header["typ"] = accessTokenType
	signedToken, signErr := token.SignedString(retiredKey)
	if signErr != nil {
		t.Fatalf("sign retained-key token: %v", signErr)
	}
	parsedClaims, parseErr := signer.ParseAccessToken(signedToken, now)
	if parseErr != nil || parsedClaims.GrantID != "grant-one" || parsedClaims.ClientID != "client-one" {
		t.Fatalf("parse retained-key token: claims=%#v err=%v", parsedClaims, parseErr)
	}
}

func generateSignerTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	privateKey, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if keyErr != nil {
		t.Fatalf("generate key: %v", keyErr)
	}
	return privateKey
}

func signerTestPrivateKey(t *testing.T, privateKey *ecdsa.PrivateKey) string {
	t.Helper()
	der, marshalErr := x509.MarshalPKCS8PrivateKey(privateKey)
	if marshalErr != nil {
		t.Fatalf("marshal private key: %v", marshalErr)
	}
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func signerTestPublicKey(t *testing.T, publicKey *ecdsa.PublicKey) string {
	t.Helper()
	der, marshalErr := x509.MarshalPKIXPublicKey(publicKey)
	if marshalErr != nil {
		t.Fatalf("marshal public key: %v", marshalErr)
	}
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

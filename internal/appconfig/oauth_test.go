package appconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestOAuthServerConfigurationContract(t *testing.T) {
	raw := validOAuthServerSettingsForTest(t)
	config, parseErr := parseOAuthServerConfig(raw)
	if parseErr != nil {
		t.Fatalf("parse OAuth server: %v", parseErr)
	}
	if !config.Enabled() || config.Issuer() != "https://auth.example.com" || config.ActiveSigningKeyID() != "active" || len(config.SigningKeys()) != 1 {
		t.Fatalf("unexpected OAuth server config: %#v", config)
	}
	if config.SigningKeys()[0].Algorithm() != "ES256" || config.SigningKeys()[0].PrivateKey() == nil {
		t.Fatal("expected parsed ES256 signing key")
	}
	rotating := validOAuthServerSettingsForTest(t)
	rotating.SigningKeys = append(rotating.SigningKeys, FileOAuthSigningKey{ID: "retired", PublicKey: publicKeyPEMForTest(t, rotating.SigningKeys[0])})
	rotatingConfig, rotatingErr := parseOAuthServerConfig(rotating)
	if rotatingErr != nil || len(rotatingConfig.SigningKeys()) != 2 || rotatingConfig.SigningKeys()[1].PrivateKey() != nil || rotatingConfig.SigningKeys()[1].PublicKey() == nil {
		t.Fatalf("expected retained verification-only key: config=%#v err=%v", rotatingConfig, rotatingErr)
	}

	testCases := []struct {
		name   string
		mutate func(*FileOAuthSettings)
		code   string
	}{
		{name: "issuer uses https", mutate: func(value *FileOAuthSettings) { value.Issuer = "http://auth.example.com" }, code: ErrorCodeOAuthInvalidIssuer},
		{name: "endpoints are unique", mutate: func(value *FileOAuthSettings) { value.RevocationEndpoint = value.TokenEndpoint }, code: ErrorCodeOAuthDuplicateEndpoint},
		{name: "endpoints do not replace TAuth routes", mutate: func(value *FileOAuthSettings) { value.JWKSURI = value.Issuer + "/health" }, code: ErrorCodeOAuthDuplicateEndpoint},
		{name: "code ttl is bounded", mutate: func(value *FileOAuthSettings) { value.AuthorizationCodeTTL = "10m" }, code: ErrorCodeOAuthInvalidCodeTTL},
		{name: "active key exists", mutate: func(value *FileOAuthSettings) { value.ActiveSigningKeyID = "missing" }, code: ErrorCodeOAuthInvalidActiveSigningKey},
		{name: "active key has private material", mutate: func(value *FileOAuthSettings) {
			value.SigningKeys[0] = FileOAuthSigningKey{ID: "active", PublicKey: publicKeyPEMForTest(t, value.SigningKeys[0])}
		}, code: ErrorCodeOAuthInvalidActiveSigningKey},
		{name: "private key has one PEM block", mutate: func(value *FileOAuthSettings) { value.SigningKeys[0].PrivateKey += "unexpected" }, code: ErrorCodeOAuthInvalidSigningKey},
		{name: "metadata response is bounded", mutate: func(value *FileOAuthSettings) { value.ClientMetadata.MaximumBytes = 6000 }, code: ErrorCodeOAuthInvalidMetadataSize},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			candidate := validOAuthServerSettingsForTest(t)
			testCase.mutate(&candidate)
			_, candidateErr := parseOAuthServerConfig(candidate)
			if candidateErr == nil || !strings.Contains(candidateErr.Error(), testCase.code) {
				t.Fatalf("expected %s, got %v", testCase.code, candidateErr)
			}
		})
	}
}

func publicKeyPEMForTest(t *testing.T, raw FileOAuthSigningKey) string {
	t.Helper()
	privateKey, parseErr := parseOAuthPrivateKey(raw)
	if parseErr != nil {
		t.Fatalf("parse test private key: %v", parseErr)
	}
	encoded, marshalErr := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if marshalErr != nil {
		t.Fatalf("marshal public key: %v", marshalErr)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}))
}

func validOAuthServerSettingsForTest(t *testing.T) FileOAuthSettings {
	t.Helper()
	privateKey, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if keyErr != nil {
		t.Fatalf("generate key: %v", keyErr)
	}
	encoded, marshalErr := x509.MarshalPKCS8PrivateKey(privateKey)
	if marshalErr != nil {
		t.Fatalf("marshal key: %v", marshalErr)
	}
	privateKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}))
	return FileOAuthSettings{
		Enabled: true, Issuer: "https://auth.example.com",
		AuthorizationEndpoint:   "https://auth.example.com/oauth/authorize",
		TokenEndpoint:           "https://auth.example.com/oauth/token",
		RevocationEndpoint:      "https://auth.example.com/oauth/revoke",
		JWKSURI:                 "https://auth.example.com/oauth/jwks",
		LoginEndpoint:           "https://auth.example.com/oauth/login",
		ConsentEndpoint:         "https://auth.example.com/oauth/consent",
		AuthorizationRequestTTL: "5m", AuthorizationCodeTTL: "1m", ActiveSigningKeyID: "active",
		SigningKeys: []FileOAuthSigningKey{{ID: "active", PrivateKey: privateKeyPEM}},
		ClientMetadata: FileClientMetadataPolicy{
			RequestTimeout: "2s", MaximumBytes: 5120, MinimumCacheTTL: "1m", MaximumCacheTTL: "1h",
		},
	}
}

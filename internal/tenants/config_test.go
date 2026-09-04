package tenants

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	testGoogleWebClientID = "client.apps.googleusercontent.com"
	testSessionTTL        = "30m"
	testRefreshTTL        = "720h"
)

func TestLoadConfigSuccess(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "tenants.yaml")
	configYAML := []byte(`tenants:
  - id: "demo"
    display_name: "Demo Tenant"
    tenant_origins:
      - "https://demo.localhost"
      - "https://demo.example.com"
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    google_native_client_id: "demo-native.apps.googleusercontent.com"
    jwt_signing_key: "demo-tenant-key"
    cookie_domain: "demo.example.com"
    session_cookie_name: "app_session_demo"
    refresh_cookie_name: "app_refresh_demo"
    session_ttl: "30m"
    refresh_ttl: "720h"
    nonce_ttl: "10m"
    allow_insecure_http: "true"

  - id: "prod"
    display_name: "Production Tenant"
    tenant_origins:
      - "https://app.example.com"
      - "https://admin.example.com"
    google_web_client_id: "prod-client.apps.googleusercontent.com"
    google_native_client_id: "prod-native.apps.googleusercontent.com"
    jwt_signing_key: "prod-tenant-key"
    cookie_domain: ".example.com"
    session_cookie_name: "app_session_prod"
    refresh_cookie_name: "app_refresh_prod"
    session_ttl: "15m"
    refresh_ttl: "1440h"
    nonce_ttl: "5m"
`)
	if writeErr := os.WriteFile(configPath, configYAML, 0o600); writeErr != nil {
		t.Fatalf("failed to write config: %v", writeErr)
	}

	config, loadErr := LoadConfig(configPath)
	if loadErr != nil {
		t.Fatalf("expected config to load, got error: %v", loadErr)
	}

	tenantsList := config.Tenants()
	if len(tenantsList) != 2 {
		t.Fatalf("expected 2 tenants, got %d", len(tenantsList))
	}

	demoTenant := tenantsList[0]
	if demoTenant.ID() != "demo" {
		t.Fatalf("expected demo tenant id, got %s", demoTenant.ID())
	}
	if demoTenant.DisplayName() != "Demo Tenant" {
		t.Fatalf("unexpected display name: %s", demoTenant.DisplayName())
	}
	if demoTenant.GoogleWebClientID() != "demo-client.apps.googleusercontent.com" {
		t.Fatalf("unexpected google web client id: %s", demoTenant.GoogleWebClientID())
	}
	if demoTenant.GoogleNativeClientID() != "demo-native.apps.googleusercontent.com" {
		t.Fatalf("unexpected google native client id: %s", demoTenant.GoogleNativeClientID())
	}
	if clients := demoTenant.NativeGoogleClients(); len(clients) != 1 || clients[0].Platform() != defaultNativeGooglePlatform {
		t.Fatalf("unexpected native google clients: %#v", clients)
	}
	if string(demoTenant.SigningKey()) != "demo-tenant-key" {
		t.Fatalf("unexpected signing key: %s", demoTenant.SigningKey())
	}
	if !sameStringSlices(demoTenant.Origins(), []string{"https://demo.localhost", "https://demo.example.com"}) {
		t.Fatalf("unexpected tenant_origins: %#v", demoTenant.Origins())
	}
	if demoTenant.CookieDomain() != "demo.example.com" {
		t.Fatalf("unexpected cookie domain: %s", demoTenant.CookieDomain())
	}
	if demoTenant.SessionTTL() != 30*time.Minute {
		t.Fatalf("unexpected session ttl: %s", demoTenant.SessionTTL())
	}
	if demoTenant.RefreshTTL() != 30*24*time.Hour {
		t.Fatalf("unexpected refresh ttl: %s", demoTenant.RefreshTTL())
	}
	if demoTenant.NonceTTL() != 10*time.Minute {
		t.Fatalf("unexpected nonce ttl: %s", demoTenant.NonceTTL())
	}
	if !demoTenant.AllowInsecureHTTP() {
		t.Fatalf("expected allow insecure http to be true")
	}
	if demoTenant.AllowedUsers() != nil {
		t.Fatalf("expected allowed users to be unset, got %#v", demoTenant.AllowedUsers())
	}

	prodTenant := tenantsList[1]
	if prodTenant.ID() != "prod" {
		t.Fatalf("expected prod tenant id, got %s", prodTenant.ID())
	}
	if prodTenant.AllowInsecureHTTP() {
		t.Fatalf("expected allow insecure http to default to false")
	}
	if string(prodTenant.SigningKey()) != "prod-tenant-key" {
		t.Fatalf("expected prod signing key to be set")
	}
}

func TestLoadConfigNormalizesAllowedUsers(testingHandle *testing.T) {
	tenant := buildTestTenant("demo", []string{"https://demo.localhost"}, "demo.localhost", "app_session_demo", "app_refresh_demo", "demo-key")
	tenant.AllowedUsers = []string{"User@Example.com", "admin@example.com"}
	document := FileDocument{Tenants: []FileTenant{tenant}}

	config, loadErr := LoadConfigFromDocument(document)
	if loadErr != nil {
		testingHandle.Fatalf("expected config to load, got error: %v", loadErr)
	}
	loadedTenant, exists := config.TenantByID("demo")
	if !exists {
		testingHandle.Fatalf("expected tenant to exist")
	}
	if !sameStringSlices(loadedTenant.AllowedUsers(), []string{"user@example.com", "admin@example.com"}) {
		testingHandle.Fatalf("unexpected allowed users: %#v", loadedTenant.AllowedUsers())
	}
}

func TestLoadConfigAllowsEmptyAllowedUsers(testingHandle *testing.T) {
	tenant := buildTestTenant("demo", []string{"https://demo.localhost"}, "demo.localhost", "app_session_demo", "app_refresh_demo", "demo-key")
	tenant.AllowedUsers = []string{}
	document := FileDocument{Tenants: []FileTenant{tenant}}

	config, loadErr := LoadConfigFromDocument(document)
	if loadErr != nil {
		testingHandle.Fatalf("expected config to load, got error: %v", loadErr)
	}
	loadedTenant, exists := config.TenantByID("demo")
	if !exists {
		testingHandle.Fatalf("expected tenant to exist")
	}
	allowedUsers := loadedTenant.AllowedUsers()
	if allowedUsers == nil {
		testingHandle.Fatalf("expected allowed users to be present")
	}
	if len(allowedUsers) != 0 {
		testingHandle.Fatalf("expected allowed users to be empty, got %#v", allowedUsers)
	}
}

func TestLoadConfigParsesPasswordAuthUsers(testingHandle *testing.T) {
	passwordHashBytes, hashErr := bcrypt.GenerateFromPassword([]byte("correct horse battery staple"), bcrypt.MinCost)
	if hashErr != nil {
		testingHandle.Fatalf("failed to build test hash: %v", hashErr)
	}
	tenant := buildTestTenant("demo", []string{"https://demo.localhost"}, "demo.localhost", "app_session_demo", "app_refresh_demo", "demo-key")
	tenant.PasswordAuth = FilePasswordAuth{
		Enabled: true,
		Users: []FilePasswordUser{
			{
				Email:        "User@Example.com",
				DisplayName:  "Password User",
				AvatarURL:    "https://example.com/avatar.png",
				PasswordHash: string(passwordHashBytes),
			},
		},
	}
	config, loadErr := LoadConfigFromDocument(FileDocument{Tenants: []FileTenant{tenant}})
	if loadErr != nil {
		testingHandle.Fatalf("expected config to load, got error: %v", loadErr)
	}
	loadedTenant, exists := config.TenantByID("demo")
	if !exists {
		testingHandle.Fatalf("expected tenant to exist")
	}
	if !loadedTenant.PasswordAuthEnabled() {
		testingHandle.Fatalf("expected password auth to be enabled")
	}
	passwordUsers := loadedTenant.PasswordUsers()
	if len(passwordUsers) != 1 {
		testingHandle.Fatalf("expected one password user, got %#v", passwordUsers)
	}
	if passwordUsers[0].Email() != "user@example.com" {
		testingHandle.Fatalf("unexpected password user email: %s", passwordUsers[0].Email())
	}
	if passwordUsers[0].DisplayName() != "Password User" {
		testingHandle.Fatalf("unexpected password user display name: %s", passwordUsers[0].DisplayName())
	}
	if passwordUsers[0].AvatarURL() != "https://example.com/avatar.png" {
		testingHandle.Fatalf("unexpected password user avatar: %s", passwordUsers[0].AvatarURL())
	}
	if passwordUsers[0].PasswordHash() != string(passwordHashBytes) {
		testingHandle.Fatalf("unexpected password hash")
	}
}

func TestLoadConfigRejectsInvalidPasswordAuthHash(testingHandle *testing.T) {
	tenant := buildTestTenant("demo", []string{"https://demo.localhost"}, "demo.localhost", "app_session_demo", "app_refresh_demo", "demo-key")
	tenant.PasswordAuth = FilePasswordAuth{
		Enabled: true,
		Users: []FilePasswordUser{
			{
				Email:        "user@example.com",
				DisplayName:  "Password User",
				PasswordHash: "not-a-bcrypt-hash",
			},
		},
	}
	_, loadErr := LoadConfigFromDocument(FileDocument{Tenants: []FileTenant{tenant}})
	if loadErr == nil {
		testingHandle.Fatalf("expected invalid password hash error")
	}
	if !containsStableCode(loadErr, errorCodeInvalidPasswordHash) {
		testingHandle.Fatalf("expected error code %s, got %v", errorCodeInvalidPasswordHash, loadErr)
	}
}

func TestLoadConfigParsesAccountManagement(testingHandle *testing.T) {
	tenant := buildTestTenant("demo", []string{"https://demo.localhost"}, "demo.localhost", "app_session_demo", "app_refresh_demo", "demo-key")
	tenant.AccountManagement = FileAccountManagement{
		Enabled: true,
		PasswordSignup: FilePasswordSignup{
			Enabled: true,
		},
		ReturnChallengeTokens: true,
		EmailVerificationTTL:  "45m",
		PasswordResetTTL:      "20m",
	}
	config, loadErr := LoadConfigFromDocument(FileDocument{Tenants: []FileTenant{tenant}})
	if loadErr != nil {
		testingHandle.Fatalf("expected config to load, got error: %v", loadErr)
	}
	loadedTenant, exists := config.TenantByID("demo")
	if !exists {
		testingHandle.Fatalf("expected tenant to exist")
	}
	settings := loadedTenant.AccountManagement()
	if !settings.Enabled() || !settings.PasswordSignupEnabled() || !settings.ReturnChallengeTokens() {
		testingHandle.Fatalf("unexpected account management booleans: %#v", settings)
	}
	if settings.EmailVerificationTTL() != 45*time.Minute || settings.PasswordResetTTL() != 20*time.Minute {
		testingHandle.Fatalf("unexpected account management ttls")
	}
}

func TestLoadConfigParsesEmailVerificationDelivery(testingHandle *testing.T) {
	tenant := buildTestTenant("demo", []string{"https://demo.localhost"}, "demo.localhost", "app_session_demo", "app_refresh_demo", "demo-key")
	tenant.AccountManagement = FileAccountManagement{
		Enabled: true,
		PasswordSignup: FilePasswordSignup{
			Enabled: true,
		},
		EmailDelivery: FileEmailDelivery{
			ServerAddress:            "pinguin:50051",
			APIKey:                   "tenant-api-key",
			EmailVerificationURL:     "https://ui.example.com/verify-email",
			PasswordResetURL:         "https://ui.example.com/reset-password",
			PasswordLinkURL:          "https://ui.example.com/link-password",
			ConnectionTimeoutSeconds: 3,
			OperationTimeoutSeconds:  5,
		},
	}
	config, loadErr := LoadConfigFromDocument(FileDocument{Tenants: []FileTenant{tenant}})
	if loadErr != nil {
		testingHandle.Fatalf("expected config to load, got error: %v", loadErr)
	}
	loadedTenant, exists := config.TenantByID("demo")
	if !exists {
		testingHandle.Fatalf("expected tenant to exist")
	}
	emailDelivery := loadedTenant.AccountManagement().EmailDelivery()
	if emailDelivery.ServerAddress() != "pinguin:50051" || emailDelivery.APIKey() != "tenant-api-key" {
		testingHandle.Fatalf("unexpected email delivery service settings: %#v", emailDelivery)
	}
	if emailDelivery.EmailVerificationURL() != "https://ui.example.com/verify-email" {
		testingHandle.Fatalf("unexpected email verification URL: %s", emailDelivery.EmailVerificationURL())
	}
	if emailDelivery.PasswordResetURL() != "https://ui.example.com/reset-password" || emailDelivery.PasswordLinkURL() != "https://ui.example.com/link-password" {
		testingHandle.Fatalf("unexpected password challenge URLs: %#v", emailDelivery)
	}
	if emailDelivery.ConnectionTimeoutSeconds() != 3 || emailDelivery.OperationTimeoutSeconds() != 5 {
		testingHandle.Fatalf("unexpected email delivery timeouts: %#v", emailDelivery)
	}
}

func TestLoadConfigParsesAppleOAuth(testingHandle *testing.T) {
	tenant := buildTestTenant("demo", []string{"https://demo.localhost"}, "demo.localhost", "app_session_demo", "app_refresh_demo", "demo-key")
	tenant.AppleOAuth = FileAppleOAuth{
		Enabled:               true,
		ClientID:              "com.example.web",
		NativeClientIDs:       []string{" com.example.ios ", "com.example.ipados"},
		TeamID:                "TEAMID1234",
		KeyID:                 "KEYID12345",
		PrivateKey:            generateTestApplePrivateKeyPEM(testingHandle),
		RedirectURI:           "https://tauth.example.com/auth/apple/callback",
		Scopes:                []string{"openid", "email"},
		AuthorizationEndpoint: "https://appleid.example.test/auth/authorize",
		TokenEndpoint:         "https://appleid.example.test/auth/token",
		JWKSURL:               "https://appleid.example.test/auth/keys",
	}
	config, loadErr := LoadConfigFromDocument(FileDocument{Tenants: []FileTenant{tenant}})
	if loadErr != nil {
		testingHandle.Fatalf("expected config to load, got error: %v", loadErr)
	}
	loadedTenant, exists := config.TenantByID("demo")
	if !exists {
		testingHandle.Fatalf("expected tenant to exist")
	}
	appleConfig := loadedTenant.AppleOAuth()
	if !appleConfig.Enabled() {
		testingHandle.Fatalf("expected Apple OAuth to be enabled")
	}
	if appleConfig.ClientID() != "com.example.web" || appleConfig.TeamID() != "TEAMID1234" || appleConfig.KeyID() != "KEYID12345" {
		testingHandle.Fatalf("unexpected Apple identifiers: %#v", appleConfig)
	}
	if !sameStringSlices(appleConfig.NativeClientIDs(), []string{"com.example.ios", "com.example.ipados"}) {
		testingHandle.Fatalf("unexpected native Apple client ids: %#v", appleConfig.NativeClientIDs())
	}
	if appleConfig.RedirectURI() != "https://tauth.example.com/auth/apple/callback" {
		testingHandle.Fatalf("unexpected redirect URI: %s", appleConfig.RedirectURI())
	}
	if !sameStringSlices(appleConfig.Scopes(), []string{"openid", "email"}) {
		testingHandle.Fatalf("unexpected scopes: %#v", appleConfig.Scopes())
	}
	if appleConfig.AuthorizationEndpoint() != "https://appleid.example.test/auth/authorize" {
		testingHandle.Fatalf("unexpected authorization endpoint: %s", appleConfig.AuthorizationEndpoint())
	}
}

func TestLoadConfigRejectsDuplicateNativeAppleClientID(testingHandle *testing.T) {
	document := FileDocument{
		Tenants: []FileTenant{
			buildTestTenant("alpha", []string{"https://alpha.localhost"}, "", "app_session_alpha", "app_refresh_alpha", "alpha-key"),
			buildTestTenant("beta", []string{"https://beta.localhost"}, "", "app_session_beta", "app_refresh_beta", "beta-key"),
		},
	}
	for tenantIndex := range document.Tenants {
		document.Tenants[tenantIndex].AppleOAuth = FileAppleOAuth{
			Enabled:         true,
			ClientID:        fmt.Sprintf("com.example.web.%d", tenantIndex),
			NativeClientIDs: []string{"com.example.shared"},
			TeamID:          "TEAMID1234",
			KeyID:           "KEYID12345",
			PrivateKey:      generateTestApplePrivateKeyPEM(testingHandle),
			RedirectURI:     fmt.Sprintf("https://tauth.example.com/auth/apple/callback/%d", tenantIndex),
		}
	}

	_, loadErr := LoadConfigFromDocument(document)
	if loadErr == nil {
		testingHandle.Fatalf("expected config error")
	}
	if !errors.Is(loadErr, ErrInvalidTenantConfig) {
		testingHandle.Fatalf("expected ErrInvalidTenantConfig, got %v", loadErr)
	}
	if !containsStableCode(loadErr, errorCodeDuplicateNativeAppleID) {
		testingHandle.Fatalf("expected error to contain code %s, got %v", errorCodeDuplicateNativeAppleID, loadErr)
	}
}

func TestLoadConfigRejectsInvalidNativeAppleClientIDs(testingHandle *testing.T) {
	testCases := []struct {
		name              string
		nativeClientIDs   []string
		expectedErrorCode string
	}{
		{
			name:              "empty client id",
			nativeClientIDs:   []string{""},
			expectedErrorCode: errorCodeInvalidNativeAppleID,
		},
		{
			name:              "duplicate client id",
			nativeClientIDs:   []string{"com.example.ios", "com.example.ios"},
			expectedErrorCode: errorCodeDuplicateNativeAppleID,
		},
	}

	for testCaseIndex := range testCases {
		testCase := testCases[testCaseIndex]
		testingHandle.Run(testCase.name, func(subTest *testing.T) {
			tenant := buildTestTenant("demo", []string{"https://demo.localhost"}, "", "app_session_demo", "app_refresh_demo", "demo-key")
			tenant.AppleOAuth = FileAppleOAuth{
				Enabled:         true,
				ClientID:        "com.example.web",
				NativeClientIDs: testCase.nativeClientIDs,
				TeamID:          "TEAMID1234",
				KeyID:           "KEYID12345",
				PrivateKey:      generateTestApplePrivateKeyPEM(subTest),
				RedirectURI:     "https://tauth.example.com/auth/apple/callback",
			}

			_, loadErr := LoadConfigFromDocument(FileDocument{Tenants: []FileTenant{tenant}})
			if loadErr == nil {
				subTest.Fatalf("expected config error")
			}
			if !errors.Is(loadErr, ErrInvalidTenantConfig) {
				subTest.Fatalf("expected ErrInvalidTenantConfig, got %v", loadErr)
			}
			if !containsStableCode(loadErr, testCase.expectedErrorCode) {
				subTest.Fatalf("expected error to contain code %s, got %v", testCase.expectedErrorCode, loadErr)
			}
		})
	}
}

func TestLoadConfigParsesAppleOAuthPrivateKeyBase64AndAllowsAppleOnlyTenant(testingHandle *testing.T) {
	privateKey := generateTestApplePrivateKeyPEM(testingHandle)
	tenant := buildTestTenant("demo", []string{"https://demo.localhost"}, "demo.localhost", "app_session_demo", "app_refresh_demo", "demo-key")
	tenant.GoogleWebClientID = ""
	tenant.AppleOAuth = FileAppleOAuth{
		Enabled:          true,
		ClientID:         "com.example.web",
		TeamID:           "TEAMID1234",
		KeyID:            "KEYID12345",
		PrivateKeyBase64: base64.StdEncoding.EncodeToString([]byte(privateKey)),
		RedirectURI:      "https://tauth.example.com/auth/apple/callback",
	}
	config, loadErr := LoadConfigFromDocument(FileDocument{Tenants: []FileTenant{tenant}})
	if loadErr != nil {
		testingHandle.Fatalf("expected config to load, got error: %v", loadErr)
	}
	loadedTenant, exists := config.TenantByID("demo")
	if !exists {
		testingHandle.Fatalf("expected tenant to exist")
	}
	if loadedTenant.GoogleWebClientID() != "" {
		testingHandle.Fatalf("expected empty Google web client id, got %s", loadedTenant.GoogleWebClientID())
	}
	appleConfig := loadedTenant.AppleOAuth()
	if !appleConfig.Enabled() || appleConfig.PrivateKey() != strings.TrimSpace(privateKey) {
		testingHandle.Fatalf("unexpected Apple OAuth config")
	}
}

func TestLoadConfigRejectsInvalidApplePrivateKey(testingHandle *testing.T) {
	tenant := buildTestTenant("demo", []string{"https://demo.localhost"}, "demo.localhost", "app_session_demo", "app_refresh_demo", "demo-key")
	tenant.AppleOAuth = FileAppleOAuth{
		Enabled:     true,
		ClientID:    "com.example.web",
		TeamID:      "TEAMID1234",
		KeyID:       "KEYID12345",
		PrivateKey:  "not-a-pem-key",
		RedirectURI: "https://tauth.example.com/auth/apple/callback",
	}
	_, loadErr := LoadConfigFromDocument(FileDocument{Tenants: []FileTenant{tenant}})
	if loadErr == nil {
		testingHandle.Fatalf("expected invalid Apple private key error")
	}
	if !containsStableCode(loadErr, errorCodeInvalidApplePrivateKey) {
		testingHandle.Fatalf("expected error code %s, got %v", errorCodeInvalidApplePrivateKey, loadErr)
	}
}

func TestLoadConfigRejectsPasswordSignupWithoutAccountManagement(testingHandle *testing.T) {
	tenant := buildTestTenant("demo", []string{"https://demo.localhost"}, "demo.localhost", "app_session_demo", "app_refresh_demo", "demo-key")
	tenant.AccountManagement = FileAccountManagement{
		PasswordSignup: FilePasswordSignup{Enabled: true},
	}
	_, loadErr := LoadConfigFromDocument(FileDocument{Tenants: []FileTenant{tenant}})
	if loadErr == nil {
		testingHandle.Fatalf("expected account management disabled error")
	}
	if !containsStableCode(loadErr, errorCodeAccountManagementDisabled) {
		testingHandle.Fatalf("expected error code %s, got %v", errorCodeAccountManagementDisabled, loadErr)
	}
}

func TestLoadConfigRejectsInvalidAllowedUser(testingHandle *testing.T) {
	tenant := buildTestTenant("demo", []string{"https://demo.localhost"}, "demo.localhost", "app_session_demo", "app_refresh_demo", "demo-key")
	tenant.AllowedUsers = []string{"not-an-email"}
	_, loadErr := LoadConfigFromDocument(FileDocument{Tenants: []FileTenant{tenant}})
	if loadErr == nil {
		testingHandle.Fatalf("expected invalid allowed user error")
	}
	if !containsStableCode(loadErr, errorCodeInvalidAllowedUser) {
		testingHandle.Fatalf("expected error code %s, got %v", errorCodeInvalidAllowedUser, loadErr)
	}
}

func TestLoadConfigRejectsDuplicateAllowedUser(testingHandle *testing.T) {
	tenant := buildTestTenant("demo", []string{"https://demo.localhost"}, "demo.localhost", "app_session_demo", "app_refresh_demo", "demo-key")
	tenant.AllowedUsers = []string{"user@example.com", "User@example.com"}
	_, loadErr := LoadConfigFromDocument(FileDocument{Tenants: []FileTenant{tenant}})
	if loadErr == nil {
		testingHandle.Fatalf("expected duplicate allowed user error")
	}
	if !containsStableCode(loadErr, errorCodeDuplicateAllowedUser) {
		testingHandle.Fatalf("expected error code %s, got %v", errorCodeDuplicateAllowedUser, loadErr)
	}
}

func TestLoadConfigAllowsHostOnlyCookieDomain(t *testing.T) {
	document := FileDocument{
		Tenants: []FileTenant{
			{
				ID:                "host-only",
				DisplayName:       "Host Only",
				TenantOrigins:     []string{"http://localhost"},
				GoogleWebClientID: "demo-client.apps.googleusercontent.com",
				JWTSigningKey:     "host-only-key",
				CookieDomain:      "",
				SessionCookieName: "app_session_host",
				RefreshCookieName: "app_refresh_host",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				AllowInsecureHTTP: true,
			},
		},
	}

	config, err := LoadConfigFromDocument(document)
	if err != nil {
		t.Fatalf("expected host-only cookie domain to load, got %v", err)
	}
	tenant, exists := config.TenantByID("host-only")
	if !exists {
		t.Fatalf("expected tenant to exist")
	}
	if tenant.CookieDomain() != "" {
		t.Fatalf("expected empty cookie domain, got %s", tenant.CookieDomain())
	}
}

func TestLoadConfigSupportsCustomCookieNames(t *testing.T) {
	document := FileDocument{
		Tenants: []FileTenant{
			{
				ID:                "custom",
				DisplayName:       "Custom",
				TenantOrigins:     []string{"https://custom.localhost"},
				GoogleWebClientID: "custom-client.apps.googleusercontent.com",
				JWTSigningKey:     "custom-key",
				CookieDomain:      "",
				SessionCookieName: "app_session",
				RefreshCookieName: "app_refresh",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				AllowInsecureHTTP: true,
			},
		},
	}
	config, err := LoadConfigFromDocument(document)
	if err != nil {
		t.Fatalf("expected config to load, got %v", err)
	}
	tenant, exists := config.TenantByID("custom")
	if !exists {
		t.Fatalf("tenant not found")
	}
	if tenant.SessionCookieName() != "app_session" {
		t.Fatalf("expected session cookie override, got %s", tenant.SessionCookieName())
	}
	if tenant.RefreshCookieName() != "app_refresh" {
		t.Fatalf("expected refresh cookie override, got %s", tenant.RefreshCookieName())
	}
}

func TestLoadConfigValidationErrors(t *testing.T) {
	testCases := []struct {
		name         string
		content      string
		expectedCode string
	}{
		{
			name: "missing_id",
			content: `tenants:
  - id: ""
    display_name: "Demo Tenant"
    tenant_origins: ["https://demo.localhost"]
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    jwt_signing_key: "signing"
    cookie_domain: "demo.example.com"
    session_cookie_name: "app_session_demo"
    refresh_cookie_name: "app_refresh_demo"
    session_ttl: "30m"
    refresh_ttl: "720h"
    nonce_ttl: "10m"
`,
			expectedCode: "tenant.invalid_id",
		},
		{
			name: "invalid_session_ttl",
			content: `tenants:
  - id: "demo"
    display_name: "Demo Tenant"
    tenant_origins: ["https://demo.example.com"]
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    jwt_signing_key: "signing"
    cookie_domain: "demo.example.com"
    session_cookie_name: "app_session_demo"
    refresh_cookie_name: "app_refresh_demo"
    session_ttl: "0"
    refresh_ttl: "720h"
    nonce_ttl: "10m"
`,
			expectedCode: "tenant.invalid_session_ttl",
		},
		{
			name: "unknown_field",
			content: `tenants:
  - id: "demo"
    unknown_field: "unexpected"
    tenant_origins: ["https://demo.example.com"]
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    jwt_signing_key: "signing"
    cookie_domain: "demo.example.com"
    session_cookie_name: "app_session_demo"
    refresh_cookie_name: "app_refresh_demo"
    session_ttl: "30m"
    refresh_ttl: "720h"
    nonce_ttl: "10m"
`,
			expectedCode: "field unknown_field not found",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			tempDir := t.TempDir()
			configPath := filepath.Join(tempDir, "tenants.yaml")
			if err := os.WriteFile(configPath, []byte(testCase.content), 0o600); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			_, loadErr := LoadConfig(configPath)
			if loadErr == nil {
				t.Fatalf("expected load to fail")
			}
			if !errors.Is(loadErr, ErrInvalidTenantConfig) {
				t.Fatalf("expected ErrInvalidTenantConfig, got %v", loadErr)
			}
			if !containsStableCode(loadErr, testCase.expectedCode) {
				t.Fatalf("expected error to contain code %s, got %v", testCase.expectedCode, loadErr)
			}
		})
	}
}

func TestConfigAllowsSharedOrigins(t *testing.T) {
	document := FileDocument{
		Tenants: []FileTenant{
			{
				ID:                "demo",
				DisplayName:       "Demo",
				TenantOrigins:     []string{"https://shared.localhost", "http://localhost:8000"},
				GoogleWebClientID: "demo-client.apps.googleusercontent.com",
				JWTSigningKey:     "demo-key",
				CookieDomain:      "",
				SessionCookieName: "app_session_demo",
				RefreshCookieName: "app_refresh_demo",
				SessionTTL:        "30m",
				RefreshTTL:        "720h",
			},
			{
				ID:                "admin",
				DisplayName:       "Admin",
				TenantOrigins:     []string{"https://shared.localhost", "http://localhost:4173"},
				GoogleWebClientID: "admin-client.apps.googleusercontent.com",
				JWTSigningKey:     "admin-key",
				CookieDomain:      "",
				SessionCookieName: "app_session_admin",
				RefreshCookieName: "app_refresh_admin",
				SessionTTL:        "30m",
				RefreshTTL:        "720h",
			},
		},
	}

	config, err := LoadConfigFromDocument(document)
	if err != nil {
		t.Fatalf("expected shared host config to load, got %v", err)
	}
	if tenant, ok := config.OriginOwner("http://localhost:8000"); !ok || tenant != "demo" {
		t.Fatalf("expected origin to resolve to demo, got %s", tenant)
	}
	if tenant, ok := config.OriginOwner("http://localhost:4173"); !ok || tenant != "admin" {
		t.Fatalf("expected origin to resolve to admin, got %s", tenant)
	}
	if tenant, ok := config.OriginOwner("https://shared.localhost"); !ok || tenant != "demo" {
		t.Fatalf("expected shared origin to resolve to demo, got %s", tenant)
	}
}

func TestLoadConfigRejectsOverlappingCookieNames(testContext *testing.T) {
	const (
		alphaTenantID           = "alpha"
		betaTenantID            = "beta"
		alphaSigningKey         = "alpha-key"
		betaSigningKey          = "beta-key"
		alphaHost               = "https://alpha.example.com"
		betaHost                = "https://beta.example.com"
		sharedHost              = "https://shared.localhost"
		sharedSessionCookieName = "app_session_shared"
		sharedRefreshCookieName = "app_refresh_shared"
		alphaSessionCookieName  = "app_session_alpha"
		betaSessionCookieName   = "app_session_beta"
		alphaRefreshCookieName  = "app_refresh_alpha"
		betaRefreshCookieName   = "app_refresh_beta"
		exampleCookieDomain     = ".example.com"
		subdomainCookieDomain   = "beta.example.com"
	)

	testCases := []struct {
		name         string
		document     FileDocument
		expectedCode string
	}{
		{
			name: "shared_host_duplicate_session_cookie",
			document: FileDocument{
				Tenants: []FileTenant{
					buildTestTenant(alphaTenantID, []string{sharedHost}, "", sharedSessionCookieName, alphaRefreshCookieName, alphaSigningKey),
					buildTestTenant(betaTenantID, []string{sharedHost}, "", sharedSessionCookieName, betaRefreshCookieName, betaSigningKey),
				},
			},
			expectedCode: errorCodeDuplicateSessionCookieName,
		},
		{
			name: "overlapping_domain_duplicate_refresh_cookie",
			document: FileDocument{
				Tenants: []FileTenant{
					buildTestTenant(alphaTenantID, []string{alphaHost}, exampleCookieDomain, alphaSessionCookieName, sharedRefreshCookieName, alphaSigningKey),
					buildTestTenant(betaTenantID, []string{betaHost}, subdomainCookieDomain, betaSessionCookieName, sharedRefreshCookieName, betaSigningKey),
				},
			},
			expectedCode: errorCodeDuplicateRefreshCookieName,
		},
		{
			name: "domain_host_overlap_duplicate_session_cookie",
			document: FileDocument{
				Tenants: []FileTenant{
					buildTestTenant(alphaTenantID, []string{alphaHost}, exampleCookieDomain, sharedSessionCookieName, alphaRefreshCookieName, alphaSigningKey),
					buildTestTenant(betaTenantID, []string{betaHost}, "", sharedSessionCookieName, betaRefreshCookieName, betaSigningKey),
				},
			},
			expectedCode: errorCodeDuplicateSessionCookieName,
		},
		{
			name: "shared_host_cross_type_cookie_name",
			document: FileDocument{
				Tenants: []FileTenant{
					buildTestTenant(alphaTenantID, []string{sharedHost}, "", sharedSessionCookieName, alphaRefreshCookieName, alphaSigningKey),
					buildTestTenant(betaTenantID, []string{sharedHost}, "", betaSessionCookieName, sharedSessionCookieName, betaSigningKey),
				},
			},
			expectedCode: errorCodeDuplicateCookieNameCross,
		},
	}

	for testCaseIndex := range testCases {
		testCase := testCases[testCaseIndex]
		testContext.Run(testCase.name, func(subTestContext *testing.T) {
			_, loadErr := LoadConfigFromDocument(testCase.document)
			if loadErr == nil {
				subTestContext.Fatalf("expected config error")
			}
			if !errors.Is(loadErr, ErrInvalidTenantConfig) {
				subTestContext.Fatalf("expected ErrInvalidTenantConfig, got %v", loadErr)
			}
			if !containsStableCode(loadErr, testCase.expectedCode) {
				subTestContext.Fatalf("expected error to contain code %s, got %v", testCase.expectedCode, loadErr)
			}
		})
	}
}

func TestLoadConfigRejectsDuplicateNativeGoogleClientID(t *testing.T) {
	document := FileDocument{
		Tenants: []FileTenant{
			buildTestTenant("alpha", []string{"https://alpha.localhost"}, "", "app_session_alpha", "app_refresh_alpha", "alpha-key"),
			buildTestTenant("beta", []string{"https://beta.localhost"}, "", "app_session_beta", "app_refresh_beta", "beta-key"),
		},
	}
	document.Tenants[0].GoogleNativeClientID = "shared-native.apps.googleusercontent.com"
	document.Tenants[1].GoogleNativeClientID = "shared-native.apps.googleusercontent.com"

	_, loadErr := LoadConfigFromDocument(document)
	if loadErr == nil {
		t.Fatalf("expected config error")
	}
	if !errors.Is(loadErr, ErrInvalidTenantConfig) {
		t.Fatalf("expected ErrInvalidTenantConfig, got %v", loadErr)
	}
	if !containsStableCode(loadErr, errorCodeDuplicateNativeGoogleID) {
		t.Fatalf("expected error to contain code %s, got %v", errorCodeDuplicateNativeGoogleID, loadErr)
	}
}

func TestLoadConfigParsesPlatformNativeGoogleClients(t *testing.T) {
	document := FileDocument{
		Tenants: []FileTenant{
			buildTestTenant("mobile", []string{"https://mobile.localhost"}, "", "app_session_mobile", "app_refresh_mobile", "mobile-key"),
		},
	}
	document.Tenants[0].GoogleNativeClients = []FileNativeGoogleClient{
		{
			Platform: "iOS",
			ClientID: "ios-client.apps.googleusercontent.com",
			RedirectURIs: []string{
				"com.promptdew.mobile://oauth2redirect/google",
				"https://promptdew.example.com/oauth/google/callback",
			},
		},
		{
			Platform:     "android",
			ClientID:     "android-client.apps.googleusercontent.com",
			RedirectURIs: []string{"com.promptdew.mobile:/oauth2redirect/google"},
		},
	}

	config, loadErr := LoadConfigFromDocument(document)
	if loadErr != nil {
		t.Fatalf("expected config to load, got %v", loadErr)
	}
	tenant, exists := config.TenantByID("mobile")
	if !exists {
		t.Fatalf("expected mobile tenant")
	}
	if tenant.GoogleNativeClientID() != "ios-client.apps.googleusercontent.com" {
		t.Fatalf("unexpected first native client id: %s", tenant.GoogleNativeClientID())
	}
	if !sameStringSlices(tenant.NativeGoogleClientIDs(), []string{"ios-client.apps.googleusercontent.com", "android-client.apps.googleusercontent.com"}) {
		t.Fatalf("unexpected native client ids: %#v", tenant.NativeGoogleClientIDs())
	}
	clients := tenant.NativeGoogleClients()
	if len(clients) != 2 {
		t.Fatalf("expected two native clients, got %d", len(clients))
	}
	if clients[0].Platform() != "ios" {
		t.Fatalf("expected normalized ios platform, got %s", clients[0].Platform())
	}
	if !sameStringSlices(clients[0].RedirectURIs(), []string{"com.promptdew.mobile://oauth2redirect/google", "https://promptdew.example.com/oauth/google/callback"}) {
		t.Fatalf("unexpected ios redirect uris: %#v", clients[0].RedirectURIs())
	}
}

func TestLoadConfigRejectsInvalidNativeGoogleRedirectURI(t *testing.T) {
	document := FileDocument{
		Tenants: []FileTenant{
			buildTestTenant("mobile", []string{"https://mobile.localhost"}, "", "app_session_mobile", "app_refresh_mobile", "mobile-key"),
		},
	}
	document.Tenants[0].GoogleNativeClients = []FileNativeGoogleClient{
		{
			Platform:     "ios",
			ClientID:     "ios-client.apps.googleusercontent.com",
			RedirectURIs: []string{"/oauth2redirect/google"},
		},
	}

	_, loadErr := LoadConfigFromDocument(document)
	if loadErr == nil {
		t.Fatalf("expected config error")
	}
	if !errors.Is(loadErr, ErrInvalidTenantConfig) {
		t.Fatalf("expected ErrInvalidTenantConfig, got %v", loadErr)
	}
	if !containsStableCode(loadErr, errorCodeInvalidNativeRedirectURI) {
		t.Fatalf("expected error to contain code %s, got %v", errorCodeInvalidNativeRedirectURI, loadErr)
	}
}

func TestLoadConfigAllowsMissingNativeGoogleClientID(t *testing.T) {
	document := FileDocument{
		Tenants: []FileTenant{
			buildTestTenant("alpha", []string{"https://alpha.localhost"}, "", "app_session_alpha", "app_refresh_alpha", "alpha-key"),
			buildTestTenant("beta", []string{"https://beta.localhost"}, "", "app_session_beta", "app_refresh_beta", "beta-key"),
		},
	}

	config, loadErr := LoadConfigFromDocument(document)
	if loadErr != nil {
		t.Fatalf("expected config to load, got %v", loadErr)
	}
	alphaTenant, exists := config.TenantByID("alpha")
	if !exists {
		t.Fatalf("expected alpha tenant")
	}
	if alphaTenant.GoogleNativeClientID() != "" {
		t.Fatalf("expected empty native client id, got %s", alphaTenant.GoogleNativeClientID())
	}
}

func TestBuildTenantErrors(t *testing.T) {
	testCases := []struct {
		name    string
		tenant  FileTenant
		wantErr string
	}{
		{
			name: "missing auth provider",
			tenant: FileTenant{
				ID:                "demo",
				DisplayName:       "Demo",
				TenantOrigins:     []string{"https://demo.localhost"},
				JWTSigningKey:     "key",
				CookieDomain:      "demo.localhost",
				SessionCookieName: "app_session_demo",
				RefreshCookieName: "app_refresh_demo",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
				AllowInsecureHTTP: true,
			},
			wantErr: errorCodeMissingAuthProvider,
		},
		{
			name: "invalid session ttl",
			tenant: FileTenant{
				ID:                "demo",
				DisplayName:       "Demo",
				TenantOrigins:     []string{"https://demo.localhost"},
				GoogleWebClientID: "client",
				JWTSigningKey:     "key",
				CookieDomain:      "demo.localhost",
				SessionCookieName: "app_session_demo",
				RefreshCookieName: "app_refresh_demo",
				SessionTTL:        "-1m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
			},
			wantErr: errorCodeInvalidSessionTTL,
		},
		{
			name: "invalid nonce ttl",
			tenant: FileTenant{
				ID:                "demo",
				DisplayName:       "Demo",
				TenantOrigins:     []string{"https://demo.localhost"},
				GoogleWebClientID: "client",
				JWTSigningKey:     "key",
				CookieDomain:      "demo.localhost",
				SessionCookieName: "app_session_demo",
				RefreshCookieName: "app_refresh_demo",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "-5m",
			},
			wantErr: errorCodeInvalidNonceTTL,
		},
		{
			name: "invalid origin",
			tenant: FileTenant{
				ID:                "demo",
				DisplayName:       "Demo",
				TenantOrigins:     []string{"demo.localhost"},
				GoogleWebClientID: "client",
				JWTSigningKey:     "key",
				CookieDomain:      "demo.localhost",
				SessionCookieName: "app_session_demo",
				RefreshCookieName: "app_refresh_demo",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
			},
			wantErr: errorCodeInvalidOrigin,
		},
		{
			name: "duplicate origins",
			tenant: FileTenant{
				ID:                "demo",
				DisplayName:       "Demo",
				TenantOrigins:     []string{"https://demo.localhost", "https://DEMO.LOCALHOST"},
				GoogleWebClientID: "client",
				JWTSigningKey:     "key",
				CookieDomain:      "demo.localhost",
				SessionCookieName: "app_session_demo",
				RefreshCookieName: "app_refresh_demo",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
			},
			wantErr: errorCodeDuplicateOrigin,
		},
		{
			name: "missing signing key",
			tenant: FileTenant{
				ID:                "demo",
				DisplayName:       "Demo",
				TenantOrigins:     []string{"https://demo.localhost"},
				GoogleWebClientID: "client",
				CookieDomain:      "demo.localhost",
				SessionCookieName: "app_session_demo",
				RefreshCookieName: "app_refresh_demo",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
			},
			wantErr: errorCodeMissingSigningKey,
		},
		{
			name: "missing session cookie name",
			tenant: FileTenant{
				ID:                "demo",
				DisplayName:       "Demo",
				TenantOrigins:     []string{"https://demo.localhost"},
				GoogleWebClientID: "client",
				JWTSigningKey:     "key",
				CookieDomain:      "demo.localhost",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
				RefreshCookieName: "app_refresh_demo",
			},
			wantErr: errorCodeMissingSessionCookieName,
		},
		{
			name: "missing refresh cookie name",
			tenant: FileTenant{
				ID:                "demo",
				DisplayName:       "Demo",
				TenantOrigins:     []string{"https://demo.localhost"},
				GoogleWebClientID: "client",
				JWTSigningKey:     "key",
				CookieDomain:      "demo.localhost",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
				SessionCookieName: "app_session_demo",
			},
			wantErr: errorCodeMissingRefreshCookieName,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadConfigFromDocument(FileDocument{Tenants: []FileTenant{tc.tenant}})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error %s, got %v", tc.wantErr, err)
			}
		})
	}

	sharedHostConfig := FileDocument{
		Tenants: []FileTenant{
			{
				ID:                "demo",
				DisplayName:       "Demo",
				TenantOrigins:     []string{"https://demo.localhost", "https://demo.example.com"},
				GoogleWebClientID: "client",
				JWTSigningKey:     "key1",
				CookieDomain:      "demo.localhost",
				SessionCookieName: "app_session_demo",
				RefreshCookieName: "app_refresh_demo",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
			},
			{
				ID:                "prod",
				DisplayName:       "Prod",
				TenantOrigins:     []string{"https://demo.localhost"},
				GoogleWebClientID: "prod-client",
				JWTSigningKey:     "key2",
				CookieDomain:      "prod.localhost",
				SessionCookieName: "app_session_prod",
				RefreshCookieName: "app_refresh_prod",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
			},
		},
	}
	config, err := LoadConfigFromDocument(sharedHostConfig)
	if err != nil {
		t.Fatalf("expected shared host config to load, got %v", err)
	}
	if tenant, ok := config.OriginOwner("https://demo.localhost"); !ok || tenant != "demo" {
		t.Fatalf("expected shared origin to resolve to demo, got %s", tenant)
	}
}

func TestInvalidOriginErrorIncludesExpectation(t *testing.T) {
	invalidTenant := FileTenant{
		ID:                "demo",
		DisplayName:       "Demo",
		TenantOrigins:     []string{"demo.localhost"},
		GoogleWebClientID: "client",
		JWTSigningKey:     "key",
		CookieDomain:      "demo.localhost",
		SessionCookieName: "app_session_demo",
		RefreshCookieName: "app_refresh_demo",
		SessionTTL:        "15m",
		RefreshTTL:        "720h",
		NonceTTL:          "5m",
	}

	_, loadErr := LoadConfigFromDocument(FileDocument{Tenants: []FileTenant{invalidTenant}})
	if loadErr == nil {
		t.Fatalf("expected config error")
	}
	if !strings.Contains(loadErr.Error(), originReasonMissingScheme) {
		t.Fatalf("expected invalid origin error to mention %q, got %v", originReasonMissingScheme, loadErr)
	}
	if !strings.Contains(loadErr.Error(), originExpectation) {
		t.Fatalf("expected invalid origin error to mention %q, got %v", originExpectation, loadErr)
	}
}

func TestLoadConfigExpandsEnvVars(t *testing.T) {
	t.Setenv("TENANT_COOKIE_DOMAIN", ".example.com")
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "tenants.yaml")
	configYAML := []byte(`tenants:
  - id: "demo"
    display_name: ""
    tenant_origins: ["https://demo.localhost"]
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    jwt_signing_key: "demo-key"
    cookie_domain: "${TENANT_COOKIE_DOMAIN}"
    session_cookie_name: "app_session_demo"
    refresh_cookie_name: "app_refresh_demo"
    session_ttl: "30m"
    refresh_ttl: "720h"
    nonce_ttl: "10m"
`)
	if writeErr := os.WriteFile(configPath, configYAML, 0o600); writeErr != nil {
		t.Fatalf("failed to write config: %v", writeErr)
	}

	config, loadErr := LoadConfig(configPath)
	if loadErr != nil {
		t.Fatalf("expected config to load, got error: %v", loadErr)
	}

	tenant, exists := config.TenantByID("demo")
	if !exists {
		t.Fatalf("expected demo tenant to exist")
	}
	if tenant.CookieDomain() != ".example.com" {
		t.Fatalf("expected cookie domain from env, got %s", tenant.CookieDomain())
	}
	if tenant.DisplayName() != "demo" {
		t.Fatalf("expected fallback display name, got %s", tenant.DisplayName())
	}
}

func TestLoadConfigPreservesLiteralPasswordHashFromFile(t *testing.T) {
	hashBytes, hashErr := bcrypt.GenerateFromPassword([]byte("secret-password"), bcrypt.MinCost)
	if hashErr != nil {
		t.Fatalf("failed to generate password hash: %v", hashErr)
	}
	passwordHash := string(hashBytes)
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "tenants.yaml")
	configYAML := []byte(fmt.Sprintf(`tenants:
  - id: "demo"
    display_name: "Demo"
    tenant_origins: ["https://demo.localhost"]
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    password_auth:
      enabled: true
      users:
        - email: "User@Example.com"
          display_name: "Demo User"
          password_hash: "%s"
    jwt_signing_key: "demo-key"
    cookie_domain: "demo.localhost"
    session_cookie_name: "app_session_demo"
    refresh_cookie_name: "app_refresh_demo"
    session_ttl: "30m"
    refresh_ttl: "720h"
`, passwordHash))
	if writeErr := os.WriteFile(configPath, configYAML, 0o600); writeErr != nil {
		t.Fatalf("failed to write config: %v", writeErr)
	}

	config, loadErr := LoadConfig(configPath)
	if loadErr != nil {
		t.Fatalf("expected config to load, got error: %v", loadErr)
	}
	tenant, exists := config.TenantByID("demo")
	if !exists {
		t.Fatalf("expected demo tenant to exist")
	}
	users := tenant.PasswordUsers()
	if len(users) != 1 {
		t.Fatalf("expected one password user, got %d", len(users))
	}
	if users[0].PasswordHash() != passwordHash {
		t.Fatalf("expected literal bcrypt hash to be preserved")
	}
}

func TestLoadConfigFromDocumentExpandsEnvVars(t *testing.T) {
	t.Setenv("TENANT_ALLOWED_HOST", "https://env.localhost")
	t.Setenv("TENANT_CLIENT_ID", "env-client.apps.googleusercontent.com")
	t.Setenv("TENANT_NATIVE_CLIENT_ID", "env-native.apps.googleusercontent.com")
	t.Setenv("TENANT_SIGNING_KEY", "env-signing-key")
	t.Setenv("TENANT_COOKIE_DOMAIN", ".env.example.com")
	t.Setenv("SESSION_COOKIE_NAME", "env_session_cookie")
	t.Setenv("REFRESH_COOKIE_NAME", "env_refresh_cookie")
	t.Setenv("SESSION_TTL", "45m")
	t.Setenv("REFRESH_TTL", "900h")
	t.Setenv("NONCE_TTL", "6m")

	document := FileDocument{
		Tenants: []FileTenant{
			{
				ID:                   "env-demo",
				DisplayName:          "Env Demo",
				TenantOrigins:        []string{"${TENANT_ALLOWED_HOST}"},
				GoogleWebClientID:    "$TENANT_CLIENT_ID",
				GoogleNativeClientID: "$TENANT_NATIVE_CLIENT_ID",
				JWTSigningKey:        "${TENANT_SIGNING_KEY}",
				CookieDomain:         "$TENANT_COOKIE_DOMAIN",
				SessionCookieName:    "$SESSION_COOKIE_NAME",
				RefreshCookieName:    "${REFRESH_COOKIE_NAME}",
				SessionTTL:           "${SESSION_TTL}",
				RefreshTTL:           "$REFRESH_TTL",
				NonceTTL:             "$NONCE_TTL",
			},
		},
	}

	config, err := LoadConfigFromDocument(document)
	if err != nil {
		t.Fatalf("expected document to load with env vars, got %v", err)
	}
	tenant, ok := config.TenantByID("env-demo")
	if !ok {
		t.Fatalf("expected env-demo tenant to exist")
	}
	if tenant.CookieDomain() != ".env.example.com" {
		t.Fatalf("expected env cookie domain, got %s", tenant.CookieDomain())
	}
	if tenant.GoogleWebClientID() != "env-client.apps.googleusercontent.com" {
		t.Fatalf("expected env client id, got %s", tenant.GoogleWebClientID())
	}
	if tenant.GoogleNativeClientID() != "env-native.apps.googleusercontent.com" {
		t.Fatalf("expected env native client id, got %s", tenant.GoogleNativeClientID())
	}
	if string(tenant.SigningKey()) != "env-signing-key" {
		t.Fatalf("expected env signing key, got %s", tenant.SigningKey())
	}
	if !sameStringSlices(tenant.Origins(), []string{"https://env.localhost"}) {
		t.Fatalf("expected env origin to be expanded, got %#v", tenant.Origins())
	}
	if tenant.SessionCookieName() != "env_session_cookie" {
		t.Fatalf("expected env session cookie name, got %s", tenant.SessionCookieName())
	}
	if tenant.RefreshCookieName() != "env_refresh_cookie" {
		t.Fatalf("expected env refresh cookie name, got %s", tenant.RefreshCookieName())
	}
	if tenant.SessionTTL() != 45*time.Minute {
		t.Fatalf("expected env session ttl, got %s", tenant.SessionTTL())
	}
	if tenant.RefreshTTL() != 900*time.Hour {
		t.Fatalf("expected env refresh ttl, got %s", tenant.RefreshTTL())
	}
	if tenant.NonceTTL() != 6*time.Minute {
		t.Fatalf("expected env nonce ttl, got %s", tenant.NonceTTL())
	}
}

func TestLoadConfigHandlesMissingEnvVars(t *testing.T) {
	document := FileDocument{
		Tenants: []FileTenant{
			{
				ID:                "demo",
				DisplayName:       "${MISSING_DISPLAY_NAME}",
				TenantOrigins:     []string{"https://demo.localhost"},
				GoogleWebClientID: "demo-client.apps.googleusercontent.com",
				JWTSigningKey:     "demo-key",
				CookieDomain:      "$UNSET_COOKIE_DOMAIN",
				SessionCookieName: "app_session_demo",
				RefreshCookieName: "app_refresh_demo",
				SessionTTL:        "30m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
			},
		},
	}

	config, err := LoadConfigFromDocument(document)
	if err != nil {
		t.Fatalf("expected config to load with missing env vars, got %v", err)
	}
	tenant, ok := config.TenantByID("demo")
	if !ok {
		t.Fatalf("expected demo tenant to exist")
	}
	if tenant.CookieDomain() != "" {
		t.Fatalf("expected missing cookie domain env to expand to empty string, got %s", tenant.CookieDomain())
	}
	if tenant.DisplayName() != "demo" {
		t.Fatalf("expected fallback display name when env var missing, got %s", tenant.DisplayName())
	}
}

func TestLoadConfigTrimsQuotedPath(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "quoted.yaml")
	configYAML := []byte(`tenants:
  - id: "demo"
    display_name: "Demo"
    tenant_origins: ["https://demo.localhost"]
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    jwt_signing_key: "demo-key"
    cookie_domain: "demo.localhost"
    session_cookie_name: "app_session_demo"
    refresh_cookie_name: "app_refresh_demo"
    session_ttl: "30m"
    refresh_ttl: "720h"
    nonce_ttl: "10m"
`)
	if writeErr := os.WriteFile(configPath, configYAML, 0o600); writeErr != nil {
		t.Fatalf("failed to write config: %v", writeErr)
	}

	if _, loadErr := LoadConfig(fmt.Sprintf("  \"%s\"  ", configPath)); loadErr != nil {
		t.Fatalf("expected config to load with quoted path, got %v", loadErr)
	}
}

func TestConfigTenantsReturnsCopy(t *testing.T) {
	config := Config{
		tenants: []Tenant{
			{id: "demo"},
		},
	}
	list := config.Tenants()
	if len(list) != 1 || list[0].ID() != "demo" {
		t.Fatalf("expected one tenant copy")
	}
	list[0].id = "mutated"
	if config.tenants[0].ID() != "demo" {
		t.Fatalf("expected original slice to remain unchanged")
	}
}

func buildTestTenant(tenantID string, tenantOrigins []string, cookieDomain string, sessionCookieName string, refreshCookieName string, signingKey string) FileTenant {
	return FileTenant{
		ID:                tenantID,
		TenantOrigins:     tenantOrigins,
		GoogleWebClientID: testGoogleWebClientID,
		JWTSigningKey:     signingKey,
		CookieDomain:      cookieDomain,
		SessionCookieName: sessionCookieName,
		RefreshCookieName: refreshCookieName,
		SessionTTL:        testSessionTTL,
		RefreshTTL:        testRefreshTTL,
	}
}

func generateTestApplePrivateKeyPEM(testingHandle *testing.T) string {
	testingHandle.Helper()
	privateKey, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if keyErr != nil {
		testingHandle.Fatalf("generate test Apple private key: %v", keyErr)
	}
	encodedKey, marshalErr := x509.MarshalPKCS8PrivateKey(privateKey)
	if marshalErr != nil {
		testingHandle.Fatalf("marshal test Apple private key: %v", marshalErr)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey}))
}

func sameStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func containsStableCode(err error, code string) bool {
	return strings.Contains(err.Error(), code)
}

package tenants

import (
	"strings"
	"testing"
)

func TestTenantOAuthConfigurationContract(t *testing.T) {
	tenant := validOAuthTenantForTest()
	config, configErr := LoadConfigFromDocument(FileDocument{Tenants: []FileTenant{tenant}})
	if configErr != nil {
		t.Fatalf("load OAuth tenant: %v", configErr)
	}
	loaded, exists := config.TenantByID("oauth-test")
	if !exists || !loaded.OAuthAuthorization().Enabled() {
		t.Fatal("expected enabled OAuth tenant")
	}
	authorization := loaded.OAuthAuthorization()
	if authorization.AccessTokenTTL().String() != "5m0s" || authorization.RefreshTokenTTL().String() != "24h0m0s" || authorization.ConsentTTL().String() != "12h0m0s" {
		t.Fatalf("unexpected OAuth lifetimes: %#v", authorization)
	}

	testCases := []struct {
		name   string
		mutate func(*FileTenant)
		code   string
	}{
		{name: "browser provider required", mutate: func(value *FileTenant) {
			value.PasswordAuth = FilePasswordAuth{}
			value.GoogleWebClientID = ""
			value.GoogleNativeClientID = "oauth-test-native.apps.googleusercontent.com"
		}, code: errorCodeOAuthMissingBrowserAuth},
		{name: "resource must be declared URL", mutate: func(value *FileTenant) { value.OAuth.Resources[0].Identifier = "not-a-resource" }, code: errorCodeOAuthInvalidResource},
		{name: "scope must have description", mutate: func(value *FileTenant) { value.OAuth.Resources[0].Scopes[0].Description = "" }, code: errorCodeOAuthInvalidScope},
		{name: "redirect must be exact URL", mutate: func(value *FileTenant) { value.OAuth.Clients[0].RedirectURIs[0] = "http://private.example/callback" }, code: errorCodeOAuthInvalidRedirectURI},
		{name: "client grant must name resource", mutate: func(value *FileTenant) { value.OAuth.Clients[0].Grants[0].Resource = "https://other.example" }, code: errorCodeOAuthInvalidClientGrant},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			candidate := validOAuthTenantForTest()
			testCase.mutate(&candidate)
			_, loadErr := LoadConfigFromDocument(FileDocument{Tenants: []FileTenant{candidate}})
			if loadErr == nil || !strings.Contains(loadErr.Error(), testCase.code) {
				t.Fatalf("expected %s, got %v", testCase.code, loadErr)
			}
		})
	}

	googleOnly := validOAuthTenantForTest()
	googleOnly.PasswordAuth = FilePasswordAuth{}
	if _, googleOnlyErr := LoadConfigFromDocument(FileDocument{Tenants: []FileTenant{googleOnly}}); googleOnlyErr != nil {
		t.Fatalf("load Google-only OAuth tenant: %v", googleOnlyErr)
	}

	duplicateResourceTenant := validOAuthTenantForTest()
	duplicateResourceTenant.ID = "oauth-other"
	duplicateResourceTenant.TenantOrigins = []string{"https://other.example.com"}
	duplicateResourceTenant.OAuth.Clients[0].ID = "oauth-other-client"
	duplicateResourceTenant.SessionCookieName = "session_oauth_other"
	duplicateResourceTenant.RefreshCookieName = "refresh_oauth_other"
	if _, duplicateResourceErr := LoadConfigFromDocument(FileDocument{Tenants: []FileTenant{validOAuthTenantForTest(), duplicateResourceTenant}}); duplicateResourceErr == nil || !strings.Contains(duplicateResourceErr.Error(), errorCodeOAuthDuplicateResource) {
		t.Fatalf("expected cross-tenant resource isolation, got %v", duplicateResourceErr)
	}

	duplicateClientTenant := validOAuthTenantForTest()
	duplicateClientTenant.ID = "oauth-other"
	duplicateClientTenant.TenantOrigins = []string{"https://other.example.com"}
	duplicateClientTenant.OAuth.Resources[0].Identifier = "https://other-api.example.com"
	duplicateClientTenant.OAuth.Clients[0].Grants[0].Resource = "https://other-api.example.com"
	duplicateClientTenant.SessionCookieName = "session_oauth_other"
	duplicateClientTenant.RefreshCookieName = "refresh_oauth_other"
	if _, duplicateClientErr := LoadConfigFromDocument(FileDocument{Tenants: []FileTenant{validOAuthTenantForTest(), duplicateClientTenant}}); duplicateClientErr == nil || !strings.Contains(duplicateClientErr.Error(), errorCodeOAuthDuplicateClient) {
		t.Fatalf("expected cross-tenant client isolation, got %v", duplicateClientErr)
	}
}

func validOAuthTenantForTest() FileTenant {
	return FileTenant{
		ID: "oauth-test", DisplayName: "OAuth Test", TenantOrigins: []string{"https://app.example.com"},
		GoogleWebClientID: "oauth-test.apps.googleusercontent.com",
		PasswordAuth:      FilePasswordAuth{Enabled: true},
		OAuth: FileOAuthAuthorization{
			Enabled: true, AccessTokenTTL: "5m", RefreshTokenTTL: "24h", ConsentTTL: "12h",
			Resources: []FileOAuthResource{{
				Identifier: "https://api.example.com", DisplayName: "API",
				Scopes: []FileOAuthScope{{Identifier: "api:use", DisplayName: "Use API", Description: "Use the API."}},
			}},
			Clients: []FileOAuthClient{{
				ID: "oauth-client", DisplayName: "OAuth Client", ApplicationType: "web",
				RedirectURIs: []string{"https://client.example.com/callback"},
				Grants:       []FileOAuthClientGrant{{Resource: "https://api.example.com", Scopes: []string{"api:use"}}},
			}},
		},
		JWTSigningKey: "tenant-session-signing-key", SessionCookieName: "session_oauth_test",
		RefreshCookieName: "refresh_oauth_test", SessionTTL: "15m", RefreshTTL: "24h", NonceTTL: "5m",
	}
}

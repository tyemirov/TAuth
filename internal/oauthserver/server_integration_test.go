package oauthserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/tenants"
	"github.com/tyemirov/tauth/internal/web"
	"github.com/tyemirov/tauth/pkg/oauthvalidator"
	"google.golang.org/api/idtoken"
)

const (
	testOAuthResource    = "http://127.0.0.1:9999"
	testOAuthClient      = "test-client"
	testOAuthRedirect    = "http://127.0.0.1:7777/callback"
	testOAuthScope       = "resource:use"
	testOAuthPassword    = "correct horse battery staple"
	testMetadataClient   = "https://client.example/oauth/metadata.json"
	testMetadataRedirect = "http://127.0.0.1:7788/callback"
	testGoogleClientID   = "oauth-test.apps.googleusercontent.com"
)

type fixtureMetadataResolver struct{}

func (fixtureMetadataResolver) Resolve(ctx context.Context, clientID string) (Client, error) {
	if clientID != testMetadataClient {
		return Client{}, ErrUnknownClient
	}
	return Client{
		ID: testMetadataClient, DisplayName: "Metadata Client", ApplicationType: "native",
		RedirectURIs: []string{testMetadataRedirect}, Source: clientSourceMetadata,
	}, nil
}

type fixtureGoogleValidator struct {
	nonce string
}

func (validator fixtureGoogleValidator) Validate(ctx context.Context, token string, audience string) (*idtoken.Payload, error) {
	if token != "fixture-google-id-token" || audience != testGoogleClientID {
		return nil, fmt.Errorf("fixture.google_token_invalid")
	}
	return &idtoken.Payload{Claims: map[string]any{
		"iss": "https://accounts.google.com", "sub": "google-user", "email": "google@example.com",
		"email_verified": true, "name": "Google User", "picture": "https://images.example/avatar.png", "nonce": validator.nonce,
	}}, nil
}

func TestAuthorizationServerBrowserPKCERefreshAndRevocation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	listener, listenErr := net.Listen("tcp", "127.0.0.1:0")
	if listenErr != nil {
		t.Fatalf("listen: %v", listenErr)
	}
	issuer := "http://" + listener.Addr().String()
	appConfig, tenantConfig := loadOAuthTestConfig(t, issuer)

	baseConfig := authkit.ServerConfig{AppJWTIssuer: "tauth", SessionTTL: 15 * time.Minute, RefreshTTL: time.Hour, NonceTTL: 5 * time.Minute}
	tenantRegistry, registryErr := authkit.BuildTenantRegistry(baseConfig, tenantConfig, authkit.NewSameSiteResolver(false))
	if registryErr != nil {
		t.Fatalf("build tenant registry: %v", registryErr)
	}
	users := web.NewInMemoryUsers()
	refreshSessions := authkit.NewMemoryRefreshTokenStore()
	passwords := authkit.NewMemoryPasswordCredentialStore()
	passwordHash, hashErr := authkit.HashPassword(testOAuthPassword)
	if hashErr != nil {
		t.Fatalf("hash password: %v", hashErr)
	}
	if seedErr := passwords.UpsertPasswordCredential(context.Background(), "demo", authkit.PasswordCredentialSeed{
		UserEmail: "user@example.com", DisplayName: "Demo User", PasswordHash: passwordHash,
	}); seedErr != nil {
		t.Fatalf("seed password: %v", seedErr)
	}

	registry, oauthRegistryErr := NewRegistry(tenantConfig)
	if oauthRegistryErr != nil {
		t.Fatalf("build oauth registry: %v", oauthRegistryErr)
	}
	signer, signerErr := NewSigner(appConfig.OAuthServer())
	if signerErr != nil {
		t.Fatalf("build signer: %v", signerErr)
	}
	store := NewMemoryStore()
	nonces := authkit.NewMemoryNonceStore(5 * time.Minute)
	oauthHandler, handlerErr := NewServer(
		appConfig.OAuthServer(), registry, store, signer, fixtureMetadataResolver{},
		authkit.NewOAuthBrowserSessions(tenantRegistry, users, refreshSessions, nonces, passwords),
	)
	if handlerErr != nil {
		t.Fatalf("build server: %v", handlerErr)
	}
	router := gin.New()
	if mountErr := oauthHandler.Mount(router); mountErr != nil {
		t.Fatalf("mount server: %v", mountErr)
	}
	httpServer := &http.Server{Handler: router, ReadHeaderTimeout: time.Second}
	go func() { _ = httpServer.Serve(listener) }()
	t.Cleanup(func() { _ = httpServer.Shutdown(context.Background()) })

	jar, jarErr := cookiejar.New(nil)
	if jarErr != nil {
		t.Fatalf("cookie jar: %v", jarErr)
	}
	client := &http.Client{Jar: jar, CheckRedirect: func(request *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}

	metadataResponse := doRequest(t, client, http.MethodGet, issuer+authorizationServerMetadataPath, nil)
	assertStatus(t, metadataResponse, http.StatusOK)
	metadataBody := readBody(t, metadataResponse)
	if !strings.Contains(metadataBody, `"code_challenge_methods_supported":["S256"]`) || !strings.Contains(metadataBody, `"client_id_metadata_document_supported":true`) || !strings.Contains(metadataBody, `"resource_parameter_supported":true`) || !strings.Contains(metadataBody, `"authorization_response_iss_parameter_supported":true`) {
		t.Fatalf("metadata missing OAuth contract: %s", metadataBody)
	}
	jwksResponse := doRequest(t, client, http.MethodGet, issuer+"/oauth/jwks", nil)
	assertStatus(t, jwksResponse, http.StatusOK)
	jwksBody := readBody(t, jwksResponse)
	if !strings.Contains(jwksBody, `"kid":"test-key"`) || strings.Contains(jwksBody, `"d":`) || strings.Contains(jwksBody, "PRIVATE KEY") {
		t.Fatalf("unsafe JWKS response: %s", jwksBody)
	}

	verifier := strings.Repeat("a", 43)
	challenge := pkceChallenge(verifier)
	authorizeURL := authorizationURL(issuer, challenge, "state-one", testOAuthRedirect, testOAuthResource, testOAuthScope, testOAuthClient)
	authorizeResponse := doRequest(t, client, http.MethodGet, authorizeURL, nil)
	assertStatus(t, authorizeResponse, http.StatusSeeOther)
	loginLocation := authorizeResponse.Header.Get("Location")
	if !strings.HasPrefix(loginLocation, issuer+"/oauth/login?request=") {
		t.Fatalf("expected login redirect, got %s", loginLocation)
	}

	loginPageResponse := doRequest(t, client, http.MethodGet, loginLocation, nil)
	assertStatus(t, loginPageResponse, http.StatusOK)
	loginHTML := readBody(t, loginPageResponse)
	assertBrowserContentSafe(t, loginHTML, "Test Client", "Test Resource")
	requestToken := queryValue(t, loginLocation, "request")
	loginForm := url.Values{"request": {requestToken}, "provider": {"password"}, "email": {"user@example.com"}, "password": {testOAuthPassword}}
	loginResponse := doRequest(t, client, http.MethodPost, issuer+"/oauth/login", strings.NewReader(loginForm.Encode()))
	assertStatus(t, loginResponse, http.StatusSeeOther)
	consentLocation := loginResponse.Header.Get("Location")

	consentPageResponse := doRequest(t, client, http.MethodGet, consentLocation, nil)
	assertStatus(t, consentPageResponse, http.StatusOK)
	consentHTML := readBody(t, consentPageResponse)
	assertBrowserContentSafe(t, consentHTML, "Test Client", "Use the protected test resource.")
	consentForm := url.Values{"request": {queryValue(t, consentLocation, "request")}, "decision": {"approve"}}
	crossOriginConsent := doRequestWithOrigin(t, client, http.MethodPost, issuer+"/oauth/consent", strings.NewReader(consentForm.Encode()), "https://attacker.example")
	assertOAuthError(t, crossOriginConsent, "invalid_request")
	consentResponse := doRequest(t, client, http.MethodPost, issuer+"/oauth/consent", strings.NewReader(consentForm.Encode()))
	assertStatus(t, consentResponse, http.StatusSeeOther)
	callbackLocation := consentResponse.Header.Get("Location")
	assertOAuthError(t, doRequest(t, client, http.MethodPost, issuer+"/oauth/consent", strings.NewReader(consentForm.Encode())), "invalid_request")
	code := queryValue(t, callbackLocation, "code")
	if queryValue(t, callbackLocation, "state") != "state-one" || queryValue(t, callbackLocation, "iss") != issuer || strings.Contains(callbackLocation, "access_token") || strings.Contains(callbackLocation, "refresh_token") {
		t.Fatalf("unsafe callback redirect: %s", callbackLocation)
	}

	missingVerifierForm := codeTokenForm(code, verifier)
	missingVerifierForm.Del("code_verifier")
	assertOAuthError(t, doRequest(t, client, http.MethodPost, issuer+"/oauth/token", strings.NewReader(missingVerifierForm.Encode())), "invalid_request")
	duplicateClientForm := codeTokenForm(code, verifier)
	duplicateClientForm["client_id"] = []string{testOAuthClient, testOAuthClient}
	assertOAuthError(t, doRequest(t, client, http.MethodPost, issuer+"/oauth/token", strings.NewReader(duplicateClientForm.Encode())), "invalid_request")
	wrongVerifierForm := codeTokenForm(code, strings.Repeat("b", 43))
	wrongVerifierResponse := doRequest(t, client, http.MethodPost, issuer+"/oauth/token", strings.NewReader(wrongVerifierForm.Encode()))
	assertOAuthError(t, wrongVerifierResponse, "invalid_grant")
	unknownTokenResourceForm := codeTokenForm(code, verifier)
	unknownTokenResourceForm.Set("resource", "http://127.0.0.1:8888")
	assertOAuthError(t, doRequest(t, client, http.MethodPost, issuer+"/oauth/token", strings.NewReader(unknownTokenResourceForm.Encode())), "invalid_target")
	tokenResponse := doRequest(t, client, http.MethodPost, issuer+"/oauth/token", strings.NewReader(codeTokenForm(code, verifier).Encode()))
	assertStatus(t, tokenResponse, http.StatusOK)
	tokens := decodeTokenResponse(t, tokenResponse)

	validator := newResourceValidator(t, issuer, signer.JWKS(), time.Now)
	claims, validateErr := validator.ValidateToken(context.Background(), tokens.AccessToken)
	if validateErr != nil {
		t.Fatalf("validate access token: %v", validateErr)
	}
	if claims.Subject != "email:user@example.com" || claims.Audience[0] != testOAuthResource || claims.ClientID != testOAuthClient || claims.TenantID != "demo" || claims.Scope != testOAuthScope {
		t.Fatalf("unexpected access claims: %#v", claims)
	}
	repeatAuthorize := doRequest(t, client, http.MethodGet, authorizationURL(issuer, challenge, "state-repeat", testOAuthRedirect, testOAuthResource, testOAuthScope, testOAuthClient), nil)
	assertStatus(t, repeatAuthorize, http.StatusSeeOther)
	if queryValue(t, repeatAuthorize.Header.Get("Location"), "state") != "state-repeat" || queryValue(t, repeatAuthorize.Header.Get("Location"), "code") == "" {
		t.Fatal("active exact consent was not reused")
	}

	replayResponse := doRequest(t, client, http.MethodPost, issuer+"/oauth/token", strings.NewReader(codeTokenForm(code, verifier).Encode()))
	assertOAuthError(t, replayResponse, "invalid_grant")
	refreshForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}, "client_id": {testOAuthClient}, "resource": {testOAuthResource}}
	unknownRefreshResource := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}, "client_id": {testOAuthClient}, "resource": {"http://127.0.0.1:8888"}}
	assertOAuthError(t, doRequest(t, client, http.MethodPost, issuer+"/oauth/token", strings.NewReader(unknownRefreshResource.Encode())), "invalid_target")
	invalidRefreshScope := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}, "client_id": {testOAuthClient}, "resource": {testOAuthResource}, "scope": {"other:scope"}}
	assertOAuthError(t, doRequest(t, client, http.MethodPost, issuer+"/oauth/token", strings.NewReader(invalidRefreshScope.Encode())), "invalid_scope")
	duplicateRefreshScope := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}, "client_id": {testOAuthClient}, "resource": {testOAuthResource}, "scope": {testOAuthScope, testOAuthScope}}
	assertOAuthError(t, doRequest(t, client, http.MethodPost, issuer+"/oauth/token", strings.NewReader(duplicateRefreshScope.Encode())), "invalid_request")
	refreshForm.Set("scope", testOAuthScope)
	refreshResponse := doRequest(t, client, http.MethodPost, issuer+"/oauth/token", strings.NewReader(refreshForm.Encode()))
	assertStatus(t, refreshResponse, http.StatusOK)
	rotated := decodeTokenResponse(t, refreshResponse)
	if rotated.RefreshToken == tokens.RefreshToken {
		t.Fatal("refresh token was not rotated")
	}
	reuseResponse := doRequest(t, client, http.MethodPost, issuer+"/oauth/token", strings.NewReader(refreshForm.Encode()))
	assertOAuthError(t, reuseResponse, "invalid_grant")
	rotatedForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rotated.RefreshToken}, "client_id": {testOAuthClient}, "resource": {testOAuthResource}}
	rotatedAfterReuse := doRequest(t, client, http.MethodPost, issuer+"/oauth/token", strings.NewReader(rotatedForm.Encode()))
	assertOAuthError(t, rotatedAfterReuse, "invalid_grant")

	deniedAuthorize := doRequest(t, client, http.MethodGet, authorizationURL(issuer, challenge, "state-deny", testOAuthRedirect, testOAuthResource, testOAuthScope, testOAuthClient), nil)
	assertStatus(t, deniedAuthorize, http.StatusSeeOther)
	denialForm := url.Values{"request": {queryValue(t, deniedAuthorize.Header.Get("Location"), "request")}, "decision": {"deny"}}
	denialResponse := doRequest(t, client, http.MethodPost, issuer+"/oauth/consent", strings.NewReader(denialForm.Encode()))
	assertStatus(t, denialResponse, http.StatusSeeOther)
	if queryValue(t, denialResponse.Header.Get("Location"), "error") != "access_denied" || queryValue(t, denialResponse.Header.Get("Location"), "iss") != issuer || strings.Contains(denialResponse.Header.Get("Location"), "code=") {
		t.Fatalf("unsafe denial redirect: %s", denialResponse.Header.Get("Location"))
	}

	revokeAuthorize := doRequest(t, client, http.MethodGet, authorizationURL(issuer, challenge, "state-revoke", testOAuthRedirect, testOAuthResource, testOAuthScope, testOAuthClient), nil)
	assertStatus(t, revokeAuthorize, http.StatusSeeOther)
	revokeConsentForm := url.Values{"request": {queryValue(t, revokeAuthorize.Header.Get("Location"), "request")}, "decision": {"approve"}}
	revokeConsentResponse := doRequest(t, client, http.MethodPost, issuer+"/oauth/consent", strings.NewReader(revokeConsentForm.Encode()))
	assertStatus(t, revokeConsentResponse, http.StatusSeeOther)
	revokeCode := queryValue(t, revokeConsentResponse.Header.Get("Location"), "code")
	revokeTokenResponse := doRequest(t, client, http.MethodPost, issuer+"/oauth/token", strings.NewReader(codeTokenForm(revokeCode, verifier).Encode()))
	assertStatus(t, revokeTokenResponse, http.StatusOK)
	revokedTokens := decodeTokenResponse(t, revokeTokenResponse)
	revocationForm := url.Values{"token": {revokedTokens.RefreshToken}, "client_id": {testOAuthClient}, "token_type_hint": {"future_token_type"}}
	assertStatus(t, doRequest(t, client, http.MethodPost, issuer+"/oauth/revoke", strings.NewReader(revocationForm.Encode())), http.StatusOK)
	revokedRefreshForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {revokedTokens.RefreshToken}, "client_id": {testOAuthClient}, "resource": {testOAuthResource}}
	assertOAuthError(t, doRequest(t, client, http.MethodPost, issuer+"/oauth/token", strings.NewReader(revokedRefreshForm.Encode())), "invalid_grant")
	if _, stillValidErr := validator.ValidateToken(context.Background(), revokedTokens.AccessToken); stillValidErr != nil {
		t.Fatalf("short-lived access token must remain valid until expiry: %v", stillValidErr)
	}
	expiredValidator := newResourceValidator(t, issuer, signer.JWKS(), func() time.Time { return time.Now().Add(2 * time.Minute) })
	if _, expiredErr := expiredValidator.ValidateToken(context.Background(), revokedTokens.AccessToken); expiredErr == nil {
		t.Fatal("revoked access token remained valid past its bounded expiry")
	}

	invalidRedirect := authorizationURL(issuer, challenge, "state-two", "http://127.0.0.1:7777/other", testOAuthResource, testOAuthScope, testOAuthClient)
	assertOAuthError(t, doRequest(t, client, http.MethodGet, invalidRedirect, nil), "invalid_request")
	unknownResource := authorizationURL(issuer, challenge, "state-three", testOAuthRedirect, "http://127.0.0.1:8888", testOAuthScope, testOAuthClient)
	assertOAuthError(t, doRequest(t, client, http.MethodGet, unknownResource, nil), "invalid_target")
	unknownClient := authorizationURL(issuer, challenge, "state-four", testOAuthRedirect, testOAuthResource, testOAuthScope, "unknown-client")
	assertOAuthError(t, doRequest(t, client, http.MethodGet, unknownClient, nil), "unauthorized_client")
	metadataAuthorize := authorizationURL(issuer, challenge, "state-metadata", testMetadataRedirect, testOAuthResource, testOAuthScope, testMetadataClient)
	metadataAuthorizeResponse := doRequest(t, client, http.MethodGet, metadataAuthorize, nil)
	assertStatus(t, metadataAuthorizeResponse, http.StatusSeeOther)
	if !strings.HasPrefix(metadataAuthorizeResponse.Header.Get("Location"), issuer+"/oauth/consent?request=") {
		t.Fatalf("valid metadata client did not reach consent: %s", metadataAuthorizeResponse.Header.Get("Location"))
	}
	metadataRedirectMismatch := authorizationURL(issuer, challenge, "state-metadata-mismatch", testOAuthRedirect, testOAuthResource, testOAuthScope, testMetadataClient)
	assertOAuthError(t, doRequest(t, client, http.MethodGet, metadataRedirectMismatch, nil), "invalid_request")
	invalidScope := doRequest(t, client, http.MethodGet, authorizationURL(issuer, challenge, "state-five", testOAuthRedirect, testOAuthResource, "resource:admin", testOAuthClient), nil)
	assertStatus(t, invalidScope, http.StatusSeeOther)
	if queryValue(t, invalidScope.Header.Get("Location"), "error") != "invalid_scope" {
		t.Fatalf("expected invalid_scope redirect, got %s", invalidScope.Header.Get("Location"))
	}
	plainChallenge := strings.Replace(authorizeURL, "code_challenge_method=S256", "code_challenge_method=plain", 1)
	assertOAuthError(t, doRequest(t, client, http.MethodGet, plainChallenge, nil), "invalid_request")
	unsupportedResponseType := strings.Replace(authorizeURL, "response_type=code", "response_type=token", 1)
	assertOAuthError(t, doRequest(t, client, http.MethodGet, unsupportedResponseType, nil), "unsupported_response_type")

	googleNonce, googleNonceErr := nonces.Issue(context.Background(), "demo")
	if googleNonceErr != nil {
		t.Fatalf("issue Google nonce: %v", googleNonceErr)
	}
	authkit.ProvideGoogleTokenValidator(fixtureGoogleValidator{nonce: googleNonce})
	t.Cleanup(func() { authkit.ProvideGoogleTokenValidator(nil) })
	googleJar, googleJarErr := cookiejar.New(nil)
	if googleJarErr != nil {
		t.Fatalf("Google cookie jar: %v", googleJarErr)
	}
	googleClient := &http.Client{Jar: googleJar, CheckRedirect: func(request *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	googleAuthorize := doRequest(t, googleClient, http.MethodGet, authorizationURL(issuer, challenge, "state-google", testOAuthRedirect, testOAuthResource, testOAuthScope, testOAuthClient), nil)
	assertStatus(t, googleAuthorize, http.StatusSeeOther)
	googleLoginLocation := googleAuthorize.Header.Get("Location")
	googleLoginPage := doRequest(t, googleClient, http.MethodGet, googleLoginLocation, nil)
	assertStatus(t, googleLoginPage, http.StatusOK)
	googleLoginHTML := readBody(t, googleLoginPage)
	if !strings.Contains(googleLoginHTML, testGoogleClientID) || !strings.Contains(googleLoginHTML, "https://accounts.google.com/gsi/client") {
		t.Fatalf("Google login method missing: %s", googleLoginHTML)
	}
	googleLoginForm := url.Values{
		"request": {queryValue(t, googleLoginLocation, "request")}, "provider": {"google"},
		"google_id_token": {"fixture-google-id-token"}, "nonce_token": {googleNonce},
	}
	googleLoginResponse := doJSONLoginRequest(t, googleClient, issuer+"/oauth/login", googleLoginForm)
	assertStatus(t, googleLoginResponse, http.StatusOK)
	var googleContinuation map[string]string
	if decodeErr := json.NewDecoder(googleLoginResponse.Body).Decode(&googleContinuation); decodeErr != nil {
		t.Fatalf("decode Google login continuation: %v", decodeErr)
	}
	_ = googleLoginResponse.Body.Close()
	googleConsent := doRequest(t, googleClient, http.MethodGet, googleContinuation["next"], nil)
	assertStatus(t, googleConsent, http.StatusOK)
	_ = readBody(t, googleConsent)
	googleConsentForm := url.Values{"request": {queryValue(t, googleContinuation["next"], "request")}, "decision": {"approve"}}
	googleConsentResponse := doRequest(t, googleClient, http.MethodPost, issuer+"/oauth/consent", strings.NewReader(googleConsentForm.Encode()))
	assertStatus(t, googleConsentResponse, http.StatusSeeOther)
	googleCode := queryValue(t, googleConsentResponse.Header.Get("Location"), "code")
	googleTokenResponse := doRequest(t, googleClient, http.MethodPost, issuer+"/oauth/token", strings.NewReader(codeTokenForm(googleCode, verifier).Encode()))
	assertStatus(t, googleTokenResponse, http.StatusOK)
	googleTokens := decodeTokenResponse(t, googleTokenResponse)
	googleClaims, googleValidateErr := validator.ValidateToken(context.Background(), googleTokens.AccessToken)
	if googleValidateErr != nil || googleClaims.Subject != "google:google-user" || googleClaims.TenantID != "demo" {
		t.Fatalf("validate Google-authorized token: claims=%#v err=%v", googleClaims, googleValidateErr)
	}
}

func loadOAuthTestConfig(t *testing.T, issuer string) (*appconfig.ApplicationConfig, tenants.Config) {
	t.Helper()
	privateKey, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if keyErr != nil {
		t.Fatalf("generate key: %v", keyErr)
	}
	keyDER, marshalErr := x509.MarshalPKCS8PrivateKey(privateKey)
	if marshalErr != nil {
		t.Fatalf("marshal key: %v", marshalErr)
	}
	keyBase64 := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	config := fmt.Sprintf(`server:
  listen_addr: %q
  database_url: ""
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
  active_signing_key_id: "test-key"
  signing_keys:
    - id: "test-key"
      private_key_base64: %q
  client_metadata:
    request_timeout: "1s"
    maximum_bytes: 5120
    minimum_cache_ttl: "1s"
    maximum_cache_ttl: "1h"
tenants:
  - id: "demo"
    display_name: "Demo"
    tenant_origins: ["http://127.0.0.1:9000"]
    google_web_client_id: %q
    password_auth:
      enabled: true
      users: []
    oauth:
      enabled: true
      access_token_ttl: "1m"
      refresh_token_ttl: "1h"
      consent_ttl: "30m"
      allow_client_metadata_documents: true
      resources:
        - identifier: %q
          display_name: "Test Resource"
          scopes:
            - identifier: %q
              display_name: "Use resource"
              description: "Use the protected test resource."
      clients:
        - id: %q
          display_name: "Test Client"
          application_type: "native"
          redirect_uris: [%q]
          grants:
            - resource: %q
              scopes: [%q]
    jwt_signing_key: "test-session-signing-key-with-sufficient-entropy"
    session_cookie_name: "app_session_demo"
    refresh_cookie_name: "app_refresh_demo"
    session_ttl: "15m"
    refresh_ttl: "1h"
    nonce_ttl: "5m"
    allow_insecure_http: true
`, listenerAddress(issuer), issuer, issuer+"/oauth/authorize", issuer+"/oauth/token", issuer+"/oauth/revoke", issuer+"/oauth/jwks", issuer+"/oauth/login", issuer+"/oauth/consent", keyBase64, testGoogleClientID, testOAuthResource, testOAuthScope, testOAuthClient, testOAuthRedirect, testOAuthResource, testOAuthScope)
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if writeErr := os.WriteFile(configPath, []byte(config), 0o600); writeErr != nil {
		t.Fatalf("write config: %v", writeErr)
	}
	appConfig, loadErr := appconfig.LoadConfig(configPath)
	if loadErr != nil {
		t.Fatalf("load app config: %v", loadErr)
	}
	tenantConfig, tenantErr := tenants.LoadConfigFromDocument(appConfig.TenantDocument())
	if tenantErr != nil {
		t.Fatalf("load tenant config: %v", tenantErr)
	}
	return appConfig, tenantConfig
}

func listenerAddress(issuer string) string { return strings.TrimPrefix(issuer, "http://") }

func authorizationURL(issuer string, challenge string, state string, redirectURI string, resource string, scope string, clientID string) string {
	values := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
		"resource": {resource}, "scope": {scope}, "state": {state},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	return issuer + "/oauth/authorize?" + values.Encode()
}

func codeTokenForm(code string, verifier string) url.Values {
	return url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {testOAuthClient},
		"resource": {testOAuthResource}, "code_verifier": {verifier},
	}
}

func pkceChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func doRequest(t *testing.T, client *http.Client, method string, address string, body io.Reader) *http.Response {
	t.Helper()
	request, requestErr := http.NewRequest(method, address, body)
	if requestErr != nil {
		t.Fatalf("new request: %v", requestErr)
	}
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		parsed, parseErr := url.Parse(address)
		if parseErr == nil && (parsed.Path == "/oauth/login" || parsed.Path == "/oauth/consent") {
			request.Header.Set("Origin", parsed.Scheme+"://"+parsed.Host)
		}
	}
	response, responseErr := client.Do(request)
	if responseErr != nil {
		t.Fatalf("request %s %s: %v", method, address, responseErr)
	}
	return response
}

func doRequestWithOrigin(t *testing.T, client *http.Client, method string, address string, body io.Reader, origin string) *http.Response {
	t.Helper()
	request, requestErr := http.NewRequest(method, address, body)
	if requestErr != nil {
		t.Fatalf("new request: %v", requestErr)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", origin)
	response, responseErr := client.Do(request)
	if responseErr != nil {
		t.Fatalf("request %s %s: %v", method, address, responseErr)
	}
	return response
}

func doJSONLoginRequest(t *testing.T, client *http.Client, address string, form url.Values) *http.Response {
	t.Helper()
	request, requestErr := http.NewRequest(http.MethodPost, address, strings.NewReader(form.Encode()))
	if requestErr != nil {
		t.Fatalf("new Google login request: %v", requestErr)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	parsed, parseErr := url.Parse(address)
	if parseErr != nil {
		t.Fatalf("parse Google login address: %v", parseErr)
	}
	request.Header.Set("Origin", parsed.Scheme+"://"+parsed.Host)
	response, responseErr := client.Do(request)
	if responseErr != nil {
		t.Fatalf("Google login request: %v", responseErr)
	}
	return response
}

func readBody(t *testing.T, response *http.Response) string {
	t.Helper()
	defer func() { _ = response.Body.Close() }()
	payload, readErr := io.ReadAll(response.Body)
	if readErr != nil {
		t.Fatalf("read body: %v", readErr)
	}
	return string(payload)
}

func assertStatus(t *testing.T, response *http.Response, expected int) {
	t.Helper()
	if response.StatusCode != expected {
		t.Fatalf("expected status %d, got %d: %s", expected, response.StatusCode, readBody(t, response))
	}
}

func assertOAuthError(t *testing.T, response *http.Response, code string) {
	t.Helper()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", response.StatusCode, readBody(t, response))
	}
	body := readBody(t, response)
	if body != fmt.Sprintf("{\"error\":%q}\n", code) {
		t.Fatalf("unexpected OAuth error: %s", body)
	}
}

func queryValue(t *testing.T, address string, name string) string {
	t.Helper()
	parsed, parseErr := url.Parse(address)
	if parseErr != nil || parsed.Query().Get(name) == "" {
		t.Fatalf("missing %s in %s", name, address)
	}
	return parsed.Query().Get(name)
}

func assertBrowserContentSafe(t *testing.T, body string, expected ...string) {
	t.Helper()
	for _, value := range expected {
		if !strings.Contains(body, value) {
			t.Fatalf("browser page missing %q", value)
		}
	}
	for _, forbidden := range []string{"access_token", "refresh_token", "PRIVATE KEY", testOAuthPassword} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("browser page exposed %q", forbidden)
		}
	}
}

type tokenResponsePayload struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func decodeTokenResponse(t *testing.T, response *http.Response) tokenResponsePayload {
	t.Helper()
	defer func() { _ = response.Body.Close() }()
	var payload tokenResponsePayload
	if decodeErr := json.NewDecoder(response.Body).Decode(&payload); decodeErr != nil || payload.AccessToken == "" || payload.RefreshToken == "" {
		t.Fatalf("decode token response: %v", decodeErr)
	}
	return payload
}

func newResourceValidator(t *testing.T, issuer string, keys JWKSet, clock func() time.Time) *oauthvalidator.Validator {
	t.Helper()
	publicKeys := make([]oauthvalidator.JWK, 0, len(keys.Keys))
	for _, key := range keys.Keys {
		publicKeys = append(publicKeys, oauthvalidator.JWK{
			KeyType: key.KeyType, Use: key.Use, KeyID: key.KeyID, Algorithm: key.Algorithm,
			Curve: key.Curve, X: key.X, Y: key.Y,
		})
	}
	validator, validatorErr := oauthvalidator.New(oauthvalidator.Config{
		Issuer: issuer, Audience: testOAuthResource, RequiredScopes: []string{testOAuthScope},
		JWKSet: oauthvalidator.JWKSet{Keys: publicKeys}, Clock: clock,
	})
	if validatorErr != nil {
		t.Fatalf("build resource validator: %v", validatorErr)
	}
	return validator
}

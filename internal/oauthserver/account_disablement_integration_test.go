package oauthserver

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/web"
)

type accountCredentialStore interface {
	authkit.PasswordCredentialStore
	authkit.AccountManagementStore
}

type accountLookupStore struct {
	accountCredentialStore
	lookupErr   error
	completeErr error
}

func (store *accountLookupStore) ResolveAccountProfile(ctx context.Context, tenantID string, userID string) (authkit.AccountProfile, error) {
	if store.lookupErr != nil {
		return authkit.AccountProfile{}, store.lookupErr
	}
	return store.accountCredentialStore.ResolveAccountProfile(ctx, tenantID, userID)
}

func (store *accountLookupStore) CompleteAccountDisable(ctx context.Context, tenantID string, userID string) (authkit.AccountProfile, error) {
	if store.completeErr != nil {
		return authkit.AccountProfile{}, store.completeErr
	}
	return store.accountCredentialStore.CompleteAccountDisable(ctx, tenantID, userID)
}

type revocationStore struct {
	Store
	revokeErr error
}

func (store *revocationStore) RevokeUser(ctx context.Context, tenantID string, userID string, nowUnix int64) error {
	if store.revokeErr != nil {
		return store.revokeErr
	}
	return store.Store.RevokeUser(ctx, tenantID, userID, nowUnix)
}

type applicationRevocationStore struct {
	authkit.RefreshTokenStore
	revokeErr error
}

func (store *applicationRevocationStore) RevokeUser(ctx context.Context, tenantID string, userID string) error {
	if store.revokeErr != nil {
		return store.revokeErr
	}
	return store.RefreshTokenStore.RevokeUser(ctx, tenantID, userID)
}

type accountOAuthFixture struct {
	issuer      string
	store       *revocationStore
	accounts    *accountLookupStore
	refresh     *applicationRevocationStore
	databaseURL string
}

func newAccountOAuthFixture(t *testing.T, storage string) accountOAuthFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	issuer := "http://" + listener.Addr().String()
	config, tenantConfig := loadOAuthTestConfig(t, issuer)
	registry, err := authkit.BuildTenantRegistry(authkit.ServerConfig{AppJWTIssuer: "tauth"}, tenantConfig, authkit.NewSameSiteResolver(false))
	if err != nil {
		t.Fatal(err)
	}
	accountConfig := registry.DefaultConfig()
	accountConfig.AccountManagementEnabled = true
	registry = authkit.NewSingleTenantRegistry(accountConfig)
	databaseURL := "sqlite://" + filepath.Join(t.TempDir(), "tauth.db")
	var credentials accountCredentialStore = authkit.NewMemoryPasswordCredentialStore()
	if storage == "sqlite" {
		credentials, err = authkit.NewDatabaseUserStore(context.Background(), databaseURL)
		if err != nil {
			t.Fatal(err)
		}
	}
	accounts := &accountLookupStore{accountCredentialStore: credentials}
	passwordHash, err := authkit.HashPassword(testOAuthPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := accounts.UpsertPasswordCredential(context.Background(), "demo", authkit.PasswordCredentialSeed{
		UserEmail: "user@example.com", DisplayName: "Demo User", PasswordHash: passwordHash,
	}); err != nil {
		t.Fatal(err)
	}
	store := &revocationStore{Store: NewMemoryStore()}
	if storage == "sqlite" {
		store.Store, err = NewDatabaseStore(context.Background(), databaseURL)
		if err != nil {
			t.Fatal(err)
		}
	}
	oauthRegistry, err := NewRegistry(tenantConfig)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(config.OAuthServer())
	if err != nil {
		t.Fatal(err)
	}
	users := web.NewInMemoryUsers()
	refresh := &applicationRevocationStore{RefreshTokenStore: authkit.NewMemoryRefreshTokenStore()}
	if storage == "sqlite" {
		refresh.RefreshTokenStore, err = authkit.NewDatabaseRefreshTokenStore(context.Background(), databaseURL)
		if err != nil {
			t.Fatal(err)
		}
	}
	nonces := authkit.NewMemoryNonceStore(time.Minute)
	sessions := authkit.NewOAuthBrowserSessions(registry, users, refresh, nonces, accounts)
	server, err := NewServer(config.OAuthServer(), oauthRegistry, store, signer, fixtureMetadataResolver{}, sessions)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	if err := server.Mount(router); err != nil {
		t.Fatal(err)
	}
	authkit.MountAuthRoutesWithPassword(router, registry, users, refresh, nonces, accounts, nil, store)
	httpServer := &http.Server{Handler: router, ReadHeaderTimeout: time.Second}
	go func() { _ = httpServer.Serve(listener) }()
	t.Cleanup(func() { _ = httpServer.Shutdown(context.Background()) })
	return accountOAuthFixture{issuer: issuer, store: store, accounts: accounts, refresh: refresh, databaseURL: databaseURL}
}

func (fixture accountOAuthFixture) browser(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response := doRequest(t, client, http.MethodGet, fixture.authorizeURL(), nil)
	assertStatus(t, response, http.StatusSeeOther)
	requestToken := queryValue(t, response.Header.Get("Location"), "request")
	readBody(t, response)
	form := url.Values{"request": {requestToken}, "provider": {"password"}, "email": {"user@example.com"}, "password": {testOAuthPassword}}
	response = doRequest(t, client, http.MethodPost, fixture.issuer+"/oauth/login", strings.NewReader(form.Encode()))
	assertStatus(t, response, http.StatusSeeOther)
	readBody(t, response)
	return client
}

func (fixture accountOAuthFixture) authorizeURL() string {
	return authorizationURL(fixture.issuer, pkceChallenge(strings.Repeat("a", 43)), "disable-state", testOAuthRedirect, testOAuthResource, testOAuthScope, testOAuthClient)
}

func (fixture accountOAuthFixture) code(t *testing.T, client *http.Client) string {
	t.Helper()
	response := doRequest(t, client, http.MethodGet, fixture.authorizeURL(), nil)
	assertStatus(t, response, http.StatusSeeOther)
	location := response.Header.Get("Location")
	readBody(t, response)
	if strings.HasPrefix(location, fixture.issuer+"/oauth/consent?") {
		form := url.Values{"request": {queryValue(t, location, "request")}, "decision": {"approve"}}
		response = doRequest(t, client, http.MethodPost, fixture.issuer+"/oauth/consent", strings.NewReader(form.Encode()))
		assertStatus(t, response, http.StatusSeeOther)
		location = response.Header.Get("Location")
		readBody(t, response)
	}
	code := queryValue(t, location, "code")
	if code == "" {
		t.Fatalf("authorization did not return a code")
	}
	return code
}

func TestDisabledAccountOAuthHTTP(t *testing.T) {
	for _, storage := range []string{"memory", "sqlite"} {
		for _, operation := range []string{"authorize", "consent", "code", "refresh", "direct_code", "direct_refresh", "reactivate"} {
			t.Run(storage+"/"+operation, func(t *testing.T) {
				fixture := newAccountOAuthFixture(t, storage)
				first := fixture.browser(t)
				second := fixture.browser(t)
				pending := doRequest(t, second, http.MethodGet, fixture.authorizeURL(), nil)
				pendingToken := queryValue(t, pending.Header.Get("Location"), "request")
				readBody(t, pending)
				code := fixture.code(t, first)
				tokens := decodeTokenResponse(t, doRequest(t, first, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(codeTokenForm(code, strings.Repeat("a", 43)).Encode())))
				outstandingCode := fixture.code(t, second)
				profile, err := fixture.accounts.EnsurePasswordAccount(context.Background(), "demo", "user@example.com")
				if err != nil {
					t.Fatal(err)
				}
				if strings.HasPrefix(operation, "direct_") {
					if _, err := fixture.accounts.BeginAccountDisable(context.Background(), "demo", profile.AccountID); err != nil {
						t.Fatal(err)
					}
				} else {
					disabled := doRequest(t, first, http.MethodPost, fixture.issuer+"/auth/account/disable", nil)
					assertStatus(t, disabled, http.StatusNoContent)
					readBody(t, disabled)
				}
				switch operation {
				case "authorize", "consent":
					var response *http.Response
					if operation == "authorize" {
						response = doRequest(t, second, http.MethodGet, fixture.authorizeURL(), nil)
					} else {
						form := url.Values{"request": {pendingToken}, "decision": {"approve"}}
						response = doRequest(t, second, http.MethodPost, fixture.issuer+"/oauth/consent", strings.NewReader(form.Encode()))
					}
					assertStatus(t, response, http.StatusSeeOther)
					if !strings.HasPrefix(response.Header.Get("Location"), fixture.issuer+"/oauth/login?") {
						t.Fatal("disabled browser session still authorizes OAuth access")
					}
					readBody(t, response)
				case "code", "direct_code":
					assertOAuthError(t, doRequest(t, second, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(codeTokenForm(outstandingCode, strings.Repeat("a", 43)).Encode())), "invalid_grant")
				case "refresh", "direct_refresh":
					form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}, "client_id": {testOAuthClient}, "resource": {testOAuthResource}}
					assertOAuthError(t, doRequest(t, second, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(form.Encode())), "invalid_grant")
				case "reactivate":
					if _, err := fixture.accounts.ReactivateAccount(context.Background(), "demo", profile.AccountID); err != nil {
						t.Fatal(err)
					}
					key := ConsentKey{TenantID: "demo", UserID: profile.AccountID, ClientID: testOAuthClient, Resource: testOAuthResource, Scope: testOAuthScope}
					if _, exists, err := fixture.store.FindConsent(context.Background(), key, time.Now().Unix()); err != nil || exists {
						t.Fatalf("disabled account retained consent: exists=%v error=%v", exists, err)
					}
					assertOAuthError(t, doRequest(t, second, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(codeTokenForm(outstandingCode, strings.Repeat("a", 43)).Encode())), "invalid_grant")
					form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}, "client_id": {testOAuthClient}, "resource": {testOAuthResource}}
					assertOAuthError(t, doRequest(t, second, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(form.Encode())), "invalid_grant")
				}
			})
		}
	}
}

func TestAccountOAuthStoreFailuresHTTP(t *testing.T) {
	for _, operation := range []string{"authorize", "login", "consent", "code", "refresh", "disable"} {
		t.Run(operation, func(t *testing.T) {
			fixture := newAccountOAuthFixture(t, "memory")
			client := fixture.browser(t)
			pending := doRequest(t, client, http.MethodGet, fixture.authorizeURL(), nil)
			pendingToken := queryValue(t, pending.Header.Get("Location"), "request")
			readBody(t, pending)
			code := fixture.code(t, client)
			var tokens tokenResponsePayload
			if operation == "refresh" || operation == "disable" {
				tokens = decodeTokenResponse(t, doRequest(t, client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(codeTokenForm(code, strings.Repeat("a", 43)).Encode())))
			}
			fixture.accounts.lookupErr = errors.New("fixture.account_store_unavailable")
			if operation == "authorize" || operation == "login" || operation == "consent" {
				address := fixture.authorizeURL()
				if operation != "authorize" {
					address = fixture.issuer + "/oauth/" + operation + "?request=" + url.QueryEscape(pendingToken)
				}
				response := doRequest(t, client, http.MethodGet, address, nil)
				if response.StatusCode != http.StatusInternalServerError {
					t.Fatalf("account lookup failure returned %d instead of 500", response.StatusCode)
				}
				if body := strings.TrimSpace(readBody(t, response)); body != `{"error":"server_error"}` {
					t.Fatal("unsafe OAuth store failure response")
				}
				return
			}
			if operation == "disable" {
				fixture.accounts.lookupErr = nil
				fixture.store.revokeErr = errors.New("fixture.oauth_store_unavailable")
				response := doRequest(t, client, http.MethodPost, fixture.issuer+"/auth/account/disable", nil)
				assertStatus(t, response, http.StatusInternalServerError)
				readBody(t, response)
				fixture.store.revokeErr = nil
				form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}, "client_id": {testOAuthClient}, "resource": {testOAuthResource}}
				assertOAuthError(t, doRequest(t, client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(form.Encode())), "invalid_grant")
				return
			}
			form := codeTokenForm(code, strings.Repeat("a", 43))
			if operation == "refresh" {
				form = url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}, "client_id": {testOAuthClient}, "resource": {testOAuthResource}}
			}
			response := doRequest(t, client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(form.Encode()))
			assertStatus(t, response, http.StatusInternalServerError)
			if body := strings.TrimSpace(readBody(t, response)); body != `{"error":"server_error"}` {
				t.Fatal("unsafe OAuth store failure response")
			}
		})
	}
}

func TestOAuthExchangeRetryAfterAccountLookupFailure(t *testing.T) {
	for _, storage := range []string{"memory", "sqlite"} {
		for _, operation := range []string{"code", "refresh"} {
			t.Run(storage+"/"+operation, func(t *testing.T) {
				fixture := newAccountOAuthFixture(t, storage)
				client := fixture.browser(t)
				form := codeTokenForm(fixture.code(t, client), strings.Repeat("a", 43))
				if operation == "refresh" {
					tokens := decodeTokenResponse(t, doRequest(t, client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(form.Encode())))
					form = url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}, "client_id": {testOAuthClient}, "resource": {testOAuthResource}}
				}
				fixture.accounts.lookupErr = errors.New("fixture.account_store_unavailable")
				response := doRequest(t, client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(form.Encode()))
				assertStatus(t, response, http.StatusInternalServerError)
				readBody(t, response)
				fixture.accounts.lookupErr = nil
				response = doRequest(t, client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(form.Encode()))
				if response.StatusCode != http.StatusOK {
					t.Fatalf("credential retry after recovery returned %d", response.StatusCode)
				}
				tokens := decodeTokenResponse(t, response)
				form = url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}, "client_id": {testOAuthClient}, "resource": {testOAuthResource}}
				response = doRequest(t, client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(form.Encode()))
				assertStatus(t, response, http.StatusOK)
				readBody(t, response)
			})
		}
	}
}

func TestAccountDisablementRecoveryHTTP(t *testing.T) {
	for _, storage := range []string{"memory", "sqlite"} {
		for _, failure := range []string{"oauth", "application", "completion"} {
			for _, recovery := range []string{"retry", "reactivation", "resume"} {
				t.Run(storage+"/"+failure+"/"+recovery, func(t *testing.T) {
					fixture := newAccountOAuthFixture(t, storage)
					client := fixture.browser(t)
					second := fixture.browser(t)
					profile, err := fixture.accounts.EnsurePasswordAccount(context.Background(), "demo", "user@example.com")
					if err != nil {
						t.Fatal(err)
					}
					code := fixture.code(t, client)
					tokens := decodeTokenResponse(t, doRequest(t, client, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(codeTokenForm(code, strings.Repeat("a", 43)).Encode())))
					applicationURL, err := url.Parse(fixture.issuer + "/auth/refresh")
					if err != nil {
						t.Fatal(err)
					}
					var applicationRefresh string
					for _, cookie := range second.Jar.Cookies(applicationURL) {
						if cookie.Name == "app_refresh_demo" {
							applicationRefresh = cookie.Value
						}
					}
					if applicationRefresh == "" {
						t.Fatal("missing application refresh cookie")
					}
					switch failure {
					case "oauth":
						fixture.store.revokeErr = errors.New("fixture.oauth_store_unavailable")
					case "application":
						fixture.refresh.revokeErr = errors.New("fixture.refresh_store_unavailable")
					case "completion":
						fixture.accounts.completeErr = errors.New("fixture.account_store_unavailable")
					}
					response := doRequest(t, client, http.MethodPost, fixture.issuer+"/auth/account/disable", nil)
					assertStatus(t, response, http.StatusInternalServerError)
					readBody(t, response)
					if recovery == "reactivation" {
						if _, err := fixture.accounts.ReactivateAccount(context.Background(), "demo", profile.AccountID); !errors.Is(err, authkit.ErrAccountNotActive) {
							t.Fatalf("incomplete disablement accepted reactivation: %v", err)
						}
						return
					}
					if recovery == "resume" {
						if err := authkit.ResumeAccountDisablements(context.Background(), fixture.accounts, fixture.refresh, fixture.store, time.Now().UTC().Unix()); err == nil {
							t.Fatal("resume ignored a store failure")
						}
					}
					fixture.store.revokeErr = nil
					fixture.refresh.revokeErr = nil
					fixture.accounts.completeErr = nil
					if recovery == "resume" {
						if storage == "sqlite" {
							reopened, err := authkit.NewDatabaseUserStore(context.Background(), fixture.databaseURL)
							if err != nil {
								t.Fatal(err)
							}
							fixture.accounts.accountCredentialStore = reopened
						}
						if err := authkit.ResumeAccountDisablements(context.Background(), fixture.accounts, fixture.refresh, fixture.store, time.Now().UTC().Unix()); err != nil {
							t.Fatal(err)
						}
					} else {
						response = doRequest(t, client, http.MethodPost, fixture.issuer+"/auth/account/disable", nil)
						if response.StatusCode != http.StatusNoContent {
							t.Fatalf("disable retry returned %d", response.StatusCode)
						}
						readBody(t, response)
					}
					if _, err := fixture.accounts.ReactivateAccount(context.Background(), "demo", profile.AccountID); err != nil {
						t.Fatal(err)
					}
					form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}, "client_id": {testOAuthClient}, "resource": {testOAuthResource}}
					assertOAuthError(t, doRequest(t, second, http.MethodPost, fixture.issuer+"/oauth/token", strings.NewReader(form.Encode())), "invalid_grant")
					if _, _, _, err := fixture.refresh.Validate(context.Background(), "demo", applicationRefresh); err == nil {
						t.Fatal("application refresh survived disable retry")
					}
				})
			}
		}
	}
}

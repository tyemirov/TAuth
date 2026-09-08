package authkit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/tyemirov/tauth/internal/testsupport"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/tenants"
	"github.com/tyemirov/tauth/internal/web"
)

func TestGitHubHTTPStart(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tenantConfig, err := tenants.LoadConfigFromDocument(tenants.FileDocument{Tenants: []tenants.FileTenant{{
		ID: "github", DisplayName: "GitHub", TenantOrigins: []string{"https://app.example.com"},
		GitHubOAuth:   tenants.FileGitHubOAuth{Enabled: true, ClientID: "github-client", ClientSecret: "test-secret", RedirectURI: "https://auth.example.com/auth/github/callback"},
		JWTSigningKey: "test-signing-key", SessionCookieName: "github_session", RefreshCookieName: "github_refresh", SessionTTL: "30m", RefreshTTL: "720h",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := BuildTenantRegistry(ServerConfig{AppJWTIssuer: "tauth"}, tenantConfig, NewSameSiteResolver(true))
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	users := web.NewInMemoryUsers()
	refresh := NewMemoryRefreshTokenStore()
	nonces := NewMemoryNonceStore(time.Minute)
	MountAuthRoutes(router, registry, users, refresh, nonces)
	login, err := NewGitHubLogin(NewOAuthBrowserSessions(registry, users, refresh, nonces, NewMemoryPasswordCredentialStore()), NewMemoryGitHubTransactionStore(), NewGitHubProvider(http.DefaultTransport), nil)
	if err != nil {
		t.Fatal(err)
	}
	login.Mount(router)
	server := httptest.NewTLSServer(router)
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Get(server.URL + "/auth/github/start?tenant_id=github&return_to=" + url.QueryEscape("https://app.example.com/done"))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound {
		t.Fatalf("GitHub start: want 302, got %d", response.StatusCode)
	}
	location, err := response.Location()
	if err != nil {
		t.Fatal(err)
	}
	query := location.Query()
	if location.Host != "github.com" || query.Get("scope") != tenants.GitHubIdentityScope || query.Get("code_challenge_method") != "S256" || len(query.Get("code_challenge")) != 43 || query.Get("state") == "" || query.Get("code_verifier") != "" {
		t.Fatal("invalid GitHub authorization contract")
	}
	if len(response.Cookies()) != 1 || !response.Cookies()[0].HttpOnly || !response.Cookies()[0].Secure {
		t.Fatal("missing secure browser binding")
	}
}

type githubHTTPFixture struct {
	server      *httptest.Server
	client      *http.Client
	provider    *testsupport.GitHub
	login       *GitHubLogin
	users       UserStore
	accounts    AccountManagementStore
	databaseURL string
}

func newGitHubHTTPFixture(t *testing.T, database bool, accountManaged bool) *githubHTTPFixture {
	t.Helper()
	provider := testsupport.NewGitHub()
	t.Cleanup(provider.Server.Close)
	router := gin.New()
	server := httptest.NewUnstartedServer(router)
	issuer := "https://" + server.Listener.Addr().String()
	rawTenant := tenants.FileTenant{
		ID: "github", DisplayName: "GitHub", TenantOrigins: []string{"https://app.example.com", issuer},
		GitHubOAuth:   tenants.FileGitHubOAuth{Enabled: true, ClientID: "github-client", ClientSecret: "test-secret", RedirectURI: issuer + tenants.GitHubCallbackPath},
		JWTSigningKey: "test-signing-key", SessionCookieName: "github_session", RefreshCookieName: "github_refresh", SessionTTL: "30m", RefreshTTL: "720h",
	}
	if accountManaged {
		rawTenant.AccountManagement = tenants.FileAccountManagement{Enabled: true, ReturnChallengeTokens: true}
	}
	config, err := tenants.LoadConfigFromDocument(tenants.FileDocument{Tenants: []tenants.FileTenant{rawTenant}})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := BuildTenantRegistry(ServerConfig{AppJWTIssuer: "tauth"}, config, NewSameSiteResolver(true))
	if err != nil {
		t.Fatal(err)
	}
	var users UserStore = web.NewInMemoryUsers()
	var passwords PasswordCredentialStore = NewMemoryPasswordCredentialStore()
	var refresh RefreshTokenStore = NewMemoryRefreshTokenStore()
	transactions := NewMemoryGitHubTransactionStore()
	databaseURL := ""
	if database {
		databaseURL = "sqlite://" + filepath.Join(t.TempDir(), "github.sqlite")
		persistentUsers, err := NewDatabaseUserStore(context.Background(), databaseURL)
		if err != nil {
			t.Fatal(err)
		}
		users, passwords = persistentUsers, persistentUsers
		refresh, err = NewDatabaseRefreshTokenStore(context.Background(), databaseURL)
		if err != nil {
			t.Fatal(err)
		}
		transactions, err = NewDatabaseGitHubTransactionStore(context.Background(), databaseURL)
		if err != nil {
			t.Fatal(err)
		}
	}
	nonces := NewMemoryNonceStore(time.Minute)
	sessions := NewOAuthBrowserSessions(registry, users, refresh, nonces, passwords)
	login, err := NewGitHubLogin(sessions, transactions, NewGitHubProvider(provider), nil)
	if err != nil {
		t.Fatal(err)
	}
	login.Mount(router)
	MountAuthRoutesWithPassword(router, registry, users, refresh, nonces, passwords, nil, nil)
	server.StartTLS()
	t.Cleanup(server.Close)
	client := server.Client()
	client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &githubHTTPFixture{server, client, provider, login, users, passwords.(AccountManagementStore), databaseURL}
}

func (fixture *githubHTTPFixture) callbackURL(t *testing.T, parameters string) string {
	t.Helper()
	response, err := fixture.client.Get(fixture.server.URL + tenants.GitHubStartPath + "?tenant_id=github&return_to=" + url.QueryEscape("https://app.example.com/done") + parameters)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusFound {
		t.Fatalf("start status=%d", response.StatusCode)
	}
	authorize, err := response.Location()
	if err != nil {
		t.Fatal(err)
	}
	providerClient := *fixture.provider.Server.Client()
	providerClient.CheckRedirect = fixture.client.CheckRedirect
	response, err = providerClient.Get(fixture.provider.Server.URL + authorize.RequestURI())
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	callback, err := response.Location()
	if err != nil {
		t.Fatal(err)
	}
	return callback.String()
}

func githubHTTPResponse(t *testing.T, client *http.Client, address string) (int, string) {
	t.Helper()
	response, err := client.Get(address)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, string(body)
}

func (fixture *githubHTTPFixture) profile(t *testing.T) map[string]any {
	t.Helper()
	status, body := githubHTTPResponse(t, fixture.client, fixture.server.URL+"/auth/session")
	if status != http.StatusOK {
		t.Fatalf("session status=%d", status)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["user_id"] == nil {
		t.Fatalf("session missing: %s", body)
	}
	return payload
}

func TestGitHubHTTPPrivateEmailAndStableAccount(t *testing.T) {
	for _, database := range []bool{false, true} {
		for _, managed := range []bool{false, true} {
			t.Run(fmt.Sprintf("database=%v/managed=%v", database, managed), func(t *testing.T) {
				fixture := newGitHubHTTPFixture(t, database, managed)
				callback := fixture.callbackURL(t, "")
				if status, _ := githubHTTPResponse(t, fixture.client, callback); status != http.StatusSeeOther {
					t.Fatalf("callback status=%d", status)
				}
				profile := fixture.profile(t)
				if profile["user_email"] != "private@example.com" {
					t.Fatalf("private verified email not used: %v", profile)
				}
				subject := profile["user_id"].(string)
				if managed {
					if validateOpaqueAccountID(subject) != nil {
						t.Fatal("noncanonical account subject")
					}
				} else if subject != "github:9007199254740993" {
					t.Fatalf("GitHub ID lost precision: %s", subject)
				}
				fixture.provider.UserJSON = `{"id":9007199254740993,"login":"new-login","name":"New Name"}`
				fixture.provider.EmailsJSON = `[{"email":"changed@example.com","primary":true,"verified":true}]`
				if status, _ := githubHTTPResponse(t, fixture.client, fixture.callbackURL(t, "")); status != http.StatusSeeOther {
					t.Fatalf("repeat callback status=%d", status)
				}
				updated := fixture.profile(t)
				if updated["user_id"] != subject || updated["user_email"] != "changed@example.com" || updated["display"] != "New Name" {
					t.Fatalf("profile identity changed or became stale: %v", updated)
				}
				if status, _ := githubHTTPResponse(t, fixture.client, callback); status != http.StatusBadRequest {
					t.Fatalf("replay status=%d", status)
				}
			})
		}
	}
}

func TestGitHubHTTPFailureBoundaries(t *testing.T) {
	cases := []struct {
		name   string
		change func(*githubHTTPFixture)
		code   string
	}{
		{"no email", func(f *githubHTTPFixture) { f.provider.EmailsJSON = `[]` }, "github_verified_email_required"},
		{"unverified", func(f *githubHTTPFixture) {
			f.provider.EmailsJSON = `[{"email":"private@example.com","primary":true,"verified":false}]`
		}, "github_verified_email_required"},
		{"duplicate primary", func(f *githubHTTPFixture) {
			f.provider.EmailsJSON = `[{"email":"a@example.com","primary":true,"verified":true},{"email":"b@example.com","primary":true,"verified":true}]`
		}, "github_verified_email_required"},
		{"invalid id", func(f *githubHTTPFixture) { f.provider.UserJSON = `{"id":0,"login":"name"}` }, "github_provider_rejected"},
		{"duplicate id", func(f *githubHTTPFixture) { f.provider.UserJSON = `{"id":1,"id":2,"login":"name"}` }, "github_provider_rejected"},
		{"duplicate email proof", func(f *githubHTTPFixture) {
			f.provider.EmailsJSON = `[{"email":"private@example.com","primary":true,"verified":false,"verified":true}]`
		}, "github_provider_rejected"},
		{"fractional id", func(f *githubHTTPFixture) { f.provider.UserJSON = `{"id":1.5,"login":"name"}` }, "github_provider_rejected"},
		{"excess scope", func(f *githubHTTPFixture) {
			f.provider.TokenJSON = `{"access_token":"provider-secret-token","token_type":"bearer","scope":"repo,read:user,user:email"}`
		}, "github_provider_rejected"},
		{"insufficient scope", func(f *githubHTTPFixture) {
			f.provider.TokenJSON = `{"access_token":"provider-secret-token","token_type":"bearer","scope":"read:user"}`
		}, "github_provider_rejected"},
		{"ambiguous exchange", func(f *githubHTTPFixture) { f.provider.TokenJSON = `{` }, "github_provider_rejected"},
		{"rate limit", func(f *githubHTTPFixture) { f.provider.TokenStatus = 429 }, "github_provider_rejected"},
		{"large body", func(f *githubHTTPFixture) { f.provider.UserJSON = strings.Repeat("x", githubMaximumResponseBytes+1) }, "github_provider_rejected"},
		{"deny all", func(f *githubHTTPFixture) {
			cfg := f.login.sessions.registry.configs["github"]
			cfg.AllowedUsers = map[string]struct{}{}
			f.login.sessions.registry.configs["github"] = cfg
		}, "user_not_allowed"},
	}
	for _, scenario := range cases {
		t.Run(scenario.name, func(t *testing.T) {
			fixture := newGitHubHTTPFixture(t, false, true)
			scenario.change(fixture)
			callback := fixture.callbackURL(t, "")
			status, body := githubHTTPResponse(t, fixture.client, callback)
			if status < 400 || !strings.Contains(body, scenario.code) {
				t.Fatalf("status=%d body=%s", status, body)
			}
			if strings.Contains(body, "test-secret") || strings.Contains(body, "provider-secret-token") || strings.Contains(body, "provider-code") {
				t.Fatal("provider credential in error")
			}
			if fixture.provider.Calls.Load() != 1 {
				t.Fatal("code exchange repeated")
			}
			_, body = githubHTTPResponse(t, fixture.client, fixture.server.URL+"/auth/session")
			if strings.Contains(body, `"authenticated":true`) {
				t.Fatal("failed login issued a session")
			}
		})
	}
}

func TestGitHubHTTPBrowserBindingAndConcurrentCallback(t *testing.T) {
	for _, database := range []bool{false, true} {
		t.Run(fmt.Sprint(database), func(t *testing.T) {
			fixture := newGitHubHTTPFixture(t, database, true)
			callback := fixture.callbackURL(t, "")
			foreign := *fixture.client
			foreign.Jar = nil
			if status, _ := githubHTTPResponse(t, &foreign, callback); status != 400 {
				t.Fatalf("foreign browser status=%d", status)
			}
			if fixture.provider.Calls.Load() != 0 {
				t.Fatal("foreign browser exchanged code")
			}
			var group sync.WaitGroup
			statuses := make(chan int, 2)
			for range 2 {
				group.Add(1)
				go func() {
					defer group.Done()
					status, _ := githubHTTPResponse(t, fixture.client, callback)
					statuses <- status
				}()
			}
			group.Wait()
			close(statuses)
			success := 0
			for status := range statuses {
				if status == 303 {
					success++
				} else if status != 400 {
					t.Fatalf("concurrent status=%d", status)
				}
			}
			if success != 1 || fixture.provider.Calls.Load() != 1 {
				t.Fatal("callback was not claimed once")
			}
		})
	}
}

func TestGitHubHTTPRestartAndExpiry(t *testing.T) {
	fixture := newGitHubHTTPFixture(t, true, true)
	callback := fixture.callbackURL(t, "")
	store, err := NewDatabaseGitHubTransactionStore(context.Background(), fixture.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	fixture.login.transactions = store
	if status, _ := githubHTTPResponse(t, fixture.client, callback); status != 303 {
		t.Fatalf("restart callback status=%d", status)
	}
	callback = fixture.callbackURL(t, "")
	fixture.login.sessions.clock = &controllableClock{current: time.Now().Add(githubTransactionTTL + time.Second)}
	if status, _ := githubHTTPResponse(t, fixture.client, callback); status != 400 {
		t.Fatalf("expired callback status=%d", status)
	}
	if fixture.provider.Calls.Load() != 1 {
		t.Fatal("expired transaction exchanged code")
	}
}

func TestGitHubHTTPConcurrentFirstLogin(t *testing.T) {
	for _, database := range []bool{false, true} {
		t.Run(fmt.Sprint(database), func(t *testing.T) {
			fixture := newGitHubHTTPFixture(t, database, true)
			first := fixture.callbackURL(t, "")
			second := fixture.callbackURL(t, "")
			var group sync.WaitGroup
			for _, callback := range []string{first, second} {
				group.Add(1)
				go func() {
					defer group.Done()
					status, body := githubHTTPResponse(t, fixture.client, callback)
					if status != 303 {
						t.Errorf("concurrent first login status=%d body=%s", status, body)
					}
				}()
			}
			group.Wait()
			profile := fixture.profile(t)
			if validateOpaqueAccountID(profile["user_id"].(string)) != nil {
				t.Fatal("invalid concurrent account")
			}
		})
	}
}

func TestGitHubHTTPAccountLinkAndDisable(t *testing.T) {
	for _, database := range []bool{false, true} {
		t.Run(fmt.Sprint(database), func(t *testing.T) {
			fixture := newGitHubHTTPFixture(t, database, true)
			if status, _ := githubHTTPResponse(t, fixture.client, fixture.callbackURL(t, "")); status != 303 {
				t.Fatal("initial login failed")
			}
			accountID := fixture.profile(t)["user_id"]
			status := githubAccountRequest(t, fixture, "/auth/account/unlink", `{"provider":"github","provider_id":"9007199254740993"}`)
			if status != 409 {
				t.Fatalf("last identity removal status=%d", status)
			}
			fixture.provider.UserJSON = `{"id":123,"login":"linked-name","name":"Linked User"}`
			if status, body := githubHTTPResponse(t, fixture.client, fixture.callbackURL(t, "&operation=link")); status != 303 {
				t.Fatalf("link status=%d body=%s", status, body)
			}
			if fixture.profile(t)["user_id"] != accountID {
				t.Fatal("link replaced account subject")
			}
			if status := githubAccountRequest(t, fixture, "/auth/account/unlink", `{"provider":"github","provider_id":"123"}`); status != 200 {
				t.Fatalf("unlink status=%d", status)
			}
			other, err := fixture.accounts.UpsertProviderAccount(context.Background(), "github", AccountProviderIdentity{Provider: "github", Subject: "456", UserEmail: "private@example.com"})
			if err != nil {
				t.Fatal(err)
			}
			if other.AccountID == accountID {
				t.Fatal("accounts merged by email")
			}
			fixture.provider.UserJSON = `{"id":456,"login":"other-account"}`
			if status, _ := githubHTTPResponse(t, fixture.client, fixture.callbackURL(t, "&operation=link")); status != 409 {
				t.Fatalf("identity collision status=%d", status)
			}
			pending := fixture.callbackURL(t, "&operation=link")
			if status := githubAccountRequest(t, fixture, "/auth/account/disable", `{}`); status != 204 {
				t.Fatalf("disable status=%d", status)
			}
			calls := fixture.provider.Calls.Load()
			if status, _ := githubHTTPResponse(t, fixture.client, pending); status != 403 {
				t.Fatalf("disabled link status=%d", status)
			}
			if fixture.provider.Calls.Load() != calls {
				t.Fatal("disabled linking exchanged code")
			}
			fixture.provider.UserJSON = `{"id":9007199254740993,"login":"disabled-account"}`
			if status, _ := githubHTTPResponse(t, fixture.client, fixture.callbackURL(t, "")); status != 403 {
				t.Fatalf("disabled login status=%d", status)
			}
		})
	}
}

func githubAccountRequest(t *testing.T, fixture *githubHTTPFixture, path, body string) int {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, fixture.server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", fixture.server.URL)
	request.Header.Set("X-Requested-With", "XMLHttpRequest")
	response, err := fixture.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	return response.StatusCode
}

type githubFailingRefresh struct{ RefreshTokenStore }

func (store githubFailingRefresh) Issue(context.Context, string, string, int64, string) (string, string, error) {
	return "", "", errors.New("test refresh failure")
}

type githubFailingUsers struct{ UserStore }

func (store githubFailingUsers) UpsertAccountUser(context.Context, string, string, string, string, string) (string, []string, error) {
	return "", nil, errors.New("test user failure")
}

func TestGitHubHTTPPersistenceFailures(t *testing.T) {
	for _, scenario := range []string{"profile", "refresh", "transaction"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := newGitHubHTTPFixture(t, true, true)
			callback := fixture.callbackURL(t, "")
			switch scenario {
			case "profile":
				fixture.login.sessions.users = githubFailingUsers{fixture.users}
			case "refresh":
				fixture.login.sessions.refreshTokens = githubFailingRefresh{fixture.login.sessions.refreshTokens}
			case "transaction":
				database := fixture.login.transactions.(*databaseGitHubTransactions)
				connection, err := database.db.DB()
				if err != nil {
					t.Fatal(err)
				}
				if err := connection.Close(); err != nil {
					t.Fatal(err)
				}
			}
			status, body := githubHTTPResponse(t, fixture.client, callback)
			if status != 500 || !strings.Contains(body, "store_failure") {
				t.Fatalf("failure status=%d body=%s", status, body)
			}
			status, _ = githubHTTPResponse(t, fixture.client, fixture.server.URL+"/auth/session")
			if status != 204 {
				t.Fatalf("failure issued session: %d", status)
			}
		})
	}
}

func TestGitHubHTTPCallbackPolicyBeforeExchange(t *testing.T) {
	for _, scenario := range []string{"wrong tenant", "disabled provider", "changed client", "changed origin", "denial", "invalid PKCE"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := newGitHubHTTPFixture(t, false, true)
			callback := fixture.callbackURL(t, "")
			expectedCalls := int64(0)
			switch scenario {
			case "wrong tenant":
				callback += "&tenant_id=foreign"
			case "disabled provider":
				config := fixture.login.sessions.registry.configs["github"]
				config.GitHubOAuth = tenants.GitHubOAuth{}
				fixture.login.sessions.registry.configs["github"] = config
			case "changed client":
				store := fixture.login.transactions.(*memoryGitHubTransactions)
				for key, transaction := range store.transactions {
					transaction.ClientID = "other-client"
					store.transactions[key] = transaction
				}
			case "changed origin":
				config := fixture.login.sessions.registry.configs["github"]
				config.TenantOrigins = []string{"https://new.example.com"}
				fixture.login.sessions.registry.configs["github"] = config
			case "denial":
				parsed, _ := url.Parse(callback)
				query := parsed.Query()
				query.Del("code")
				query.Set("error", "access_denied")
				parsed.RawQuery = query.Encode()
				callback = parsed.String()
			case "invalid PKCE":
				expectedCalls = 1
				store := fixture.login.transactions.(*memoryGitHubTransactions)
				for key, transaction := range store.transactions {
					transaction.Verifier = strings.Repeat("x", 43)
					store.transactions[key] = transaction
				}
			}
			status, _ := githubHTTPResponse(t, fixture.client, callback)
			if status < 400 {
				t.Fatalf("invalid callback accepted: %d", status)
			}
			if fixture.provider.Calls.Load() != expectedCalls {
				t.Fatal("callback validation occurred after exchange")
			}
		})
	}
}

func TestGitHubHTTPReturnDestinations(t *testing.T) {
	fixture := newGitHubHTTPFixture(t, false, false)
	for _, destination := range []string{"https://foreign.example/path", "https://app.example.com.evil/path", "https://app.example.com@evil.example/", "//evil.example/", "javascript:alert(1)", "https://app.example.com:443/", "https://app.example.com\\@evil.example/"} {
		status, _ := githubHTTPResponse(t, fixture.client, fixture.server.URL+tenants.GitHubStartPath+"?tenant_id=github&return_to="+url.QueryEscape(destination))
		if status != 400 {
			t.Fatalf("unapproved destination status=%d", status)
		}
	}
}

func TestGitHubHTTPMemoryCapacity(t *testing.T) {
	fixture := newGitHubHTTPFixture(t, false, false)
	store := fixture.login.transactions.(*memoryGitHubTransactions)
	now := time.Now().Unix()
	for index := 0; index < githubTransactionCapacity; index++ {
		store.transactions[fmt.Sprint(index)] = githubTransaction{ExpiresAtUnix: now + 300}
	}
	status, _ := githubHTTPResponse(t, fixture.client, fixture.server.URL+tenants.GitHubStartPath+"?tenant_id=github&return_to="+url.QueryEscape("https://app.example.com"))
	if status != 503 {
		t.Fatalf("full store status=%d", status)
	}
	for key, transaction := range store.transactions {
		transaction.ExpiresAtUnix = now - 1
		store.transactions[key] = transaction
	}
	status, _ = githubHTTPResponse(t, fixture.client, fixture.server.URL+tenants.GitHubStartPath+"?tenant_id=github&return_to="+url.QueryEscape("https://app.example.com"))
	if status != 302 {
		t.Fatalf("expired records retained capacity: %d", status)
	}
}

func TestGitHubHTTPDeadlineDoesNotResubmitCode(t *testing.T) {
	fixture := newGitHubHTTPFixture(t, false, false)
	callback := fixture.callbackURL(t, "")
	provider := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if _, err := io.Copy(io.Discard, request.Body); err != nil {
			return
		}
		<-request.Context().Done()
	}))
	defer provider.Close()
	fixture.provider.Server.Close()
	fixture.provider.Server = provider
	fixture.login.provider.client.Timeout = 20 * time.Millisecond
	status, body := githubHTTPResponse(t, fixture.client, callback)
	if status != 502 || !strings.Contains(body, "github_provider_rejected") {
		t.Fatalf("deadline status=%d body=%s", status, body)
	}
	if status, _ := githubHTTPResponse(t, fixture.client, callback); status != 400 {
		t.Fatalf("ambiguous callback replay status=%d", status)
	}
}

func TestGitHubCallbackLogsOmitCredentials(t *testing.T) {
	previousMode := gin.Mode()
	gin.SetMode(gin.DebugMode)
	defer gin.SetMode(previousMode)
	var logs bytes.Buffer
	router := gin.New()
	router.Use(gin.RecoveryWithWriter(&logs))
	router.Use(RedactGitHubCallbackQuery())
	router.GET(tenants.GitHubCallbackPath, func(*gin.Context) { panic("test recovery") })
	server := httptest.NewServer(router)
	defer server.Close()
	request, err := http.NewRequest(http.MethodGet, server.URL+tenants.GitHubCallbackPath+"?state=private-state&code=private-code", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(&http.Cookie{Name: "session", Value: "private-cookie"})
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	status := response.StatusCode
	if status != 500 || strings.Contains(logs.String(), "private-state") || strings.Contains(logs.String(), "private-code") || strings.Contains(logs.String(), "private-cookie") {
		t.Fatal("callback credential in recovery log")
	}
}

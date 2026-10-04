package authkit

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type erasureHTTPFixture struct {
	server      *httptest.Server
	client      *http.Client
	accounts    *DatabaseUserStore
	refresh     *DatabaseRefreshTokenStore
	profile     AccountProfile
	config      ServerConfig
	databaseURL string
}

func newErasureHTTPFixture(t *testing.T) *erasureHTTPFixture {
	t.Helper()
	config := newTestServerConfig()
	config.AccountManagementEnabled = true
	config.PasswordAuthEnabled = true
	databaseURL := sqliteDatabaseURL(t)
	accounts, err := NewDatabaseUserStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := NewDatabaseRefreshTokenStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := accounts.CreatePasswordSignup(context.Background(), config.TenantID, AccountPasswordRequest{UserEmail: "parent@example.com", DisplayName: "Parent", Password: "correct horse battery staple"}, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	profile, err := accounts.VerifyEmailChallenge(context.Background(), config.TenantID, challenge.Token)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(config), accounts, refresh, nil, accounts, nil, nil)
	server := httptest.NewTLSServer(router)
	t.Cleanup(server.Close)
	client := server.Client()
	client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Post(server.URL+"/auth/password/login", "application/json", strings.NewReader(`{"email":"parent@example.com","password":"correct horse battery staple"}`))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", response.StatusCode)
	}
	return &erasureHTTPFixture{server, client, accounts, refresh, profile, config, databaseURL}
}

func newErasureStatusKey(t *testing.T) string {
	t.Helper()
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func erasureHTTP(t *testing.T, fixture *erasureHTTPFixture, method, path, key string) (int, map[string]any) {
	t.Helper()
	body := ""
	if method == http.MethodDelete {
		body = `{"status_key":"` + key + `"}`
	}
	request, err := http.NewRequest(method, fixture.server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if method == http.MethodGet {
		request.Header.Set("Authorization", "Bearer "+key)
	}
	response, err := fixture.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	bytes, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{}
	if len(bytes) > 0 && json.Valid(bytes) {
		if err := json.Unmarshal(bytes, &payload); err != nil {
			t.Fatal(err)
		}
	}
	if response.StatusCode < 300 && response.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("erasure response must use no-store")
	}
	return response.StatusCode, payload
}

func TestAccountErasureHTTPCompletedReceiptAndActualPurge(t *testing.T) {
	fixture := newErasureHTTPFixture(t)
	statusKey := newErasureStatusKey(t)
	status, operation := erasureHTTP(t, fixture, http.MethodDelete, "/auth/account", statusKey)
	if status != http.StatusAccepted {
		t.Fatalf("DELETE: %d %+v", status, operation)
	}
	status, receipt := erasureHTTP(t, fixture, http.MethodGet, "/auth/account-erasure", statusKey)
	if status != http.StatusOK || receipt["state"] != "completed" || receipt["operation_id"] != operation["operation_id"] {
		t.Fatalf("status: %d %+v", status, receipt)
	}
	if _, err := fixture.accounts.ResolveAccountProfile(context.Background(), fixture.config.TenantID, fixture.profile.AccountID); err != ErrAccountNotFound {
		t.Fatalf("account not erased: %v", err)
	}
	for _, table := range []string{"accounts", "user_profiles", "password_credentials", "account_identities", "account_challenges", "github_credentials", "refresh_tokens"} {
		var count int64
		if err := fixture.accounts.db.Table(table).Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Errorf("erasure retained %d %s rows", count, table)
		}
	}
	status, retry := erasureHTTP(t, fixture, http.MethodDelete, "/auth/account", statusKey)
	if status != http.StatusAccepted || retry["operation_id"] != operation["operation_id"] {
		t.Fatalf("lost-response retry: %d %+v", status, retry)
	}
	if status, _ := erasureHTTP(t, fixture, http.MethodGet, "/auth/account-erasure", newErasureStatusKey(t)); status != http.StatusNotFound {
		t.Fatalf("unknown status key: %d", status)
	}
}

func TestAccountErasureHTTPBlockedProviderAndWrites(t *testing.T) {
	fixture := newErasureHTTPFixture(t)
	identity := AccountProviderIdentity{Provider: "apple", Subject: "apple-parent", UserEmail: "parent@example.com", DisplayName: "Parent"}
	if _, err := fixture.accounts.LinkProviderIdentity(context.Background(), fixture.config.TenantID, fixture.profile.AccountID, identity); err != nil {
		t.Fatal(err)
	}
	key := newErasureStatusKey(t)
	status, operation := erasureHTTP(t, fixture, http.MethodDelete, "/auth/account", key)
	if status != http.StatusAccepted || operation["state"] != "blocked" || operation["reason"] != "provider_revocation_unavailable" {
		t.Fatalf("provider block: %d %+v", status, operation)
	}
	if status, retry := erasureHTTP(t, fixture, http.MethodDelete, "/auth/account", key); status != http.StatusAccepted || retry["operation_id"] != operation["operation_id"] {
		t.Fatalf("operation replaced: %d %+v", status, retry)
	}
	if status, _ := erasureHTTP(t, fixture, http.MethodDelete, "/auth/account", newErasureStatusKey(t)); status != http.StatusConflict {
		t.Fatalf("capability rotation accepted: %d", status)
	}
	if status, _ := patchAccountProfile(t, &githubHTTPFixture{server: fixture.server, client: fixture.client}, `{"display_name":"Forbidden"}`); status != http.StatusForbidden {
		t.Fatalf("erasing profile write: %d", status)
	}
	if _, err := fixture.accounts.ReactivateAccount(context.Background(), fixture.config.TenantID, fixture.profile.AccountID); err == nil {
		t.Fatal("erasing account reactivated")
	}
	if _, err := fixture.accounts.UpsertProviderAccount(context.Background(), fixture.config.TenantID, identity); err == nil {
		t.Fatal("erasing identity recreated")
	}
	hash, err := HashPassword("replacement correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.accounts.UpsertPasswordCredential(context.Background(), fixture.config.TenantID, PasswordCredentialSeed{UserEmail: "parent@example.com", PasswordHash: hash}); err == nil {
		t.Fatal("config seed detached erasing credential")
	}
	if _, _, err := fixture.accounts.UpsertAccountUser(context.Background(), fixture.config.TenantID, fixture.profile.AccountID, "parent@example.com", "Late Login", ""); err == nil {
		t.Fatal("late profile write accepted")
	}
	if _, _, err := fixture.refresh.Issue(context.Background(), fixture.config.TenantID, fixture.profile.AccountID, time.Now().Add(time.Hour).Unix(), ""); err == nil {
		t.Fatal("late refresh issuance accepted")
	}
	profile, err := fixture.accounts.ResolveAccountProfile(context.Background(), fixture.config.TenantID, fixture.profile.AccountID)
	if err != nil || profile.State != "erasing" {
		t.Fatalf("blocked provider account lost: %+v %v", profile, err)
	}
	var job databaseAccountErasure
	if err := fixture.accounts.db.Take(&job).Error; err != nil {
		t.Fatal(err)
	}
	if job.StatusHash == key || job.AccountID == nil || job.ExpiresUnix != 0 {
		t.Fatalf("unsafe pending receipt: %+v", job)
	}
}

func TestAccountErasureHTTPConfiguredCredentialConflict(t *testing.T) {
	fixture := newErasureHTTPFixture(t)
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.accounts.UpsertPasswordCredential(context.Background(), fixture.config.TenantID, PasswordCredentialSeed{UserEmail: "parent@example.com", PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	status, body := erasureHTTP(t, fixture, http.MethodDelete, "/auth/account", newErasureStatusKey(t))
	if status != http.StatusConflict || body["error"] != "configured_credential" {
		t.Fatalf("configured credential: %d %+v", status, body)
	}
	profile, err := fixture.accounts.ResolveAccountProfile(context.Background(), fixture.config.TenantID, fixture.profile.AccountID)
	if err != nil || profile.State != "active" {
		t.Fatalf("unsupported erasure disabled account: %+v %v", profile, err)
	}
	var count int64
	if err := fixture.accounts.db.Model(&databaseAccountErasure{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("unsupported erasure created job: %d %v", count, err)
	}
}

func TestAccountErasureHTTPConcurrentLostResponseAndExpiry(t *testing.T) {
	fixture := newErasureHTTPFixture(t)
	key := newErasureStatusKey(t)
	var wait sync.WaitGroup
	operationIDs := make(chan any, 12)
	for attempt := 0; attempt < 12; attempt++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			status, body := erasureHTTP(t, fixture, http.MethodDelete, "/auth/account", key)
			if status != http.StatusAccepted {
				t.Errorf("concurrent retry: %d %+v", status, body)
			}
			operationIDs <- body["operation_id"]
		}()
	}
	wait.Wait()
	close(operationIDs)
	var operationID any
	for id := range operationIDs {
		if operationID == nil {
			operationID = id
		}
		if id != operationID {
			t.Errorf("duplicate job IDs: %v %v", operationID, id)
		}
	}
	status, body := erasureHTTP(t, fixture, http.MethodGet, "/auth/account-erasure", key)
	if status != http.StatusOK || body["operation_id"] != operationID || body["state"] != "completed" {
		t.Fatalf("lost initial response status: %d %+v", status, body)
	}
	var job databaseAccountErasure
	if err := fixture.accounts.db.Take(&job).Error; err != nil {
		t.Fatal(err)
	}
	if job.AccountID != nil || job.Phase != "" || job.LeaseToken != "" || job.StatusHash == key {
		t.Fatalf("completion retained identifiers: %+v", job)
	}
	fixture.accounts.now = func() time.Time { return time.Unix(job.ExpiresUnix+1, 0) }
	if status, _ := erasureHTTP(t, fixture, http.MethodGet, "/auth/account-erasure", key); status != http.StatusNotFound {
		t.Fatalf("expired status: %d", status)
	}
	coordinator, err := NewAccountErasureCoordinator(fixture.accounts, fixture.accounts, fixture.refresh, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	var count int64
	if err := fixture.accounts.db.Model(&databaseAccountErasure{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("expired receipt retained: %d %v", count, err)
	}
}

func TestAccountErasureHTTPPurgeFailureAndRestart(t *testing.T) {
	fixture := newErasureHTTPFixture(t)
	if err := fixture.accounts.db.Exec("CREATE TRIGGER fail_refresh_purge BEFORE DELETE ON refresh_tokens BEGIN SELECT RAISE(ABORT, 'fixture refresh purge failure'); END;").Error; err != nil {
		t.Fatal(err)
	}
	key := newErasureStatusKey(t)
	status, body := erasureHTTP(t, fixture, http.MethodDelete, "/auth/account", key)
	if status != http.StatusAccepted || body["state"] != "blocked" || body["reason"] != "refresh_purge_failed" {
		t.Fatalf("split store failure: %d %+v", status, body)
	}
	if err := fixture.accounts.db.Exec("DROP TRIGGER fail_refresh_purge").Error; err != nil {
		t.Fatal(err)
	}
	handle, err := fixture.accounts.db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewDatabaseUserStore(context.Background(), fixture.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	reopened.now = func() time.Time { return time.Now().Add(time.Minute) }
	coordinator, err := NewAccountErasureCoordinator(reopened, reopened, fixture.refresh, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(fixture.config), reopened, fixture.refresh, nil, reopened, nil, nil)
	server := httptest.NewTLSServer(router)
	defer server.Close()
	resumed := &erasureHTTPFixture{server: server, client: server.Client()}
	status, receipt := erasureHTTP(t, resumed, http.MethodGet, "/auth/account-erasure", key)
	if status != http.StatusOK || receipt["state"] != "completed" || receipt["operation_id"] != body["operation_id"] {
		t.Fatalf("restart status: %d %+v", status, receipt)
	}
	if _, err := reopened.ResolveAccountProfile(context.Background(), fixture.config.TenantID, fixture.profile.AccountID); err != ErrAccountNotFound {
		t.Fatalf("restart did not purge: %v", err)
	}
}

func TestAccountErasureHTTPTenantAndOwnerIsolation(t *testing.T) {
	fixture := newErasureHTTPFixture(t)
	ctx := context.Background()
	tenantB := "tenant-b"
	challenge, err := fixture.accounts.CreatePasswordSignup(ctx, tenantB, AccountPasswordRequest{UserEmail: "parent@example.com", DisplayName: "Other Parent", Password: "correct horse battery staple"}, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	other, err := fixture.accounts.VerifyEmailChallenge(ctx, tenantB, challenge.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.accounts.db.Exec("CREATE TABLE owner_accounts (account_id TEXT PRIMARY KEY, user_email TEXT)").Error; err != nil {
		t.Fatal(err)
	}
	if err := fixture.accounts.db.Exec("INSERT INTO owner_accounts VALUES (?, ?)", fixture.profile.AccountID, "parent@example.com").Error; err != nil {
		t.Fatal(err)
	}
	key := newErasureStatusKey(t)
	status, body := erasureHTTP(t, fixture, http.MethodDelete, "/auth/account", key)
	if status != http.StatusAccepted || body["state"] != "completed" {
		t.Fatalf("delete: %d %+v", status, body)
	}
	preserved, err := fixture.accounts.ResolveAccountProfile(ctx, tenantB, other.AccountID)
	if err != nil || preserved.DisplayName != "Other Parent" {
		t.Fatalf("other tenant changed: %+v %v", preserved, err)
	}
	var owners int64
	if err := fixture.accounts.db.Table("owner_accounts").Count(&owners).Error; err != nil || owners != 1 {
		t.Fatalf("owner changed: %d %v", owners, err)
	}
	configB := fixture.config
	configB.TenantID = tenantB
	router := gin.New()
	MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(configB), fixture.accounts, fixture.refresh, nil, fixture.accounts, nil, nil)
	server := httptest.NewTLSServer(router)
	defer server.Close()
	if status, _ := erasureHTTP(t, &erasureHTTPFixture{server: server, client: server.Client()}, http.MethodGet, "/auth/account-erasure", key); status != http.StatusNotFound {
		t.Fatalf("tenant B read capability: %d", status)
	}
}

func TestAccountErasureHTTPInFlightPasswordLogin(t *testing.T) {
	fixture := newErasureHTTPFixture(t)
	if _, err := fixture.accounts.LinkProviderIdentity(context.Background(), fixture.config.TenantID, fixture.profile.AccountID, AccountProviderIdentity{Provider: "apple", Subject: "inflight-parent", UserEmail: "parent@example.com"}); err != nil {
		t.Fatal(err)
	}
	original := fixture.accounts.passwordHashComparer
	entered := make(chan struct{})
	release := make(chan struct{})
	fixture.accounts.passwordHashComparer = func(hash, password []byte) error { close(entered); <-release; return original(hash, password) }
	result := make(chan int, 1)
	go func() {
		response, err := fixture.client.Post(fixture.server.URL+"/auth/password/login", "application/json", strings.NewReader(`{"email":"parent@example.com","password":"correct horse battery staple"}`))
		if err != nil {
			result <- 0
			return
		}
		response.Body.Close()
		result <- response.StatusCode
	}()
	<-entered
	status, body := erasureHTTP(t, fixture, http.MethodDelete, "/auth/account", newErasureStatusKey(t))
	if status != http.StatusAccepted || body["state"] != "blocked" {
		t.Fatalf("delete: %d %+v", status, body)
	}
	close(release)
	if status := <-result; status == http.StatusOK || status == 0 {
		t.Fatalf("in-flight login accepted: %d", status)
	}
	profile, err := fixture.accounts.ResolveAccountProfile(context.Background(), fixture.config.TenantID, fixture.profile.AccountID)
	if err != nil || profile.State != "erasing" {
		t.Fatalf("login recreated identity: %+v %v", profile, err)
	}
}

type fixtureProviderRevoker struct {
	url    string
	client *http.Client
}

func (revoker fixtureProviderRevoker) RevokeAccountProvider(ctx context.Context, tenant, account, provider string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, revoker.url, strings.NewReader(provider))
	if err != nil {
		return err
	}
	response, err := revoker.client.Do(request)
	if err != nil {
		return err
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("fixture revocation status %d", response.StatusCode)
	}
	return nil
}

func TestAccountErasureHTTPFencedProviderCompletion(t *testing.T) {
	fixture := newErasureHTTPFixture(t)
	ctx := context.Background()
	if _, err := fixture.accounts.LinkProviderIdentity(ctx, fixture.config.TenantID, fixture.profile.AccountID, AccountProviderIdentity{Provider: "apple", Subject: "fenced-parent", UserEmail: "parent@example.com"}); err != nil {
		t.Fatal(err)
	}
	key := newErasureStatusKey(t)
	_, body := erasureHTTP(t, fixture, http.MethodDelete, "/auth/account", key)
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int64
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		w.WriteHeader(200)
	}))
	defer provider.Close()
	var clock atomic.Int64
	clock.Store(time.Now().Add(time.Minute).Unix())
	fixture.accounts.now = func() time.Time { return time.Unix(clock.Load(), 0) }
	coordinator, err := NewAccountErasureCoordinator(fixture.accounts, fixture.accounts, fixture.refresh, nil, fixtureProviderRevoker{provider.URL, provider.Client()})
	if err != nil {
		t.Fatal(err)
	}
	first := make(chan error, 1)
	go func() { first <- coordinator.Process(ctx, body["operation_id"].(string)) }()
	<-entered
	clock.Add(int64(erasureLeaseTTL/time.Second) + 1)
	if err := coordinator.Process(ctx, body["operation_id"].(string)); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-first; !errors.Is(err, errErasureLeaseLost) {
		t.Fatalf("stale worker not fenced: %v", err)
	}
	status, receipt := erasureHTTP(t, fixture, http.MethodGet, "/auth/account-erasure", key)
	if status != 200 || receipt["state"] != "completed" || receipt["reason"] != "" {
		t.Fatalf("stale worker changed completion: %d %+v", status, receipt)
	}
}

func TestAccountErasureHTTPValidationAndGitHubBlock(t *testing.T) {
	fixture := newErasureHTTPFixture(t)
	request, _ := http.NewRequest(http.MethodDelete, fixture.server.URL+"/auth/account", strings.NewReader(`{"status_key":"`+newErasureStatusKey(t)+`","email":"other@example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	response, err := fixture.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 400 {
		t.Fatalf("unknown field: %d", response.StatusCode)
	}
	if status, _ := erasureHTTP(t, fixture, http.MethodDelete, "/auth/account", "invalid"); status != 422 {
		t.Fatalf("invalid key: %d", status)
	}
	anonymousClient := *fixture.client
	anonymousClient.Jar = nil
	anonymous := &erasureHTTPFixture{server: fixture.server, client: &anonymousClient}
	if status, _ := erasureHTTP(t, anonymous, http.MethodDelete, "/auth/account", newErasureStatusKey(t)); status != 401 {
		t.Fatalf("unauthenticated initiation: %d", status)
	}
	if err := fixture.accounts.SaveGitHubCredential(context.Background(), fixture.config.TenantID, fixture.profile.AccountID, []byte("synthetic fixture ciphertext")); err != nil {
		t.Fatal(err)
	}
	status, body := erasureHTTP(t, fixture, http.MethodDelete, "/auth/account", newErasureStatusKey(t))
	if status != 202 || body["reason"] != "provider_revocation_unavailable" {
		t.Fatalf("GitHub revocation gap: %d %+v", status, body)
	}
	if _, err := fixture.accounts.LoadGitHubCredential(context.Background(), fixture.config.TenantID, fixture.profile.AccountID); err != nil {
		t.Fatalf("blocked credential removed: %v", err)
	}
	config := fixture.config
	config.AccountManagementEnabled = false
	router := gin.New()
	MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(config), fixture.accounts, fixture.refresh, nil, fixture.accounts, nil, nil)
	server := httptest.NewTLSServer(router)
	defer server.Close()
	disabledClient := server.Client()
	disabledClient.Jar = fixture.client.Jar
	if status, _ := erasureHTTP(t, &erasureHTTPFixture{server: server, client: disabledClient}, http.MethodDelete, "/auth/account", newErasureStatusKey(t)); status != 404 {
		t.Fatalf("disabled policy: %d", status)
	}
}

func TestAccountErasureHTTPAutomaticSchemaSevenMigration(t *testing.T) {
	fixture := newErasureHTTPFixture(t)
	if err := fixture.accounts.db.Migrator().DropTable(&databaseAccountErasure{}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.accounts.db.Model(&schemaMigrationRecord{}).Where(schemaMigrationLookupByName, userStoreErrorPrefix).Update("version", 7).Error; err != nil {
		t.Fatal(err)
	}
	handle, err := fixture.accounts.db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewDatabaseUserStore(context.Background(), fixture.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := reopened.ResolveAccountProfile(context.Background(), fixture.config.TenantID, fixture.profile.AccountID)
	if err != nil || profile.DisplayName != "Parent" {
		t.Fatalf("migration lost account: %+v %v", profile, err)
	}
	var marker schemaMigrationRecord
	if err := reopened.db.Where(schemaMigrationLookupByName, userStoreErrorPrefix).Take(&marker).Error; err != nil || marker.Version != 8 {
		t.Fatalf("migration marker: %+v %v", marker, err)
	}
	router := gin.New()
	MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(fixture.config), reopened, fixture.refresh, nil, reopened, nil, nil)
	server := httptest.NewTLSServer(router)
	defer server.Close()
	client := server.Client()
	client.Jar = fixture.client.Jar
	status, body := erasureHTTP(t, &erasureHTTPFixture{server: server, client: client}, http.MethodDelete, "/auth/account", newErasureStatusKey(t))
	if status != 202 || body["state"] != "completed" {
		t.Fatalf("migrated public erasure: %d %+v", status, body)
	}
}

func TestAccountErasureHTTPResetCreationRace(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(fmt.Sprint("blocked=", blocked), func(t *testing.T) {
			fixture := newErasureHTTPFixture(t)
			if blocked {
				if _, err := fixture.accounts.LinkProviderIdentity(context.Background(), fixture.config.TenantID, fixture.profile.AccountID, AccountProviderIdentity{Provider: "apple", Subject: "reset-block", UserEmail: "parent@example.com"}); err != nil {
					t.Fatal(err)
				}
			}
			entered := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			if err := fixture.accounts.db.Callback().Query().After("gorm:query").Register("fixture:pause_reset_lookup", func(db *gorm.DB) {
				if _, ok := db.Statement.Dest.(*passwordCredentialRecord); ok {
					once.Do(func() { close(entered); <-release })
				}
			}); err != nil {
				t.Fatal(err)
			}
			result := make(chan int, 1)
			go func() {
				response, err := fixture.client.Post(fixture.server.URL+"/auth/password/reset/start", "application/json", strings.NewReader(`{"email":"parent@example.com"}`))
				if err != nil {
					result <- 0
					return
				}
				response.Body.Close()
				result <- response.StatusCode
			}()
			<-entered
			status, body := erasureHTTP(t, fixture, http.MethodDelete, "/auth/account", newErasureStatusKey(t))
			if status != 202 {
				t.Fatalf("delete: %d %+v", status, body)
			}
			close(release)
			if status := <-result; status != 202 {
				t.Fatalf("reset masking response: %d", status)
			}
			var count int64
			if err := fixture.accounts.db.Model(&databaseAccountChallengeRecord{}).Where("tenant_id = ? AND account_id = ? AND challenge_kind = ?", fixture.config.TenantID, fixture.profile.AccountID, accountChallengePasswordReset).Count(&count).Error; err != nil || count != 0 {
				t.Fatalf("reset recreated erased data: %d %v", count, err)
			}
		})
	}
}

type pausedGitHubCreation struct {
	GitHubTransactionStore
	entered chan struct{}
	release chan struct{}
}

func (store pausedGitHubCreation) create(ctx context.Context, transaction githubTransaction) error {
	close(store.entered)
	<-store.release
	return store.GitHubTransactionStore.create(ctx, transaction)
}

func TestAccountErasureHTTPGitHubLinkTransactions(t *testing.T) {
	for _, inflight := range []bool{false, true} {
		t.Run(fmt.Sprint("inflight=", inflight), func(t *testing.T) {
			github := newGitHubHTTPFixture(t, true, true)
			accounts := github.users.(*DatabaseUserStore)
			ctx := context.Background()
			tenant := "github"
			challenge, err := accounts.CreatePasswordSignup(ctx, tenant, AccountPasswordRequest{UserEmail: "parent@example.com", DisplayName: "Parent", Password: "correct horse battery staple"}, time.Now().Add(time.Hour).Unix())
			if err != nil {
				t.Fatal(err)
			}
			profile, err := accounts.VerifyEmailChallenge(ctx, tenant, challenge.Token)
			if err != nil {
				t.Fatal(err)
			}
			config := github.login.sessions.registry.Config(tenant)
			token, _, err := MintAppJWT(fixedClock{timestamp: time.Now()}, tenant, profile.AccountID, profile.UserEmail, profile.DisplayName, profile.AvatarURL, profile.Roles, config.AppJWTIssuer, config.AppJWTSigningKey, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			serverURL, _ := url.Parse(github.server.URL)
			github.client.Jar.SetCookies(serverURL, []*http.Cookie{{Name: config.SessionCookieName, Value: token, Path: "/", Secure: true}})
			transactions := github.login.transactions.(*databaseGitHubTransactions)
			for index, other := range []githubTransaction{{TenantID: tenant, AccountID: "other-account"}, {TenantID: "other-tenant", AccountID: profile.AccountID}} {
				other.StateHash = fmt.Sprint("unrelated-", index)
				other.ExpiresAtUnix = time.Now().Add(time.Hour).Unix()
				if err := transactions.db.Create(&other).Error; err != nil {
					t.Fatal(err)
				}
			}
			startURL := github.server.URL + "/auth/github/start?tenant_id=github&operation=link&return_to=https%3A%2F%2Fapp.example.com%2Fdone"
			entered := make(chan struct{})
			release := make(chan struct{})
			result := make(chan int, 1)
			if inflight {
				github.login.transactions = pausedGitHubCreation{transactions, entered, release}
				go func() {
					response, err := github.client.Get(startURL)
					if err != nil {
						result <- 0
						return
					}
					response.Body.Close()
					result <- response.StatusCode
				}()
				<-entered
			} else {
				response, err := github.client.Get(startURL)
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if response.StatusCode != 302 {
					t.Fatalf("start: %d", response.StatusCode)
				}
			}
			status, body := erasureHTTP(t, &erasureHTTPFixture{server: github.server, client: github.client}, http.MethodDelete, "/auth/account", newErasureStatusKey(t))
			if status != 202 || body["state"] != "completed" {
				t.Fatalf("delete: %d %+v", status, body)
			}
			if inflight {
				close(release)
				if status := <-result; status == 302 || status == 0 {
					t.Fatalf("late link created: %d", status)
				}
			}
			var owned, others int64
			if err := transactions.db.Model(&githubTransaction{}).Where("tenant_id = ? AND account_id = ?", tenant, profile.AccountID).Count(&owned).Error; err != nil || owned != 0 {
				t.Fatalf("account links retained: %d %v", owned, err)
			}
			if err := transactions.db.Model(&githubTransaction{}).Count(&others).Error; err != nil || others != 2 {
				t.Fatalf("unrelated links changed: %d %v", others, err)
			}
		})
	}
}

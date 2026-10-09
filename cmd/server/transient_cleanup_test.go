package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/oauthserver"
)

type cleanupTestStore struct {
	mu      sync.Mutex
	calls   int
	err     error
	entered chan int64
	block   bool
}

type notifyingCleaner struct {
	transientCleaner
	finished chan struct{}
}

func (store notifyingCleaner) CleanupExpired(ctx context.Context, now int64) error {
	err := store.transientCleaner.CleanupExpired(ctx, now)
	store.finished <- struct{}{}
	return err
}

func TestTransientCleanupPersistentLifecycleHTTP(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	url := "sqlite://" + filepath.Join(t.TempDir(), "cleanup.db")
	accounts, err := authkit.NewDatabaseUserStore(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := authkit.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if err := accounts.UpsertPasswordCredential(ctx, "tenant", authkit.PasswordCredentialSeed{UserEmail: "active@example.com", PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	abandoned, err := accounts.CreatePasswordSignup(ctx, "tenant", authkit.AccountPasswordRequest{UserEmail: "abandoned@example.com", Password: "correct horse battery staple"}, now.Add(time.Minute).Unix())
	if err != nil {
		t.Fatal(err)
	}
	nonces, err := authkit.NewDatabaseNonceStore(ctx, url, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nonces.Issue(ctx, "tenant"); err != nil {
		t.Fatal(err)
	}
	refresh, err := authkit.NewDatabaseRefreshTokenStore(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	oauth, err := oauthserver.NewDatabaseStore(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oauth.CreateAuthorizationRequest(ctx, oauthserver.AuthorizationRequest{TenantID: "tenant", CreatedAtUnix: now.Unix(), ExpiresAtUnix: now.Add(time.Minute).Unix()}); err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{}, 2)
	ticks := make(chan time.Time, 1)
	stop, err := startTransientCleanup(ctx, []namedTransientStore{{"accounts", accounts}, {"nonces", nonces}, {"refresh", refresh}, {"oauth", notifyingCleaner{oauth, finished}}}, func() time.Time { return now }, ticks, func(err error) { t.Errorf("periodic cleanup: %v", err) })
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	<-finished
	if _, err := accounts.ResolveAccountProfile(ctx, "tenant", abandoned.AccountID); err != nil {
		t.Fatalf("startup removed live signup: %v", err)
	}
	ticks <- now.Add(2 * time.Minute)
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("persistent sweep did not finish")
	}
	if _, err := accounts.ResolveAccountProfile(ctx, "tenant", abandoned.AccountID); !errors.Is(err, authkit.ErrAccountNotFound) {
		t.Fatalf("expired signup remains: %v", err)
	}
	db, err := authkit.OpenControlDatabase(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"nonce_tokens", "account_challenges", "oauth_authorization_requests"} {
		var count int64
		if err := db.Table(table).Count(&count).Error; err != nil || count != 0 {
			t.Fatalf("%s rows=%d err=%v", table, count, err)
		}
	}
	router := gin.New()
	resetDispatcher, err := authkit.NewPasswordResetDispatcher(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resetDispatcher.Close)
	config := authkit.ServerConfig{TenantID: "tenant", PasswordAuthEnabled: true, AccountManagementEnabled: true, AppJWTSigningKey: []byte("cleanup-test-signing-key-1234567890"), AppJWTIssuer: "cleanup-test", SessionCookieName: "app_session", RefreshCookieName: "app_refresh", SessionTTL: time.Minute, RefreshTTL: time.Hour}
	authkit.MountAuthRoutesWithPassword(router, authkit.NewSingleTenantRegistry(config), accounts, refresh, nonces, accounts, resetDispatcher, nil, nil)
	server := httptest.NewTLSServer(router)
	defer server.Close()
	response, err := server.Client().Post(server.URL+"/auth/password/login", "application/json", strings.NewReader(`{"email":"active@example.com","password":"correct horse battery staple"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || len(response.Cookies()) != 2 {
		t.Fatalf("cleanup broke active login: status=%d cookies=%d", response.StatusCode, len(response.Cookies()))
	}
}

func (store *cleanupTestStore) CleanupExpired(ctx context.Context, now int64) error {
	store.mu.Lock()
	store.calls++
	calls, failure, block := store.calls, store.err, store.block
	store.mu.Unlock()
	if store.entered != nil {
		store.entered <- now
	}
	if block && calls > 1 {
		<-ctx.Done()
		return ctx.Err()
	}
	return failure
}

func TestTransientCleanupInitialFailure(t *testing.T) {
	failure := errors.New("cleanup fixture failure")
	first := &cleanupTestStore{err: failure}
	second := &cleanupTestStore{}
	stop, err := startTransientCleanup(context.Background(), []namedTransientStore{{"first", first}, {"second", second}}, time.Now, make(chan time.Time), func(error) {})
	if stop != nil || !errors.Is(err, failure) || !strings.Contains(err.Error(), "first") || first.calls != 1 || second.calls != 1 {
		t.Fatalf("startup did not report failure after all stores: stop=%v err=%v calls=%d/%d", stop != nil, err, first.calls, second.calls)
	}
}

func TestTransientCleanupPeriodicAndJoinedShutdown(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(map[bool]string{false: "reported_failure", true: "canceled_work"}[blocked], func(t *testing.T) {
			store := &cleanupTestStore{entered: make(chan int64, 2), block: blocked}
			ticks := make(chan time.Time, 1)
			errorsReported := make(chan error, 1)
			now := time.Unix(100, 0)
			stop, err := startTransientCleanup(context.Background(), []namedTransientStore{{"fixture", store}}, func() time.Time { return now }, ticks, func(err error) { errorsReported <- err })
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			if initial := <-store.entered; initial != now.Unix() {
				t.Fatalf("startup time=%d", initial)
			}
			store.mu.Lock()
			store.err = errors.New("periodic fixture failure")
			store.mu.Unlock()
			ticks <- now.Add(time.Minute)
			select {
			case swept := <-store.entered:
				if swept != now.Add(time.Minute).Unix() {
					t.Fatalf("periodic time=%d", swept)
				}
			case <-time.After(time.Second):
				t.Fatal("periodic sweep did not start")
			}
			if !blocked {
				select {
				case err := <-errorsReported:
					if !strings.Contains(err.Error(), "fixture") {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("periodic error was lost")
				}
			}
			joined := make(chan struct{})
			go func() { stop(); close(joined) }()
			select {
			case <-joined:
			case <-time.After(time.Second):
				t.Fatal("cleanup worker did not cancel and join")
			}
			store.mu.Lock()
			calls := store.calls
			store.mu.Unlock()
			if calls != 2 {
				t.Fatalf("cleanup calls=%d", calls)
			}
		})
	}
}

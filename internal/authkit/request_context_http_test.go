package authkit

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

type requestContextKey struct{}

type requestContextReference struct {
	context context.Context
}

type requestContextObservation struct {
	context context.Context
	request context.Context
}

type requestContextAccounts struct {
	*DatabaseUserStore
	mutex        sync.Mutex
	observations []requestContextObservation
	entered      chan struct{}
	cancelled    chan error
}

func (store *requestContextAccounts) observe(ctx context.Context) {
	var expected context.Context
	if reference, ok := ctx.Value(requestContextKey{}).(*requestContextReference); ok {
		expected = reference.context
	}
	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.observations = append(store.observations, requestContextObservation{ctx, expected})
}

func (store *requestContextAccounts) EnsurePasswordAccount(ctx context.Context, tenantID, email string) (AccountProfile, error) {
	store.observe(ctx)
	if store.entered != nil {
		close(store.entered)
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
			store.cancelled <- errors.New("account operation did not receive request cancellation")
			return AccountProfile{}, context.DeadlineExceeded
		}
		_, err := store.DatabaseUserStore.EnsurePasswordAccount(ctx, tenantID, email)
		store.cancelled <- err
		return AccountProfile{}, err
	}
	return store.DatabaseUserStore.EnsurePasswordAccount(ctx, tenantID, email)
}

func (store *requestContextAccounts) ResolveAccountForUser(ctx context.Context, tenantID, userID string) (AccountProfile, error) {
	store.observe(ctx)
	return store.DatabaseUserStore.ResolveAccountForUser(ctx, tenantID, userID)
}

func newRequestContextHTTPFixture(t *testing.T, cancelled bool) (*requestContextAccounts, *httptest.Server, *http.Client, <-chan struct{}) {
	t.Helper()
	config := newTestServerConfig()
	config.PasswordAuthEnabled = true
	config.AccountManagementEnabled = true
	databaseURL := sqliteDatabaseURL(t)
	database, err := NewDatabaseUserStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	rawDatabase, err := database.db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rawDatabase.Close() })
	refresh, err := NewDatabaseRefreshTokenStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	rawRefresh, err := refresh.db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rawRefresh.Close() })
	hash, err := HashPassword(passwordSeedTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertPasswordCredential(context.Background(), config.TenantID, PasswordCredentialSeed{UserEmail: "parent@example.com", DisplayName: "Parent", PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	accounts := &requestContextAccounts{DatabaseUserStore: database}
	if cancelled {
		accounts.entered = make(chan struct{})
		accounts.cancelled = make(chan error, 1)
	}
	completed := make(chan struct{}, 16)
	router := gin.New()
	router.Use(func(contextGin *gin.Context) {
		reference := &requestContextReference{}
		requestContext := context.WithValue(contextGin.Request.Context(), requestContextKey{}, reference)
		reference.context = requestContext
		contextGin.Request = contextGin.Request.WithContext(requestContext)
		contextGin.Next()
		completed <- struct{}{}
	})
	registry := NewSingleTenantRegistry(config)
	MountAuthRoutesWithPassword(router, registry, database, refresh, nil, accounts, newTestPasswordResetDispatcher(t), nil, nil)
	router.GET("/protected", RequireSession(registry), RequireActiveAccountSession(registry, accounts), func(contextGin *gin.Context) {
		contextGin.Status(http.StatusNoContent)
	})
	server := httptest.NewTLSServer(router)
	t.Cleanup(server.Close)
	client := server.Client()
	client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return accounts, server, client, completed
}

func TestRequestContextHTTPAccountOperations(t *testing.T) {
	accounts, server, client, completed := newRequestContextHTTPFixture(t, false)
	for iteration := 0; iteration < 3; iteration++ {
		for _, endpoint := range []struct {
			method string
			path   string
			body   string
			status int
		}{
			{http.MethodPost, "/auth/password/login", `{"email":"parent@example.com","password":"` + passwordSeedTestPassword + `"}`, http.StatusOK},
			{http.MethodGet, "/auth/session", "", http.StatusOK},
			{http.MethodGet, "/protected", "", http.StatusNoContent},
		} {
			request, err := http.NewRequest(endpoint.method, server.URL+endpoint.path, strings.NewReader(endpoint.body))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/json")
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != endpoint.status {
				t.Fatalf("%s: status=%d, want %d", endpoint.path, response.StatusCode, endpoint.status)
			}
			<-completed
		}
	}
	accounts.mutex.Lock()
	observations := append([]requestContextObservation(nil), accounts.observations...)
	accounts.mutex.Unlock()
	if len(observations) != 9 {
		t.Fatalf("account boundary observations=%d, want 9", len(observations))
	}
	for _, observation := range observations {
		if _, unsafe := observation.context.(*gin.Context); unsafe {
			t.Errorf("account boundary retained a pooled Gin context")
			continue
		}
		if observation.request == nil || observation.context != observation.request || observation.context.Done() != observation.request.Done() {
			t.Errorf("account boundary lost the HTTP request context value or cancellation channel")
			continue
		}
		select {
		case <-observation.context.Done():
		case <-time.After(5 * time.Second):
			t.Error("completed HTTP request context was not cancelled")
		}
		if observation.context.Err() != context.Canceled {
			t.Errorf("completed request context error=%v, want context.Canceled", observation.context.Err())
		}
	}
}

func TestRequestContextHTTPCancellation(t *testing.T) {
	accounts, server, client, completed := newRequestContextHTTPFixture(t, true)
	clientContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, err := http.NewRequestWithContext(clientContext, http.MethodPost, server.URL+"/auth/password/login", strings.NewReader(`{"email":"parent@example.com","password":"`+passwordSeedTestPassword+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	clientDone := make(chan error, 1)
	go func() {
		response, requestErr := client.Do(request)
		if response != nil {
			response.Body.Close()
		}
		clientDone <- requestErr
	}()
	select {
	case <-accounts.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("account operation did not start")
	}
	cancel()
	if err := <-clientDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled HTTP client: %v", err)
	}
	if err := <-accounts.cancelled; !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled database account operation: %v", err)
	}
	select {
	case <-completed:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled HTTP handler did not complete")
	}
	accounts.mutex.Lock()
	defer accounts.mutex.Unlock()
	if len(accounts.observations) != 1 {
		t.Fatalf("cancelled account observations=%d, want 1", len(accounts.observations))
	}
	if _, unsafe := accounts.observations[0].context.(*gin.Context); unsafe {
		t.Error("cancelled account operation received a pooled Gin context")
	}
}

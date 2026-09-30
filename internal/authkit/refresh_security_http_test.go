package authkit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

type synchronizedRefreshValidation struct {
	RefreshTokenStore
	ready sync.WaitGroup
}

func (store *synchronizedRefreshValidation) Validate(ctx context.Context, tenant, opaque string) (string, string, int64, error) {
	user, token, expiry, err := store.RefreshTokenStore.Validate(ctx, tenant, opaque)
	store.ready.Done()
	store.ready.Wait()
	return user, token, expiry, err
}

func TestSecurityConcurrentRefreshConsumesOnce(t *testing.T) {
	for _, backend := range []string{"memory", "database"} {
		for _, path := range []string{"/auth/session", "/auth/refresh"} {
			t.Run(backend+path, func(t *testing.T) {
				var store RefreshTokenStore = NewMemoryRefreshTokenStore()
				if backend == "database" {
					persistent, err := NewDatabaseRefreshTokenStore(context.Background(), sqliteDatabaseURL(t))
					if err != nil {
						t.Fatal(err)
					}
					store = persistent
				}
				config := newTestServerConfig()
				tenant := NewSingleTenantRegistry(config).DefaultTenantID()
				users := newTestUserStore()
				user, _, err := users.UpsertGoogleUser(context.Background(), tenant, "race", "race@example.com", "Race", "")
				if err != nil {
					t.Fatal(err)
				}
				_, opaque, err := store.Issue(context.Background(), tenant, user, time.Now().Add(time.Hour).Unix(), "")
				if err != nil {
					t.Fatal(err)
				}
				synchronized := &synchronizedRefreshValidation{RefreshTokenStore: store}
				synchronized.ready.Add(2)
				router := gin.New()
				MountAuthRoutes(router, NewSingleTenantRegistry(config), users, synchronized, nil)
				server := httptest.NewTLSServer(router)
				defer server.Close()
				responses := make(chan *http.Response, 2)
				failures := make(chan error, 2)
				method := http.MethodPost
				if path == "/auth/session" {
					method = http.MethodGet
				}
				for index := 0; index < 2; index++ {
					go func() {
						request, requestErr := http.NewRequest(method, server.URL+path, nil)
						if requestErr != nil {
							failures <- requestErr
							return
						}
						request.AddCookie(&http.Cookie{Name: config.RefreshCookieName, Value: opaque})
						response, callErr := server.Client().Do(request)
						if callErr != nil {
							failures <- callErr
							return
						}
						responses <- response
					}()
				}
				successes := 0
				var successor string
				for index := 0; index < 2; index++ {
					select {
					case err := <-failures:
						t.Fatal(err)
					case response := <-responses:
						response.Body.Close()
						next := captureAuthCookies(authCookieState{}, response.Cookies(), config).refresh
						if next != "" {
							successes++
							successor = next
						} else if response.StatusCode != http.StatusUnauthorized && response.StatusCode != http.StatusNoContent {
							t.Fatalf("unexpected rejection: %d", response.StatusCode)
						}
					}
				}
				if successes != 1 {
					t.Fatalf("one rotation must succeed, got %d", successes)
				}
				if _, _, _, err := store.Validate(context.Background(), tenant, successor); err == nil {
					t.Fatal("reused parent must revoke its successor family")
				}
			})
		}
	}
}

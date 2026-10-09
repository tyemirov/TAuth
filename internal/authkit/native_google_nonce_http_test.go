package authkit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"google.golang.org/api/idtoken"
)

type synchronizedNativeUserStore struct {
	*testUserStore
	mutex sync.Mutex
}

func (store *synchronizedNativeUserStore) UpsertAccountUser(ctx context.Context, tenantID, accountID, email, display, avatar string) (string, []string, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	return store.testUserStore.UpsertAccountUser(ctx, tenantID, accountID, email, display, avatar)
}

type failingNativeNonceStore struct{ NonceStore }

func (store failingNativeNonceStore) Consume(context.Context, string, string) error {
	return errors.New("injected nonce storage failure")
}

type nativeNonceValidator struct {
	nonce   string
	arrived chan struct{}
	release chan struct{}
}

func (validator *nativeNonceValidator) Validate(_ context.Context, token, _ string) (*idtoken.Payload, error) {
	if validator.arrived != nil {
		validator.arrived <- struct{}{}
		<-validator.release
	}
	nonce := validator.nonce
	if token == "wrong-claim" {
		nonce = "wrong-nonce"
	}
	if token == "hashed-claim" {
		nonce = hashOpaque(nonce)
	}
	return &idtoken.Payload{Claims: map[string]interface{}{
		"iss": googleIssuerHTTPS, "sub": "native-subject", "email": "native@example.com", "email_verified": true, "nonce": nonce,
	}}, nil
}

func TestNativeGoogleIssuedNonceHTTP(t *testing.T) {
	for _, backend := range []string{"memory", "database"} {
		t.Run(backend, func(t *testing.T) {
			for _, scenario := range []string{"replay", "unknown", "expiry", "tenant", "claim", "hashed-claim", "storage", "concurrent"} {
				t.Run(scenario, func(t *testing.T) {
					var clockSeconds atomic.Int64
					clockSeconds.Store(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC).Unix())
					now := func() time.Time { return time.Unix(clockSeconds.Load(), 0) }
					var nonces NonceStore
					if backend == "memory" {
						store := NewMemoryNonceStore(time.Minute).(*memoryNonceStore)
						store.now = now
						nonces = store
					} else {
						store, err := NewDatabaseNonceStore(context.Background(), sqliteDatabaseURL(t), time.Minute)
						if err != nil {
							t.Fatal(err)
						}
						store.now = now
						nonces = store
					}
					if scenario == "storage" {
						nonces = failingNativeNonceStore{nonces}
					}
					accounts := NewMemoryPasswordCredentialStore()
					users := &synchronizedNativeUserStore{testUserStore: newTestUserStore()}
					refresh := NewMemoryRefreshTokenStore()
					validator := &nativeNonceValidator{}
					ProvideGoogleTokenValidator(validator)
					t.Cleanup(func() { ProvideGoogleTokenValidator(nil) })
					config := newTestServerConfig()
					mount := func(config ServerConfig) *httptest.Server {
						router := gin.New()
						MountAuthRoutes(router, NewSingleTenantRegistry(config), users, refresh, nonces, accounts, newTestPasswordResetDispatcher(t))
						server := httptest.NewServer(router)
						t.Cleanup(server.Close)
						return server
					}
					server := mount(config)
					issueResponse, err := server.Client().Post(server.URL+"/auth/nonce", "application/json", nil)
					if err != nil {
						t.Fatal(err)
					}
					var issued struct {
						Nonce string `json:"nonce"`
					}
					decodeErr := json.NewDecoder(issueResponse.Body).Decode(&issued)
					issueResponse.Body.Close()
					if issueResponse.StatusCode != http.StatusOK || decodeErr != nil || issued.Nonce == "" {
						t.Fatalf("issue status=%d nonce=%q err=%v", issueResponse.StatusCode, issued.Nonce, decodeErr)
					}
					validator.nonce = issued.Nonce
					login := func(target *httptest.Server, token, nonce string) (*http.Response, error) {
						encoded, err := json.Marshal(map[string]string{"google_id_token": token, "nonce_token": nonce})
						if err != nil {
							return nil, err
						}
						return target.Client().Post(target.URL+"/auth/google/native", "application/json", bytes.NewReader(encoded))
					}
					assertResponse := func(response *http.Response, err error, status int) {
						t.Helper()
						if err != nil {
							t.Fatal(err)
						}
						defer response.Body.Close()
						if status == http.StatusInternalServerError {
							if response.StatusCode != status || len(response.Cookies()) != 0 {
								t.Fatalf("storage failure status=%d cookies=%v", response.StatusCode, response.Cookies())
							}
							return
						}
						var result map[string]interface{}
						if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
							t.Fatal(err)
						}
						if response.StatusCode != status {
							t.Fatalf("login status=%d want=%d payload=%v", response.StatusCode, status, result)
						}
						cookies := collectCookies(response.Cookies())
						if status == http.StatusUnauthorized {
							if result["error"] != "invalid_nonce" || len(cookies) != 0 {
								t.Fatalf("rejected login payload=%v cookies=%v", result, cookies)
							}
						} else if cookies[config.SessionCookieName] == nil || cookies[config.RefreshCookieName] == nil {
							t.Fatalf("successful login missing credential cookies: %v", cookies)
						}
					}
					assertNoWrites := func() {
						t.Helper()
						if len(users.profiles) != 0 || len(accounts.accounts) != 0 || len(accounts.identities) != 0 || len(refresh.byID) != 0 {
							t.Fatal("rejected nonce changed account or user state")
						}
					}
					switch scenario {
					case "storage":
						response, err := login(server, "identity", issued.Nonce)
						assertResponse(response, err, http.StatusInternalServerError)
						assertNoWrites()
					case "unknown":
						validator.nonce = "never-issued"
						response, err := login(server, "identity", validator.nonce)
						assertResponse(response, err, http.StatusUnauthorized)
						assertNoWrites()
					case "expiry":
						clockSeconds.Add(60)
						response, err := login(server, "identity", issued.Nonce)
						assertResponse(response, err, http.StatusUnauthorized)
						assertNoWrites()
					case "tenant":
						other := config
						other.TenantID = "other-tenant"
						response, err := login(mount(other), "identity", issued.Nonce)
						assertResponse(response, err, http.StatusUnauthorized)
						assertNoWrites()
						response, err = login(server, "identity", issued.Nonce)
						assertResponse(response, err, http.StatusOK)
					case "claim", "hashed-claim":
						token := "wrong-claim"
						if scenario == "hashed-claim" {
							token = scenario
						}
						response, err := login(server, token, issued.Nonce)
						assertResponse(response, err, http.StatusUnauthorized)
						assertNoWrites()
						response, err = login(server, "identity", issued.Nonce)
						assertResponse(response, err, http.StatusOK)
					case "replay":
						response, err := login(server, "identity", issued.Nonce)
						assertResponse(response, err, http.StatusOK)
						response, err = login(server, "identity", issued.Nonce)
						assertResponse(response, err, http.StatusUnauthorized)
						if len(accounts.accounts[config.TenantID]) != 1 || len(refresh.byID) != 1 {
							t.Fatal("replay changed account count")
						}
					case "concurrent":
						const contenders = 8
						validator.arrived = make(chan struct{}, contenders)
						validator.release = make(chan struct{})
						responses := make([]*http.Response, contenders)
						errors := make([]error, contenders)
						var wait sync.WaitGroup
						for index := range contenders {
							wait.Add(1)
							go func() { defer wait.Done(); responses[index], errors[index] = login(server, "identity", issued.Nonce) }()
						}
						for range contenders {
							select {
							case <-validator.arrived:
							case <-time.After(5 * time.Second):
								t.Fatal("concurrent validation barrier timed out")
							}
						}
						close(validator.release)
						wait.Wait()
						successes := 0
						for index, response := range responses {
							if errors[index] != nil {
								t.Fatal(errors[index])
							}
							status := http.StatusUnauthorized
							if response.StatusCode == http.StatusOK {
								status = http.StatusOK
								successes++
							}
							assertResponse(response, errors[index], status)
						}
						if len(refresh.byID) != 1 {
							t.Fatalf("concurrent refresh credentials=%d want=1", len(refresh.byID))
						}
						if successes != 1 {
							t.Fatalf("concurrent successful sessions=%d want=1", successes)
						}
					}
				})
			}
		})
	}
}

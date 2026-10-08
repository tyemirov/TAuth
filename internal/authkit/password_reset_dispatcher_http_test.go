package authkit

import (
	"context"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type blockedResetStore struct {
	*MemoryPasswordCredentialStore
	entered chan struct{}
	release chan struct{}
}

func (store *blockedResetStore) StartPasswordReset(ctx context.Context, tenant, email string, expiry int64) (AccountChallenge, error) {
	close(store.entered)
	select {
	case <-store.release:
	case <-ctx.Done():
		return AccountChallenge{}, ctx.Err()
	}
	return store.MemoryPasswordCredentialStore.StartPasswordReset(ctx, tenant, email, expiry)
}
func TestPasswordResetResponseDoesNotWaitForStore(t *testing.T) {
	config := newTestServerConfig()
	config.AccountManagementEnabled = true
	store := &blockedResetStore{NewMemoryPasswordCredentialStore(), make(chan struct{}), make(chan struct{})}
	router := gin.New()
	MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), nil, store, newTestPasswordResetDispatcher(t), nil, nil)
	server := httptest.NewTLSServer(router)
	defer server.Close()
	result := make(chan *http.Response, 1)
	go func() {
		response, err := server.Client().Post(server.URL+"/auth/password/reset/start", "application/json", strings.NewReader(`{"email":"unknown@example.com"}`))
		if err == nil {
			result <- response
		}
	}()
	<-store.entered
	select {
	case response := <-result:
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != 202 || string(body) != `{"status":"accepted"}` {
			t.Fatalf("unexpected response: %d %s", response.StatusCode, body)
		}
	case <-time.After(500 * time.Millisecond):
		close(store.release)
		t.Fatal("reset response waits for account-dependent storage")
	}
	close(store.release)
}

type controlledResetSender struct {
	entered  chan EmailChallengeRequest
	contexts chan context.Context
	release  chan struct{}
	fail     bool
}

func (sender *controlledResetSender) SendEmailChallenge(ctx context.Context, request EmailChallengeRequest) error {
	sender.entered <- request
	if sender.contexts != nil {
		sender.contexts <- ctx
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-sender.release:
	}
	if sender.fail {
		return errors.New("controlled delivery failure")
	}
	return nil
}

func TestPasswordResetDispatcherRecovery(t *testing.T) {
	for _, backend := range []string{"memory", "database"} {
		t.Run(backend, func(t *testing.T) {
			config := newTestServerConfig()
			config.AccountManagementEnabled = true
			config.EmailDeliveryEnabled = true
			config.PasswordResetURL = "https://app.example/reset"
			var store AccountManagementStore
			var credentials PasswordCredentialStore
			if backend == "memory" {
				memory := NewMemoryPasswordCredentialStore()
				store, credentials = memory, memory
			} else {
				database, err := NewDatabaseUserStore(context.Background(), sqliteDatabaseURL(t))
				if err != nil {
					t.Fatal(err)
				}
				store, credentials = database, database
			}
			signup, err := store.CreatePasswordSignup(context.Background(), config.TenantID, AccountPasswordRequest{UserEmail: "known@example.com", Password: "correct horse battery staple"}, time.Now().Add(time.Hour).Unix())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = store.VerifyEmailChallenge(context.Background(), config.TenantID, signup.Token); err != nil {
				t.Fatal(err)
			}
			dispatcher := newTestPasswordResetDispatcher(t)
			sender := &controlledResetSender{entered: make(chan EmailChallengeRequest, 2), release: make(chan struct{}), fail: true, contexts: make(chan context.Context, 1)}
			router := gin.New()
			MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), nil, credentials, dispatcher, sender, nil)
			server := httptest.NewTLSServer(router)
			defer server.Close()
			requestCtx, cancel := context.WithCancel(context.Background())
			request, _ := http.NewRequestWithContext(requestCtx, http.MethodPost, server.URL+"/auth/password/reset/start", strings.NewReader(`{"email":"KNOWN@example.com"}`))
			request.Header.Set("Content-Type", "application/json")
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			cancel()
			if response.StatusCode != 202 || string(body) != `{"status":"accepted"}` || len(response.Cookies()) != 0 {
				t.Fatalf("reset response %d %s", response.StatusCode, body)
			}
			delivery := <-sender.entered
			workerContext := <-sender.contexts
			if workerContext.Err() != nil {
				t.Fatal("request cancellation canceled recovery worker")
			}
			for _, email := range []string{"unknown@example.com", "known@example.com", "", "invalid"} {
				response, err := server.Client().Post(server.URL+"/auth/password/reset/start", "application/json", strings.NewReader(`{"email":"`+email+`"}`))
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(response.Body)
				response.Body.Close()
				if response.StatusCode != 202 || string(body) != `{"status":"accepted"}` || len(response.Cookies()) != 0 {
					t.Fatalf("nonuniform response %d %s", response.StatusCode, body)
				}
			}
			close(sender.release)
			waitTestPasswordResetIdle(t, dispatcher)
			token := challengeTokenFromDeliveryURL(t, delivery, EmailChallengeKindPasswordReset)
			if _, err := store.CompletePasswordReset(context.Background(), config.TenantID, token, "replacement correct horse battery staple"); !errors.Is(err, ErrAccountChallengeInvalid) {
				t.Fatalf("failed delivery challenge usable: %v", err)
			}
			// A successful recovery remains usable through the public completion endpoint.
			delivered := &recordingEmailChallengeSender{}
			recoveredDispatcher := newTestPasswordResetDispatcher(t)
			// Clear the time-window budget deterministically at its persistence boundary.
			switch concrete := store.(type) {
			case *MemoryPasswordCredentialStore:
				concrete.mu.Lock()
				concrete.abuseBudgets = make(map[string]abuseBudgetRecord)
				concrete.mu.Unlock()
			case *DatabaseUserStore:
				if err := concrete.db.Where("1 = 1").Delete(&abuseBudgetRecord{}).Error; err != nil {
					t.Fatal(err)
				}
			}
			recoveryRouter := gin.New()
			MountAuthRoutesWithPassword(recoveryRouter, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), nil, credentials, recoveredDispatcher, delivered, nil)
			recoveryServer := httptest.NewTLSServer(recoveryRouter)
			defer recoveryServer.Close()
			response, err = recoveryServer.Client().Post(recoveryServer.URL+"/auth/password/reset/start", "application/json", strings.NewReader(`{"email":"known@example.com"}`))
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			delivered.WaitRequests(t, 1)
			waitTestPasswordResetIdle(t, recoveredDispatcher)
			token = challengeTokenFromDeliveryURL(t, delivered.Snapshot()[0], EmailChallengeKindPasswordReset)
			response, err = recoveryServer.Client().Post(recoveryServer.URL+"/auth/password/reset/complete", "application/json", strings.NewReader(`{"token":"`+token+`","password":"replacement correct horse battery staple"}`))
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("recovery completion: %d", response.StatusCode)
			}
		})
	}
}

func TestPasswordResetDispatcherAdmissionAndShutdown(t *testing.T) {
	dispatcher := newTestPasswordResetDispatcher(t)
	store := &blockedResetStore{NewMemoryPasswordCredentialStore(), make(chan struct{}), make(chan struct{})}
	config := newTestServerConfig()
	config.AccountManagementEnabled = true
	enqueue := func(tenant, email, source string) {
		dispatcher.enqueue(passwordResetJob{tenantID: tenant, email: email, source: source, resetURL: config.PasswordResetURL, resetTTL: config.PasswordResetTTL, emailDeliveryEnabled: config.EmailDeliveryEnabled, store: store, clock: NewSystemClock()})
	}
	enqueue("first", "active@example.com", "source")
	<-store.entered
	for index := 0; index < 100; index++ {
		enqueue("first", "active@example.com", "other")
	}
	for index := 0; index < 100; index++ {
		enqueue("first", fmt.Sprintf("source%d@example.com", index), "source")
	}
	dispatcher.mu.Lock()
	if dispatcher.outstanding != passwordResetSourceCapacity {
		t.Errorf("source limit/coalescing: %d", dispatcher.outstanding)
	}
	dispatcher.mu.Unlock()
	for index := 0; index < 100; index++ {
		enqueue("first", fmt.Sprintf("tenant%d@example.com", index), fmt.Sprintf("source%d", index))
	}
	dispatcher.mu.Lock()
	if dispatcher.tenants["first"] != passwordResetTenantCapacity {
		t.Errorf("tenant limit: %d", dispatcher.tenants["first"])
	}
	dispatcher.mu.Unlock()
	for index := 0; index < 400; index++ {
		enqueue(fmt.Sprintf("tenant%d", index), fmt.Sprintf("email%d@example.com", index), fmt.Sprintf("source-global%d", index))
	}
	dispatcher.mu.Lock()
	if dispatcher.outstanding != passwordResetQueueCapacity {
		t.Errorf("global limit: %d", dispatcher.outstanding)
	}
	dispatcher.mu.Unlock()
	router := gin.New()
	MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), nil, store, dispatcher, nil, nil)
	server := httptest.NewTLSServer(router)
	defer server.Close()
	for _, email := range []string{"known@example.com", "unknown@example.com"} {
		response, err := server.Client().Post(server.URL+"/auth/password/reset/start", "application/json", strings.NewReader(`{"email":"`+email+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != 202 || string(body) != `{"status":"accepted"}` || len(response.Cookies()) != 0 {
			t.Fatalf("full queue response: %d %s", response.StatusCode, body)
		}
	}
	dispatcher.Close()
	enqueue("after", "closed@example.com", "closed")
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	if dispatcher.outstanding != 0 || len(dispatcher.pending) != 0 || len(dispatcher.sources) != 0 || len(dispatcher.tenants) != 0 {
		t.Fatal("shutdown retained outstanding work")
	}
}

func TestPasswordResetStorageCapacityResponse(t *testing.T) {
	for _, backend := range []string{"memory", "database"} {
		t.Run(backend, func(t *testing.T) {
			config := newTestServerConfig()
			config.AccountManagementEnabled = true
			var store AccountManagementStore
			var credentials PasswordCredentialStore
			if backend == "memory" {
				memory := NewMemoryPasswordCredentialStore()
				store, credentials = memory, memory
			} else {
				database, err := NewDatabaseUserStore(context.Background(), sqliteDatabaseURL(t))
				if err != nil {
					t.Fatal(err)
				}
				store, credentials = database, database
			}
			signup, err := store.CreatePasswordSignup(context.Background(), config.TenantID, AccountPasswordRequest{UserEmail: "known@example.com", Password: "correct horse battery staple"}, time.Now().Add(time.Hour).Unix())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = store.VerifyEmailChallenge(context.Background(), config.TenantID, signup.Token); err != nil {
				t.Fatal(err)
			}
			expiry := time.Now().Add(time.Hour).Unix()
			switch concrete := store.(type) {
			case *MemoryPasswordCredentialStore:
				concrete.mu.Lock()
				concrete.ensureAccountMaps(config.TenantID)
				for index := 0; index < transientTenantCapacity; index++ {
					id := fmt.Sprint(index)
					concrete.challenges[config.TenantID][id] = &accountChallengeRecord{accountID: id, kind: accountChallengePasswordReset, expiresUnix: expiry}
				}
				concrete.mu.Unlock()
			case *DatabaseUserStore:
				records := make([]databaseAccountChallengeRecord, transientTenantCapacity)
				for index := range records {
					id := fmt.Sprint(index)
					records[index] = databaseAccountChallengeRecord{TenantID: config.TenantID, TokenHash: id, AccountID: id, ChallengeKind: accountChallengePasswordReset, ExpiresUnix: expiry}
				}
				if err := concrete.db.CreateInBatches(&records, 100).Error; err != nil {
					t.Fatal(err)
				}
			}
			dispatcher := newTestPasswordResetDispatcher(t)
			router := gin.New()
			MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), nil, credentials, dispatcher, nil, nil)
			server := httptest.NewTLSServer(router)
			defer server.Close()
			for _, email := range []string{"known@example.com", "unknown@example.com"} {
				response, err := server.Client().Post(server.URL+"/auth/password/reset/start", "application/json", strings.NewReader(`{"email":"`+email+`"}`))
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(response.Body)
				response.Body.Close()
				if response.StatusCode != 202 || string(body) != `{"status":"accepted"}` || len(response.Cookies()) != 0 {
					t.Fatalf("capacity exposes account state: %d %s", response.StatusCode, body)
				}
			}
			waitTestPasswordResetIdle(t, dispatcher)
		})
	}
}

func TestPasswordResetCanceledDeliveryCleanup(t *testing.T) {
	store := NewMemoryPasswordCredentialStore()
	config := newTestServerConfig()
	config.AccountManagementEnabled = true
	config.EmailDeliveryEnabled = true
	config.PasswordResetURL = "https://app.example/reset"
	signup, err := store.CreatePasswordSignup(context.Background(), config.TenantID, AccountPasswordRequest{UserEmail: "known@example.com", Password: "correct horse battery staple"}, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.VerifyEmailChallenge(context.Background(), config.TenantID, signup.Token); err != nil {
		t.Fatal(err)
	}
	sender := &controlledResetSender{entered: make(chan EmailChallengeRequest, 1), release: make(chan struct{})}
	dispatcher := newTestPasswordResetDispatcher(t)
	router := gin.New()
	MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), nil, store, dispatcher, sender, nil)
	server := httptest.NewTLSServer(router)
	defer server.Close()
	response, err := server.Client().Post(server.URL+"/auth/password/reset/start", "application/json", strings.NewReader(`{"email":"known@example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	delivery := <-sender.entered
	dispatcher.Close()
	token := challengeTokenFromDeliveryURL(t, delivery, EmailChallengeKindPasswordReset)
	if _, err := store.CompletePasswordReset(context.Background(), config.TenantID, token, "replacement correct horse battery staple"); !errors.Is(err, ErrAccountChallengeInvalid) {
		t.Fatalf("shutdown left undelivered challenge: %v", err)
	}
}

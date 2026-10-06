package authkit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/web"
)

const passwordSeedTestPassword = "correct horse battery staple"

type passwordSeedStore interface {
	PasswordCredentialStore
	AccountManagementStore
}

type passwordSeedHTTPFixture struct {
	store  passwordSeedStore
	config ServerConfig
	client *http.Client
	server *httptest.Server
	seed   PasswordCredentialSeed
}

type passwordSeedHTTPProfile struct {
	UserID      string   `json:"user_id"`
	DisplayName string   `json:"display"`
	AvatarURL   string   `json:"avatar_url"`
	Roles       []string `json:"roles"`
}

func newPasswordSeedHTTPFixture(t *testing.T, storage string) passwordSeedHTTPFixture {
	t.Helper()
	config := newTestServerConfig()
	config.PasswordAuthEnabled = true
	config.AccountManagementEnabled = true
	var store passwordSeedStore
	var users UserStore
	switch storage {
	case "database":
		database, err := NewDatabaseUserStore(context.Background(), sqliteDatabaseURL(t))
		if err != nil {
			t.Fatal(err)
		}
		store, users = database, database
		t.Cleanup(func() { raw, _ := database.db.DB(); raw.Close() })
	case "memory":
		store, users = NewMemoryPasswordCredentialStore(), web.NewInMemoryUsers()
	default:
		t.Fatalf("unknown test storage %q", storage)
	}
	hash, err := HashPassword(passwordSeedTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	seed := PasswordCredentialSeed{UserEmail: "parent@example.com", DisplayName: "Parent", AvatarURL: "https://example.com/parent.png", PasswordHash: hash}
	if err := store.UpsertPasswordCredential(context.Background(), config.TenantID, seed); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(config), users, NewMemoryRefreshTokenStore(), nil, store, nil, nil)
	server := httptest.NewTLSServer(router)
	t.Cleanup(server.Close)
	client := server.Client()
	client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return passwordSeedHTTPFixture{store: store, config: config, client: client, server: server, seed: seed}
}

func (fixture passwordSeedHTTPFixture) request(t *testing.T, method, path, body string, expectedStatus int) passwordSeedHTTPProfile {
	t.Helper()
	request, err := http.NewRequest(method, fixture.server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := fixture.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != expectedStatus {
		t.Fatalf("%s %s: status=%d, want %d", method, path, response.StatusCode, expectedStatus)
	}
	var profile passwordSeedHTTPProfile
	if response.StatusCode == http.StatusOK {
		if err := json.NewDecoder(response.Body).Decode(&profile); err != nil {
			t.Fatal(err)
		}
	}
	return profile
}

func (fixture passwordSeedHTTPFixture) login(t *testing.T, expectedStatus int) passwordSeedHTTPProfile {
	t.Helper()
	body, err := json.Marshal(map[string]string{"email": fixture.seed.UserEmail, "password": passwordSeedTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	return fixture.request(t, http.MethodPost, "/auth/password/login", string(body), expectedStatus)
}

func TestPasswordSeedRestorationHTTP(t *testing.T) {
	for _, storage := range []string{"database", "memory"} {
		t.Run(storage, func(t *testing.T) {
			fixture := newPasswordSeedHTTPFixture(t, storage)
			before := fixture.login(t, http.StatusOK)
			account, err := fixture.store.ResolveAccountForUser(context.Background(), fixture.config.TenantID, before.UserID)
			if err != nil {
				t.Fatal(err)
			}
			if err := fixture.store.ReconcilePasswordCredentials(context.Background(), fixture.config.TenantID, nil); err != nil {
				t.Fatal(err)
			}
			fixture.login(t, http.StatusUnauthorized)
			if err := fixture.store.UpsertPasswordCredential(context.Background(), fixture.config.TenantID, fixture.seed); err != nil {
				t.Fatalf("restore configured credential: %v", err)
			}
			after := fixture.login(t, http.StatusOK)
			if after.UserID != before.UserID {
				t.Fatalf("restoration changed public user ID: %s -> %s", before.UserID, after.UserID)
			}
			restored, err := fixture.store.ResolveAccountForUser(context.Background(), fixture.config.TenantID, after.UserID)
			if err != nil || restored.AccountID != account.AccountID {
				t.Fatalf("restoration changed internal account ID: %+v, %v", restored, err)
			}
			if _, err := fixture.store.BeginAccountDisable(context.Background(), fixture.config.TenantID, account.AccountID); err != nil {
				t.Fatal(err)
			}
			if err := fixture.store.ReconcilePasswordCredentials(context.Background(), fixture.config.TenantID, nil); err != nil {
				t.Fatal(err)
			}
			if err := fixture.store.UpsertPasswordCredential(context.Background(), fixture.config.TenantID, fixture.seed); !errors.Is(err, ErrAccountNotActive) {
				t.Fatalf("restoration of inactive account: %v", err)
			}
			fixture.login(t, http.StatusUnauthorized)
		})
	}
}

func TestPasswordSeedProfileUpdateHTTP(t *testing.T) {
	for _, storage := range []string{"database", "memory"} {
		t.Run(storage, func(t *testing.T) {
			for _, override := range []bool{false, true} {
				label := "configured"
				if override {
					label = "explicit"
				}
				t.Run(label, func(t *testing.T) {
					fixture := newPasswordSeedHTTPFixture(t, storage)
					before := fixture.login(t, http.StatusOK)
					expectedDisplay := "Updated Parent"
					if override {
						expectedDisplay = "Explicit Parent"
						fixture.request(t, http.MethodPatch, accountProfilePath, `{"display_name":"Explicit Parent"}`, http.StatusOK)
					}
					fixture.seed.DisplayName = "Updated Parent"
					fixture.seed.AvatarURL = "https://example.com/updated.png"
					if err := fixture.store.UpsertPasswordCredential(context.Background(), fixture.config.TenantID, fixture.seed); err != nil {
						t.Fatal(err)
					}
					for _, after := range []passwordSeedHTTPProfile{
						fixture.request(t, http.MethodGet, "/auth/session", "", http.StatusOK),
						fixture.login(t, http.StatusOK),
					} {
						if after.UserID != before.UserID || after.DisplayName != expectedDisplay || after.AvatarURL != fixture.seed.AvatarURL || !slices.Equal(after.Roles, before.Roles) {
							t.Fatalf("configured profile update: before=%+v, after=%+v", before, after)
						}
					}
				})
			}
		})
	}
}

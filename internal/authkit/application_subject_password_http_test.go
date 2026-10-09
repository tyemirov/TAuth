package authkit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func newApplicationSubjectRouter(t *testing.T, registry TenantRegistry, users *DatabaseUserStore, refresh RefreshTokenStore) *gin.Engine {
	router := gin.New()
	MountAuthRoutesWithPassword(router, registry, users, refresh, nil, users, newTestPasswordResetDispatcher(t), nil, nil)
	return router
}

func TestApplicationSubjectPasswordHTTP(t *testing.T) {
	config := newTestServerConfig()
	config.PasswordAuthEnabled = true
	databaseURL := sqliteDatabaseURL(t)
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	db, err := OpenControlDatabase(context.Background(), databaseURL, &userProfileRecord{}, &passwordCredentialRecord{})
	if err != nil {
		t.Fatal(err)
	}
	profile := userProfileRecord{TenantID: config.TenantID, UserID: "email:parent@example.com", UserEmail: "parent@example.com", UserDisplayName: "Parent", UserRoles: roleList{"parent"}}
	if err = db.Create(&profile).Error; err != nil {
		t.Fatal(err)
	}
	credential := passwordCredentialRecord{TenantID: config.TenantID, UserID: profile.UserID, UserEmail: profile.UserEmail, UserDisplayName: profile.UserDisplayName, PasswordHash: hash, EmailVerified: true}
	if err = db.Create(&credential).Error; err != nil {
		t.Fatal(err)
	}
	if err = db.Transaction(func(tx *gorm.DB) error { return MigrateApplicationSubjects(context.Background(), tx) }); err != nil {
		t.Fatal(err)
	}
	raw, _ := db.DB()
	if err = raw.Close(); err != nil {
		t.Fatal(err)
	}
	users, err := NewDatabaseUserStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := NewDatabaseRefreshTokenStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	registry := NewSingleTenantRegistry(config)
	server := httptest.NewTLSServer(newApplicationSubjectRouter(t, registry, users, refresh))
	t.Cleanup(server.Close)
	client := server.Client()
	client.Jar, _ = cookiejar.New(nil)
	login := func() string {
		response, err := client.Post(server.URL+"/auth/password/login", "application/json", strings.NewReader(`{"email":"parent@example.com","password":"correct horse battery staple"}`))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var result map[string]any
		if err = json.NewDecoder(response.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK {
			t.Fatalf("password login=%d %v", response.StatusCode, result)
		}
		return result["user_id"].(string)
	}
	if id := login(); id != profile.UserID {
		t.Fatalf("password migration changed subject: %s", id)
	}
	for _, enabled := range []bool{true, false, true} {
		next := registry.configs[config.TenantID]
		next.AccountManagementEnabled = enabled
		registry.configs[config.TenantID] = next
		if id := login(); id != profile.UserID {
			t.Fatalf("password flag changed subject: %s", id)
		}
	}
	raw, _ = users.db.DB()
	if err = raw.Close(); err != nil {
		t.Fatal(err)
	}
	users, err = NewDatabaseUserStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = newApplicationSubjectRouter(t, registry, users, refresh)
	if id := login(); id != profile.UserID {
		t.Fatal("password restart changed public subject")
	}
}

func TestApplicationSubjectConcurrentPasswordHTTP(t *testing.T) {
	config := newTestServerConfig()
	config.PasswordAuthEnabled = true
	databaseURL := sqliteDatabaseURL(t)
	users, err := NewDatabaseUserStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if err = users.UpsertPasswordCredential(context.Background(), config.TenantID, PasswordCredentialSeed{UserEmail: "parent@example.com", DisplayName: "Parent", PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	refresh, err := NewDatabaseRefreshTokenStore(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	registry := NewSingleTenantRegistry(config)
	server := httptest.NewTLSServer(newApplicationSubjectRouter(t, registry, users, refresh))
	t.Cleanup(server.Close)
	expected, err := users.EnsurePasswordAccount(context.Background(), config.TenantID, "parent@example.com")
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		status  int
		cookies int
		id      string
		err     error
	}
	for _, enabled := range []bool{false, true} {
		next := registry.configs[config.TenantID]
		next.AccountManagementEnabled = enabled
		registry.configs[config.TenantID] = next
		ready := make(chan struct{})
		results := make(chan result, 2)
		for index := 0; index < 2; index++ {
			go func() {
				<-ready
				response, err := server.Client().Post(server.URL+"/auth/password/login", "application/json", strings.NewReader(`{"email":"parent@example.com","password":"correct horse battery staple"}`))
				if err != nil {
					results <- result{err: err}
					return
				}
				defer response.Body.Close()
				var profile map[string]any
				if response.StatusCode == http.StatusOK {
					err = json.NewDecoder(response.Body).Decode(&profile)
				}
				id, _ := profile["user_id"].(string)
				results <- result{status: response.StatusCode, cookies: len(response.Cookies()), id: id, err: err}
			}()
		}
		close(ready)
		successes := 0
		for index := 0; index < 2; index++ {
			outcome := <-results
			if outcome.status == http.StatusTooManyRequests {
				if outcome.cookies != 0 {
					t.Fatal("throttled login issued cookies")
				}
				continue
			}
			successes++
			if outcome.err != nil || outcome.status != http.StatusOK || outcome.id != expected.UserID {
				t.Fatalf("concurrent password flag=%v outcome=%+v", enabled, outcome)
			}
		}
		if successes < 1 || successes > 2 {
			t.Fatalf("concurrent login successes=%d", successes)
		}
	}
}

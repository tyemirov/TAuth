package authkit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

type delayedRefreshValidation struct{ RefreshTokenStore }

func (store delayedRefreshValidation) Validate(ctx context.Context, tenant, opaque string) (string, string, int64, error) {
	user, token, expiry, err := store.RefreshTokenStore.Validate(ctx, tenant, opaque)
	time.Sleep(100 * time.Millisecond)
	return user, token, expiry, err
}

func TestSecurityBrowserRefresh(t *testing.T) {
	for _, backend := range []string{"memory", "database"} {
		t.Run(backend, func(t *testing.T) {
			databaseURL := sqliteDatabaseURL(t)
			var store RefreshTokenStore = NewMemoryRefreshTokenStore()
			var accounts AccountManagementStore = NewMemoryPasswordCredentialStore()
			if backend == "database" {
				database, err := NewDatabaseRefreshTokenStore(context.Background(), databaseURL)
				if err != nil {
					t.Fatal(err)
				}
				store = database
				accounts, err = NewDatabaseUserStore(context.Background(), databaseURL)
				if err != nil {
					t.Fatal(err)
				}
			}
			config := newTestServerConfig()
			users := newTestUserStore()
			profile, err := accounts.UpsertProviderAccount(context.Background(), config.TenantID, AccountProviderIdentity{Provider: "google", Subject: "browser-race", UserEmail: "browser@example.com", DisplayName: "Browser"})
			if err != nil {
				t.Fatal(err)
			}
			user, _, err := users.UpsertAccountUser(context.Background(), config.TenantID, profile.UserID, profile.UserEmail, profile.DisplayName, profile.AvatarURL)
			if err != nil {
				t.Fatal(err)
			}
			_, opaque, err := store.Issue(context.Background(), config.TenantID, user, time.Now().Add(time.Hour).Unix(), "")
			if err != nil {
				t.Fatal(err)
			}
			router := gin.New()
			router.GET("/fixture", func(ctx *gin.Context) {
				ctx.Data(http.StatusOK, "text/html", []byte(`<html><body><script src="/tauth.js"></script></body></html>`))
			})
			router.GET("/tauth.js", func(ctx *gin.Context) { ctx.File("../../web/tauth.js") })
			MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(config), users, delayedRefreshValidation{store}, nil, accounts.(PasswordCredentialStore), newTestPasswordResetDispatcher(t), nil, nil)
			server := httptest.NewTLSServer(router)
			defer server.Close()
			command := exec.CommandContext(context.Background(), "node", "../../tests/auth-refresh.browser.cjs")
			command.Env = append(os.Environ(), "TAUTH_REFRESH_TEST_URL="+server.URL, "TAUTH_REFRESH_TEST_TOKEN="+opaque, "TAUTH_REFRESH_COOKIE="+config.RefreshCookieName, "TAUTH_SESSION_COOKIE="+config.SessionCookieName)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("browser refresh: %v\n%s", err, output)
			}
		})
	}
}

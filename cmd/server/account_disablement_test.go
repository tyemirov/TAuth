package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/oauthserver"
)

func TestServerResumesPersistedAccountDisablement(t *testing.T) {
	ctx := context.Background()
	databaseURL := "sqlite://" + filepath.Join(t.TempDir(), "tauth.db")
	accounts, err := authkit.NewDatabaseUserStore(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := accounts.UpsertGoogleAccount(ctx, "alpha", authkit.GoogleAccountIdentity{Subject: "disabled-user", UserEmail: "user@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := authkit.NewDatabaseRefreshTokenStore(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	_, applicationToken, err := refresh.Issue(ctx, "alpha", profile.AccountID, time.Now().Add(time.Hour).Unix(), "")
	if err != nil {
		t.Fatal(err)
	}
	oauth, err := oauthserver.NewDatabaseStore(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	key := oauthserver.ConsentKey{TenantID: "alpha", UserID: profile.AccountID, ClientID: "client", Resource: "https://resource.example", Scope: "read"}
	consent, err := oauth.SaveConsent(ctx, oauthserver.Consent{ConsentKey: key, ExpiresAtUnix: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oauth.IssueRefreshToken(ctx, oauthserver.RefreshGrant{ConsentID: consent.ID, TenantID: key.TenantID, UserID: key.UserID, ClientID: key.ClientID, Resource: key.Resource, Scope: key.Scope, ExpiresAtUnix: consent.ExpiresAtUnix}); err != nil {
		t.Fatal(err)
	}
	if _, err := accounts.BeginAccountDisable(ctx, "alpha", profile.AccountID); err != nil {
		t.Fatal(err)
	}

	restoreValidator := withGoogleValidatorBuilderStub(func(context.Context) (authkit.GoogleTokenValidator, error) { return noopGoogleValidator{}, nil })
	defer restoreValidator()
	served := false
	restoreServe := withServeHTTPStub(func(server *http.Server) error {
		served = true
		if pending, err := accounts.PendingAccountDisablements(ctx); err != nil || len(pending) != 0 {
			t.Fatalf("server accepted traffic before cleanup: pending=%d error=%v", len(pending), err)
		}
		if _, exists, err := oauth.FindConsent(ctx, key, time.Now().Unix()); err != nil || exists {
			t.Fatalf("restart retained OAuth consent: exists=%v error=%v", exists, err)
		}
		if _, _, _, err := refresh.Validate(ctx, "alpha", applicationToken); err == nil {
			t.Fatal("restart retained application refresh token")
		}
		listener := httptest.NewServer(server.Handler)
		defer listener.Close()
		response, err := http.Get(listener.URL + "/health")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("health returned %d", response.StatusCode)
		}
		return http.ErrServerClosed
	})
	defer restoreServe()
	config := sampleApplicationConfig()
	config.Server.DatabaseURL = databaseURL
	command := &cobra.Command{RunE: runServer}
	command.SetContext(context.WithValue(ctx, appConfigContextKey, &config))
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if !served {
		t.Fatal("server did not start")
	}
	if _, err := accounts.ReactivateAccount(ctx, "alpha", profile.AccountID); err != nil {
		t.Fatal(err)
	}
}

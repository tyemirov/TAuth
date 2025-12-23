package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/tenants"
)

func TestSameSiteResolverCoversCombinations(t *testing.T) {
	testCases := []struct {
		name          string
		enableCORS    bool
		allowInsecure bool
		expected      http.SameSite
	}{
		{
			name:          "cors_secure",
			enableCORS:    true,
			allowInsecure: false,
			expected:      http.SameSiteNoneMode,
		},
		{
			name:          "cors_insecure",
			enableCORS:    true,
			allowInsecure: true,
			expected:      http.SameSiteLaxMode,
		},
		{
			name:          "no_cors_insecure",
			enableCORS:    false,
			allowInsecure: true,
			expected:      http.SameSiteLaxMode,
		},
		{
			name:          "no_cors_secure",
			enableCORS:    false,
			allowInsecure: false,
			expected:      http.SameSiteStrictMode,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			resolver := authkit.NewSameSiteResolver(testCase.enableCORS)
			if got := resolver(testCase.allowInsecure); got != testCase.expected {
				t.Fatalf("expected %v, got %v", testCase.expected, got)
			}
		})
	}
}

func TestHostAllowedHandlesAmbiguity(t *testing.T) {
	document := tenants.FileDocument{
		Tenants: []tenants.FileTenant{
			{
				ID:                "alpha",
				DisplayName:       "Alpha",
				AllowedHosts:      []string{"shared.localhost", "http://alpha.localhost:8000"},
				GoogleWebClientID: "alpha-client",
				JWTSigningKey:     "alpha-key",
				CookieDomain:      "",
				SessionCookieName: "app_session_alpha",
				RefreshCookieName: "app_refresh_alpha",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
				AllowInsecureHTTP: true,
			},
			{
				ID:                "beta",
				DisplayName:       "Beta",
				AllowedHosts:      []string{"shared.localhost", "http://beta.localhost:8000"},
				GoogleWebClientID: "beta-client",
				JWTSigningKey:     "beta-key",
				CookieDomain:      "",
				SessionCookieName: "app_session_beta",
				RefreshCookieName: "app_refresh_beta",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
				AllowInsecureHTTP: true,
			},
		},
	}

	config, err := tenants.LoadConfigFromDocument(document)
	if err != nil {
		t.Fatalf("expected tenants config to load: %v", err)
	}

	missingHost := &http.Request{Host: ""}
	if hostAllowed(missingHost, config, false) {
		t.Fatalf("expected missing host to be rejected")
	}

	request := &http.Request{Host: "shared.localhost", Header: make(http.Header)}
	request.Header.Set("Origin", "http://alpha.localhost:8000")
	if !hostAllowed(request, config, false) {
		t.Fatalf("expected alpha origin to be allowed")
	}

	requestUnknownOrigin := &http.Request{Host: "shared.localhost", Header: make(http.Header)}
	requestUnknownOrigin.Header.Set("Origin", "http://unknown.localhost:8000")
	if hostAllowed(requestUnknownOrigin, config, false) {
		t.Fatalf("expected unknown origin to be rejected")
	}

	requestNoOrigin := &http.Request{Host: "shared.localhost", Header: make(http.Header)}
	if hostAllowed(requestNoOrigin, config, false) {
		t.Fatalf("expected shared host without origin to be rejected when override disabled")
	}
	if !hostAllowed(requestNoOrigin, config, true) {
		t.Fatalf("expected shared host without origin to be allowed when override enabled")
	}
}

func TestPrepareServerConfigReturnsErrorWhenFlagMissing(t *testing.T) {
	command := &cobra.Command{}
	if err := prepareServerConfig(command, nil); err == nil {
		t.Fatalf("expected error when config flag missing")
	}
}

func TestPrepareServerConfigHonorsEnvOverride(t *testing.T) {
	configPath := writeTempConfig(t, `
server:
  listen_addr: ":8080"

tenants:
  - id: "demo"
    allowed_hosts: ["demo.localhost"]
    google_web_client_id: "demo-client"
    jwt_signing_key: "demo-key"
    cookie_domain: ""
    session_cookie_name: "app_session_demo"
    refresh_cookie_name: "app_refresh_demo"
    session_ttl: "15m"
    refresh_ttl: "720h"
    nonce_ttl: "5m"
    allow_insecure_http: true
`)

	command := &cobra.Command{}
	command.Flags().String("config", "missing.yaml", "")
	if err := os.Setenv("TAUTH_CONFIG_FILE", configPath); err != nil {
		t.Fatalf("setenv failed: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Unsetenv("TAUTH_CONFIG_FILE")
	})

	command.SetContext(context.Background())
	if err := prepareServerConfig(command, nil); err != nil {
		t.Fatalf("expected config to load via env override: %v", err)
	}

	value := command.Context().Value(appConfigContextKey)
	if value == nil {
		t.Fatalf("expected config to be stored in command context")
	}
}

func TestRunServerReturnsErrorForInvalidCORSOrigins(t *testing.T) {
	restoreValidator := withGoogleValidatorBuilderStub(func(ctx context.Context) (authkit.GoogleTokenValidator, error) {
		return noopGoogleValidator{}, nil
	})
	defer restoreValidator()

	cfg := sampleApplicationConfig()
	cfg.Server.EnableCORS = true
	cfg.Server.CORSAllowedOrigins = []string{" "}

	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), appConfigContextKey, &cfg))

	if err := runServer(command, nil); err == nil {
		t.Fatalf("expected CORS origin validation to fail")
	}
}

func TestRunServerReturnsErrorWhenValidatorInitFails(t *testing.T) {
	restoreValidator := withGoogleValidatorBuilderStub(func(ctx context.Context) (authkit.GoogleTokenValidator, error) {
		return nil, errors.New("validator.init.failed")
	})
	defer restoreValidator()

	restoreServe := withServeHTTPStub(func(server *http.Server) error {
		return http.ErrServerClosed
	})
	defer restoreServe()

	cfg := sampleApplicationConfig()
	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), appConfigContextKey, &cfg))

	err := runServer(command, nil)
	if err == nil || !strings.Contains(err.Error(), configCodeGoogleValidatorInit) {
		t.Fatalf("expected validator init error, got %v", err)
	}
}

func TestRunServerReturnsListenErrorForServeHTTPFailure(t *testing.T) {
	restoreValidator := withGoogleValidatorBuilderStub(func(ctx context.Context) (authkit.GoogleTokenValidator, error) {
		return noopGoogleValidator{}, nil
	})
	defer restoreValidator()

	restoreServe := withServeHTTPStub(func(server *http.Server) error {
		return errors.New("listen.failed")
	})
	defer restoreServe()

	cfg := sampleApplicationConfig()
	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), appConfigContextKey, &cfg))

	err := runServer(command, nil)
	if err == nil || !strings.Contains(err.Error(), "listen error") {
		t.Fatalf("expected listen error, got %v", err)
	}
}

func TestRunServerReturnsErrorWhenPersistentRefreshStoreFails(t *testing.T) {
	restoreValidator := withGoogleValidatorBuilderStub(func(ctx context.Context) (authkit.GoogleTokenValidator, error) {
		return noopGoogleValidator{}, nil
	})
	defer restoreValidator()

	cfg := sampleApplicationConfig()
	cfg.Server.DatabaseURL = "sqlite://file:/data/tauth.db"

	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), appConfigContextKey, &cfg))

	if err := runServer(command, nil); err == nil {
		t.Fatalf("expected refresh store initialization to fail")
	}
}

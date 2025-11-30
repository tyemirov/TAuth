package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/tenants"
	"go.uber.org/zap"
	"google.golang.org/api/idtoken"
)

func TestZapLoggerMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger, err := zap.NewProduction()
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer func() { _ = logger.Sync() }()

	router := gin.New()
	router.Use(zapLoggerMiddleware(logger))
	router.GET("/ping", func(contextGin *gin.Context) {
		contextGin.Status(http.StatusNoContent)
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/ping", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", recorder.Code)
	}
}

func TestRunServerMissingConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	viper.Reset()
	defer viper.Reset()

	err := runServer(&cobra.Command{}, nil)
	if err == nil {
		t.Fatalf("expected configuration error")
	}

	expectedMessage := "config.uninitialized_server_config: server configuration not prepared; PreRunE must execute before RunE"
	if err.Error() != expectedMessage {
		t.Fatalf("expected error %q, got %q", expectedMessage, err.Error())
	}
}

func TestLoadServerConfigRequiresSigningKey(t *testing.T) {
	gin.SetMode(gin.TestMode)

	viper.Reset()
	defer viper.Reset()

	_, err := LoadServerConfig()
	if err == nil {
		t.Fatalf("expected configuration error when jwt_signing_key missing")
	}

	expectedMessage := "config.missing_jwt_signing_key: jwt_signing_key must be provided"
	if err.Error() != expectedMessage {
		t.Fatalf("expected error %q, got %q", expectedMessage, err.Error())
	}
}

func TestRunServerValidatorInitFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)

	viper.Reset()
	defer viper.Reset()

	restoreServe := withServeHTTPStub(func(server *http.Server) error {
		return http.ErrServerClosed
	})
	defer restoreServe()

	restoreValidator := withGoogleValidatorBuilderStub(func(ctx context.Context) (authkit.GoogleTokenValidator, error) {
		return nil, errors.New("validator_fail")
	})
	defer restoreValidator()

	viper.Set("listen_addr", ":0")
	viper.Set("tenants_file", writeSampleTenantsFile(t))

	config := mustLoadServerConfig(t)

	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), serverConfigContextKey, config))

	if err := runServer(command, nil); err == nil || err.Error() != "config.google_validator_init: validator_fail" {
		t.Fatalf("expected google validator init error, got %v", err)
	}
}

func TestRunServerRequiresTenantsFile(t *testing.T) {
	gin.SetMode(gin.TestMode)

	viper.Reset()
	defer viper.Reset()

	config := mustLoadServerConfig(t)
	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), serverConfigContextKey, config))

	err := runServer(command, nil)
	if err == nil {
		t.Fatalf("expected error when tenants_file missing")
	}
	expected := "config.missing_tenants_file: tenants_file must be provided"
	if err.Error() != expected {
		t.Fatalf("expected %q, got %q", expected, err.Error())
	}
}

func TestRunServerSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)

	viper.Reset()
	defer viper.Reset()

	restoreServe := withServeHTTPStub(func(server *http.Server) error {
		if server.Handler == nil {
			t.Fatalf("expected handler to be configured")
		}
		return http.ErrServerClosed
	})
	defer restoreServe()

	restoreValidator := withGoogleValidatorBuilderStub(func(ctx context.Context) (authkit.GoogleTokenValidator, error) {
		return noopGoogleValidator{}, nil
	})
	defer restoreValidator()

	viper.Set("listen_addr", ":0")
	viper.Set("tenants_file", writeSampleTenantsFile(t))
	viper.Set("database_url", "sqlite://file::memory:?cache=shared")
	viper.Set("enable_cors", true)
	viper.Set("cors_allowed_origins", []string{"http://localhost"})

	config := mustLoadServerConfig(t)

	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), serverConfigContextKey, config))

	if err := runServer(command, nil); err != nil {
		t.Fatalf("expected runServer to succeed, got %v", err)
	}
}

func TestRunServerWithSQLiteFilePath(t *testing.T) {
	gin.SetMode(gin.TestMode)

	viper.Reset()
	defer viper.Reset()

	restoreServe := withServeHTTPStub(func(server *http.Server) error {
		if server.Handler == nil {
			t.Fatalf("expected handler to be configured")
		}
		return http.ErrServerClosed
	})
	defer restoreServe()

	restoreValidator := withGoogleValidatorBuilderStub(func(ctx context.Context) (authkit.GoogleTokenValidator, error) {
		return noopGoogleValidator{}, nil
	})
	defer restoreValidator()

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "tauth.db")
	dsn := fmt.Sprintf("sqlite:///%s", filepath.ToSlash(filePath))

	viper.Set("listen_addr", ":0")
	viper.Set("tenants_file", writeSampleTenantsFile(t))
	viper.Set("database_url", dsn)

	config := mustLoadServerConfig(t)

	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), serverConfigContextKey, config))

	if err := runServer(command, nil); err != nil {
		t.Fatalf("expected runServer to succeed with file-backed sqlite, got %v", err)
	}

	if _, err := os.Stat(filePath); err != nil {
		t.Fatalf("expected sqlite database file to exist, got %v", err)
	}
}

func TestRunServerInMemoryStore(t *testing.T) {
	gin.SetMode(gin.TestMode)

	viper.Reset()
	defer viper.Reset()

	restoreServe := withServeHTTPStub(func(server *http.Server) error {
		return http.ErrServerClosed
	})
	defer restoreServe()

	restoreValidator := withGoogleValidatorBuilderStub(func(ctx context.Context) (authkit.GoogleTokenValidator, error) {
		return noopGoogleValidator{}, nil
	})
	defer restoreValidator()

	viper.Set("listen_addr", ":0")
	viper.Set("tenants_file", writeSampleTenantsFile(t))
	viper.Set("cors_allowed_origins", []string{"http://localhost"})

	config := mustLoadServerConfig(t)

	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), serverConfigContextKey, config))

	if err := runServer(command, nil); err != nil {
		t.Fatalf("expected runServer to succeed with in-memory store, got %v", err)
	}
}

func TestRunServerHonorsContextCancellation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	viper.Reset()
	defer viper.Reset()

	shutdownTriggered := make(chan struct{})
	restoreServe := withServeHTTPStub(func(server *http.Server) error {
		server.RegisterOnShutdown(func() {
			close(shutdownTriggered)
		})
		<-shutdownTriggered
		return http.ErrServerClosed
	})
	defer restoreServe()

	restoreValidator := withGoogleValidatorBuilderStub(func(ctx context.Context) (authkit.GoogleTokenValidator, error) {
		return noopGoogleValidator{}, nil
	})
	defer restoreValidator()

	viper.Set("listen_addr", ":0")
	viper.Set("tenants_file", writeSampleTenantsFile(t))

	config := mustLoadServerConfig(t)

	commandContext, cancel := context.WithCancel(context.Background())
	defer cancel()

	command := &cobra.Command{}
	command.SetContext(context.WithValue(commandContext, serverConfigContextKey, config))

	done := make(chan error, 1)
	go func() {
		done <- runServer(command, nil)
	}()

	cancel()

	select {
	case <-shutdownTriggered:
	case <-time.After(time.Second):
		t.Fatalf("expected shutdown to be triggered after context cancellation")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected runServer to exit cleanly after cancellation, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("runServer did not exit after cancellation")
	}
}

func TestBuildTenantRegistryUsesTenantSettings(t *testing.T) {
	tenantDocument := `{
  "tenants": [
    {
      "id": "alpha",
      "display_name": "Alpha",
      "hosts": ["alpha.localhost"],
      "google_web_client_id": "alpha-client.apps.googleusercontent.com",
      "cookie_domain": ".example.com",
      "session_ttl": "20m",
      "refresh_ttl": "480h",
      "nonce_ttl": "3m",
      "allow_insecure_http": true
    },
    {
      "id": "beta",
      "display_name": "Beta",
      "hosts": ["beta.localhost"],
      "google_web_client_id": "beta-client.apps.googleusercontent.com",
      "cookie_domain": "beta.localhost",
      "session_ttl": "10m",
      "refresh_ttl": "240h",
      "nonce_ttl": "5m",
      "allow_insecure_http": false
    }
  ]
}`

	configPath := writeTenantsFileContents(t, tenantDocument)
	tenantConfig, err := tenants.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("expected tenants config to load, got %v", err)
	}

	base := authkit.ServerConfig{
		AppJWTSigningKey:  []byte("signing"),
		AppJWTIssuer:      "issuer",
		SessionCookieName: sessionCookieName,
		RefreshCookieName: refreshCookieName,
	}

	registry, err := buildTenantRegistry(base, tenantConfig, true)
	if err != nil {
		t.Fatalf("expected registry build to succeed, got %v", err)
	}

	alpha := registry.Config("alpha")
	if alpha.TenantID != "alpha" {
		t.Fatalf("expected alpha tenant, got %s", alpha.TenantID)
	}
	if alpha.GoogleWebClientID != "alpha-client.apps.googleusercontent.com" {
		t.Fatalf("unexpected google client: %s", alpha.GoogleWebClientID)
	}
	if alpha.CookieDomain != ".example.com" {
		t.Fatalf("unexpected cookie domain: %s", alpha.CookieDomain)
	}
	if alpha.NonceTTL != 3*time.Minute {
		t.Fatalf("expected nonce ttl 3m, got %s", alpha.NonceTTL)
	}
	if alpha.SameSiteMode != http.SameSiteNoneMode {
		t.Fatalf("expected SameSite None with CORS enabled")
	}

	beta := registry.Config("beta")
	if beta.AllowInsecureHTTP {
		t.Fatalf("expected beta to disallow insecure HTTP")
	}
	if beta.SessionTTL != 10*time.Minute {
		t.Fatalf("unexpected session ttl: %s", beta.SessionTTL)
	}
	if beta.RefreshTTL != 240*time.Hour {
		t.Fatalf("unexpected refresh ttl: %s", beta.RefreshTTL)
	}
}

func TestNewRootCommandHelp(t *testing.T) {
	cmd := newRootCommand()
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected help execution to succeed: %v", err)
	}
}

func TestConfigStringSlice(t *testing.T) {
	viper.Reset()
	defer viper.Reset()

	viper.Set("sample_slice", []string{"https://one.example , https://two.example", "https://three.example"})
	result := configStringSlice("sample_slice")
	expected := []string{"https://one.example", "https://two.example", "https://three.example"}

	if !reflect.DeepEqual(result, expected) {
		t.Fatalf("expected %v, got %v", expected, result)
	}
}

func TestExpandCommaSeparatedEntries(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "CommaSeparatedEntries",
			input:    []string{"https://one.example,https://two.example"},
			expected: []string{"https://one.example", "https://two.example"},
		},
		{
			name:     "TrimsWhitespace",
			input:    []string{" https://one.example , https://two.example ", "https://three.example"},
			expected: []string{"https://one.example", "https://two.example", "https://three.example"},
		},
		{
			name:     "IgnoresEmptyValues",
			input:    []string{"", "   ", "https://one.example,,https://two.example"},
			expected: []string{"https://one.example", "https://two.example"},
		},
	}

	for _, testCase := range testCases {
		tc := testCase
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := expandCommaSeparatedEntries(tc.input)
			if !reflect.DeepEqual(result, tc.expected) {
				t.Fatalf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestDemoConfigUsesResolvedTenant(t *testing.T) {
	gin.SetMode(gin.TestMode)
	viper.Reset()
	defer viper.Reset()

	tenantDocument := `{
  "tenants": [
    {
      "id": "alpha",
      "display_name": "Alpha",
      "hosts": ["alpha.localhost"],
      "google_web_client_id": "alpha-client",
      "cookie_domain": ".example.com",
      "session_ttl": "10m",
      "refresh_ttl": "10m",
      "nonce_ttl": "5m",
      "allow_insecure_http": true
    },
    {
      "id": "beta",
      "display_name": "Beta",
      "hosts": ["beta.localhost"],
      "google_web_client_id": "beta-client",
      "cookie_domain": ".example.com",
      "session_ttl": "10m",
      "refresh_ttl": "10m",
      "nonce_ttl": "5m",
      "allow_insecure_http": true
    }
  ]
}`
	viper.Set("tenants_file", writeTenantsFileContents(t, tenantDocument))
	viper.Set("listen_addr", ":0")
	viper.Set("jwt_signing_key", "secret")

	restoreServe := withServeHTTPStub(func(server *http.Server) error {
		req := httptest.NewRequest("GET", "/demo/config.js", nil)
		req.Host = "beta.localhost"
		w := httptest.NewRecorder()
		server.Handler.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Errorf("expected 200, got %d", w.Code)
		}
		body := w.Body.String()
		if !strings.Contains(body, "beta-client") {
			t.Errorf("expected beta-client in response, got %s", body)
		}
		return http.ErrServerClosed
	})
	defer restoreServe()

	restoreValidator := withGoogleValidatorBuilderStub(func(ctx context.Context) (authkit.GoogleTokenValidator, error) {
		return noopGoogleValidator{}, nil
	})
	defer restoreValidator()

	config := mustLoadServerConfig(t)
	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), serverConfigContextKey, config))

	_ = runServer(command, nil)
}

func withServeHTTPStub(stub func(server *http.Server) error) func() {
	previous := serveHTTP
	serveHTTP = stub
	return func() {
		serveHTTP = previous
	}
}

type noopGoogleValidator struct{}

func (noopGoogleValidator) Validate(ctx context.Context, token string, audience string) (*idtoken.Payload, error) {
	return &idtoken.Payload{}, nil
}

func withGoogleValidatorBuilderStub(stub func(ctx context.Context) (authkit.GoogleTokenValidator, error)) func() {
	previous := buildGoogleTokenValidator
	buildGoogleTokenValidator = stub
	return func() {
		buildGoogleTokenValidator = previous
	}
}

const sampleTenantsDocument = `{
  "tenants": [
    {
      "id": "alpha",
      "display_name": "Alpha",
      "hosts": ["alpha.localhost"],
      "google_web_client_id": "alpha-client.apps.googleusercontent.com",
      "cookie_domain": "alpha.localhost",
      "session_ttl": "15m",
      "refresh_ttl": "720h",
      "nonce_ttl": "5m",
      "allow_insecure_http": true
    }
  ]
}`

func writeSampleTenantsFile(t *testing.T) string {
	t.Helper()
	return writeTenantsFileContents(t, sampleTenantsDocument)
}

func writeTenantsFileContents(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "tenants.json")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatalf("failed to write tenants file: %v", err)
	}
	return path
}

func mustLoadServerConfig(t *testing.T) authkit.ServerConfig {
	t.Helper()
	viper.Set("jwt_signing_key", "signing-secret")
	config, err := LoadServerConfig()
	if err != nil {
		t.Fatalf("expected configuration load to succeed, got %v", err)
	}
	return config
}

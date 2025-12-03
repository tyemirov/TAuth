package main

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/tenants"
	"go.uber.org/zap"
	"google.golang.org/api/idtoken"
	"gopkg.in/yaml.v3"
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

	err := runServer(&cobra.Command{}, nil)
	if err == nil {
		t.Fatalf("expected configuration error")
	}

	expectedMessage := "config.uninitialized_server_config: server configuration not prepared; PreRunE must execute before RunE"
	if err.Error() != expectedMessage {
		t.Fatalf("expected error %q, got %q", expectedMessage, err.Error())
	}
}

func TestPrepareServerConfigLoadsFile(t *testing.T) {
	configPath := writeConfigFileFromStruct(t, sampleApplicationConfig())
	command := newRootCommand()
	if err := command.Flags().Set("config", configPath); err != nil {
		t.Fatalf("failed to set config flag: %v", err)
	}

	if err := command.PreRunE(command, nil); err != nil {
		t.Fatalf("expected prepare to succeed: %v", err)
	}
	value := command.Context().Value(appConfigContextKey)
	if value == nil {
		t.Fatalf("expected config in context")
	}
	loaded, ok := value.(*applicationConfig)
	if !ok || loaded.Server.JWTSigningKey != "signing-secret" {
		t.Fatalf("expected loaded config, got %#v", value)
	}
}

func TestPrepareServerConfigUsesEnvOverride(t *testing.T) {
	configPath := writeConfigFileFromStruct(t, sampleApplicationConfig())
	t.Setenv("TAUTH_CONFIG_FILE", configPath)
	command := newRootCommand()

	if err := command.PreRunE(command, nil); err != nil {
		t.Fatalf("expected prepare to succeed with env override: %v", err)
	}
	value := command.Context().Value(appConfigContextKey)
	if _, ok := value.(*applicationConfig); !ok {
		t.Fatalf("expected applicationConfig in context")
	}
}

func TestLoadApplicationConfigRequiresSigningKey(t *testing.T) {
	cfg := sampleApplicationConfig()
	cfg.Server.JWTSigningKey = ""
	path := writeConfigFileFromStruct(t, cfg)

	_, err := loadApplicationConfig(path)
	if err == nil {
		t.Fatalf("expected error when jwt_signing_key missing")
	}
	if !strings.Contains(err.Error(), configCodeMissingJWTSigningKey) {
		t.Fatalf("expected jwt signing key error, got %v", err)
	}
}

func TestLoadApplicationConfigRequiresTenants(t *testing.T) {
	cfg := sampleApplicationConfig()
	cfg.Tenants = nil
	path := writeConfigFileFromStruct(t, cfg)

	_, err := loadApplicationConfig(path)
	if err == nil {
		t.Fatalf("expected error when tenants missing")
	}
	if !strings.Contains(err.Error(), configCodeMissingTenants) {
		t.Fatalf("expected missing tenants error, got %v", err)
	}
}

func TestRunServerValidatorInitFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restoreServe := withServeHTTPStub(func(server *http.Server) error {
		return http.ErrServerClosed
	})
	defer restoreServe()

	restoreValidator := withGoogleValidatorBuilderStub(func(ctx context.Context) (authkit.GoogleTokenValidator, error) {
		return nil, errors.New("validator_fail")
	})
	defer restoreValidator()

	cfg := sampleApplicationConfig()
	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), appConfigContextKey, &cfg))

	if err := runServer(command, nil); err == nil || err.Error() != "config.google_validator_init: validator_fail" {
		t.Fatalf("expected google validator init error, got %v", err)
	}
}

func TestRunServerSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)

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

	cfg := sampleApplicationConfig()
	cfg.Server.DatabaseURL = "sqlite://file::memory:?cache=shared"
	cfg.Server.EnableCORS = true
	cfg.Server.CORSAllowedOrigins = []string{"http://localhost"}

	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), appConfigContextKey, &cfg))

	if err := runServer(command, nil); err != nil {
		t.Fatalf("expected runServer to succeed, got %v", err)
	}
}

func TestRunServerWithSQLiteFilePath(t *testing.T) {
	gin.SetMode(gin.TestMode)

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

	cfg := sampleApplicationConfig()
	cfg.Server.DatabaseURL = dsn

	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), appConfigContextKey, &cfg))

	if err := runServer(command, nil); err != nil {
		t.Fatalf("expected runServer to succeed with file-backed sqlite, got %v", err)
	}

	if _, err := os.Stat(filePath); err != nil {
		t.Fatalf("expected sqlite database file to exist, got %v", err)
	}
}

func TestRunServerInMemoryStore(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restoreServe := withServeHTTPStub(func(server *http.Server) error {
		return http.ErrServerClosed
	})
	defer restoreServe()

	restoreValidator := withGoogleValidatorBuilderStub(func(ctx context.Context) (authkit.GoogleTokenValidator, error) {
		return noopGoogleValidator{}, nil
	})
	defer restoreValidator()

	cfg := sampleApplicationConfig()
	cfg.Server.CORSAllowedOrigins = []string{"http://localhost"}

	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), appConfigContextKey, &cfg))

	if err := runServer(command, nil); err != nil {
		t.Fatalf("expected runServer to succeed with in-memory store, got %v", err)
	}
}

func TestRunServerHonorsContextCancellation(t *testing.T) {
	gin.SetMode(gin.TestMode)

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

	commandContext, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := sampleApplicationConfig()
	command := &cobra.Command{}
	command.SetContext(context.WithValue(commandContext, appConfigContextKey, &cfg))

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
	tenantDocument := `tenants:
  - id: "alpha"
    display_name: "Alpha"
    hosts: ["alpha.localhost"]
    google_web_client_id: "alpha-client.apps.googleusercontent.com"
    cookie_domain: ".example.com"
    session_ttl: "20m"
    refresh_ttl: "480h"
    nonce_ttl: "3m"
    allow_insecure_http: true

  - id: "beta"
    display_name: "Beta"
    hosts: ["beta.localhost"]
    google_web_client_id: "beta-client.apps.googleusercontent.com"
    cookie_domain: "beta.localhost"
    session_ttl: "10m"
    refresh_ttl: "240h"
    nonce_ttl: "5m"
    allow_insecure_http: false
`

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

	tenantDocument := `tenants:
  - id: "alpha"
    display_name: "Alpha"
    hosts: ["alpha.localhost"]
    google_web_client_id: "alpha-client"
    cookie_domain: ".example.com"
    session_ttl: "10m"
    refresh_ttl: "10m"
    nonce_ttl: "5m"
    allow_insecure_http: true

  - id: "beta"
    display_name: "Beta"
    hosts: ["beta.localhost"]
    google_web_client_id: "beta-client"
    cookie_domain: ".example.com"
    session_ttl: "10m"
    refresh_ttl: "10m"
    nonce_ttl: "5m"
    allow_insecure_http: true
`
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

	cfg := sampleApplicationConfig()
	cfg.Tenants = mustParseTenantsDocument(t, tenantDocument)
	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), appConfigContextKey, &cfg))

	_ = runServer(command, nil)
}

func TestRunServerEndToEndDemoConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restoreValidator := withGoogleValidatorBuilderStub(func(ctx context.Context) (authkit.GoogleTokenValidator, error) {
		return noopGoogleValidator{}, nil
	})
	defer restoreValidator()

	restoreServe := withServeHTTPStub(func(server *http.Server) error {
		testServer := httptest.NewServer(server.Handler)
		defer testServer.Close()

		req, err := http.NewRequest(http.MethodGet, testServer.URL+"/demo/config.js", nil)
		if err != nil {
			return err
		}
		req.Host = "beta.localhost"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("expected 200 from /demo/config.js, got %d", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		if !strings.Contains(string(body), "beta-client.apps.googleusercontent.com") {
			return fmt.Errorf("expected beta client in config")
		}

		_ = server.Shutdown(context.Background())
		return http.ErrServerClosed
	})
	defer restoreServe()

	cfg := sampleApplicationConfig()
	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), appConfigContextKey, &cfg))

	if err := runServer(command, nil); err != nil {
		t.Fatalf("expected server to run, got %v", err)
	}
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

const sampleTenantsDocument = `tenants:
  - id: "alpha"
    display_name: "Alpha"
    hosts: ["alpha.localhost"]
    google_web_client_id: "alpha-client.apps.googleusercontent.com"
    cookie_domain: "alpha.localhost"
    session_ttl: "15m"
    refresh_ttl: "720h"
    nonce_ttl: "5m"
    allow_insecure_http: true
`

func writeSampleTenantsFile(t *testing.T) string {
	t.Helper()
	return writeTenantsFileContents(t, sampleTenantsDocument)
}

func writeTenantsFileContents(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "tenants.yaml")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatalf("failed to write tenants file: %v", err)
	}
	return path
}

func sampleApplicationConfig() applicationConfig {
	return applicationConfig{
		Server: serverSettings{
			ListenAddr:                 ":0",
			JWTSigningKey:              "signing-secret",
			DatabaseURL:                "",
			EnableCORS:                 false,
			CORSAllowedOrigins:         nil,
			EnableTenantHeaderOverride: false,
		},
		Tenants: []tenants.FileTenant{
			{
				ID:                "alpha",
				DisplayName:       "Alpha",
				Hosts:             []string{"alpha.localhost"},
				GoogleWebClientID: "alpha-client.apps.googleusercontent.com",
				CookieDomain:      ".example.com",
				SessionTTL:        "20m",
				RefreshTTL:        "480h",
				NonceTTL:          "3m",
				AllowInsecureHTTP: true,
			},
			{
				ID:                "beta",
				DisplayName:       "Beta",
				Hosts:             []string{"beta.localhost"},
				GoogleWebClientID: "beta-client.apps.googleusercontent.com",
				CookieDomain:      "beta.localhost",
				SessionTTL:        "10m",
				RefreshTTL:        "240h",
				AllowInsecureHTTP: true,
				NonceTTL:          "5m",
			},
		},
	}
}

func writeConfigFileFromStruct(t *testing.T, cfg applicationConfig) string {
	t.Helper()
	payload, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	return path
}

func mustParseTenantsDocument(t *testing.T, contents string) []tenants.FileTenant {
	t.Helper()
	var doc tenants.FileDocument
	decoder := yaml.NewDecoder(strings.NewReader(contents))
	decoder.KnownFields(true)
	if err := decoder.Decode(&doc); err != nil {
		t.Fatalf("failed to parse tenants document: %v", err)
	}
	return doc.Tenants
}

func TestDeriveSameSite(t *testing.T) {
	t.Parallel()
	if mode := deriveSameSite(true, false); mode != http.SameSiteNoneMode {
		t.Fatalf("expected SameSiteNone when CORS enabled, got %v", mode)
	}
	if mode := deriveSameSite(false, true); mode != http.SameSiteLaxMode {
		t.Fatalf("expected SameSiteLax when insecure allowed, got %v", mode)
	}
	if mode := deriveSameSite(false, false); mode != http.SameSiteStrictMode {
		t.Fatalf("expected SameSiteStrict for default, got %v", mode)
	}
}

func TestPrepareServerConfigMissingFile(t *testing.T) {
	command := newRootCommand()
	if err := command.Flags().Set("config", "/path/does/not/exist"); err != nil {
		t.Fatalf("failed to set config flag: %v", err)
	}
	err := command.PreRunE(command, nil)
	if err == nil || !strings.Contains(err.Error(), configCodeMissingConfigFile) {
		t.Fatalf("expected missing config file error, got %v", err)
	}
}

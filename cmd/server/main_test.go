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
	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/tenants"
	"github.com/tyemirov/tauth/internal/web"
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
	if err := command.PersistentFlags().Set("config", configPath); err != nil {
		t.Fatalf("failed to set config flag: %v", err)
	}

	if err := command.PreRunE(command, nil); err != nil {
		t.Fatalf("expected prepare to succeed: %v", err)
	}
	value := command.Context().Value(appConfigContextKey)
	if value == nil {
		t.Fatalf("expected config in context")
	}
	if _, ok := value.(*appconfig.ApplicationConfig); !ok {
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
	if _, ok := value.(*appconfig.ApplicationConfig); !ok {
		t.Fatalf("expected applicationConfig in context")
	}
}

func TestLoadApplicationConfigRequiresTenants(t *testing.T) {
	cfg := sampleApplicationConfig()
	cfg.Tenants = nil
	path := writeConfigFileFromStruct(t, cfg)

	_, err := appconfig.LoadConfig(path)
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
	cfg.Server.CORSAllowedOrigins = []string{"https://alpha.localhost"}

	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), appConfigContextKey, &cfg))

	if err := runServer(command, nil); err != nil {
		t.Fatalf("expected runServer to succeed, got %v", err)
	}
}

func TestRunServerRejectsCORSOriginsOutsideTenants(testingHandle *testing.T) {
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
	cfg.Server.EnableCORS = true
	cfg.Server.CORSAllowedOrigins = []string{"https://external.example.com"}

	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), appConfigContextKey, &cfg))

	runErr := runServer(command, nil)
	if runErr == nil {
		testingHandle.Fatalf("expected CORS allowlist validation error")
	}
	if !strings.Contains(runErr.Error(), configCodeCORSOriginNotAllowed) {
		testingHandle.Fatalf("expected CORS allowlist error code, got %v", runErr)
	}
}

func TestRunServerAllowsCORSExceptionOrigins(testingHandle *testing.T) {
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
	cfg.Server.EnableCORS = true
	cfg.Server.CORSAllowedOrigins = []string{"https://accounts.google.com"}
	cfg.Server.CORSAllowedOriginExceptions = []string{"https://accounts.google.com"}

	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), appConfigContextKey, &cfg))

	if err := runServer(command, nil); err != nil {
		testingHandle.Fatalf("expected CORS exception to be allowed, got %v", err)
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
	cfg.Server.CORSAllowedOrigins = []string{"https://alpha.localhost"}

	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), appConfigContextKey, &cfg))

	if err := runServer(command, nil); err != nil {
		t.Fatalf("expected runServer to succeed with in-memory store, got %v", err)
	}
}

func TestRunServerHonorsContextCancellation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	shutdownTriggered := make(chan struct{})
	serverReady := make(chan struct{})
	restoreServe := withServeHTTPStub(func(server *http.Server) error {
		server.RegisterOnShutdown(func() {
			close(shutdownTriggered)
		})
		close(serverReady)
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

	select {
	case <-serverReady:
	case <-time.After(time.Second):
		t.Fatalf("runServer did not start serving before cancellation")
	}

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
    tenant_origins: ["https://alpha.localhost"]
    google_web_client_id: "alpha-client.apps.googleusercontent.com"
    jwt_signing_key: "alpha-tenant-key"
    cookie_domain: ".example.com"
    session_cookie_name: "app_session_alpha"
    refresh_cookie_name: "app_refresh_alpha"
    session_ttl: "20m"
    refresh_ttl: "480h"
    nonce_ttl: "3m"
    allow_insecure_http: true

  - id: "beta"
    display_name: "Beta"
    tenant_origins: ["https://beta.localhost"]
    google_web_client_id: "beta-client.apps.googleusercontent.com"
    jwt_signing_key: "beta-tenant-key"
    cookie_domain: "beta.localhost"
    session_cookie_name: "app_session_beta"
    refresh_cookie_name: "app_refresh_beta"
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

	sameSiteResolver := authkit.NewSameSiteResolver(true)
	registry, err := authkit.BuildTenantRegistry(base, tenantConfig, sameSiteResolver)
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
	if alpha.SameSiteMode != http.SameSiteLaxMode {
		t.Fatalf("expected SameSite Lax when CORS enabled but insecure HTTP allowed")
	}

	beta := registry.Config("beta")
	if beta.AllowInsecureHTTP {
		t.Fatalf("expected beta to disallow insecure HTTP")
	}
	if beta.SameSiteMode != http.SameSiteNoneMode {
		t.Fatalf("expected SameSite None for secure tenant behind CORS")
	}
	if beta.SessionTTL != 10*time.Minute {
		t.Fatalf("unexpected session ttl: %s", beta.SessionTTL)
	}
	if beta.RefreshTTL != 240*time.Hour {
		t.Fatalf("unexpected refresh ttl: %s", beta.RefreshTTL)
	}
}

func TestBuildTenantRegistryUsesTenantSpecificCookieNames(t *testing.T) {
	base := authkit.ServerConfig{
		AppJWTSigningKey:  []byte("signing"),
		AppJWTIssuer:      "issuer",
		SessionCookieName: sessionCookieName,
		RefreshCookieName: refreshCookieName,
	}
	document := tenants.FileDocument{
		Tenants: []tenants.FileTenant{
			{
				ID:                "alpha",
				DisplayName:       "Alpha",
				TenantOrigins:     []string{"https://alpha.localhost"},
				GoogleWebClientID: "alpha-client.apps.googleusercontent.com",
				JWTSigningKey:     "alpha-key",
				CookieDomain:      "",
				SessionCookieName: "app_session_alpha",
				RefreshCookieName: "app_refresh_alpha",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
			},
			{
				ID:                "beta",
				DisplayName:       "Beta",
				TenantOrigins:     []string{"https://beta.localhost"},
				GoogleWebClientID: "beta-client.apps.googleusercontent.com",
				JWTSigningKey:     "beta-key",
				CookieDomain:      "",
				SessionCookieName: "app_session_beta",
				RefreshCookieName: "app_refresh_beta",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
			},
		},
	}
	tenantConfig, err := tenants.LoadConfigFromDocument(document)
	if err != nil {
		t.Fatalf("load tenant config: %v", err)
	}

	sameSiteResolver := authkit.NewSameSiteResolver(false)
	registry, err := authkit.BuildTenantRegistry(base, tenantConfig, sameSiteResolver)
	if err != nil {
		t.Fatalf("build registry: %v", err)
	}
	alpha := registry.Config("alpha")
	if alpha.SessionCookieName != "app_session_alpha" || alpha.RefreshCookieName != "app_refresh_alpha" {
		t.Fatalf("expected alpha cookies to be tenant-specific, got %s / %s", alpha.SessionCookieName, alpha.RefreshCookieName)
	}
	beta := registry.Config("beta")
	if beta.SessionCookieName != "app_session_beta" || beta.RefreshCookieName != "app_refresh_beta" {
		t.Fatalf("expected beta cookies to be tenant-specific, got %s / %s", beta.SessionCookieName, beta.RefreshCookieName)
	}
}

func TestStaticAuthClientRequiresKnownOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	document := tenants.FileDocument{
		Tenants: []tenants.FileTenant{
			{
				ID:                "demo",
				DisplayName:       "Demo",
				TenantOrigins:     []string{"https://demo.localhost"},
				GoogleWebClientID: "demo-client.apps.googleusercontent.com",
				JWTSigningKey:     "demo-key",
				CookieDomain:      "",
				SessionCookieName: "app_session_demo",
				RefreshCookieName: "app_refresh_demo",
				SessionTTL:        "30m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
				AllowInsecureHTTP: true,
			},
		},
	}
	config, err := tenants.LoadConfigFromDocument(document)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	router := gin.New()
	router.GET("/tauth.js", serveStaticJSHandler(config, "tauth.js"))

	validRequest := httptest.NewRequest(http.MethodGet, "/tauth.js", nil)
	validRequest.Host = "demo.localhost"
	validRequest.Header.Set("Origin", "https://demo.localhost")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, validRequest)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for known origin, got %d", recorder.Code)
	}

	unknownRequest := httptest.NewRequest(http.MethodGet, "/tauth.js", nil)
	unknownRequest.Host = "unknown.localhost"
	unknownRequest.Header.Set("Origin", "https://unknown.localhost")
	unknownRecorder := httptest.NewRecorder()
	router.ServeHTTP(unknownRecorder, unknownRequest)
	if unknownRecorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unknown origin, got %d", unknownRecorder.Code)
	}
}

func TestStaticAuthClientAllowsMissingOriginForSharedOrigins(t *testing.T) {
	gin.SetMode(gin.TestMode)
	document := tenants.FileDocument{
		Tenants: []tenants.FileTenant{
			{
				ID:                "notes",
				DisplayName:       "Notes",
				TenantOrigins:     []string{"https://shared.localhost", "http://localhost:8000"},
				GoogleWebClientID: "notes-client.apps.googleusercontent.com",
				JWTSigningKey:     "notes-key",
				CookieDomain:      "",
				SessionCookieName: "app_session_notes",
				RefreshCookieName: "app_refresh_notes",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
				AllowInsecureHTTP: true,
			},
			{
				ID:                "mpr",
				DisplayName:       "MPR",
				TenantOrigins:     []string{"https://shared.localhost", "http://localhost:4173"},
				GoogleWebClientID: "mpr-client.apps.googleusercontent.com",
				JWTSigningKey:     "mpr-key",
				CookieDomain:      "",
				SessionCookieName: "app_session_mpr",
				RefreshCookieName: "app_refresh_mpr",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
				AllowInsecureHTTP: true,
			},
		},
	}
	config, err := tenants.LoadConfigFromDocument(document)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	router := gin.New()
	router.GET("/tauth.js", serveStaticJSHandler(config, "tauth.js"))

	makeRecorder := func(origin string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "/tauth.js", nil)
		request.Host = "shared.localhost"
		if origin != "" {
			request.Header.Set("Origin", origin)
		}
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		return recorder
	}

	if resp := makeRecorder("http://localhost:8000"); resp.Code != http.StatusOK {
		t.Fatalf("expected 200 for notes origin, got %d", resp.Code)
	}
	if resp := makeRecorder("http://localhost:4173"); resp.Code != http.StatusOK {
		t.Fatalf("expected 200 for mpr origin, got %d", resp.Code)
	}
	if resp := makeRecorder(""); resp.Code != http.StatusOK {
		t.Fatalf("expected 200 when origin missing, got %d", resp.Code)
	}
	if resp := makeRecorder("http://unknown.localhost"); resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unknown origin, got %d", resp.Code)
	}
}

func TestOriginGateMiddlewareRequiresOriginForSharedOrigins(t *testing.T) {
	gin.SetMode(gin.TestMode)
	document := tenants.FileDocument{
		Tenants: []tenants.FileTenant{
			{
				ID:                "notes",
				DisplayName:       "Notes",
				TenantOrigins:     []string{"https://shared.localhost", "http://localhost:8000"},
				GoogleWebClientID: "notes-client.apps.googleusercontent.com",
				JWTSigningKey:     "notes-key",
				CookieDomain:      "",
				SessionCookieName: "app_session_notes",
				RefreshCookieName: "app_refresh_notes",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
			},
			{
				ID:                "mpr",
				DisplayName:       "MPR",
				TenantOrigins:     []string{"https://shared.localhost", "http://localhost:4173"},
				GoogleWebClientID: "mpr-client.apps.googleusercontent.com",
				JWTSigningKey:     "mpr-key",
				CookieDomain:      "",
				SessionCookieName: "app_session_mpr",
				RefreshCookieName: "app_refresh_mpr",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
			},
		},
	}
	config, err := tenants.LoadConfigFromDocument(document)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	router := gin.New()
	router.Use(originGateMiddleware(config, false))
	router.GET("/ping", func(context *gin.Context) {
		context.Status(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodGet, "/ping", nil)
	request.Host = "shared.localhost"
	request.Header.Set("Origin", "http://localhost:8000")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for allowed origin, got %d", recorder.Code)
	}

	noOrigin := httptest.NewRequest(http.MethodGet, "/ping", nil)
	noOrigin.Host = "shared.localhost"
	noOriginRecorder := httptest.NewRecorder()
	router.ServeHTTP(noOriginRecorder, noOrigin)
	if noOriginRecorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when origin missing, got %d", noOriginRecorder.Code)
	}

	unknownOrigin := httptest.NewRequest(http.MethodGet, "/ping", nil)
	unknownOrigin.Host = "shared.localhost"
	unknownOrigin.Header.Set("Origin", "http://unknown.localhost")
	unknownOriginRecorder := httptest.NewRecorder()
	router.ServeHTTP(unknownOriginRecorder, unknownOrigin)
	if unknownOriginRecorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unknown origin, got %d", unknownOriginRecorder.Code)
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
			result := appconfig.ExpandCommaSeparatedEntries(tc.input)
			if !reflect.DeepEqual(result, tc.expected) {
				t.Fatalf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestSeedPasswordUsersLoadsConfiguredCredentials(testingHandle *testing.T) {
	passwordHash, hashErr := authkit.HashPassword("correct horse battery staple")
	if hashErr != nil {
		testingHandle.Fatalf("failed to hash password: %v", hashErr)
	}
	tenant := tenants.FileTenant{
		ID:                "alpha",
		DisplayName:       "Alpha",
		TenantOrigins:     []string{"https://alpha.localhost"},
		GoogleWebClientID: "alpha-client.apps.googleusercontent.com",
		JWTSigningKey:     "alpha-key",
		CookieDomain:      ".example.com",
		SessionCookieName: "app_session_alpha",
		RefreshCookieName: "app_refresh_alpha",
		SessionTTL:        "20m",
		RefreshTTL:        "480h",
		NonceTTL:          "3m",
		AllowInsecureHTTP: true,
		PasswordAuth: tenants.FilePasswordAuth{
			Enabled: true,
			Users: []tenants.FilePasswordUser{
				{
					Email:        "User@Example.com",
					DisplayName:  "Password User",
					AvatarURL:    "https://example.com/password.png",
					PasswordHash: passwordHash,
				},
			},
		},
	}
	tenantConfig, configErr := tenants.LoadConfigFromDocument(tenants.FileDocument{Tenants: []tenants.FileTenant{tenant}})
	if configErr != nil {
		testingHandle.Fatalf("failed to load tenant config: %v", configErr)
	}
	userStore := web.NewInMemoryUsers()
	passwordStore := authkit.NewMemoryPasswordCredentialStore()
	seedErr := seedPasswordUsers(context.Background(), tenantConfig, userStore, passwordStore)
	if seedErr != nil {
		testingHandle.Fatalf("failed to seed password users: %v", seedErr)
	}
	profile, authErr := passwordStore.AuthenticatePassword(context.Background(), "alpha", "user@example.com", "correct horse battery staple")
	if authErr != nil {
		testingHandle.Fatalf("expected password auth to pass: %v", authErr)
	}
	if profile.UserEmail != "user@example.com" || profile.DisplayName != "Password User" {
		testingHandle.Fatalf("unexpected password profile: %#v", profile)
	}
	email, display, avatarURL, roles, profileErr := userStore.GetUserProfile(context.Background(), "alpha", "email:user@example.com")
	if profileErr != nil {
		testingHandle.Fatalf("expected seeded user profile: %v", profileErr)
	}
	if email != "user@example.com" || display != "Password User" || avatarURL != "https://example.com/password.png" {
		testingHandle.Fatalf("unexpected seeded user profile")
	}
	if len(roles) != 1 || roles[0] != "user" {
		testingHandle.Fatalf("unexpected seeded roles: %#v", roles)
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

func writeTenantsFileContents(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "tenants.yaml")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatalf("failed to write tenants file: %v", err)
	}
	return path
}

func sampleApplicationConfig() appconfig.ApplicationConfig {
	return appconfig.ApplicationConfig{
		Server: appconfig.ServerSettings{
			ListenAddr:                 ":0",
			DatabaseURL:                "",
			EnableCORS:                 false,
			CORSAllowedOrigins:         nil,
			EnableTenantHeaderOverride: false,
		},
		Tenants: []tenants.FileTenant{
			{
				ID:                "alpha",
				DisplayName:       "Alpha",
				TenantOrigins:     []string{"https://alpha.localhost"},
				GoogleWebClientID: "alpha-client.apps.googleusercontent.com",
				JWTSigningKey:     "alpha-key",
				CookieDomain:      ".example.com",
				SessionCookieName: "app_session_alpha",
				RefreshCookieName: "app_refresh_alpha",
				SessionTTL:        "20m",
				RefreshTTL:        "480h",
				NonceTTL:          "3m",
				AllowInsecureHTTP: true,
			},
			{
				ID:                "beta",
				DisplayName:       "Beta",
				TenantOrigins:     []string{"https://beta.localhost"},
				GoogleWebClientID: "beta-client.apps.googleusercontent.com",
				JWTSigningKey:     "beta-key",
				CookieDomain:      "beta.localhost",
				SessionCookieName: "app_session_beta",
				RefreshCookieName: "app_refresh_beta",
				SessionTTL:        "10m",
				RefreshTTL:        "240h",
				AllowInsecureHTTP: true,
				NonceTTL:          "5m",
			},
		},
	}
}

func writeConfigFileFromStruct(t *testing.T, cfg appconfig.ApplicationConfig) string {
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

func TestOriginAllowedRequiresOverrideWhenOriginMissing(testingHandle *testing.T) {
	testingHandle.Helper()
	document := tenants.FileDocument{
		Tenants: []tenants.FileTenant{
			{
				ID:                "notes",
				DisplayName:       "Notes",
				TenantOrigins:     []string{"https://shared.localhost", "http://localhost:8000"},
				GoogleWebClientID: "notes-client",
				JWTSigningKey:     "notes-key",
				CookieDomain:      "",
				SessionCookieName: "app_session_notes",
				RefreshCookieName: "app_refresh_notes",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
			},
			{
				ID:                "mpr",
				DisplayName:       "MPR",
				TenantOrigins:     []string{"https://shared.localhost", "http://localhost:4173"},
				GoogleWebClientID: "mpr-client",
				JWTSigningKey:     "mpr-key",
				CookieDomain:      "",
				SessionCookieName: "app_session_mpr",
				RefreshCookieName: "app_refresh_mpr",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
			},
		},
	}
	config, err := tenants.LoadConfigFromDocument(document)
	if err != nil {
		testingHandle.Fatalf("load tenant config: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/auth/nonce", nil)
	request.Host = "shared.localhost"

	if originAllowed(request, config, false) {
		testingHandle.Fatalf("expected missing origin to be rejected when header override disabled")
	}
	if originAllowed(request, config, true) {
		testingHandle.Fatalf("expected missing origin to be rejected without override header")
	}
	request.Header.Set(tenantHeaderName, "missing")
	if originAllowed(request, config, true) {
		testingHandle.Fatalf("expected missing origin to be rejected with invalid override")
	}
	request.Header.Set(tenantHeaderName, "notes")
	if !originAllowed(request, config, true) {
		testingHandle.Fatalf("expected missing origin to pass with valid override")
	}
}

func TestDeriveSameSite(t *testing.T) {
	t.Parallel()
	if mode := authkit.NewSameSiteResolver(true)(true); mode != http.SameSiteLaxMode {
		t.Fatalf("expected SameSiteLax when CORS enabled but HTTP is allowed, got %v", mode)
	}
	if mode := authkit.NewSameSiteResolver(true)(false); mode != http.SameSiteNoneMode {
		t.Fatalf("expected SameSiteNone when CORS enabled, got %v", mode)
	}
	if mode := authkit.NewSameSiteResolver(false)(true); mode != http.SameSiteLaxMode {
		t.Fatalf("expected SameSiteLax when insecure allowed, got %v", mode)
	}
	if mode := authkit.NewSameSiteResolver(false)(false); mode != http.SameSiteStrictMode {
		t.Fatalf("expected SameSiteStrict for default, got %v", mode)
	}
}

func TestPrepareServerConfigMissingFile(t *testing.T) {
	command := newRootCommand()
	if err := command.PersistentFlags().Set("config", "/path/does/not/exist"); err != nil {
		t.Fatalf("failed to set config flag: %v", err)
	}
	err := command.PreRunE(command, nil)
	if err == nil || !strings.Contains(err.Error(), configCodeMissingConfigFile) {
		t.Fatalf("expected missing config file error, got %v", err)
	}
}

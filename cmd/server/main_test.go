package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/tyemirov/tauth/internal/authkit"
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

func TestLoadServerConfigRequiresGoogleClientID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	viper.Reset()
	defer viper.Reset()

	viper.Set("jwt_signing_key", "signing-secret")
	viper.Set("session_ttl", time.Minute)
	viper.Set("refresh_ttl", time.Hour)

	_, err := LoadServerConfig()
	if err == nil {
		t.Fatalf("expected error when google_web_client_id is missing")
	}
	expectedMessage := "config.missing_google_web_client_id: google_web_client_id must be provided"
	if err.Error() != expectedMessage {
		t.Fatalf("expected error %q, got %q", expectedMessage, err.Error())
	}
}

func TestLoadServerConfigRequiresPositiveSessionTTL(t *testing.T) {
	gin.SetMode(gin.TestMode)

	viper.Reset()
	defer viper.Reset()

	viper.Set("google_web_client_id", "client")
	viper.Set("jwt_signing_key", "signing-secret")
	viper.Set("session_ttl", 0)
	viper.Set("refresh_ttl", time.Hour)

	_, err := LoadServerConfig()
	if err == nil {
		t.Fatalf("expected error when session_ttl is non-positive")
	}

	expectedMessage := "config.invalid_session_ttl: session_ttl must be greater than zero"
	if err.Error() != expectedMessage {
		t.Fatalf("expected error %q, got %q", expectedMessage, err.Error())
	}
}

func TestRunServerMissingSigningKeyReportsField(t *testing.T) {
	gin.SetMode(gin.TestMode)

	viper.Reset()
	defer viper.Reset()

	viper.Set("google_web_client_id", "provided-client-id")

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
	viper.Set("google_web_client_id", "client")
	viper.Set("jwt_signing_key", "signing-secret")
	viper.Set("session_ttl", time.Minute)
	viper.Set("refresh_ttl", time.Hour)

	config, err := LoadServerConfig()
	if err != nil {
		t.Fatalf("expected configuration load to succeed, got %v", err)
	}

	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), serverConfigContextKey, config))

	if err := runServer(command, nil); err == nil || err.Error() != "config.google_validator_init: validator_fail" {
		t.Fatalf("expected google validator init error, got %v", err)
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
	viper.Set("google_web_client_id", "client")
	viper.Set("jwt_signing_key", "signing-secret")
	viper.Set("cookie_domain", "localhost")
	viper.Set("session_ttl", time.Minute)
	viper.Set("refresh_ttl", time.Hour)
	viper.Set("dev_insecure_http", true)
	viper.Set("database_url", "sqlite://file::memory:?cache=shared")
	viper.Set("enable_cors", true)

	config, err := LoadServerConfig()
	if err != nil {
		t.Fatalf("expected configuration load to succeed, got %v", err)
	}

	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), serverConfigContextKey, config))

	if err := runServer(command, nil); err != nil {
		t.Fatalf("expected runServer to succeed, got %v", err)
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
	viper.Set("google_web_client_id", "client")
	viper.Set("jwt_signing_key", "signing-secret")
	viper.Set("session_ttl", time.Minute)
	viper.Set("refresh_ttl", time.Hour)
	viper.Set("dev_insecure_http", true)

	config, err := LoadServerConfig()
	if err != nil {
		t.Fatalf("expected configuration load to succeed, got %v", err)
	}

	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), serverConfigContextKey, config))

	if err := runServer(command, nil); err != nil {
		t.Fatalf("expected runServer to succeed with in-memory store, got %v", err)
	}
}

func TestNewRootCommandHelp(t *testing.T) {
	cmd := newRootCommand()
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected help execution to succeed: %v", err)
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

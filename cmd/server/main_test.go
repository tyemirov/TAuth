package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
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

	viper.Set("listen_addr", ":0")
	viper.Set("google_web_client_id", "client")
	viper.Set("jwt_signing_key", "signing-secret")
	viper.Set("cookie_domain", "localhost")
	viper.Set("session_ttl", time.Minute)
	viper.Set("refresh_ttl", time.Hour)
	viper.Set("dev_insecure_http", true)
	viper.Set("database_url", "sqlite://file::memory:?cache=shared")
	viper.Set("enable_cors", true)

	if err := runServer(&cobra.Command{}, nil); err != nil {
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

	viper.Set("listen_addr", ":0")
	viper.Set("google_web_client_id", "client")
	viper.Set("jwt_signing_key", "signing-secret")
	viper.Set("session_ttl", time.Minute)
	viper.Set("refresh_ttl", time.Hour)
	viper.Set("dev_insecure_http", true)

	if err := runServer(&cobra.Command{}, nil); err != nil {
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

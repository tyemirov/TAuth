package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/web"
	webassets "github.com/tyemirov/tauth/web"
	"go.uber.org/zap"
)

var serveHTTP = func(server *http.Server) error {
	return server.ListenAndServe()
}

var buildGoogleTokenValidator = func(ctx context.Context) (authkit.GoogleTokenValidator, error) {
	return authkit.NewGoogleTokenValidator(ctx)
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:     "tauth",
		Short:   "Auth service with Google Sign-In verification, JWT sessions, and rotating refresh tokens",
		PreRunE: prepareServerConfig,
		RunE:    runServer,
	}

	rootCmd.Flags().String("listen_addr", ":8080", "HTTP listen address")
	rootCmd.Flags().String("cookie_domain", "", "Cookie domain; empty for host-only")
	rootCmd.Flags().String("google_web_client_id", "", "Google Web OAuth Client ID")
	rootCmd.Flags().String("jwt_signing_key", "", "HS256 signing secret for access JWT")
	rootCmd.Flags().Duration("session_ttl", 15*time.Minute, "Access token TTL")
	rootCmd.Flags().Duration("refresh_ttl", 60*24*time.Hour, "Refresh token TTL")
	rootCmd.Flags().Bool("dev_insecure_http", false, "Allow insecure HTTP for local dev")
	rootCmd.Flags().String("database_url", "", "Database URL for refresh tokens (postgres:// or sqlite://; leave empty for in-memory store)")
	rootCmd.Flags().Bool("enable_cors", false, "Enable CORS for cross-origin clients (required to set SameSite=None cookies)")
	rootCmd.Flags().StringSlice("cors_allowed_origins", []string{}, "Allowed origins when CORS is enabled (required if enable_cors is true)")
	rootCmd.Flags().Duration("nonce_ttl", 5*time.Minute, "Nonce lifetime for Google Sign-In exchanges")

	_ = viper.BindPFlag("listen_addr", rootCmd.Flags().Lookup("listen_addr"))
	_ = viper.BindPFlag("cookie_domain", rootCmd.Flags().Lookup("cookie_domain"))
	_ = viper.BindPFlag("google_web_client_id", rootCmd.Flags().Lookup("google_web_client_id"))
	_ = viper.BindPFlag("jwt_signing_key", rootCmd.Flags().Lookup("jwt_signing_key"))
	_ = viper.BindPFlag("session_ttl", rootCmd.Flags().Lookup("session_ttl"))
	_ = viper.BindPFlag("refresh_ttl", rootCmd.Flags().Lookup("refresh_ttl"))
	_ = viper.BindPFlag("dev_insecure_http", rootCmd.Flags().Lookup("dev_insecure_http"))
	_ = viper.BindPFlag("database_url", rootCmd.Flags().Lookup("database_url"))
	_ = viper.BindPFlag("enable_cors", rootCmd.Flags().Lookup("enable_cors"))
	_ = viper.BindPFlag("cors_allowed_origins", rootCmd.Flags().Lookup("cors_allowed_origins"))
	_ = viper.BindPFlag("nonce_ttl", rootCmd.Flags().Lookup("nonce_ttl"))

	viper.SetEnvPrefix("APP")
	viper.AutomaticEnv()

	return rootCmd
}

const (
	sessionCookieName = "app_session"
	refreshCookieName = "app_refresh"

	configCodeMissingGoogleClientID   = "config.missing_google_web_client_id"
	configCodeMissingJWTSigningKey    = "config.missing_jwt_signing_key"
	configCodeInvalidSessionTTL       = "config.invalid_session_ttl"
	configCodeInvalidRefreshTTL       = "config.invalid_refresh_ttl"
	configCodeUninitializedServerConf = "config.uninitialized_server_config"
	configCodeGoogleValidatorInit     = "config.google_validator_init"
)

type contextKey string

const serverConfigContextKey contextKey = "serverConfig"

func prepareServerConfig(command *cobra.Command, arguments []string) error {
	serverConfig, loadErr := LoadServerConfig()
	if loadErr != nil {
		return loadErr
	}
	existingContext := command.Context()
	if existingContext == nil {
		existingContext = context.Background()
	}
	command.SetContext(context.WithValue(existingContext, serverConfigContextKey, serverConfig))
	return nil
}

func configError(code, message string) error {
	return fmt.Errorf("%s: %s", code, message)
}

func LoadServerConfig() (authkit.ServerConfig, error) {
	googleWebClientID := viper.GetString("google_web_client_id")
	if googleWebClientID == "" {
		return authkit.ServerConfig{}, configError(configCodeMissingGoogleClientID, "google_web_client_id must be provided")
	}

	jwtSigningKey := viper.GetString("jwt_signing_key")
	if jwtSigningKey == "" {
		return authkit.ServerConfig{}, configError(configCodeMissingJWTSigningKey, "jwt_signing_key must be provided")
	}

	sessionTTL := viper.GetDuration("session_ttl")
	if sessionTTL <= 0 {
		return authkit.ServerConfig{}, configError(configCodeInvalidSessionTTL, "session_ttl must be greater than zero")
	}

	refreshTTL := viper.GetDuration("refresh_ttl")
	if refreshTTL <= 0 {
		return authkit.ServerConfig{}, configError(configCodeInvalidRefreshTTL, "refresh_ttl must be greater than zero")
	}

	nonceTTL := 5 * time.Minute
	if configuredNonceTTL := viper.GetDuration("nonce_ttl"); configuredNonceTTL > 0 {
		nonceTTL = configuredNonceTTL
	}

	return authkit.ServerConfig{
		GoogleWebClientID: googleWebClientID,
		AppJWTSigningKey:  []byte(jwtSigningKey),
		AppJWTIssuer:      "mprlab-auth",
		CookieDomain:      viper.GetString("cookie_domain"),
		SessionCookieName: sessionCookieName,
		RefreshCookieName: refreshCookieName,
		SessionTTL:        sessionTTL,
		RefreshTTL:        refreshTTL,
		NonceTTL:          nonceTTL,
	}, nil
}

func runServer(command *cobra.Command, arguments []string) error {
	logger, loggerErr := zap.NewProduction()
	if loggerErr != nil {
		return loggerErr
	}
	defer func() { _ = logger.Sync() }()

	commandContext := command.Context()
	var contextValue any
	if commandContext != nil {
		contextValue = commandContext.Value(serverConfigContextKey)
	}
	serverConfig, ok := contextValue.(authkit.ServerConfig)
	if !ok {
		return configError(configCodeUninitializedServerConf, "server configuration not prepared; PreRunE must execute before RunE")
	}

	listenAddr := viper.GetString("listen_addr")
	devInsecureHTTP := viper.GetBool("dev_insecure_http")
	databaseURL := viper.GetString("database_url")
	enableCORS := viper.GetBool("enable_cors")
	corsAllowedOrigins := viper.GetStringSlice("cors_allowed_origins")

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(zapLoggerMiddleware(logger))

	if enableCORS {
		corsMiddleware, corsErr := web.PermissiveCORS(corsAllowedOrigins)
		if corsErr != nil {
			return corsErr
		}
		router.Use(corsMiddleware)
	}

	router.GET("/static/auth-client.js", func(contextGin *gin.Context) {
		web.ServeEmbeddedStaticJS(contextGin, webassets.FS, "auth-client.js")
	})

	router.GET("/demo/config.js", func(contextGin *gin.Context) {
		web.ServeDemoConfig(contextGin, web.DemoConfig{
			GoogleClientID: serverConfig.GoogleWebClientID,
		})
	})

	router.GET("/demo", func(contextGin *gin.Context) {
		contextGin.File("web/demo.html")
	})

	userStore := web.NewInMemoryUsers()
	var refreshStore authkit.RefreshTokenStore

	if databaseURL != "" {
		persistentStore, storeErr := authkit.NewDatabaseRefreshTokenStore(context.Background(), databaseURL)
		if storeErr != nil {
			return storeErr
		}
		refreshStore = persistentStore
		logger.Info("using persistent refresh token store", zap.String("driver", persistentStore.Driver()))
	} else {
		refreshStore = authkit.NewMemoryRefreshTokenStore()
		logger.Info("using in-memory refresh token store")
	}

	serverConfig.AllowInsecureHTTP = devInsecureHTTP
	serverConfig.SameSiteMode = http.SameSiteStrictMode
	if enableCORS {
		serverConfig.SameSiteMode = http.SameSiteNoneMode
	}

	nonceStore := authkit.NewMemoryNonceStore(serverConfig.NonceTTL)

	validator, validatorErr := buildGoogleTokenValidator(command.Context())
	if validatorErr != nil {
		return fmt.Errorf("%s: %w", configCodeGoogleValidatorInit, validatorErr)
	}
	authkit.ProvideGoogleTokenValidator(validator)
	defer authkit.ProvideGoogleTokenValidator(nil)

	clock := authkit.NewSystemClock()
	authkit.ProvideClock(clock)
	defer authkit.ProvideClock(nil)

	authkit.ProvideLogger(logger)
	defer authkit.ProvideLogger(nil)

	metricsRecorder := authkit.NewCounterMetrics()
	authkit.ProvideMetrics(metricsRecorder)
	defer authkit.ProvideMetrics(nil)

	authkit.MountAuthRoutes(router, serverConfig, userStore, refreshStore, nonceStore)

	protected := router.Group("/api")
	protected.Use(authkit.RequireSession(serverConfig))
	protected.GET("/me", web.HandleWhoAmI(userStore, logger))

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}

	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	defer shutdownCancel()

	go func() {
		stopSignals := make(chan os.Signal, 1)
		signal.Notify(stopSignals, syscall.SIGINT, syscall.SIGTERM)
		<-stopSignals
		graceCtx, graceCancel := context.WithTimeout(shutdownCtx, 10*time.Second)
		defer graceCancel()
		if err := server.Shutdown(graceCtx); err != nil {
			logger.Error("server shutdown error", zap.Error(err))
		}
	}()

	logger.Info("listening", zap.String("addr", listenAddr))
	if err := serveHTTP(server); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("listen error: %w", err)
	}
	return nil
}

func zapLoggerMiddleware(logger *zap.Logger) gin.HandlerFunc {
	return func(contextGin *gin.Context) {
		startTime := time.Now()
		contextGin.Next()
		duration := time.Since(startTime)
		logger.Info("http",
			zap.String("method", contextGin.Request.Method),
			zap.String("path", contextGin.Request.URL.Path),
			zap.Int("status", contextGin.Writer.Status()),
			zap.String("ip", contextGin.ClientIP()),
			zap.Duration("elapsed", duration),
		)
	}
}

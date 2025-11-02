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
	"github.com/tyemirov/authservice/internal/authkit"
	"github.com/tyemirov/authservice/internal/authkitpg"
	"github.com/tyemirov/authservice/internal/web"
	webassets "github.com/tyemirov/authservice/web"
	"go.uber.org/zap"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "authservice",
		Short: "Auth service with Google Sign-In verification, JWT sessions, and rotating refresh tokens",
		RunE:  runServer,
	}

	rootCmd.Flags().String("listen_addr", ":8080", "HTTP listen address")
	rootCmd.Flags().String("cookie_domain", "", "Cookie domain; empty for host-only")
	rootCmd.Flags().String("google_web_client_id", "", "Google Web OAuth Client ID")
	rootCmd.Flags().String("jwt_signing_key", "", "HS256 signing secret for access JWT")
	rootCmd.Flags().Duration("session_ttl", 15*time.Minute, "Access token TTL")
	rootCmd.Flags().Duration("refresh_ttl", 60*24*time.Hour, "Refresh token TTL")
	rootCmd.Flags().Bool("dev_insecure_http", false, "Allow insecure HTTP for local dev")
	rootCmd.Flags().String("postgres_url", "", "PostgreSQL URL for refresh tokens (leave empty to use in-memory store)")
	rootCmd.Flags().Bool("enable_cors", false, "Enable permissive CORS (only if serving cross-origin UI)")

	_ = viper.BindPFlag("listen_addr", rootCmd.Flags().Lookup("listen_addr"))
	_ = viper.BindPFlag("cookie_domain", rootCmd.Flags().Lookup("cookie_domain"))
	_ = viper.BindPFlag("google_web_client_id", rootCmd.Flags().Lookup("google_web_client_id"))
	_ = viper.BindPFlag("jwt_signing_key", rootCmd.Flags().Lookup("jwt_signing_key"))
	_ = viper.BindPFlag("session_ttl", rootCmd.Flags().Lookup("session_ttl"))
	_ = viper.BindPFlag("refresh_ttl", rootCmd.Flags().Lookup("refresh_ttl"))
	_ = viper.BindPFlag("dev_insecure_http", rootCmd.Flags().Lookup("dev_insecure_http"))
	_ = viper.BindPFlag("postgres_url", rootCmd.Flags().Lookup("postgres_url"))
	_ = viper.BindPFlag("enable_cors", rootCmd.Flags().Lookup("enable_cors"))

	viper.SetEnvPrefix("APP")
	viper.AutomaticEnv()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runServer(command *cobra.Command, arguments []string) error {
	logger, loggerErr := zap.NewProduction()
	if loggerErr != nil {
		return loggerErr
	}
	defer func() { _ = logger.Sync() }()

	listenAddr := viper.GetString("listen_addr")
	googleWebClientID := viper.GetString("google_web_client_id")
	jwtSigningKey := viper.GetString("jwt_signing_key")
	cookieDomain := viper.GetString("cookie_domain")
	sessionTTL := viper.GetDuration("session_ttl")
	refreshTTL := viper.GetDuration("refresh_ttl")
	devInsecureHTTP := viper.GetBool("dev_insecure_http")
	postgresURL := viper.GetString("postgres_url")
	enableCORS := viper.GetBool("enable_cors")

	if googleWebClientID == "" || jwtSigningKey == "" {
		return errors.New("missing required configuration: google_web_client_id or jwt_signing_key")
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(zapLoggerMiddleware(logger))

	if enableCORS {
		router.Use(web.PermissiveCORS())
	}

	router.GET("/static/auth-client.js", func(contextGin *gin.Context) {
		web.ServeEmbeddedStaticJS(contextGin, webassets.FS, "auth-client.js")
	})

	router.GET("/demo", func(contextGin *gin.Context) {
		contextGin.File("web/demo.html")
	})

	userStore := web.NewInMemoryUsers()
	var refreshStore authkit.RefreshTokenStore

	if postgresURL != "" {
		pool, poolErr := authkitpg.BuildPool(context.Background(), postgresURL)
		if poolErr != nil {
			return poolErr
		}
		if err := authkitpg.EnsureSchema(context.Background(), pool); err != nil {
			return err
		}
		refreshStore = authkitpg.NewPostgresRefreshTokenStore(pool)
		logger.Info("using postgres refresh token store")
	} else {
		refreshStore = authkit.NewMemoryRefreshTokenStore()
		logger.Info("using in-memory refresh token store")
	}

	sameSiteMode := http.SameSiteStrictMode
	if enableCORS {
		sameSiteMode = http.SameSiteNoneMode
	}

	configuration := authkit.ServerConfig{
		GoogleWebClientID: googleWebClientID,
		AppJWTSigningKey:  []byte(jwtSigningKey),
		AppJWTIssuer:      "mprlab-auth",
		CookieDomain:      cookieDomain,

		SessionCookieName: "app_session",
		RefreshCookieName: "app_refresh",

		SessionTTL: sessionTTL,
		RefreshTTL: refreshTTL,

		SameSiteMode:      sameSiteMode,
		AllowInsecureHTTP: devInsecureHTTP,
	}

	authkit.MountAuthRoutes(router, configuration, userStore, refreshStore)

	protected := router.Group("/api")
	protected.Use(authkit.RequireSession(configuration))
	protected.GET("/me", web.HandleWhoAmI())

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
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

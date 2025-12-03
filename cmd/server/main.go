package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/tenants"
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

	rootCmd.Flags().String("config", "config.yaml", "Path to application config file (overridden by TAUTH_CONFIG_FILE env)")

	return rootCmd
}

const (
	sessionCookieName = "app_session"
	refreshCookieName = "app_refresh"
	defaultTenantID   = "default"

	configCodeMissingJWTSigningKey    = "config.missing_jwt_signing_key"
	configCodeMissingConfigFile       = "config.missing_config_file"
	configCodeInvalidConfigFile       = "config.invalid_config_file"
	configCodeMissingTenants          = "config.missing_tenants"
	configCodeUninitializedServerConf = "config.uninitialized_server_config"
	configCodeGoogleValidatorInit     = "config.google_validator_init"
)

type contextKey string

const appConfigContextKey contextKey = "appConfig"

func prepareServerConfig(command *cobra.Command, arguments []string) error {
	configPath, err := command.Flags().GetString("config")
	if err != nil {
		return err
	}
	if envPath := strings.TrimSpace(os.Getenv("TAUTH_CONFIG_FILE")); envPath != "" {
		configPath = envPath
	}
	appConfig, loadErr := loadApplicationConfig(configPath)
	if loadErr != nil {
		return loadErr
	}
	existingContext := command.Context()
	if existingContext == nil {
		existingContext = context.Background()
	}
	command.SetContext(context.WithValue(existingContext, appConfigContextKey, appConfig))
	return nil
}

func configError(code, message string) error {
	return fmt.Errorf("%s: %s", code, message)
}

func expandCommaSeparatedEntries(entries []string) []string {
	expanded := make([]string, 0, len(entries))
	for _, entry := range entries {
		for _, chunk := range strings.Split(entry, ",") {
			value := strings.TrimSpace(chunk)
			if value != "" {
				expanded = append(expanded, value)
			}
		}
	}
	return expanded
}

func runServer(command *cobra.Command, arguments []string) error {
	logger, loggerErr := zap.NewProduction()
	if loggerErr != nil {
		return loggerErr
	}
	defer func() { _ = logger.Sync() }()

	commandContext := command.Context()
	if commandContext == nil {
		commandContext = context.Background()
	}
	shutdownContext, stopShutdownContext := signal.NotifyContext(commandContext, syscall.SIGINT, syscall.SIGTERM)
	defer stopShutdownContext()

	contextValue := commandContext.Value(appConfigContextKey)
	appConfig, ok := contextValue.(*applicationConfig)
	if !ok || appConfig == nil {
		return configError(configCodeUninitializedServerConf, "server configuration not prepared; PreRunE must execute before RunE")
	}

	baseServerConfig := authkit.ServerConfig{
		AppJWTSigningKey:  []byte(appConfig.Server.JWTSigningKey),
		AppJWTIssuer:      "mprlab-auth",
		TenantID:          defaultTenantID,
		CookieDomain:      "",
		SessionCookieName: sessionCookieName,
		RefreshCookieName: refreshCookieName,
		SessionTTL:        15 * time.Minute,
		RefreshTTL:        60 * 24 * time.Hour,
		NonceTTL:          5 * time.Minute,
	}

	listenAddr := appConfig.Server.ListenAddr
	databaseURL := strings.TrimSpace(appConfig.Server.DatabaseURL)
	enableCORS := bool(appConfig.Server.EnableCORS)
	corsAllowedOrigins := expandCommaSeparatedEntries(appConfig.Server.CORSAllowedOrigins)
	enableTenantHeaderOverride := bool(appConfig.Server.EnableTenantHeaderOverride)

	userStore := web.NewInMemoryUsers()
	var refreshStore authkit.RefreshTokenStore

	if databaseURL != "" {
		persistentStore, storeErr := authkit.NewDatabaseRefreshTokenStore(shutdownContext, databaseURL)
		if storeErr != nil {
			return storeErr
		}
		refreshStore = persistentStore
		logger.Info("using persistent refresh token store", zap.String("driver", persistentStore.Driver()))
	} else {
		refreshStore = authkit.NewMemoryRefreshTokenStore()
		logger.Info("using in-memory refresh token store")
	}

	tenantConfig, loadErr := tenants.LoadConfigFromDocument(appConfig.tenantDocument())
	if loadErr != nil {
		return loadErr
	}
	registry, registryErr := buildTenantRegistry(baseServerConfig, tenantConfig, enableCORS)
	if registryErr != nil {
		return registryErr
	}
	resolverOptions := []tenants.ResolverOption{}
	if enableTenantHeaderOverride {
		resolverOptions = append(resolverOptions, tenants.WithHeaderOverride(""))
	}
	tenantResolver, resolverErr := tenants.NewResolver(tenantConfig, resolverOptions...)
	if resolverErr != nil {
		return resolverErr
	}

	defaultTenantConfig := registry.DefaultConfig()
	nonceStore := authkit.NewMemoryNonceStoreWithTTLResolver(func(tenantID string) time.Duration {
		return registry.Config(tenantID).NonceTTL
	})

	validator, validatorErr := buildGoogleTokenValidator(shutdownContext)
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

	router.Use(tenants.TenantMiddleware(tenantResolver, http.StatusNotFound))

	router.GET("/static/auth-client.js", func(contextGin *gin.Context) {
		web.ServeEmbeddedStaticJS(contextGin, webassets.FS, "auth-client.js")
	})

	router.GET("/static/mpr-sites.js", func(contextGin *gin.Context) {
		web.ServeEmbeddedStaticJS(contextGin, webassets.FS, "mpr-sites.js")
	})

	router.GET("/demo/config.js", func(contextGin *gin.Context) {
		clientID := defaultTenantConfig.GoogleWebClientID
		if tenant, ok := tenants.TenantFromContext(contextGin); ok {
			clientID = tenant.GoogleWebClientID()
		}
		web.ServeDemoConfig(contextGin, web.DemoConfig{
			GoogleClientID: clientID,
		})
	})

	router.GET("/demo", func(contextGin *gin.Context) {
		contextGin.File("web/demo.html")
	})

	authkit.MountAuthRoutes(router, registry, userStore, refreshStore, nonceStore)

	protected := router.Group("/api")
	protected.Use(authkit.RequireSession(registry))
	protected.GET("/me", web.HandleWhoAmI(userStore, logger))

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}

	shutdownOnce := sync.Once{}
	shutdownServer := func() {
		shutdownOnce.Do(func() {
			graceCtx, graceCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer graceCancel()
			if err := server.Shutdown(graceCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("server shutdown error", zap.Error(err))
			}
		})
	}

	go func() {
		<-shutdownContext.Done()
		shutdownServer()
	}()

	logger.Info("listening", zap.String("addr", listenAddr))
	if err := serveHTTP(server); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("listen error: %w", err)
	}
	shutdownServer()
	return nil
}

func deriveSameSite(enableCORS bool, allowInsecure bool) http.SameSite {
	if enableCORS {
		return http.SameSiteNoneMode
	}
	if allowInsecure {
		return http.SameSiteLaxMode
	}
	return http.SameSiteStrictMode
}

func buildTenantRegistry(base authkit.ServerConfig, tenantConfig tenants.Config, enableCORS bool) (authkit.TenantRegistry, error) {
	tenantList := tenantConfig.Tenants()
	if len(tenantList) == 0 {
		return authkit.TenantRegistry{}, fmt.Errorf("config: no tenants configured")
	}
	configs := make(map[string]authkit.ServerConfig, len(tenantList))
	for _, tenant := range tenantList {
		tenantServerConfig := base
		tenantServerConfig.TenantID = string(tenant.ID())
		tenantServerConfig.GoogleWebClientID = tenant.GoogleWebClientID()
		tenantServerConfig.CookieDomain = tenant.CookieDomain()
		tenantServerConfig.SessionTTL = tenant.SessionTTL()
		tenantServerConfig.RefreshTTL = tenant.RefreshTTL()
		tenantServerConfig.NonceTTL = tenant.NonceTTL()
		tenantServerConfig.AllowInsecureHTTP = tenant.AllowInsecureHTTP()
		tenantServerConfig.SameSiteMode = deriveSameSite(enableCORS, tenant.AllowInsecureHTTP())
		configs[tenantServerConfig.TenantID] = tenantServerConfig
	}
	defaultTenantID := string(tenantList[0].ID())
	return authkit.NewTenantRegistryFromMap(defaultTenantID, configs), nil
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

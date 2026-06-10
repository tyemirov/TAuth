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
	"github.com/tyemirov/tauth/internal/appconfig"
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

var executeRootCommand = func() error {
	return newRootCommand().Execute()
}

var exitProcess = os.Exit

func main() {
	if err := executeRootCommand(); err != nil {
		exitProcess(1)
	}
}

func newRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:     "tauth",
		Short:   "Auth service with Google Sign-In verification, JWT sessions, and rotating refresh tokens",
		PreRunE: prepareServerConfig,
		RunE:    runServer,
	}

	rootCmd.PersistentFlags().String("config", "config.yaml", "Path to application config file (overridden by TAUTH_CONFIG_FILE env)")
	rootCmd.AddCommand(newPreflightCommand())
	rootCmd.AddCommand(newDoctorCommand())

	return rootCmd
}

const (
	sessionCookieName   = "app_session"
	refreshCookieName   = "app_refresh"
	defaultTenantID     = "default"
	defaultAppJWTIssuer = appconfig.DefaultJWTIssuer
	defaultCookieDomain = ""
	tenantHeaderName    = "X-TAuth-Tenant"

	configCodeMissingConfigFile       = appconfig.ErrorCodeMissingConfigFile
	configCodeInvalidConfigFile       = appconfig.ErrorCodeInvalidConfigFile
	configCodeMissingTenants          = appconfig.ErrorCodeMissingTenants
	configCodeInvalidCORSOrigin       = appconfig.ErrorCodeInvalidCORSOrigin
	configCodeCORSOriginNotAllowed    = appconfig.ErrorCodeCORSOriginNotAllowed
	configCodeUninitializedServerConf = "config.uninitialized_server_config"
	configCodeGoogleValidatorInit     = "config.google_validator_init"
)

type contextKey string

const appConfigContextKey contextKey = "appConfig"

func prepareServerConfig(command *cobra.Command, arguments []string) error {
	configPath, err := resolveConfigPath(command)
	if err != nil {
		return err
	}
	appConfig, loadErr := appconfig.LoadConfig(configPath)
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

func resolveConfigPath(command *cobra.Command) (string, error) {
	configPath, err := readConfigFlag(command)
	if err != nil {
		return "", err
	}
	if envPath := strings.TrimSpace(os.Getenv("TAUTH_CONFIG_FILE")); envPath != "" {
		configPath = envPath
	}
	return configPath, nil
}

func readConfigFlag(command *cobra.Command) (string, error) {
	if command.Flags().Lookup("config") != nil {
		return command.Flags().GetString("config")
	}
	if command.PersistentFlags().Lookup("config") != nil {
		return command.PersistentFlags().GetString("config")
	}
	if command.InheritedFlags().Lookup("config") != nil {
		return command.InheritedFlags().GetString("config")
	}
	return "", fmt.Errorf("%s: config flag not defined", configCodeMissingConfigFile)
}

func configError(code, message string) error {
	return fmt.Errorf("%s: %s", code, message)
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
	appConfig, ok := contextValue.(*appconfig.ApplicationConfig)
	if !ok || appConfig == nil {
		return configError(configCodeUninitializedServerConf, "server configuration not prepared; PreRunE must execute before RunE")
	}

	baseServerConfig := authkit.ServerConfig{
		AppJWTSigningKey:  nil,
		AppJWTIssuer:      defaultAppJWTIssuer,
		TenantID:          defaultTenantID,
		CookieDomain:      defaultCookieDomain,
		SessionCookieName: sessionCookieName,
		RefreshCookieName: refreshCookieName,
		SessionTTL:        15 * time.Minute,
		RefreshTTL:        60 * 24 * time.Hour,
		NonceTTL:          5 * time.Minute,
	}

	listenAddr := appConfig.Server.ListenAddr
	databaseURL := strings.TrimSpace(appConfig.Server.DatabaseURL)
	enableCORS := bool(appConfig.Server.EnableCORS)
	enableTenantHeaderOverride := bool(appConfig.Server.EnableTenantHeaderOverride)

	var userStore authkit.UserStore
	var refreshStore authkit.RefreshTokenStore
	var passwordCredentialStore authkit.PasswordCredentialStore

	if databaseURL != "" {
		persistentStore, storeErr := authkit.NewDatabaseRefreshTokenStore(shutdownContext, databaseURL)
		if storeErr != nil {
			return storeErr
		}
		refreshStore = persistentStore
		logger.Info("using persistent refresh token store", zap.String("driver", persistentStore.Driver()))
		persistentUserStore, userStoreErr := authkit.NewDatabaseUserStore(shutdownContext, databaseURL)
		if userStoreErr != nil {
			return userStoreErr
		}
		userStore = persistentUserStore
		passwordCredentialStore = persistentUserStore
		logger.Info("using persistent user store", zap.String("driver", persistentUserStore.Driver()))
	} else {
		refreshStore = authkit.NewMemoryRefreshTokenStore()
		logger.Info("using in-memory refresh token store")
		userStore = web.NewInMemoryUsers()
		passwordCredentialStore = authkit.NewMemoryPasswordCredentialStore()
		logger.Info("using in-memory user store")
	}

	tenantConfig, loadErr := tenants.LoadConfigFromDocument(appConfig.TenantDocument())
	if loadErr != nil {
		return loadErr
	}
	if corsErr := appconfig.ValidateCORSAllowlist(appConfig.Server, tenantConfig); corsErr != nil {
		return corsErr
	}
	if passwordSeedErr := seedPasswordUsers(shutdownContext, tenantConfig, userStore, passwordCredentialStore); passwordSeedErr != nil {
		return passwordSeedErr
	}
	corsAllowedOrigins := appconfig.ExpandCommaSeparatedEntries(appConfig.Server.CORSAllowedOrigins)
	sameSiteResolver := authkit.NewSameSiteResolver(enableCORS)
	registry, registryErr := authkit.BuildTenantRegistry(baseServerConfig, tenantConfig, sameSiteResolver)
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

	var nonceStore authkit.NonceStore
	if databaseURL != "" {
		persistentNonceStore, nonceStoreErr := authkit.NewDatabaseNonceStoreWithTTLResolver(shutdownContext, databaseURL, func(tenantID string) time.Duration {
			return registry.Config(tenantID).NonceTTL
		})
		if nonceStoreErr != nil {
			return nonceStoreErr
		}
		nonceStore = persistentNonceStore
		logger.Info("using persistent nonce store", zap.String("driver", persistentNonceStore.Driver()))
	} else {
		nonceStore = authkit.NewMemoryNonceStoreWithTTLResolver(func(tenantID string) time.Duration {
			return registry.Config(tenantID).NonceTTL
		})
		logger.Info("using in-memory nonce store")
	}

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

	router.GET("/tauth.js", serveStaticJSHandler(tenantConfig, "tauth.js"))

	tenantRouter := router.Group("/")
	tenantRouter.Use(originGateMiddleware(tenantConfig, enableTenantHeaderOverride))
	tenantRouter.Use(tenantMiddleware(tenantResolver, http.StatusNotFound))

	authkit.MountAuthRoutesWithPassword(tenantRouter, registry, userStore, refreshStore, nonceStore, passwordCredentialStore)

	protected := tenantRouter.Group("/api")
	protected.Use(authkit.RequireSession(registry))
	protected.GET("/me", web.HandleWhoAmI(logger))

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

func seedPasswordUsers(ctx context.Context, tenantConfig tenants.Config, userStore authkit.UserStore, passwordCredentialStore authkit.PasswordCredentialStore) error {
	if userStore == nil || passwordCredentialStore == nil {
		return nil
	}
	for _, tenant := range tenantConfig.Tenants() {
		if !tenant.PasswordAuthEnabled() {
			continue
		}
		tenantID := string(tenant.ID())
		configuredEmails := make([]string, 0, len(tenant.PasswordUsers()))
		for _, passwordUser := range tenant.PasswordUsers() {
			configuredEmails = append(configuredEmails, passwordUser.Email())
			_, _, profileErr := userStore.UpsertPasswordUser(ctx, tenantID, passwordUser.Email(), passwordUser.DisplayName(), passwordUser.AvatarURL())
			if profileErr != nil {
				return fmt.Errorf("password_auth.seed_profile tenant=%s user=%s: %w", tenantID, passwordUser.Email(), profileErr)
			}
			credentialErr := passwordCredentialStore.UpsertPasswordCredential(ctx, tenantID, authkit.PasswordCredentialSeed{
				UserEmail:    passwordUser.Email(),
				DisplayName:  passwordUser.DisplayName(),
				AvatarURL:    passwordUser.AvatarURL(),
				PasswordHash: passwordUser.PasswordHash(),
			})
			if credentialErr != nil {
				return fmt.Errorf("password_auth.seed_credential tenant=%s user=%s: %w", tenantID, passwordUser.Email(), credentialErr)
			}
		}
		reconcileErr := passwordCredentialStore.ReconcilePasswordCredentials(ctx, tenantID, configuredEmails)
		if reconcileErr != nil {
			return fmt.Errorf("password_auth.reconcile_credentials tenant=%s: %w", tenantID, reconcileErr)
		}
	}
	return nil
}

func serveStaticJSHandler(config tenants.Config, asset string) gin.HandlerFunc {
	return func(contextGin *gin.Context) {
		if !staticOriginAllowed(contextGin.Request, config) {
			contextGin.AbortWithStatus(http.StatusForbidden)
			return
		}
		web.ServeEmbeddedStaticJS(contextGin, webassets.FS, asset)
	}
}

func originGateMiddleware(config tenants.Config, allowHeaderOverride bool) gin.HandlerFunc {
	return func(context *gin.Context) {
		if appleOAuthBypassPath(context.Request) {
			context.Next()
			return
		}
		if !originAllowed(context.Request, config, allowHeaderOverride) {
			context.AbortWithStatus(http.StatusForbidden)
			return
		}
		context.Next()
	}
}

func tenantMiddleware(resolver *tenants.Resolver, rejectionStatus int) gin.HandlerFunc {
	delegate := tenants.TenantMiddleware(resolver, rejectionStatus)
	return func(context *gin.Context) {
		if appleOAuthBypassPath(context.Request) {
			context.Next()
			return
		}
		delegate(context)
	}
}

func appleOAuthBypassPath(request *http.Request) bool {
	if request == nil || request.URL == nil {
		return false
	}
	if request.URL.Path == "/auth/apple/callback" {
		return true
	}
	return request.URL.Path == "/auth/apple/start" && strings.TrimSpace(request.Header.Get("Origin")) == ""
}

func originAllowed(request *http.Request, config tenants.Config, allowHeaderOverride bool) bool {
	origin := strings.TrimSpace(request.Header.Get("Origin"))
	if origin == "" {
		if !allowHeaderOverride {
			return false
		}
		return headerOverrideAllowed(request, config)
	}
	if _, ok := config.OriginOwner(origin); !ok {
		return false
	}
	if !allowHeaderOverride && config.OriginIsAmbiguous(origin) {
		return false
	}
	return true
}

func headerOverrideAllowed(request *http.Request, config tenants.Config) bool {
	override := strings.TrimSpace(request.Header.Get(tenantHeaderName))
	if override == "" {
		return false
	}
	if strings.Contains(override, "://") {
		if config.OriginIsAmbiguous(override) {
			return false
		}
		_, ok := config.OriginOwner(override)
		return ok
	}
	_, ok := config.TenantByID(tenants.TenantID(override))
	return ok
}

func staticOriginAllowed(request *http.Request, config tenants.Config) bool {
	origin := strings.TrimSpace(request.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	_, ok := config.OriginOwner(origin)
	return ok
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

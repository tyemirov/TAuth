package tauthserver

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/tenants"
	"go.uber.org/zap"
)

// ErrEmbeddedServer indicates an embedded server could not be initialized.
var ErrEmbeddedServer = errors.New("tauthserver.embed.invalid")

const (
	errorCodeMissingRouter    = "tauthserver.embed.missing_router"
	errorCodeLoadTenantConfig = "tauthserver.embed.load_tenant_config"
	errorCodeBuildRegistry    = "tauthserver.embed.build_registry"
	errorCodeBuildResolver    = "tauthserver.embed.build_resolver"
)

// EmbeddedAuthServer mounts TAuth endpoints into a Gin router.
type EmbeddedAuthServer struct {
	tenantConfig      tenants.Config
	tenantResolver    *tenants.Resolver
	registry          authkit.TenantRegistry
	userStore         UserStore
	refreshTokenStore RefreshTokenStore
	nonceStore        NonceStore
	authkitConfig     authkitDependencyConfig
}

type authkitDependencyConfig struct {
	validator       GoogleTokenValidator
	clock           Clock
	logger          *zap.Logger
	metricsRecorder MetricsRecorder
}

// NewEmbeddedAuthServer constructs an EmbeddedAuthServer.
func NewEmbeddedAuthServer(configPath string, userStore UserStore, refreshTokenStore RefreshTokenStore, options ...Option) (*EmbeddedAuthServer, error) {
	config, configErr := newMountConfig(configPath, userStore, refreshTokenStore)
	if configErr != nil {
		return nil, configErr
	}
	for _, option := range options {
		updatedConfig, optionErr := option(config)
		if optionErr != nil {
			return nil, optionErr
		}
		config = updatedConfig
	}
	tenantConfig, loadErr := tenants.LoadConfig(config.configPath)
	if loadErr != nil {
		return nil, fmt.Errorf("%w: %s", errors.Join(ErrEmbeddedServer, loadErr), errorCodeLoadTenantConfig)
	}
	registry, registryErr := authkit.BuildTenantRegistry(buildBaseServerConfig(config), tenantConfig, config.sameSiteResolver)
	if registryErr != nil {
		return nil, fmt.Errorf("%w: %s", errors.Join(ErrEmbeddedServer, registryErr), errorCodeBuildRegistry)
	}
	resolverOptions := []tenants.ResolverOption{}
	if config.tenantHeaderOverrideEnabled {
		resolverOptions = append(resolverOptions, tenants.WithHeaderOverride(""))
	}
	tenantResolver, resolverErr := tenants.NewResolver(tenantConfig, resolverOptions...)
	if resolverErr != nil {
		return nil, fmt.Errorf("%w: %s", errors.Join(ErrEmbeddedServer, resolverErr), errorCodeBuildResolver)
	}
	nonceStore := config.nonceStore
	if nonceStore == nil {
		nonceStore = authkit.NewMemoryNonceStoreWithTTLResolver(func(tenantID string) time.Duration {
			return registry.Config(tenantID).NonceTTL
		})
	}
	server := &EmbeddedAuthServer{
		tenantConfig:      tenantConfig,
		tenantResolver:    tenantResolver,
		registry:          registry,
		userStore:         config.userStore,
		refreshTokenStore: config.refreshTokenStore,
		nonceStore:        nonceStore,
		authkitConfig: authkitDependencyConfig{
			validator:       config.googleTokenValidator,
			clock:           config.clock,
			logger:          config.logger,
			metricsRecorder: config.metricsRecorder,
		},
	}
	return server, nil
}

// Mount registers auth routes on the provided router.
func (server *EmbeddedAuthServer) Mount(router gin.IRouter) error {
	if router == nil {
		return fmt.Errorf("%w: %s", ErrEmbeddedServer, errorCodeMissingRouter)
	}
	server.configureAuthkitDependencies()
	tenantRouter := router.Group("/")
	tenantRouter.Use(tenants.TenantMiddleware(server.tenantResolver, http.StatusNotFound))
	authkit.MountAuthRoutes(tenantRouter, server.registry, server.userStore, server.refreshTokenStore, server.nonceStore)
	return nil
}

// TenantMiddleware returns the tenant middleware with the given rejection status.
func (server *EmbeddedAuthServer) TenantMiddleware(rejectionStatus int) gin.HandlerFunc {
	return tenants.TenantMiddleware(server.tenantResolver, rejectionStatus)
}

// RequireSession returns a Gin middleware that enforces session cookies.
func (server *EmbeddedAuthServer) RequireSession() gin.HandlerFunc {
	return authkit.RequireSession(server.registry)
}

// Close clears authkit dependencies configured by this server.
func (server *EmbeddedAuthServer) Close() {
	if server.authkitConfig.validator != nil {
		authkit.ProvideGoogleTokenValidator(nil)
	}
	if server.authkitConfig.clock != nil {
		authkit.ProvideClock(nil)
	}
	if server.authkitConfig.logger != nil {
		authkit.ProvideLogger(nil)
	}
	if server.authkitConfig.metricsRecorder != nil {
		authkit.ProvideMetrics(nil)
	}
}

func (server *EmbeddedAuthServer) configureAuthkitDependencies() {
	if server.authkitConfig.validator != nil {
		authkit.ProvideGoogleTokenValidator(server.authkitConfig.validator)
	}
	if server.authkitConfig.clock != nil {
		authkit.ProvideClock(server.authkitConfig.clock)
	}
	if server.authkitConfig.logger != nil {
		authkit.ProvideLogger(server.authkitConfig.logger)
	}
	if server.authkitConfig.metricsRecorder != nil {
		authkit.ProvideMetrics(server.authkitConfig.metricsRecorder)
	}
}

func buildBaseServerConfig(config mountConfig) authkit.ServerConfig {
	return authkit.ServerConfig{
		AppJWTSigningKey:  nil,
		AppJWTIssuer:      config.appJWTIssuer,
		TenantID:          defaultTenantID,
		CookieDomain:      defaultCookieDomain,
		SessionCookieName: defaultSessionCookieName,
		RefreshCookieName: defaultRefreshCookieName,
		SessionTTL:        defaultSessionTTL,
		RefreshTTL:        defaultRefreshTTL,
		NonceTTL:          defaultNonceTTL,
	}
}

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/controlplane"
	"github.com/tyemirov/tauth/internal/notification"
	"github.com/tyemirov/tauth/internal/oauthserver"
	"github.com/tyemirov/tauth/internal/tenants"
	"github.com/tyemirov/tauth/internal/web"
	"go.uber.org/zap"
)

type runtimeDependencies struct {
	config     *appconfig.ApplicationConfig
	logger     *zap.Logger
	users      authkit.UserStore
	refresh    authkit.RefreshTokenStore
	passwords  authkit.PasswordCredentialStore
	nonce      *authkit.DatabaseNonceStore
	oauth      oauthserver.Store
	github     authkit.GitHubTransactionStore
	store      *controlplane.Store
	management *controlplane.Management
	console    tenants.FileTenant
}
type runtimeSnapshot struct {
	handler http.Handler
	cleanup func()
	refs    int
	retired bool
	done    chan struct{}
}
type runtimePublisher struct {
	mu      sync.Mutex
	current *runtimeSnapshot
	retired []*runtimeSnapshot
}
type preparedSnapshot struct {
	publisher *runtimePublisher
	snapshot  *runtimeSnapshot
}

func (prepared *preparedSnapshot) Discard() { prepared.snapshot.cleanup() }
func (prepared *preparedSnapshot) Publish() {
	publisher := prepared.publisher
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	previous := publisher.current
	publisher.current = prepared.snapshot
	if previous != nil {
		previous.retired = true
		publisher.releaseRetired(previous)
		pending := publisher.retired[:0]
		for _, retired := range publisher.retired {
			if retired.refs > 0 {
				pending = append(pending, retired)
			}
		}
		publisher.retired = pending
		if previous.refs > 0 {
			publisher.retired = append(publisher.retired, previous)
		}
	}
}
func (publisher *runtimePublisher) releaseRetired(snapshot *runtimeSnapshot) {
	if snapshot.retired && snapshot.refs == 0 {
		snapshot.cleanup()
		close(snapshot.done)
		snapshot.retired = false
	}
}
func (prepared *preparedSnapshot) Drain(ctx context.Context) error {
	publisher := prepared.publisher
	publisher.mu.Lock()
	old := append([]*runtimeSnapshot{}, publisher.retired...)
	publisher.mu.Unlock()
	for _, snapshot := range old {
		select {
		case <-snapshot.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	publisher.mu.Lock()
	publisher.retired = nil
	publisher.mu.Unlock()
	return nil
}
func (publisher *runtimePublisher) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	publisher.mu.Lock()
	snapshot := publisher.current
	// Management uses the immutable console authority and is outside application drain accounting.
	counted := !strings.HasPrefix(request.URL.Path, "/api/management/")
	if counted {
		snapshot.refs++
	}
	publisher.mu.Unlock()
	if counted {
		defer func() {
			publisher.mu.Lock()
			defer publisher.mu.Unlock()
			snapshot.refs--
			publisher.releaseRetired(snapshot)
		}()
	}
	snapshot.handler.ServeHTTP(writer, request)
}
func (publisher *runtimePublisher) Close() {
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	if publisher.current != nil {
		publisher.current.retired = true
		publisher.releaseRetired(publisher.current)
	}
}
func (deps *runtimeDependencies) build(ctx context.Context, tenantConfig tenants.Config) (snapshot *runtimeSnapshot, buildErr error) {
	appConfig := deps.config
	logger := deps.logger
	managementStore := deps.store
	consoleTenant := deps.console
	userStore := deps.users
	refreshStore := deps.refresh
	passwordCredentialStore := deps.passwords
	oauthStore := deps.oauth
	githubTransactions := deps.github
	enableCORS := bool(appConfig.Server.EnableCORS)
	enableTenantHeaderOverride := bool(appConfig.Server.EnableTenantHeaderOverride)
	for _, tenant := range tenantConfig.Tenants() {
		if tenant.RequireTenantHeader() && !enableTenantHeaderOverride {
			return nil, fmt.Errorf("management.tenant_header_disabled")
		}
	}
	if err := appconfig.ValidateOAuthActivation(appConfig.OAuthServer(), tenantConfig); err != nil {
		return nil, err
	}
	cleanup := func() {}
	defer func() {
		if buildErr != nil {
			cleanup()
		}
	}()
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

	corsAllowedOrigins := appconfig.ExpandCommaSeparatedEntries(appConfig.Server.CORSAllowedOrigins)
	for _, tenant := range tenantConfig.Tenants() {
		corsAllowedOrigins = append(corsAllowedOrigins, tenant.Origins()...)
	}

	sameSiteResolver := authkit.NewSameSiteResolver(enableCORS)
	registry, registryErr := authkit.BuildTenantRegistry(baseServerConfig, tenantConfig, sameSiteResolver)
	if registryErr != nil {
		return nil, registryErr
	}
	var emailChallengeSender authkit.EmailChallengeSender
	pinguinConfigs := buildPinguinTenantConfigs(tenantConfig)
	if len(pinguinConfigs) > 0 {
		pinguinLogger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
		pinguinSender, pinguinSenderErr := notification.NewPinguinEmailChallengeSender(pinguinLogger, pinguinConfigs)
		if pinguinSenderErr != nil {
			return nil, pinguinSenderErr
		}
		cleanup = func() {
			if closeErr := pinguinSender.Close(); closeErr != nil {
				logger.Error("close Pinguin notification client", zap.Error(closeErr))
			}
		}
		emailChallengeSender = pinguinSender
	}
	resolverOptions := []tenants.ResolverOption{}
	if enableTenantHeaderOverride {
		resolverOptions = append(resolverOptions, tenants.WithHeaderOverride(""))
	}
	tenantResolver, resolverErr := tenants.NewResolver(tenantConfig, resolverOptions...)
	if resolverErr != nil {
		return nil, resolverErr
	}

	nonceStore := deps.nonce.WithTTLResolver(func(tenantID string) time.Duration { return registry.Config(tenantID).NonceTTL })

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(authkit.RedactGitHubCallbackQuery())
	router.Use(zapLoggerMiddleware(logger))

	if enableCORS {
		corsMiddleware, corsErr := web.PermissiveCORS(corsAllowedOrigins)
		if corsErr != nil {
			return nil, corsErr
		}
		oauthBrowserPaths := map[string]struct{}{}
		if appConfig.OAuthServer().Enabled() {
			oauthBrowserPaths = oauthBrowserEndpointPaths(appConfig.OAuthServer())
		}
		oauthBrowserPaths[tenants.GitHubStartPath] = struct{}{}
		oauthBrowserPaths[tenants.GitHubCallbackPath] = struct{}{}
		oauthBrowserPaths[authkit.AppleCallbackPath] = struct{}{}
		router.Use(corsMiddlewareExceptPaths(corsMiddleware, oauthBrowserPaths))
	}

	router.GET(healthEndpointPath, web.HandleHealth)

	sessions := authkit.NewOAuthBrowserSessions(registry, userStore, refreshStore, nonceStore, passwordCredentialStore)
	if err := controlplane.Mount(router, managementStore, registry.Config(controlplane.ConsoleTenantID), sessions, userStore, consoleTenant.TenantOrigins[0]); err != nil {
		return nil, err
	}

	if err := deps.management.Mount(router, registry.Config(controlplane.ConsoleTenantID), sessions, consoleTenant.TenantOrigins[0]); err != nil {
		return nil, err
	}
	var githubContinuation authkit.GitHubAuthorizationContinuation
	if appConfig.OAuthServer().Enabled() {
		oauthRegistry, oauthRegistryErr := oauthserver.NewRegistry(tenantConfig)
		if oauthRegistryErr != nil {
			return nil, oauthRegistryErr
		}
		oauthSigner, oauthSignerErr := oauthserver.NewSigner(appConfig.OAuthServer())
		if oauthSignerErr != nil {
			return nil, oauthSignerErr
		}
		oauthHandler, oauthHandlerErr := oauthserver.NewServer(
			appConfig.OAuthServer(),
			oauthRegistry,
			oauthStore,
			oauthSigner,
			oauthserver.NewClientMetadataResolver(appConfig.OAuthServer().ClientMetadata()),
			sessions,
		)
		if oauthHandlerErr != nil {
			return nil, oauthHandlerErr
		}
		githubContinuation = oauthHandler
		if mountErr := oauthHandler.Mount(router); mountErr != nil {
			return nil, mountErr
		}
	}

	githubLogin, githubErr := authkit.NewGitHubLogin(sessions, githubTransactions, authkit.NewGitHubProvider(http.DefaultTransport), githubContinuation)
	if githubErr != nil {
		return nil, githubErr
	}
	githubLogin.Mount(router)

	tenantRouter := router.Group("/")
	tenantRouter.Use(originGateMiddleware(tenantConfig, enableTenantHeaderOverride))
	tenantRouter.Use(tenantMiddleware(tenantResolver, http.StatusNotFound))
	tenantRouter.Use(func(ctx *gin.Context) {
		tenant, _ := tenants.TenantFromContext(ctx)
		if tenant.RequireTenantHeader() && ctx.GetHeader(tenantHeaderName) != string(tenant.ID()) {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}
		if string(tenant.ID()) == controlplane.ConsoleTenantID {
			switch ctx.Request.URL.Path {
			case "/auth/nonce", "/auth/google", "/auth/session", "/auth/refresh", "/auth/logout", "/me", "/api/me":
			default:
				ctx.AbortWithStatus(http.StatusNotFound)
				return
			}
		}
		ctx.Next()
	})

	authkit.MountAuthRoutesWithPassword(tenantRouter, registry, userStore, refreshStore, nonceStore, passwordCredentialStore, emailChallengeSender, oauthStore)

	protected := tenantRouter.Group("/api")
	protected.Use(authkit.RequireSession(registry))
	protected.GET("/me", web.HandleWhoAmI(logger))

	return &runtimeSnapshot{handler: router, cleanup: cleanup, done: make(chan struct{})}, nil
}

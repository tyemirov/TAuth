package tauthserver

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tyemirov/tauth/internal/authkit"
	"go.uber.org/zap"
)

// UserStore persists and retrieves application users.
type UserStore = authkit.UserStore

// RefreshTokenStore manages long-lived refresh tokens.
type RefreshTokenStore = authkit.RefreshTokenStore

// NonceStore issues one-time nonce tokens for Google sign-in flows.
type NonceStore = authkit.NonceStore

// MetricsRecorder records auth event counters.
type MetricsRecorder = authkit.MetricsRecorder

// Clock provides the current time.
type Clock = authkit.Clock

// GoogleTokenValidator validates Google ID tokens.
type GoogleTokenValidator = authkit.GoogleTokenValidator

// SameSiteResolver determines the cookie SameSite mode per tenant.
type SameSiteResolver = authkit.SameSiteResolver

// ErrMountConfig indicates invalid embed configuration.
var ErrMountConfig = errors.New("tauthserver.config.invalid")

const (
	errorCodeMissingConfigPath        = "tauthserver.config.missing_path"
	errorCodeMissingUserStore         = "tauthserver.config.missing_user_store"
	errorCodeMissingRefreshTokenStore = "tauthserver.config.missing_refresh_store"
	errorCodeMissingSameSiteResolver  = "tauthserver.config.missing_same_site_resolver"
	errorCodeMissingNonceStore        = "tauthserver.config.missing_nonce_store"
	errorCodeMissingValidator         = "tauthserver.config.missing_validator"
	errorCodeMissingLogger            = "tauthserver.config.missing_logger"
	errorCodeMissingMetricsRecorder   = "tauthserver.config.missing_metrics_recorder"
	errorCodeMissingClock             = "tauthserver.config.missing_clock"
	errorCodeMissingIssuer            = "tauthserver.config.missing_jwt_issuer"
)

const (
	defaultAppJWTIssuer      = "tauth"
	defaultTenantID          = "default"
	defaultCookieDomain      = ""
	defaultSessionCookieName = "app_session"
	defaultRefreshCookieName = "app_refresh"
	defaultSessionTTL        = 15 * time.Minute
	defaultRefreshTTL        = 60 * 24 * time.Hour
	defaultNonceTTL          = 5 * time.Minute
)

// SameOriginSameSiteResolver returns the default same-origin resolver.
func SameOriginSameSiteResolver() SameSiteResolver {
	return authkit.NewSameSiteResolver(false)
}

// CrossOriginSameSiteResolver returns a resolver for cross-origin cookies.
func CrossOriginSameSiteResolver() SameSiteResolver {
	return authkit.NewSameSiteResolver(true)
}

type mountConfig struct {
	configPath                  string
	userStore                   UserStore
	refreshTokenStore           RefreshTokenStore
	nonceStore                  NonceStore
	sameSiteResolver            SameSiteResolver
	googleTokenValidator        GoogleTokenValidator
	logger                      *zap.Logger
	metricsRecorder             MetricsRecorder
	clock                       Clock
	appJWTIssuer                string
	tenantHeaderOverrideEnabled bool
}

// Option configures embedded auth server behavior.
type Option func(mountConfig) (mountConfig, error)

func newMountConfig(configPath string, userStore UserStore, refreshTokenStore RefreshTokenStore) (mountConfig, error) {
	trimmedPath := strings.TrimSpace(configPath)
	if trimmedPath == "" {
		return mountConfig{}, fmt.Errorf("%w: %s", ErrMountConfig, errorCodeMissingConfigPath)
	}
	if userStore == nil {
		return mountConfig{}, fmt.Errorf("%w: %s", ErrMountConfig, errorCodeMissingUserStore)
	}
	if refreshTokenStore == nil {
		return mountConfig{}, fmt.Errorf("%w: %s", ErrMountConfig, errorCodeMissingRefreshTokenStore)
	}
	return mountConfig{
		configPath:        trimmedPath,
		userStore:         userStore,
		refreshTokenStore: refreshTokenStore,
		sameSiteResolver:  SameOriginSameSiteResolver(),
		appJWTIssuer:      defaultAppJWTIssuer,
	}, nil
}

// WithTenantHeaderOverride enables resolving tenants via the override header.
func WithTenantHeaderOverride() Option {
	return func(config mountConfig) (mountConfig, error) {
		config.tenantHeaderOverrideEnabled = true
		return config, nil
	}
}

// WithSameSiteResolver sets the SameSite resolver.
func WithSameSiteResolver(resolver SameSiteResolver) Option {
	return func(config mountConfig) (mountConfig, error) {
		if resolver == nil {
			return mountConfig{}, fmt.Errorf("%w: %s", ErrMountConfig, errorCodeMissingSameSiteResolver)
		}
		config.sameSiteResolver = resolver
		return config, nil
	}
}

// WithCrossOriginCookies sets the SameSite resolver for cross-origin cookies.
func WithCrossOriginCookies() Option {
	return func(config mountConfig) (mountConfig, error) {
		config.sameSiteResolver = CrossOriginSameSiteResolver()
		return config, nil
	}
}

// WithNonceStore sets a nonce store.
func WithNonceStore(nonceStore NonceStore) Option {
	return func(config mountConfig) (mountConfig, error) {
		if nonceStore == nil {
			return mountConfig{}, fmt.Errorf("%w: %s", ErrMountConfig, errorCodeMissingNonceStore)
		}
		config.nonceStore = nonceStore
		return config, nil
	}
}

// WithGoogleTokenValidator sets a Google token validator.
func WithGoogleTokenValidator(validator GoogleTokenValidator) Option {
	return func(config mountConfig) (mountConfig, error) {
		if validator == nil {
			return mountConfig{}, fmt.Errorf("%w: %s", ErrMountConfig, errorCodeMissingValidator)
		}
		config.googleTokenValidator = validator
		return config, nil
	}
}

// WithLogger sets the zap logger.
func WithLogger(logger *zap.Logger) Option {
	return func(config mountConfig) (mountConfig, error) {
		if logger == nil {
			return mountConfig{}, fmt.Errorf("%w: %s", ErrMountConfig, errorCodeMissingLogger)
		}
		config.logger = logger
		return config, nil
	}
}

// WithMetricsRecorder sets the metrics recorder.
func WithMetricsRecorder(recorder MetricsRecorder) Option {
	return func(config mountConfig) (mountConfig, error) {
		if recorder == nil {
			return mountConfig{}, fmt.Errorf("%w: %s", ErrMountConfig, errorCodeMissingMetricsRecorder)
		}
		config.metricsRecorder = recorder
		return config, nil
	}
}

// WithClock sets the clock used for token minting.
func WithClock(clock Clock) Option {
	return func(config mountConfig) (mountConfig, error) {
		if clock == nil {
			return mountConfig{}, fmt.Errorf("%w: %s", ErrMountConfig, errorCodeMissingClock)
		}
		config.clock = clock
		return config, nil
	}
}

// WithJWTIssuer sets the JWT issuer.
func WithJWTIssuer(issuer string) Option {
	return func(config mountConfig) (mountConfig, error) {
		trimmedIssuer := strings.TrimSpace(issuer)
		if trimmedIssuer == "" {
			return mountConfig{}, fmt.Errorf("%w: %s", ErrMountConfig, errorCodeMissingIssuer)
		}
		config.appJWTIssuer = trimmedIssuer
		return config, nil
	}
}

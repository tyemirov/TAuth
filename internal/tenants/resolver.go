package tenants

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// Resolver maps inbound requests to validated tenants.
type Resolver struct {
	config                Config
	headerOverrideEnabled bool
	headerOverrideName    string
}

// ResolverOption configures optional resolver behavior.
type ResolverOption func(*Resolver)

const (
	defaultTenantHeader      = "X-TAuth-Tenant"
	contextKeyResolvedTenant = "tenants.resolved_tenant"

	errorCodeMissingOrigin         = "tenantresolver.missing_origin"
	errorCodeUnknownOrigin         = "tenantresolver.unknown_origin"
	errorCodeUnknownTenantID       = "tenantresolver.unknown_tenant_id"
	errorCodeInvalidConfig         = "tenantresolver.invalid_config"
	errorCodeAmbiguousOrigin       = "tenantresolver.ambiguous_origin"
	errorCodeMissingHeaderOverride = "tenantresolver.missing_tenant_header"
)

// ErrResolverUninitialized indicates tenants were not provided.
var ErrResolverUninitialized = errors.New("tenantresolver.uninitialized")

// ErrTenantNotFound indicates no tenant matched the request.
var ErrTenantNotFound = errors.New("tenantresolver.not_found")

// WithHeaderOverride allows resolving by explicit tenant header.
func WithHeaderOverride(headerName string) ResolverOption {
	name := strings.TrimSpace(headerName)
	if name == "" {
		name = defaultTenantHeader
	}
	return func(resolver *Resolver) {
		resolver.headerOverrideEnabled = true
		resolver.headerOverrideName = name
	}
}

// NewResolver constructs a Resolver for the provided config.
func NewResolver(config Config, options ...ResolverOption) (*Resolver, error) {
	if len(config.tenants) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrResolverUninitialized, errorCodeInvalidConfig)
	}
	instance := &Resolver{
		config:                config,
		headerOverrideEnabled: false,
		headerOverrideName:    defaultTenantHeader,
	}
	for _, option := range options {
		option(instance)
	}
	return instance, nil
}

// Resolve determines the tenant for the inbound HTTP request.
func (resolver *Resolver) Resolve(request *http.Request) (Tenant, error) {
	if resolver == nil || len(resolver.config.tenants) == 0 {
		return Tenant{}, fmt.Errorf("%w: %s", ErrResolverUninitialized, errorCodeInvalidConfig)
	}
	if request == nil {
		return Tenant{}, fmt.Errorf("%w: %s", ErrTenantNotFound, errorCodeMissingOrigin)
	}

	if resolver.headerOverrideEnabled {
		override := strings.TrimSpace(request.Header.Get(resolver.headerOverrideName))
		if override != "" {
			tenant, err := resolver.resolveByHeaderOverride(override)
			if err != nil {
				return Tenant{}, err
			}
			return tenant, nil
		}
	}

	originTenant, originErr := resolver.resolveByOrigin(request)
	if originErr == nil {
		return originTenant, nil
	}
	if resolver.headerOverrideEnabled && isAmbiguousOriginError(originErr) {
		return Tenant{}, fmt.Errorf("%w: %s header=%s", ErrTenantNotFound, errorCodeMissingHeaderOverride, resolver.headerOverrideName)
	}
	return Tenant{}, originErr
}

func (resolver *Resolver) resolveByID(rawID string) (Tenant, error) {
	tenantID := TenantID(strings.TrimSpace(rawID))
	tenant, ok := resolver.config.TenantByID(tenantID)
	if !ok {
		return Tenant{}, fmt.Errorf("%w: %s id=%s", ErrTenantNotFound, errorCodeUnknownTenantID, tenantID)
	}
	return tenant, nil
}

func (resolver *Resolver) resolveByHeaderOverride(value string) (Tenant, error) {
	trimmedValue := strings.TrimSpace(value)
	tenant, err := resolver.resolveByID(trimmedValue)
	if err == nil {
		return tenant, nil
	}
	if strings.Contains(trimmedValue, "://") {
		originTenant, originErr := resolver.resolveByOriginValue(trimmedValue)
		if originErr == nil {
			return originTenant, nil
		}
		return Tenant{}, originErr
	}
	return Tenant{}, fmt.Errorf("%w: %s header=%s", ErrTenantNotFound, errorCodeUnknownTenantID, trimmedValue)
}

// TenantMiddleware resolves tenants and injects them into gin.Context.
func TenantMiddleware(resolver *Resolver, rejectionStatus int) gin.HandlerFunc {
	if resolver == nil {
		panic("tenants: resolver is required")
	}
	if rejectionStatus == 0 {
		rejectionStatus = http.StatusNotFound
	}
	return func(context *gin.Context) {
		tenant, err := resolver.Resolve(context.Request)
		if err != nil {
			status := rejectionStatus
			if errors.Is(err, ErrResolverUninitialized) {
				status = http.StatusInternalServerError
			}
			context.AbortWithStatusJSON(status, gin.H{
				"error": err.Error(),
			})
			return
		}
		context.Set(contextKeyResolvedTenant, tenant)
		context.Next()
	}
}

// TenantFromContext fetches the tenant stored by TenantMiddleware.
func TenantFromContext(context *gin.Context) (Tenant, bool) {
	value, exists := context.Get(contextKeyResolvedTenant)
	if !exists {
		return Tenant{}, false
	}
	tenant, ok := value.(Tenant)
	return tenant, ok
}

func (resolver *Resolver) resolveByOrigin(request *http.Request) (Tenant, error) {
	origin := strings.TrimSpace(request.Header.Get("Origin"))
	if origin == "" {
		return Tenant{}, fmt.Errorf("%w: %s", ErrTenantNotFound, errorCodeMissingOrigin)
	}
	return resolver.resolveByOriginValue(origin)
}

func (resolver *Resolver) resolveByOriginValue(value string) (Tenant, error) {
	owners := resolver.config.originOwners(value)
	if len(owners) == 0 {
		return Tenant{}, fmt.Errorf("%w: %s origin=%s", ErrTenantNotFound, errorCodeUnknownOrigin, value)
	}
	if len(owners) > 1 {
		return Tenant{}, fmt.Errorf("%w: %s origin=%s", ErrTenantNotFound, errorCodeAmbiguousOrigin, value)
	}
	return resolver.resolveByID(string(owners[0]))
}

func isAmbiguousOriginError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), errorCodeAmbiguousOrigin)
}

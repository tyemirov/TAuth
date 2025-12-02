package tenants

import (
	"errors"
	"fmt"
	"net"
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

	errorCodeMissingHost     = "tenantresolver.missing_host"
	errorCodeUnknownHost     = "tenantresolver.unknown_host"
	errorCodeUnknownTenantID = "tenantresolver.unknown_tenant_id"
	errorCodeInvalidConfig   = "tenantresolver.invalid_config"
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
		return Tenant{}, fmt.Errorf("%w: %s", ErrTenantNotFound, errorCodeMissingHost)
	}
	if resolver.headerOverrideEnabled {
		override := strings.TrimSpace(request.Header.Get(resolver.headerOverrideName))
		if override != "" {
			return resolver.resolveByID(override)
		}
	}
	host := extractHost(request)
	if host == "" {
		return Tenant{}, fmt.Errorf("%w: %s", ErrTenantNotFound, errorCodeMissingHost)
	}
	tenantID, exists := resolver.config.HostOwner(host)
	if !exists {
		return Tenant{}, fmt.Errorf("%w: %s host=%s", ErrTenantNotFound, errorCodeUnknownHost, host)
	}
	tenant, ok := resolver.config.TenantByID(tenantID)
	if !ok {
		return Tenant{}, fmt.Errorf("%w: %s id=%s", ErrTenantNotFound, errorCodeUnknownTenantID, tenantID)
	}
	return tenant, nil
}

func (resolver *Resolver) resolveByID(rawID string) (Tenant, error) {
	tenantID := TenantID(strings.TrimSpace(rawID))
	tenant, ok := resolver.config.TenantByID(tenantID)
	if !ok {
		return Tenant{}, fmt.Errorf("%w: %s id=%s", ErrTenantNotFound, errorCodeUnknownTenantID, tenantID)
	}
	return tenant, nil
}

func extractHost(request *http.Request) string {
	host := request.Host
	if host == "" && request.URL != nil {
		host = request.URL.Host
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}

	hostname := host
	if strings.Contains(hostname, ":") {
		if trimmed, _, err := net.SplitHostPort(hostname); err == nil {
			hostname = trimmed
		} else if strings.HasPrefix(hostname, "[") {
			if closing := strings.Index(hostname, "]"); closing >= 0 {
				hostname = hostname[:closing+1]
			}
		}
	}
	hostname = strings.Trim(hostname, "[]")
	if strings.Count(hostname, ":") == 1 {
		if colonIndex := strings.IndexByte(hostname, ':'); colonIndex >= 0 {
			hostname = hostname[:colonIndex]
		}
	}
	return normalizeHost(hostname)
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

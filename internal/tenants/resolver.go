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

	errorCodeMissingHost           = "tenantresolver.missing_host"
	errorCodeUnknownHost           = "tenantresolver.unknown_host"
	errorCodeUnknownTenantID       = "tenantresolver.unknown_tenant_id"
	errorCodeInvalidConfig         = "tenantresolver.invalid_config"
	errorCodeAmbiguousHost         = "tenantresolver.ambiguous_host"
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
		return Tenant{}, fmt.Errorf("%w: %s", ErrTenantNotFound, errorCodeMissingHost)
	}
	host, port := ExtractHostPort(request)
	if host == "" {
		return Tenant{}, fmt.Errorf("%w: %s", ErrTenantNotFound, errorCodeMissingHost)
	}
	owners := resolver.config.matchOwners(host, port)
	if len(owners) == 0 {
		return Tenant{}, fmt.Errorf("%w: %s host=%s", ErrTenantNotFound, errorCodeUnknownHost, host)
	}

	if resolver.headerOverrideEnabled {
		override := strings.TrimSpace(request.Header.Get(resolver.headerOverrideName))
		if override != "" {
			tenant, err := resolver.resolveByHeaderOverride(override, host, port)
			if err != nil {
				return Tenant{}, err
			}
			return tenant, nil
		}
	}

	if len(owners) > 1 {
		originTenant, originErr := resolver.resolveByOrigin(request)
		if originErr == nil {
			return originTenant, nil
		}
		if resolver.headerOverrideEnabled {
			return Tenant{}, fmt.Errorf("%w: %s host=%s header=%s", ErrTenantNotFound, errorCodeMissingHeaderOverride, host, resolver.headerOverrideName)
		}
		return Tenant{}, fmt.Errorf("%w: %s host=%s", ErrTenantNotFound, errorCodeAmbiguousHost, host)
	}

	return resolver.resolveByID(string(owners[0]))
}

func (resolver *Resolver) resolveByID(rawID string) (Tenant, error) {
	tenantID := TenantID(strings.TrimSpace(rawID))
	tenant, ok := resolver.config.TenantByID(tenantID)
	if !ok {
		return Tenant{}, fmt.Errorf("%w: %s id=%s", ErrTenantNotFound, errorCodeUnknownTenantID, tenantID)
	}
	return tenant, nil
}

func (resolver *Resolver) resolveByHeaderOverride(value string, host string, port string) (Tenant, error) {
	tenant, err := resolver.resolveByID(value)
	if err == nil {
		if !resolver.config.HostBelongsToTenantWithPort(host, port, tenant.ID()) {
			return Tenant{}, fmt.Errorf("%w: %s host=%s tenant=%s", ErrTenantNotFound, errorCodeUnknownHost, host, tenant.ID())
		}
		return tenant, nil
	}
	originTenant, originErr := resolver.resolveByOriginValue(value)
	if originErr == nil {
		if !resolver.config.HostBelongsToTenantWithPort(host, port, originTenant.ID()) {
			return Tenant{}, fmt.Errorf("%w: %s host=%s tenant=%s", ErrTenantNotFound, errorCodeUnknownHost, host, originTenant.ID())
		}
		return originTenant, nil
	}
	return Tenant{}, fmt.Errorf("%w: %s header=%s", ErrTenantNotFound, errorCodeUnknownTenantID, strings.TrimSpace(value))
}

// ExtractHost normalizes the host header (trim spaces, drop ports/brackets) for routing decisions.
func ExtractHost(request *http.Request) string {
	host, _ := ExtractHostPort(request)
	return host
}

func ExtractHostPort(request *http.Request) (string, string) {
	hostValue := request.Host
	if hostValue == "" && request.URL != nil {
		hostValue = request.URL.Host
	}
	if hostValue == "" {
		return "", ""
	}
	host := strings.TrimSpace(hostValue)
	if host == "" {
		return "", ""
	}
	if strings.HasPrefix(host, "[") {
		if closing := strings.Index(host, "]"); closing >= 0 {
			rest := strings.TrimSpace(host[closing+1:])
			value := strings.TrimSpace(host[:closing+1])
			if strings.HasPrefix(rest, ":") {
				return strings.Trim(value, "[]"), strings.TrimSpace(rest[1:])
			}
			return strings.Trim(value, "[]"), ""
		}
	}
	if strings.Count(host, ":") == 1 {
		if parts := strings.SplitN(host, ":", 2); len(parts) == 2 {
			return normalizeHost(parts[0]), strings.TrimSpace(parts[1])
		}
	}
	return normalizeHost(host), ""
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
		return Tenant{}, fmt.Errorf("origin missing")
	}
	return resolver.resolveByOriginValue(origin)
}

func (resolver *Resolver) resolveByOriginValue(value string) (Tenant, error) {
	tenantID, exists := resolver.config.OriginOwner(value)
	if !exists {
		return Tenant{}, fmt.Errorf("%w: %s host=%s", ErrTenantNotFound, errorCodeUnknownHost, value)
	}
	return resolver.resolveByID(string(tenantID))
}

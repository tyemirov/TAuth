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
	errorCodeOverrideMismatch      = "tenantresolver.override_mismatch"

	errorPayloadKeyError       = "error"
	errorPayloadKeyCode        = "error_code"
	errorPayloadKeyMessage     = "error_message"
	errorPayloadKeyHint        = "hint"
	errorPayloadKeyOrigin      = "origin"
	errorPayloadKeyHeaderName  = "header_name"
	errorPayloadKeyHeaderValue = "header_value"
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
	if config.tenantIndex == nil || config.originToTenantIDs == nil {
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
	if resolver == nil || resolver.config.tenantIndex == nil || resolver.config.originToTenantIDs == nil {
		return Tenant{}, fmt.Errorf("%w: %s", ErrResolverUninitialized, errorCodeInvalidConfig)
	}
	if request == nil {
		if resolver.headerOverrideEnabled {
			return Tenant{}, fmt.Errorf("%w: %s header=%s", ErrTenantNotFound, errorCodeMissingHeaderOverride, resolver.headerOverrideName)
		}
		return Tenant{}, fmt.Errorf("%w: %s", ErrTenantNotFound, errorCodeMissingOrigin)
	}

	override := ""
	if resolver.headerOverrideEnabled {
		override = strings.TrimSpace(request.Header.Get(resolver.headerOverrideName))
	}
	origin := strings.TrimSpace(request.Header.Get("Origin"))
	if origin == "" {
		if !resolver.headerOverrideEnabled {
			return Tenant{}, fmt.Errorf("%w: %s", ErrTenantNotFound, errorCodeMissingOrigin)
		}
		if override == "" {
			return Tenant{}, fmt.Errorf("%w: %s header=%s", ErrTenantNotFound, errorCodeMissingHeaderOverride, resolver.headerOverrideName)
		}
		return resolver.resolveByHeaderOverride(override)
	}

	originTenant, originErr := resolver.resolveByOriginValue(origin)
	if originErr != nil {
		if resolver.headerOverrideEnabled && isAmbiguousOriginError(originErr) {
			if override == "" {
				return Tenant{}, fmt.Errorf("%w: %s header=%s", ErrTenantNotFound, errorCodeMissingHeaderOverride, resolver.headerOverrideName)
			}
			overrideTenant, overrideErr := resolver.resolveByHeaderOverride(override)
			if overrideErr != nil {
				return Tenant{}, overrideErr
			}
			if !resolver.originAllowsTenant(origin, overrideTenant.ID()) {
				return Tenant{}, fmt.Errorf("%w: %s origin=%s header=%s", ErrTenantNotFound, errorCodeOverrideMismatch, origin, resolver.headerOverrideName)
			}
			return overrideTenant, nil
		}
		return Tenant{}, originErr
	}

	if override != "" {
		overrideTenant, overrideErr := resolver.resolveByHeaderOverride(override)
		if overrideErr != nil {
			return Tenant{}, overrideErr
		}
		if overrideTenant.ID() != originTenant.ID() {
			return Tenant{}, fmt.Errorf("%w: %s origin=%s header=%s", ErrTenantNotFound, errorCodeOverrideMismatch, origin, resolver.headerOverrideName)
		}
	}

	return originTenant, nil
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
		tenant, resolveErr := resolver.Resolve(context.Request)
		if resolveErr != nil {
			status := rejectionStatus
			if errors.Is(resolveErr, ErrResolverUninitialized) {
				status = http.StatusInternalServerError
			}
			context.AbortWithStatusJSON(status, gin.H{
				errorPayloadKeyError:      resolveErr.Error(),
				errorPayloadKeyCode:       resolveTenantErrorCode(resolveErr),
				errorPayloadKeyMessage:    resolveTenantErrorMessage(resolveErr),
				errorPayloadKeyHint:       resolveTenantErrorHint(resolver, resolveErr),
				errorPayloadKeyOrigin:     resolveTenantErrorOrigin(context.Request),
				errorPayloadKeyHeaderName: resolveTenantErrorHeaderName(resolver, resolveErr),
				errorPayloadKeyHeaderValue: resolveTenantErrorHeaderValue(
					resolver,
					context.Request,
					resolveErr,
				),
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

func (resolver *Resolver) originAllowsTenant(origin string, tenantID TenantID) bool {
	owners := resolver.config.originOwners(origin)
	for _, ownerID := range owners {
		if ownerID == tenantID {
			return true
		}
	}
	return false
}

func resolveTenantErrorCode(resolveErr error) string {
	if resolveErr == nil {
		return ""
	}
	if errors.Is(resolveErr, ErrResolverUninitialized) {
		return errorCodeInvalidConfig
	}
	message := resolveErr.Error()
	knownCodes := []string{
		errorCodeMissingOrigin,
		errorCodeUnknownOrigin,
		errorCodeUnknownTenantID,
		errorCodeInvalidConfig,
		errorCodeAmbiguousOrigin,
		errorCodeMissingHeaderOverride,
		errorCodeOverrideMismatch,
	}
	for _, codeValue := range knownCodes {
		if strings.Contains(message, codeValue) {
			return codeValue
		}
	}
	return ""
}

func resolveTenantErrorMessage(resolveErr error) string {
	errorCode := resolveTenantErrorCode(resolveErr)
	switch errorCode {
	case errorCodeMissingOrigin:
		return "Origin header is required to resolve the tenant."
	case errorCodeUnknownOrigin:
		return "Origin is not registered for any tenant."
	case errorCodeAmbiguousOrigin:
		return "Origin matches more than one tenant."
	case errorCodeMissingHeaderOverride:
		return "Tenant override header is required for this request."
	case errorCodeOverrideMismatch:
		return "Tenant override does not match the resolved origin."
	case errorCodeUnknownTenantID:
		return "Tenant override does not match any configured tenant."
	case errorCodeInvalidConfig:
		return "Tenant resolver is not configured."
	default:
		if errors.Is(resolveErr, ErrTenantNotFound) {
			return "Tenant could not be resolved."
		}
		return "Tenant resolution failed."
	}
}

func resolveTenantErrorHint(resolver *Resolver, resolveErr error) string {
	errorCode := resolveTenantErrorCode(resolveErr)
	headerName := resolveTenantErrorHeaderName(resolver, resolveErr)
	if headerName == "" {
		headerName = defaultTenantHeader
	}
	switch errorCode {
	case errorCodeMissingOrigin:
		return "Ensure the browser sends an Origin header or enable tenant header overrides for non-browser or same-origin clients."
	case errorCodeUnknownOrigin:
		return "Add the origin to tenant_origins (include scheme and port) and restart the service."
	case errorCodeAmbiguousOrigin:
		return fmt.Sprintf("Use distinct tenant_origins per tenant or provide %s to select the tenant.", headerName)
	case errorCodeMissingHeaderOverride:
		return fmt.Sprintf("Provide %s with the tenant id or frontend origin and set enable_tenant_header_override to true.", headerName)
	case errorCodeOverrideMismatch:
		return fmt.Sprintf("Ensure %s matches the tenant that owns the Origin.", headerName)
	case errorCodeUnknownTenantID:
		return "Check the tenant id spelling or use a valid frontend origin."
	case errorCodeInvalidConfig:
		return "Verify config.yaml includes at least one tenant and the server loaded the config."
	default:
		if errors.Is(resolveErr, ErrTenantNotFound) {
			return "Check tenant_origins and header override settings."
		}
		return ""
	}
}

func resolveTenantErrorOrigin(request *http.Request) string {
	if request == nil {
		return ""
	}
	return strings.TrimSpace(request.Header.Get("Origin"))
}

func resolveTenantErrorHeaderName(resolver *Resolver, resolveErr error) string {
	if resolver == nil {
		return ""
	}
	errorCode := resolveTenantErrorCode(resolveErr)
	switch errorCode {
	case errorCodeMissingHeaderOverride,
		errorCodeOverrideMismatch,
		errorCodeUnknownTenantID:
		return resolver.headerOverrideName
	default:
		return ""
	}
}

func resolveTenantErrorHeaderValue(resolver *Resolver, request *http.Request, resolveErr error) string {
	if resolver == nil || request == nil {
		return ""
	}
	errorCode := resolveTenantErrorCode(resolveErr)
	switch errorCode {
	case errorCodeMissingHeaderOverride,
		errorCodeOverrideMismatch,
		errorCodeUnknownTenantID:
		return strings.TrimSpace(request.Header.Get(resolver.headerOverrideName))
	default:
		return ""
	}
}

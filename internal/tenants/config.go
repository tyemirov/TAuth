package tenants

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config captures the immutable tenant declarations loaded from disk.
type Config struct {
	tenants        []Tenant
	tenantIndex    map[TenantID]Tenant
	hostToTenantID map[string]TenantID
}

// Tenant represents one logical deployment tenant and its auth configuration.
type Tenant struct {
	id                TenantID
	displayName       string
	hosts             []string
	googleWebClientID string
	cookieDomain      string
	sessionTTL        time.Duration
	refreshTTL        time.Duration
	nonceTTL          time.Duration
	allowInsecureHTTP bool
}

// TenantID identifies each tenant block.
type TenantID string

// ErrInvalidTenantConfig indicates the underlying configuration payload is invalid.
var ErrInvalidTenantConfig = errors.New("tenantconfig.invalid")

const (
	tenantIDPattern              = "^[a-z0-9][a-z0-9_-]{1,63}$"
	defaultNonceTTL              = 5 * time.Minute
	errorCodeInvalidPath         = "tenant.invalid_path"
	errorCodeMissingTenants      = "tenant.missing_records"
	errorCodeDuplicateTenantID   = "tenant.duplicate_id"
	errorCodeInvalidID           = "tenant.invalid_id"
	errorCodeMissingHosts        = "tenant.missing_hosts"
	errorCodeDuplicateHost       = "tenant.duplicate_host"
	errorCodeInvalidGoogleID     = "tenant.invalid_google_client_id"
	errorCodeInvalidCookieDomain = "tenant.invalid_cookie_domain"
	errorCodeInvalidSessionTTL   = "tenant.invalid_session_ttl"
	errorCodeInvalidRefreshTTL   = "tenant.invalid_refresh_ttl"
	errorCodeInvalidNonceTTL     = "tenant.invalid_nonce_ttl"
)

var tenantIDRegex = regexp.MustCompile(tenantIDPattern)

// LoadConfig reads and validates tenants from the provided YAML file path.
func LoadConfig(path string) (Config, error) {
	path = strings.TrimSpace(path)
	path = strings.Trim(path, `"'`)
	if path == "" {
		return Config{}, fmt.Errorf("%w: %s", ErrInvalidTenantConfig, errorCodeInvalidPath)
	}
	payload, readErr := os.ReadFile(path)
	if readErr != nil {
		return Config{}, fmt.Errorf("%w: %s read_file", ErrInvalidTenantConfig, errorCodeInvalidPath)
	}

	expandedPayload := os.ExpandEnv(string(payload))

	var document FileDocument
	decoder := yaml.NewDecoder(strings.NewReader(expandedPayload))
	decoder.KnownFields(true)
	if err := decoder.Decode(&document); err != nil {
		return Config{}, fmt.Errorf("%w: %s", ErrInvalidTenantConfig, err.Error())
	}
	return LoadConfigFromDocument(document)
}

// LoadConfigFromDocument constructs a Config from the parsed YAML document.
func LoadConfigFromDocument(document FileDocument) (Config, error) {
	if len(document.Tenants) == 0 {
		return Config{}, fmt.Errorf("%w: %s", ErrInvalidTenantConfig, errorCodeMissingTenants)
	}

	tenantIndex := make(map[TenantID]Tenant)
	hostToTenantID := make(map[string]TenantID)
	orderedTenants := make([]Tenant, 0, len(document.Tenants))

	for _, entry := range document.Tenants {
		tenant, err := buildTenant(entry)
		if err != nil {
			return Config{}, err
		}
		if _, exists := tenantIndex[tenant.id]; exists {
			return Config{}, fmt.Errorf("%w: %s id=%s", ErrInvalidTenantConfig, errorCodeDuplicateTenantID, tenant.id)
		}
		for _, host := range tenant.hosts {
			existingTenantID, claimed := hostToTenantID[host]
			if claimed {
				return Config{}, fmt.Errorf("%w: %s host=%s owner=%s", ErrInvalidTenantConfig, errorCodeDuplicateHost, host, existingTenantID)
			}
			hostToTenantID[host] = tenant.id
		}
		tenantIndex[tenant.id] = tenant
		orderedTenants = append(orderedTenants, tenant)
	}

	sort.SliceStable(orderedTenants, func(i, j int) bool {
		return string(orderedTenants[i].id) < string(orderedTenants[j].id)
	})

	return Config{
		tenants:        orderedTenants,
		tenantIndex:    tenantIndex,
		hostToTenantID: hostToTenantID,
	}, nil
}

// Tenants returns a copy of tenant slice for safe iteration.
func (config Config) Tenants() []Tenant {
	copyTenants := make([]Tenant, len(config.tenants))
	copy(copyTenants, config.tenants)
	return copyTenants
}

// TenantByID looks up a tenant.
func (config Config) TenantByID(id TenantID) (Tenant, bool) {
	tenant, exists := config.tenantIndex[id]
	return tenant, exists
}

// HostOwner exposes the tenant id that owns a hostname.
func (config Config) HostOwner(host string) (TenantID, bool) {
	host = normalizeHost(host)
	id, exists := config.hostToTenantID[host]
	return id, exists
}

// ID returns the tenant identifier.
func (tenant Tenant) ID() TenantID {
	return tenant.id
}

// DisplayName returns the friendly display name.
func (tenant Tenant) DisplayName() string {
	return tenant.displayName
}

// Hosts returns the allowed hostnames for the tenant.
func (tenant Tenant) Hosts() []string {
	hostsCopy := make([]string, len(tenant.hosts))
	copy(hostsCopy, tenant.hosts)
	return hostsCopy
}

// GoogleWebClientID returns the OAuth client identifier.
func (tenant Tenant) GoogleWebClientID() string {
	return tenant.googleWebClientID
}

// CookieDomain returns the configured cookie domain.
func (tenant Tenant) CookieDomain() string {
	return tenant.cookieDomain
}

// SessionTTL returns the duration of access tokens.
func (tenant Tenant) SessionTTL() time.Duration {
	return tenant.sessionTTL
}

// RefreshTTL returns the refresh token lifetime.
func (tenant Tenant) RefreshTTL() time.Duration {
	return tenant.refreshTTL
}

// NonceTTL returns the nonce expiration duration.
func (tenant Tenant) NonceTTL() time.Duration {
	return tenant.nonceTTL
}

// AllowInsecureHTTP indicates whether a tenant tolerates HTTP for development.
func (tenant Tenant) AllowInsecureHTTP() bool {
	return tenant.allowInsecureHTTP
}

func buildTenant(raw FileTenant) (Tenant, error) {
	tenantID, idErr := parseTenantID(raw.ID)
	if idErr != nil {
		return Tenant{}, idErr
	}
	hosts, hostErr := parseHosts(raw.Hosts, tenantID)
	if hostErr != nil {
		return Tenant{}, hostErr
	}
	googleWebClientID := strings.TrimSpace(raw.GoogleWebClientID)
	if googleWebClientID == "" {
		return Tenant{}, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeInvalidGoogleID, tenantID)
	}
	cookieDomain := strings.TrimSpace(raw.CookieDomain)
	if cookieDomain == "" {
		return Tenant{}, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeInvalidCookieDomain, tenantID)
	}
	sessionTTL, sessionErr := parseDuration(raw.SessionTTL)
	if sessionErr != nil || sessionTTL <= 0 {
		return Tenant{}, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeInvalidSessionTTL, tenantID)
	}
	refreshTTL, refreshErr := parseDuration(raw.RefreshTTL)
	if refreshErr != nil || refreshTTL <= 0 {
		return Tenant{}, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeInvalidRefreshTTL, tenantID)
	}
	nonceTTL := defaultNonceTTL
	if strings.TrimSpace(raw.NonceTTL) != "" {
		nonceDuration, nonceErr := parseDuration(raw.NonceTTL)
		if nonceErr != nil || nonceDuration <= 0 {
			return Tenant{}, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeInvalidNonceTTL, tenantID)
		}
		nonceTTL = nonceDuration
	}

	displayName := strings.TrimSpace(raw.DisplayName)
	if displayName == "" {
		displayName = string(tenantID)
	}

	return Tenant{
		id:                tenantID,
		displayName:       displayName,
		hosts:             hosts,
		googleWebClientID: googleWebClientID,
		cookieDomain:      cookieDomain,
		sessionTTL:        sessionTTL,
		refreshTTL:        refreshTTL,
		nonceTTL:          nonceTTL,
		allowInsecureHTTP: raw.AllowInsecureHTTP,
	}, nil
}

func parseTenantID(raw string) (TenantID, error) {
	trimmed := strings.TrimSpace(raw)
	if !tenantIDRegex.MatchString(trimmed) {
		return "", fmt.Errorf("%w: %s id=%s", ErrInvalidTenantConfig, errorCodeInvalidID, trimmed)
	}
	return TenantID(trimmed), nil
}

func parseHosts(hosts []string, tenantID TenantID) ([]string, error) {
	if len(hosts) == 0 {
		return nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeMissingHosts, tenantID)
	}
	cleanHosts := make([]string, 0, len(hosts))
	seen := make(map[string]struct{})
	for _, host := range hosts {
		normalized := normalizeHost(host)
		if normalized == "" {
			return nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeMissingHosts, tenantID)
		}
		if _, exists := seen[normalized]; exists {
			return nil, fmt.Errorf("%w: %s tenant=%s host=%s", ErrInvalidTenantConfig, errorCodeDuplicateHost, tenantID, normalized)
		}
		seen[normalized] = struct{}{}
		cleanHosts = append(cleanHosts, normalized)
	}
	return cleanHosts, nil
}

func normalizeHost(host string) string {
	normalized := strings.ToLower(strings.TrimSpace(host))
	if strings.HasPrefix(normalized, "[") && strings.HasSuffix(normalized, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(normalized, "["), "]")
	}
	return normalized
}

func parseDuration(raw string) (time.Duration, error) {
	return time.ParseDuration(strings.TrimSpace(raw))
}

// FileDocument represents the raw tenants YAML schema.
type FileDocument struct {
	Tenants []FileTenant `json:"tenants" yaml:"tenants"`
}

// FileTenant represents a single tenant entry inside the YAML document.
type FileTenant struct {
	ID                string   `json:"id" yaml:"id"`
	DisplayName       string   `json:"display_name" yaml:"display_name"`
	Hosts             []string `json:"hosts" yaml:"hosts"`
	GoogleWebClientID string   `json:"google_web_client_id" yaml:"google_web_client_id"`
	CookieDomain      string   `json:"cookie_domain" yaml:"cookie_domain"`
	SessionTTL        string   `json:"session_ttl" yaml:"session_ttl"`
	RefreshTTL        string   `json:"refresh_ttl" yaml:"refresh_ttl"`
	NonceTTL          string   `json:"nonce_ttl" yaml:"nonce_ttl"`
	AllowInsecureHTTP bool     `json:"allow_insecure_http" yaml:"allow_insecure_http"`
}

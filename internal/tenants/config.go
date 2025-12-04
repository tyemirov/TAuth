package tenants

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config captures the immutable tenant declarations loaded from disk.
type Config struct {
	tenants           []Tenant
	tenantIndex       map[TenantID]Tenant
	hostToTenantIDs   map[hostKey][]TenantID
	originToTenantIDs map[string][]TenantID
}

// Tenant represents one logical deployment tenant and its auth configuration.
type Tenant struct {
	id                TenantID
	displayName       string
	hosts             []string
	googleWebClientID string
	jwtSigningKey     []byte
	cookieDomain      string
	sessionCookieName string
	refreshCookieName string
	sessionTTL        time.Duration
	refreshTTL        time.Duration
	nonceTTL          time.Duration
	allowInsecureHTTP bool
}

type hostKey struct {
	host string
	port string
}

// TenantID identifies each tenant block.
type TenantID string

// ErrInvalidTenantConfig indicates the underlying configuration payload is invalid.
var ErrInvalidTenantConfig = errors.New("tenantconfig.invalid")

const (
	tenantIDPattern                   = "^[a-z0-9][a-z0-9_-]{1,63}$"
	defaultNonceTTL                   = 5 * time.Minute
	errorCodeInvalidPath              = "tenant.invalid_path"
	errorCodeMissingTenants           = "tenant.missing_records"
	errorCodeDuplicateTenantID        = "tenant.duplicate_id"
	errorCodeInvalidID                = "tenant.invalid_id"
	errorCodeMissingHosts             = "tenant.missing_hosts"
	errorCodeDuplicateHost            = "tenant.duplicate_host"
	errorCodeInvalidGoogleID          = "tenant.invalid_google_client_id"
	errorCodeInvalidSessionTTL        = "tenant.invalid_session_ttl"
	errorCodeInvalidRefreshTTL        = "tenant.invalid_refresh_ttl"
	errorCodeInvalidNonceTTL          = "tenant.invalid_nonce_ttl"
	errorCodeMissingSigningKey        = "tenant.missing_signing_key"
	errorCodeMissingSessionCookieName = "tenant.missing_session_cookie_name"
	errorCodeMissingRefreshCookieName = "tenant.missing_refresh_cookie_name"
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
	hostToTenantIDs := make(map[hostKey][]TenantID)
	originToTenantIDs := make(map[string][]TenantID)
	orderedTenants := make([]Tenant, 0, len(document.Tenants))

	for _, entry := range document.Tenants {
		tenant, keys, origins, err := buildTenant(entry)
		if err != nil {
			return Config{}, err
		}
		if _, exists := tenantIndex[tenant.id]; exists {
			return Config{}, fmt.Errorf("%w: %s id=%s", ErrInvalidTenantConfig, errorCodeDuplicateTenantID, tenant.id)
		}
		for _, key := range keys {
			hostToTenantIDs[key] = append(hostToTenantIDs[key], tenant.id)
		}
		for _, origin := range origins {
			originToTenantIDs[origin] = append(originToTenantIDs[origin], tenant.id)
		}
		tenantIndex[tenant.id] = tenant
		orderedTenants = append(orderedTenants, tenant)
	}

	sort.SliceStable(orderedTenants, func(i, j int) bool {
		return string(orderedTenants[i].id) < string(orderedTenants[j].id)
	})

	return Config{
		tenants:           orderedTenants,
		tenantIndex:       tenantIndex,
		hostToTenantIDs:   hostToTenantIDs,
		originToTenantIDs: originToTenantIDs,
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
	normalizedHost, port, err := normalizeHostPort(host)
	if err != nil {
		normalizedHost = normalizeHost(host)
		port = ""
	}
	owners := config.matchOwners(normalizedHost, port)
	if len(owners) == 0 {
		return "", false
	}
	return owners[0], true
}

// HostIsAmbiguous indicates whether multiple tenants share a host.
func (config Config) HostIsAmbiguous(host string) bool {
	normalizedHost, port, err := normalizeHostPort(host)
	if err != nil {
		normalizedHost = normalizeHost(host)
		port = ""
	}
	return len(config.matchOwners(normalizedHost, port)) > 1
}

// HasAmbiguousHosts reports if any hostname is claimed by multiple tenants.
func (config Config) HasAmbiguousHosts() bool {
	for key := range config.hostToTenantIDs {
		if len(config.matchOwners(key.host, key.port)) > 1 {
			return true
		}
	}
	return false
}

// HostBelongsToTenant reports whether the tenant declared ownership of host.
func (config Config) HostBelongsToTenant(host string, id TenantID) bool {
	return config.HostBelongsToTenantWithPort(host, "", id)
}

// HostBelongsToTenantWithPort checks host/port ownership.
func (config Config) HostBelongsToTenantWithPort(host string, port string, id TenantID) bool {
	owners := config.matchOwners(host, port)
	for _, owner := range owners {
		if owner == id {
			return true
		}
	}
	return false
}

// MatchOwners exposes tenant IDs that own the provided host/port combo.
func (config Config) MatchOwners(host string, port string) []TenantID {
	return config.matchOwners(host, port)
}

// OriginOwner resolves an origin URL to a tenant.
func (config Config) OriginOwner(origin string) (TenantID, bool) {
	owners := config.originOwners(origin)
	if len(owners) == 0 {
		return "", false
	}
	return owners[0], true
}

func (config Config) originOwners(origin string) []TenantID {
	canonical, err := normalizeOrigin(origin)
	if err != nil {
		return nil
	}
	owners, exists := config.originToTenantIDs[canonical]
	if !exists {
		return nil
	}
	copyOwners := make([]TenantID, len(owners))
	copy(copyOwners, owners)
	return copyOwners
}

func (config Config) matchOwners(host string, port string) []TenantID {
	normalizedHost := normalizeHost(host)
	key := hostKey{host: normalizedHost, port: strings.TrimSpace(port)}
	owners := append([]TenantID{}, config.hostToTenantIDs[key]...)
	if key.port != "" {
		wildcardKey := hostKey{host: normalizedHost, port: ""}
		owners = append(owners, config.hostToTenantIDs[wildcardKey]...)
	}
	return owners
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

// SigningKey returns a copy of the tenant-specific signing key, if provided.
func (tenant Tenant) SigningKey() []byte {
	if len(tenant.jwtSigningKey) == 0 {
		return nil
	}
	copyKey := make([]byte, len(tenant.jwtSigningKey))
	copy(copyKey, tenant.jwtSigningKey)
	return copyKey
}

// CookieDomain returns the configured cookie domain; empty strings yield host-only cookies.
func (tenant Tenant) CookieDomain() string {
	return tenant.cookieDomain
}

// SessionCookieName returns the optional explicit session cookie name.
func (tenant Tenant) SessionCookieName() string {
	return tenant.sessionCookieName
}

// RefreshCookieName returns the optional explicit refresh cookie name.
func (tenant Tenant) RefreshCookieName() string {
	return tenant.refreshCookieName
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

func buildTenant(raw FileTenant) (Tenant, []hostKey, []string, error) {
	tenantID, idErr := parseTenantID(raw.ID)
	if idErr != nil {
		return Tenant{}, nil, nil, idErr
	}
	hosts, keys, origins, hostErr := parseHosts(raw.AllowedHosts, tenantID)
	if hostErr != nil {
		return Tenant{}, nil, nil, hostErr
	}
	googleWebClientID := strings.TrimSpace(raw.GoogleWebClientID)
	if googleWebClientID == "" {
		return Tenant{}, nil, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeInvalidGoogleID, tenantID)
	}
	cookieDomain := strings.TrimSpace(raw.CookieDomain)
	sessionTTL, sessionErr := parseDuration(raw.SessionTTL)
	if sessionErr != nil || sessionTTL <= 0 {
		return Tenant{}, nil, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeInvalidSessionTTL, tenantID)
	}
	refreshTTL, refreshErr := parseDuration(raw.RefreshTTL)
	if refreshErr != nil || refreshTTL <= 0 {
		return Tenant{}, nil, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeInvalidRefreshTTL, tenantID)
	}
	nonceTTL := defaultNonceTTL
	if strings.TrimSpace(raw.NonceTTL) != "" {
		nonceDuration, nonceErr := parseDuration(raw.NonceTTL)
		if nonceErr != nil || nonceDuration <= 0 {
			return Tenant{}, nil, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeInvalidNonceTTL, tenantID)
		}
		nonceTTL = nonceDuration
	}

	displayName := strings.TrimSpace(raw.DisplayName)
	if displayName == "" {
		displayName = string(tenantID)
	}

	signingKeyValue := strings.TrimSpace(raw.JWTSigningKey)
	if signingKeyValue == "" {
		return Tenant{}, nil, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeMissingSigningKey, tenantID)
	}
	signingKey := []byte(signingKeyValue)
	sessionCookieName := strings.TrimSpace(raw.SessionCookieName)
	refreshCookieName := strings.TrimSpace(raw.RefreshCookieName)
	if sessionCookieName == "" {
		return Tenant{}, nil, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeMissingSessionCookieName, tenantID)
	}
	if refreshCookieName == "" {
		return Tenant{}, nil, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeMissingRefreshCookieName, tenantID)
	}

	return Tenant{
		id:                tenantID,
		displayName:       displayName,
		hosts:             hosts,
		googleWebClientID: googleWebClientID,
		jwtSigningKey:     signingKey,
		cookieDomain:      cookieDomain,
		sessionCookieName: sessionCookieName,
		refreshCookieName: refreshCookieName,
		sessionTTL:        sessionTTL,
		refreshTTL:        refreshTTL,
		nonceTTL:          nonceTTL,
		allowInsecureHTTP: bool(raw.AllowInsecureHTTP),
	}, keys, origins, nil
}

func parseTenantID(raw string) (TenantID, error) {
	trimmed := strings.TrimSpace(raw)
	if !tenantIDRegex.MatchString(trimmed) {
		return "", fmt.Errorf("%w: %s id=%s", ErrInvalidTenantConfig, errorCodeInvalidID, trimmed)
	}
	return TenantID(trimmed), nil
}

func parseHosts(hosts []string, tenantID TenantID) ([]string, []hostKey, []string, error) {
	if len(hosts) == 0 {
		return nil, nil, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeMissingHosts, tenantID)
	}
	cleanHosts := make([]string, 0, len(hosts))
	keys := make([]hostKey, 0, len(hosts))
	origins := make([]string, 0)
	seen := make(map[hostKey]struct{})
	seenOrigins := make(map[string]struct{})
	for _, host := range hosts {
		if strings.Contains(host, "://") {
			normalizedOrigin, err := normalizeOrigin(host)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeMissingHosts, tenantID)
			}
			if _, exists := seenOrigins[normalizedOrigin]; exists {
				return nil, nil, nil, fmt.Errorf("%w: %s tenant=%s host=%s", ErrInvalidTenantConfig, errorCodeDuplicateHost, tenantID, host)
			}
			seenOrigins[normalizedOrigin] = struct{}{}
			cleanHosts = append(cleanHosts, normalizedOrigin)
			origins = append(origins, normalizedOrigin)
			continue
		}
		normalizedHost, port, err := normalizeHostPort(host)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeMissingHosts, tenantID)
		}
		key := hostKey{host: normalizedHost, port: port}
		if _, exists := seen[key]; exists {
			return nil, nil, nil, fmt.Errorf("%w: %s tenant=%s host=%s", ErrInvalidTenantConfig, errorCodeDuplicateHost, tenantID, host)
		}
		seen[key] = struct{}{}
		display := normalizedHost
		if port != "" {
			display = fmt.Sprintf("%s:%s", normalizedHost, port)
		}
		cleanHosts = append(cleanHosts, display)
		keys = append(keys, key)
	}
	return cleanHosts, keys, origins, nil
}

func normalizeHost(host string) string {
	normalized := strings.ToLower(strings.TrimSpace(host))
	if strings.HasPrefix(normalized, "[") && strings.HasSuffix(normalized, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(normalized, "["), "]")
	}
	return normalized
}

func normalizeHostPort(host string) (string, string, error) {
	trimmed := strings.TrimSpace(host)
	if trimmed == "" {
		return "", "", fmt.Errorf("missing host")
	}
	value := trimmed
	port := ""
	if strings.HasPrefix(trimmed, "[") {
		closing := strings.Index(trimmed, "]")
		if closing < 0 {
			return "", "", fmt.Errorf("invalid host")
		}
		rest := strings.TrimSpace(trimmed[closing+1:])
		value = trimmed[:closing+1]
		if strings.HasPrefix(rest, ":") {
			port = strings.TrimSpace(rest[1:])
		}
	} else {
		colon := strings.LastIndex(trimmed, ":")
		if colon > -1 && strings.Count(trimmed, ":") == 1 {
			value = trimmed[:colon]
			port = strings.TrimSpace(trimmed[colon+1:])
		}
	}
	normalizedHost := normalizeHost(value)
	if normalizedHost == "" {
		return "", "", fmt.Errorf("invalid host")
	}
	if port != "" {
		if _, err := strconv.Atoi(port); err != nil {
			return "", "", fmt.Errorf("invalid port")
		}
	}
	return normalizedHost, port, nil
}

func normalizeOrigin(origin string) (string, error) {
	trimmed := strings.TrimSpace(origin)
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("invalid origin")
	}
	if parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("invalid origin")
	}
	host := strings.ToLower(parsed.Host)
	return fmt.Sprintf("%s://%s", scheme, host), nil
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
	AllowedHosts      []string `json:"allowed_hosts" yaml:"allowed_hosts"`
	GoogleWebClientID string   `json:"google_web_client_id" yaml:"google_web_client_id"`
	JWTSigningKey     string   `json:"jwt_signing_key" yaml:"jwt_signing_key"`
	CookieDomain      string   `json:"cookie_domain" yaml:"cookie_domain"`
	SessionCookieName string   `json:"session_cookie_name" yaml:"session_cookie_name"`
	RefreshCookieName string   `json:"refresh_cookie_name" yaml:"refresh_cookie_name"`
	SessionTTL        string   `json:"session_ttl" yaml:"session_ttl"`
	RefreshTTL        string   `json:"refresh_ttl" yaml:"refresh_ttl"`
	NonceTTL          string   `json:"nonce_ttl" yaml:"nonce_ttl"`
	AllowInsecureHTTP yamlBool `json:"allow_insecure_http" yaml:"allow_insecure_http"`
}

type yamlBool bool

func (value *yamlBool) UnmarshalYAML(node *yaml.Node) error {
	switch node.Tag {
	case "!!bool":
		var parsed bool
		if err := node.Decode(&parsed); err != nil {
			return err
		}
		*value = yamlBool(parsed)
		return nil
	case "!!str":
		parsed, err := strconv.ParseBool(strings.TrimSpace(node.Value))
		if err != nil {
			return err
		}
		*value = yamlBool(parsed)
		return nil
	case "!!int":
		var parsed int
		if err := node.Decode(&parsed); err != nil {
			return err
		}
		*value = yamlBool(parsed != 0)
		return nil
	default:
		var parsed bool
		if err := node.Decode(&parsed); err != nil {
			return err
		}
		*value = yamlBool(parsed)
		return nil
	}
}

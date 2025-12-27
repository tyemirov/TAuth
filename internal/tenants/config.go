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

// TenantID identifies each tenant block.
type TenantID string

type tenantCookieScope struct {
	tenantID          TenantID
	cookieDomain      string
	hostnames         []string
	sessionCookieName string
	refreshCookieName string
}

// ErrInvalidTenantConfig indicates the underlying configuration payload is invalid.
var ErrInvalidTenantConfig = errors.New("tenantconfig.invalid")

const (
	tenantIDPattern                     = "^[a-z0-9][a-z0-9_-]{1,63}$"
	defaultNonceTTL                     = 5 * time.Minute
	errorCodeInvalidPath                = "tenant.invalid_path"
	errorCodeMissingTenants             = "tenant.missing_records"
	errorCodeDuplicateTenantID          = "tenant.duplicate_id"
	errorCodeInvalidID                  = "tenant.invalid_id"
	errorCodeMissingHosts               = "tenant.missing_hosts"
	errorCodeInvalidOrigin              = "tenant.invalid_origin"
	errorCodeDuplicateHost              = "tenant.duplicate_host"
	errorCodeInvalidGoogleID            = "tenant.invalid_google_client_id"
	errorCodeInvalidSessionTTL          = "tenant.invalid_session_ttl"
	errorCodeInvalidRefreshTTL          = "tenant.invalid_refresh_ttl"
	errorCodeInvalidNonceTTL            = "tenant.invalid_nonce_ttl"
	errorCodeMissingSigningKey          = "tenant.missing_signing_key"
	errorCodeMissingSessionCookieName   = "tenant.missing_session_cookie_name"
	errorCodeMissingRefreshCookieName   = "tenant.missing_refresh_cookie_name"
	errorCodeDuplicateSessionCookieName = "tenant.duplicate_session_cookie_name"
	errorCodeDuplicateRefreshCookieName = "tenant.duplicate_refresh_cookie_name"
	errorCodeDuplicateCookieNameCross   = "tenant.duplicate_cookie_name_cross_type"
	errorCodeInvalidCookieScope         = "tenant.invalid_cookie_scope"
)

const (
	cookieDomainSeparator          = "."
	cookieOverlapDomainFormat      = "domain=%s"
	cookieOverlapHostFormat        = "host=%s"
	cookieScopeErrorFormat         = "%w: %s tenant=%s"
	cookieScopeOriginErrorFormat   = "%w: %s tenant=%s origin=%s"
	duplicateCookieNameErrorFormat = "%w: %s cookie_name=%s tenant=%s other_tenant=%s overlap=%s"
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
	document = expandFileDocumentEnv(document)
	if len(document.Tenants) == 0 {
		return Config{}, fmt.Errorf("%w: %s", ErrInvalidTenantConfig, errorCodeMissingTenants)
	}

	tenantIndex := make(map[TenantID]Tenant)
	originToTenantIDs := make(map[string][]TenantID)
	orderedTenants := make([]Tenant, 0, len(document.Tenants))
	cookieScopes := make([]tenantCookieScope, 0, len(document.Tenants))

	for _, entry := range document.Tenants {
		tenant, origins, err := buildTenant(entry)
		if err != nil {
			return Config{}, err
		}
		cookieScope, cookieScopeErr := buildTenantCookieScope(tenant, origins)
		if cookieScopeErr != nil {
			return Config{}, cookieScopeErr
		}
		if _, exists := tenantIndex[tenant.id]; exists {
			return Config{}, fmt.Errorf("%w: %s id=%s", ErrInvalidTenantConfig, errorCodeDuplicateTenantID, tenant.id)
		}
		for _, origin := range origins {
			originToTenantIDs[origin] = append(originToTenantIDs[origin], tenant.id)
		}
		tenantIndex[tenant.id] = tenant
		orderedTenants = append(orderedTenants, tenant)
		cookieScopes = append(cookieScopes, cookieScope)
	}

	sort.SliceStable(orderedTenants, func(i, j int) bool {
		return string(orderedTenants[i].id) < string(orderedTenants[j].id)
	})

	sort.SliceStable(cookieScopes, func(leftIndex, rightIndex int) bool {
		return string(cookieScopes[leftIndex].tenantID) < string(cookieScopes[rightIndex].tenantID)
	})
	if validationErr := validateCookieNameIsolation(cookieScopes); validationErr != nil {
		return Config{}, validationErr
	}

	return Config{
		tenants:           orderedTenants,
		tenantIndex:       tenantIndex,
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

// OriginOwner resolves an origin URL to a tenant.
func (config Config) OriginOwner(origin string) (TenantID, bool) {
	owners := config.originOwners(origin)
	if len(owners) == 0 {
		return "", false
	}
	return owners[0], true
}

// OriginIsAmbiguous indicates whether multiple tenants share an origin.
func (config Config) OriginIsAmbiguous(origin string) bool {
	return len(config.originOwners(origin)) > 1
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

// ID returns the tenant identifier.
func (tenant Tenant) ID() TenantID {
	return tenant.id
}

// DisplayName returns the friendly display name.
func (tenant Tenant) DisplayName() string {
	return tenant.displayName
}

// Hosts returns the allowed origins for the tenant.
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

func buildTenant(raw FileTenant) (Tenant, []string, error) {
	tenantID, idErr := parseTenantID(raw.ID)
	if idErr != nil {
		return Tenant{}, nil, idErr
	}
	hosts, origins, hostErr := parseHosts(raw.AllowedHosts, tenantID)
	if hostErr != nil {
		return Tenant{}, nil, hostErr
	}
	googleWebClientID := strings.TrimSpace(raw.GoogleWebClientID)
	if googleWebClientID == "" {
		return Tenant{}, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeInvalidGoogleID, tenantID)
	}
	cookieDomain := strings.TrimSpace(raw.CookieDomain)
	sessionTTL, sessionErr := parseDuration(raw.SessionTTL)
	if sessionErr != nil || sessionTTL <= 0 {
		return Tenant{}, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeInvalidSessionTTL, tenantID)
	}
	refreshTTL, refreshErr := parseDuration(raw.RefreshTTL)
	if refreshErr != nil || refreshTTL <= 0 {
		return Tenant{}, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeInvalidRefreshTTL, tenantID)
	}
	nonceTTL := defaultNonceTTL
	if strings.TrimSpace(raw.NonceTTL) != "" {
		nonceDuration, nonceErr := parseDuration(raw.NonceTTL)
		if nonceErr != nil || nonceDuration <= 0 {
			return Tenant{}, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeInvalidNonceTTL, tenantID)
		}
		nonceTTL = nonceDuration
	}

	displayName := strings.TrimSpace(raw.DisplayName)
	if displayName == "" {
		displayName = string(tenantID)
	}

	signingKeyValue := strings.TrimSpace(raw.JWTSigningKey)
	if signingKeyValue == "" {
		return Tenant{}, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeMissingSigningKey, tenantID)
	}
	signingKey := []byte(signingKeyValue)
	sessionCookieName := strings.TrimSpace(raw.SessionCookieName)
	refreshCookieName := strings.TrimSpace(raw.RefreshCookieName)
	if sessionCookieName == "" {
		return Tenant{}, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeMissingSessionCookieName, tenantID)
	}
	if refreshCookieName == "" {
		return Tenant{}, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeMissingRefreshCookieName, tenantID)
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
	}, origins, nil
}

func parseTenantID(raw string) (TenantID, error) {
	trimmed := strings.TrimSpace(raw)
	if !tenantIDRegex.MatchString(trimmed) {
		return "", fmt.Errorf("%w: %s id=%s", ErrInvalidTenantConfig, errorCodeInvalidID, trimmed)
	}
	return TenantID(trimmed), nil
}

func parseHosts(hosts []string, tenantID TenantID) ([]string, []string, error) {
	if len(hosts) == 0 {
		return nil, nil, fmt.Errorf("%w: %s tenant=%s", ErrInvalidTenantConfig, errorCodeMissingHosts, tenantID)
	}
	cleanHosts := make([]string, 0, len(hosts))
	origins := make([]string, 0, len(hosts))
	seenOrigins := make(map[string]struct{})
	for _, host := range hosts {
		normalizedOrigin, err := normalizeOrigin(host)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %s tenant=%s origin=%s", ErrInvalidTenantConfig, errorCodeInvalidOrigin, tenantID, host)
		}
		if _, exists := seenOrigins[normalizedOrigin]; exists {
			return nil, nil, fmt.Errorf("%w: %s tenant=%s host=%s", ErrInvalidTenantConfig, errorCodeDuplicateHost, tenantID, host)
		}
		seenOrigins[normalizedOrigin] = struct{}{}
		cleanHosts = append(cleanHosts, normalizedOrigin)
		origins = append(origins, normalizedOrigin)
	}
	return cleanHosts, origins, nil
}

func buildTenantCookieScope(tenant Tenant, origins []string) (tenantCookieScope, error) {
	hostnames, hostErr := extractTenantHostnames(tenant.id, origins)
	if hostErr != nil {
		return tenantCookieScope{}, hostErr
	}
	return tenantCookieScope{
		tenantID:          tenant.id,
		cookieDomain:      normalizeCookieDomain(tenant.cookieDomain),
		hostnames:         hostnames,
		sessionCookieName: tenant.sessionCookieName,
		refreshCookieName: tenant.refreshCookieName,
	}, nil
}

func extractTenantHostnames(tenantID TenantID, origins []string) ([]string, error) {
	hostSet := make(map[string]struct{})
	for _, origin := range origins {
		originHost, originErr := hostFromOrigin(origin)
		if originErr != nil {
			return nil, fmt.Errorf(cookieScopeOriginErrorFormat, ErrInvalidTenantConfig, errorCodeInvalidCookieScope, tenantID, origin)
		}
		hostSet[originHost] = struct{}{}
	}
	if len(hostSet) == 0 {
		return nil, fmt.Errorf(cookieScopeErrorFormat, ErrInvalidTenantConfig, errorCodeInvalidCookieScope, tenantID)
	}
	hostnames := make([]string, 0, len(hostSet))
	for hostname := range hostSet {
		hostnames = append(hostnames, hostname)
	}
	sort.Strings(hostnames)
	return hostnames, nil
}

func hostFromOrigin(origin string) (string, error) {
	hostValue, _, hostErr := hostPortFromOrigin(origin)
	if hostErr != nil {
		return "", hostErr
	}
	return hostValue, nil
}

func hostPortFromOrigin(origin string) (string, string, error) {
	normalizedOrigin, normalizeErr := normalizeOrigin(origin)
	if normalizeErr != nil {
		return "", "", normalizeErr
	}
	parsed, parseErr := url.Parse(normalizedOrigin)
	if parseErr != nil {
		return "", "", parseErr
	}
	if parsed.Host == "" {
		return "", "", fmt.Errorf("origin host missing")
	}
	hostValue, portValue, hostErr := normalizeHostPort(parsed.Host)
	if hostErr != nil {
		return "", "", hostErr
	}
	return hostValue, portValue, nil
}

func validateCookieNameIsolation(cookieScopes []tenantCookieScope) error {
	if len(cookieScopes) < 2 {
		return nil
	}
	for firstIndex := 0; firstIndex < len(cookieScopes); firstIndex++ {
		firstScope := cookieScopes[firstIndex]
		for secondIndex := firstIndex + 1; secondIndex < len(cookieScopes); secondIndex++ {
			secondScope := cookieScopes[secondIndex]
			overlapDescription, overlaps := cookieScopesOverlap(firstScope, secondScope)
			if !overlaps {
				continue
			}
			if firstScope.sessionCookieName == secondScope.sessionCookieName {
				return fmt.Errorf(duplicateCookieNameErrorFormat, ErrInvalidTenantConfig, errorCodeDuplicateSessionCookieName, firstScope.sessionCookieName, firstScope.tenantID, secondScope.tenantID, overlapDescription)
			}
			if firstScope.refreshCookieName == secondScope.refreshCookieName {
				return fmt.Errorf(duplicateCookieNameErrorFormat, ErrInvalidTenantConfig, errorCodeDuplicateRefreshCookieName, firstScope.refreshCookieName, firstScope.tenantID, secondScope.tenantID, overlapDescription)
			}
			if firstScope.sessionCookieName == secondScope.refreshCookieName {
				return fmt.Errorf(duplicateCookieNameErrorFormat, ErrInvalidTenantConfig, errorCodeDuplicateCookieNameCross, firstScope.sessionCookieName, firstScope.tenantID, secondScope.tenantID, overlapDescription)
			}
			if firstScope.refreshCookieName == secondScope.sessionCookieName {
				return fmt.Errorf(duplicateCookieNameErrorFormat, ErrInvalidTenantConfig, errorCodeDuplicateCookieNameCross, firstScope.refreshCookieName, firstScope.tenantID, secondScope.tenantID, overlapDescription)
			}
		}
	}
	return nil
}

func cookieScopesOverlap(firstScope tenantCookieScope, secondScope tenantCookieScope) (string, bool) {
	firstDomain := firstScope.cookieDomain
	secondDomain := secondScope.cookieDomain
	if firstDomain != "" && secondDomain != "" {
		if domainsOverlap(firstDomain, secondDomain) {
			return fmt.Sprintf(cookieOverlapDomainFormat, overlappingDomain(firstDomain, secondDomain)), true
		}
		return "", false
	}
	if firstDomain != "" {
		return domainHostOverlap(firstDomain, secondScope.hostnames)
	}
	if secondDomain != "" {
		return domainHostOverlap(secondDomain, firstScope.hostnames)
	}
	sharedHost := sharedHostName(firstScope.hostnames, secondScope.hostnames)
	if sharedHost == "" {
		return "", false
	}
	return fmt.Sprintf(cookieOverlapHostFormat, sharedHost), true
}

func domainHostOverlap(domain string, hostnames []string) (string, bool) {
	hostMatch := hostMatchingDomain(domain, hostnames)
	if hostMatch == "" {
		return "", false
	}
	return fmt.Sprintf(cookieOverlapHostFormat, hostMatch), true
}

func hostMatchingDomain(domain string, hostnames []string) string {
	for _, hostValue := range hostnames {
		if domainContainsHost(domain, hostValue) {
			return hostValue
		}
	}
	return ""
}

func sharedHostName(firstHostnames []string, secondHostnames []string) string {
	if len(firstHostnames) == 0 || len(secondHostnames) == 0 {
		return ""
	}
	hostSet := make(map[string]struct{}, len(firstHostnames))
	for _, hostValue := range firstHostnames {
		hostSet[hostValue] = struct{}{}
	}
	for _, hostValue := range secondHostnames {
		if _, exists := hostSet[hostValue]; exists {
			return hostValue
		}
	}
	return ""
}

func domainsOverlap(firstDomain string, secondDomain string) bool {
	if firstDomain == "" || secondDomain == "" {
		return false
	}
	if firstDomain == secondDomain {
		return true
	}
	if domainContainsHost(firstDomain, secondDomain) {
		return true
	}
	if domainContainsHost(secondDomain, firstDomain) {
		return true
	}
	return false
}

func overlappingDomain(firstDomain string, secondDomain string) string {
	if firstDomain == secondDomain {
		return firstDomain
	}
	if domainContainsHost(firstDomain, secondDomain) {
		return firstDomain
	}
	if domainContainsHost(secondDomain, firstDomain) {
		return secondDomain
	}
	return firstDomain
}

func domainContainsHost(domain string, host string) bool {
	normalizedDomain := normalizeCookieDomain(domain)
	normalizedHost := normalizeHost(host)
	if normalizedDomain == "" || normalizedHost == "" {
		return false
	}
	if normalizedDomain == normalizedHost {
		return true
	}
	return strings.HasSuffix(normalizedHost, cookieDomainSeparator+normalizedDomain)
}

func normalizeCookieDomain(domain string) string {
	trimmed := strings.TrimSpace(domain)
	if trimmed == "" {
		return ""
	}
	lowered := strings.ToLower(trimmed)
	return strings.TrimLeft(lowered, cookieDomainSeparator)
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

func expandFileDocumentEnv(document FileDocument) FileDocument {
	for index := range document.Tenants {
		document.Tenants[index] = expandFileTenantEnv(document.Tenants[index])
	}
	return document
}

func expandFileTenantEnv(tenant FileTenant) FileTenant {
	tenant.ID = os.ExpandEnv(tenant.ID)
	tenant.DisplayName = os.ExpandEnv(tenant.DisplayName)
	tenant.AllowedHosts = expandEnvSlice(tenant.AllowedHosts)
	tenant.GoogleWebClientID = os.ExpandEnv(tenant.GoogleWebClientID)
	tenant.JWTSigningKey = os.ExpandEnv(tenant.JWTSigningKey)
	tenant.CookieDomain = os.ExpandEnv(tenant.CookieDomain)
	tenant.SessionCookieName = os.ExpandEnv(tenant.SessionCookieName)
	tenant.RefreshCookieName = os.ExpandEnv(tenant.RefreshCookieName)
	tenant.SessionTTL = os.ExpandEnv(tenant.SessionTTL)
	tenant.RefreshTTL = os.ExpandEnv(tenant.RefreshTTL)
	tenant.NonceTTL = os.ExpandEnv(tenant.NonceTTL)
	return tenant
}

func expandEnvSlice(values []string) []string {
	if len(values) == 0 {
		return values
	}
	expanded := make([]string, len(values))
	for index, value := range values {
		expanded[index] = os.ExpandEnv(value)
	}
	return expanded
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

package appconfig

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tyemirov/tauth/internal/tenants"
	"github.com/tyemirov/tauth/internal/transportsecurity"
	"gopkg.in/yaml.v3"
)

// ErrorCodeMissingConfigFile is returned when the config path is empty or unreadable.
const ErrorCodeMissingConfigFile = "config.missing_config_file"

// ErrorCodeInvalidConfigFile is returned when the config payload cannot be decoded.
const ErrorCodeInvalidConfigFile = "config.invalid_config_file"

// ErrorCodeInvalidCORSOrigin is returned when a CORS origin is malformed.
const ErrorCodeInvalidCORSOrigin = "config.cors_invalid_origin"

// ErrorCodeCORSOriginNotAllowed is returned when a CORS origin is not allowed.
const ErrorCodeCORSOriginNotAllowed = "config.cors_origin_not_allowed"

// ConfigSchemaVersion identifies the config.yaml schema version.
const ConfigSchemaVersion = "tauth.config.v11"

// DefaultListenAddr is used when listen_addr is omitted.
const DefaultListenAddr = ":8080"

// DefaultJWTIssuer is used when no issuer override is configured.
const DefaultJWTIssuer = "tauth"

// ApplicationConfig represents the parsed config.yaml payload.
type ApplicationConfig struct {
	Admin           AdminSettings        `yaml:"admin"`
	Server          ServerSettings       `yaml:"server"`
	OAuth           FileOAuthSettings    `yaml:"oauth"`
	Tenants         []tenants.FileTenant `yaml:"tenants,omitempty"`
	oauth           OAuthServerConfig
	transportPolicy transportsecurity.Policy
}

// ServerSettings describe server-level configuration settings.
type ServerSettings struct {
	TrustedProxyCIDRs           []string `yaml:"trusted_proxy_cidrs"`
	TrustedProxyHosts           []string `yaml:"trusted_proxy_hosts"`
	TrustedProxyLookupTimeout   string   `yaml:"trusted_proxy_lookup_timeout"`
	ListenAddr                  string   `yaml:"listen_addr"`
	DatabaseURL                 string   `yaml:"database_url"`
	TenantEncryptionKey         string   `yaml:"tenant_encryption_key"`
	EnableCORS                  YamlBool `yaml:"enable_cors"`
	CORSAllowedOrigins          []string `yaml:"cors_allowed_origins"`
	CORSAllowedOriginExceptions []string `yaml:"cors_allowed_origin_exceptions"`
	EnableTenantHeaderOverride  YamlBool `yaml:"enable_tenant_header_override"`
}

// YamlBool supports bool or string YAML values.
type YamlBool bool

// UnmarshalYAML decodes boolean values encoded as booleans or strings.
func (value *YamlBool) UnmarshalYAML(node *yaml.Node) error {
	switch node.Tag {
	case "!!bool":
		var parsed bool
		if err := node.Decode(&parsed); err != nil {
			return err
		}
		*value = YamlBool(parsed)
		return nil
	case "!!str":
		parsed, err := strconv.ParseBool(strings.TrimSpace(os.ExpandEnv(node.Value)))
		if err != nil {
			return err
		}
		*value = YamlBool(parsed)
		return nil
	default:
		var parsed bool
		if err := node.Decode(&parsed); err != nil {
			return err
		}
		*value = YamlBool(parsed)
		return nil
	}
}

// LoadConfig reads and validates a config.yaml file.
func LoadConfig(path string) (*ApplicationConfig, error) {
	payload, err := readConfig(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(payload)
}

// LoadImportSource reads the bounded migration input, including tenant YAML.
func LoadImportSource(path string) (*ApplicationConfig, error) {
	payload, err := readConfig(path)
	if err != nil {
		return nil, err
	}
	return ParseImportSource(payload)
}

func readConfig(path string) ([]byte, error) {
	cleanedPath := strings.TrimSpace(path)
	cleanedPath = strings.Trim(cleanedPath, `"'`)
	if cleanedPath == "" {
		return nil, fmt.Errorf("%s: config file path must be provided", ErrorCodeMissingConfigFile)
	}
	payload, readErr := os.ReadFile(cleanedPath)
	if readErr != nil {
		return nil, fmt.Errorf("%s: read %s: %w", ErrorCodeMissingConfigFile, cleanedPath, readErr)
	}
	return payload, nil
}

// ParseConfig decodes and validates one config.yaml payload.
func ParseConfig(payload []byte) (*ApplicationConfig, error) {
	var service struct {
		Admin  AdminSettings     `yaml:"admin"`
		Server ServerSettings    `yaml:"server"`
		OAuth  FileOAuthSettings `yaml:"oauth"`
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(payload)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&service); err != nil {
		return nil, fmt.Errorf("%s: service configuration accepts no tenant YAML: %w", ErrorCodeInvalidConfigFile, err)
	}
	return finishConfig(ApplicationConfig{Admin: service.Admin, Server: service.Server, OAuth: service.OAuth})
}

// ParseImportSource decodes configuration for the one-off migration command.
func ParseImportSource(payload []byte) (*ApplicationConfig, error) {
	var document ApplicationConfig
	decoder := yaml.NewDecoder(strings.NewReader(string(payload)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("%s: %s", ErrorCodeInvalidConfigFile, err.Error())
	}
	return finishConfig(document)
}

func finishConfig(document ApplicationConfig) (*ApplicationConfig, error) {
	document = expandApplicationConfigEnv(document)
	admin, err := normalizeAdmin(document.Admin)
	if err != nil {
		return nil, err
	}
	document.Admin = admin
	var lookupTimeout time.Duration
	if document.Server.TrustedProxyLookupTimeout != "" {
		lookupTimeout, err = time.ParseDuration(document.Server.TrustedProxyLookupTimeout)
		if err != nil {
			return nil, fmt.Errorf("%s: trusted_proxy_lookup_timeout: %w", ErrorCodeInvalidConfigFile, err)
		}
	}
	policy, policyErr := transportsecurity.NewPolicy(transportsecurity.ProxyConfig{
		CIDRs: document.Server.TrustedProxyCIDRs, Hosts: document.Server.TrustedProxyHosts, LookupTimeout: lookupTimeout,
	}, net.DefaultResolver)
	if policyErr != nil {
		return nil, fmt.Errorf("%s: %w", ErrorCodeInvalidConfigFile, policyErr)
	}
	document.transportPolicy = policy
	if strings.TrimSpace(document.Server.ListenAddr) == "" {
		document.Server.ListenAddr = DefaultListenAddr
	}
	oauthConfig, oauthErr := parseOAuthServerConfig(document.OAuth)
	if oauthErr != nil {
		return nil, oauthErr
	}
	document.oauth = oauthConfig
	return &document, nil
}

// TenantDocument returns the tenants subsection as a document.
func (config ApplicationConfig) TenantDocument() tenants.FileDocument {
	return tenants.FileDocument{Tenants: config.Tenants}
}

// OAuthServer returns the validated OAuth authorization-server configuration.
func (config ApplicationConfig) OAuthServer() OAuthServerConfig {
	return config.oauth.clone()
}

// TransportPolicy returns the validated server transport policy.
func (config ApplicationConfig) TransportPolicy() transportsecurity.Policy {
	return config.transportPolicy
}

func expandApplicationConfigEnv(config ApplicationConfig) ApplicationConfig {
	var proxyCIDRs []string
	for _, raw := range config.Server.TrustedProxyCIDRs {
		expanded := os.ExpandEnv(raw)
		if strings.TrimSpace(expanded) == "" {
			continue
		}
		for _, cidr := range strings.Split(expanded, ",") {
			proxyCIDRs = append(proxyCIDRs, strings.TrimSpace(cidr))
		}
	}
	config.Server.TrustedProxyCIDRs = proxyCIDRs
	var proxyHosts []string
	for _, raw := range config.Server.TrustedProxyHosts {
		expanded := os.ExpandEnv(raw)
		if strings.TrimSpace(expanded) == "" {
			continue
		}
		for _, hostname := range strings.Split(expanded, ",") {
			proxyHosts = append(proxyHosts, strings.TrimSpace(hostname))
		}
	}
	config.Server.TrustedProxyHosts = proxyHosts
	config.Server.TrustedProxyLookupTimeout = os.ExpandEnv(config.Server.TrustedProxyLookupTimeout)
	config.Admin.Emails = expandEnvSlice(config.Admin.Emails)
	config.Server.ListenAddr = os.ExpandEnv(config.Server.ListenAddr)
	config.Server.DatabaseURL = os.ExpandEnv(config.Server.DatabaseURL)
	config.Server.TenantEncryptionKey = os.ExpandEnv(config.Server.TenantEncryptionKey)
	config.Server.CORSAllowedOrigins = expandEnvSlice(config.Server.CORSAllowedOrigins)
	config.Server.CORSAllowedOriginExceptions = expandEnvSlice(config.Server.CORSAllowedOriginExceptions)
	config.OAuth = expandOAuthSettingsEnv(config.OAuth)
	return config
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

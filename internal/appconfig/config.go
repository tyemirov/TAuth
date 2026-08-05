package appconfig

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/tyemirov/tauth/internal/tenants"
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
const ConfigSchemaVersion = "tauth.config.v5"

// DefaultListenAddr is used when listen_addr is omitted.
const DefaultListenAddr = ":8080"

// DefaultJWTIssuer is used when no issuer override is configured.
const DefaultJWTIssuer = "tauth"

// ApplicationConfig represents the parsed config.yaml payload.
type ApplicationConfig struct {
	Server  ServerSettings       `yaml:"server"`
	Tenants []tenants.FileTenant `yaml:"tenants"`
}

// ServerSettings describe server-level configuration settings.
type ServerSettings struct {
	ListenAddr                  string   `yaml:"listen_addr"`
	DatabaseURL                 string   `yaml:"database_url"`
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
	cleanedPath := strings.TrimSpace(path)
	cleanedPath = strings.Trim(cleanedPath, `"'`)
	if cleanedPath == "" {
		return nil, fmt.Errorf("%s: config file path must be provided", ErrorCodeMissingConfigFile)
	}
	payload, readErr := os.ReadFile(cleanedPath)
	if readErr != nil {
		return nil, fmt.Errorf("%s: read %s: %w", ErrorCodeMissingConfigFile, cleanedPath, readErr)
	}

	var document ApplicationConfig
	decoder := yaml.NewDecoder(strings.NewReader(string(payload)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("%s: %s", ErrorCodeInvalidConfigFile, err.Error())
	}
	document = expandApplicationConfigEnv(document)
	if strings.TrimSpace(document.Server.ListenAddr) == "" {
		document.Server.ListenAddr = DefaultListenAddr
	}
	return &document, nil
}

// TenantDocument returns the tenants subsection as a document.
func (config ApplicationConfig) TenantDocument() tenants.FileDocument {
	return tenants.FileDocument{Tenants: config.Tenants}
}

func expandApplicationConfigEnv(config ApplicationConfig) ApplicationConfig {
	config.Server.ListenAddr = os.ExpandEnv(config.Server.ListenAddr)
	config.Server.DatabaseURL = os.ExpandEnv(config.Server.DatabaseURL)
	config.Server.CORSAllowedOrigins = expandEnvSlice(config.Server.CORSAllowedOrigins)
	config.Server.CORSAllowedOriginExceptions = expandEnvSlice(config.Server.CORSAllowedOriginExceptions)
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

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/tyemirov/tauth/internal/tenants"
	"gopkg.in/yaml.v3"
)

type applicationConfig struct {
	Server  serverSettings       `yaml:"server"`
	Tenants []tenants.FileTenant `yaml:"tenants"`
}

type serverSettings struct {
	ListenAddr                 string   `yaml:"listen_addr"`
	JWTSigningKey              string   `yaml:"jwt_signing_key"`
	DatabaseURL                string   `yaml:"database_url"`
	EnableCORS                 bool     `yaml:"enable_cors"`
	CORSAllowedOrigins         []string `yaml:"cors_allowed_origins"`
	EnableTenantHeaderOverride bool     `yaml:"enable_tenant_header_override"`
}

func loadApplicationConfig(path string) (*applicationConfig, error) {
	cleaned := strings.TrimSpace(path)
	cleaned = strings.Trim(cleaned, `"'`)
	if cleaned == "" {
		return nil, configError(configCodeMissingConfigFile, "config file path must be provided")
	}
	payload, readErr := os.ReadFile(cleaned)
	if readErr != nil {
		return nil, fmt.Errorf("%s: read %s: %w", configCodeMissingConfigFile, cleaned, readErr)
	}

	expanded := os.ExpandEnv(string(payload))
	var document applicationConfig
	decoder := yaml.NewDecoder(strings.NewReader(expanded))
	decoder.KnownFields(true)
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("%s: %s", configCodeInvalidConfigFile, err.Error())
	}
	if strings.TrimSpace(document.Server.ListenAddr) == "" {
		document.Server.ListenAddr = ":8080"
	}
	if strings.TrimSpace(document.Server.JWTSigningKey) == "" {
		return nil, configError(configCodeMissingJWTSigningKey, "jwt_signing_key must be provided")
	}
	if len(document.Tenants) == 0 {
		return nil, configError(configCodeMissingTenants, "at least one tenant must be configured")
	}
	return &document, nil
}

func (config applicationConfig) tenantDocument() tenants.FileDocument {
	return tenants.FileDocument{Tenants: config.Tenants}
}

package tenants

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

func TestConfigMatchOwnersIncludesWildcardMatches(t *testing.T) {
	document := FileDocument{
		Tenants: []FileTenant{
			{
				ID:                "tenant-a",
				DisplayName:       "Tenant A",
				AllowedHosts:      []string{"shared.localhost"},
				GoogleWebClientID: "client-a",
				JWTSigningKey:     "signing-a",
				CookieDomain:      "",
				SessionCookieName: "app_session_a",
				RefreshCookieName: "app_refresh_a",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
				AllowInsecureHTTP: true,
			},
			{
				ID:                "tenant-b",
				DisplayName:       "Tenant B",
				AllowedHosts:      []string{"shared.localhost:8080"},
				GoogleWebClientID: "client-b",
				JWTSigningKey:     "signing-b",
				CookieDomain:      "",
				SessionCookieName: "app_session_b",
				RefreshCookieName: "app_refresh_b",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
				AllowInsecureHTTP: true,
			},
		},
	}

	config, err := LoadConfigFromDocument(document)
	if err != nil {
		t.Fatalf("expected config to load: %v", err)
	}

	owners := config.MatchOwners("shared.localhost", "8080")
	if len(owners) != 2 {
		t.Fatalf("expected 2 owners, got %d", len(owners))
	}
	if owners[0] != "tenant-b" || owners[1] != "tenant-a" {
		t.Fatalf("unexpected owners: %#v", owners)
	}
}

func TestExtractHostNormalizesPortsAndIPv6(t *testing.T) {
	testCases := []struct {
		name     string
		request  *http.Request
		expected string
	}{
		{
			name:     "host_with_port",
			request:  &http.Request{Host: "demo.example.com:8443"},
			expected: "demo.example.com",
		},
		{
			name:     "host_with_spaces",
			request:  &http.Request{Host: "  demo.example.com  "},
			expected: "demo.example.com",
		},
		{
			name:     "ipv6_host_with_port",
			request:  &http.Request{Host: "[2001:db8::1]:8443"},
			expected: "2001:db8::1",
		},
		{
			name: "url_host_when_host_header_missing",
			request: &http.Request{
				Host: "",
				URL:  mustParseURL(t, "http://prod.example.com:8080/api"),
			},
			expected: "prod.example.com",
		},
		{
			name:     "missing_host",
			request:  &http.Request{Host: ""},
			expected: "",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := ExtractHost(testCase.request); got != testCase.expected {
				t.Fatalf("expected %q, got %q", testCase.expected, got)
			}
		})
	}
}

func mustParseURL(testContext *testing.T, raw string) *url.URL {
	testContext.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		testContext.Fatalf("parse url: %v", err)
	}
	return parsed
}

func TestYamlBoolUnmarshalYAMLSupportsTypes(t *testing.T) {
	testCases := []struct {
		name      string
		payload   string
		expected  bool
		expectErr bool
	}{
		{
			name:     "bool_tag",
			payload:  "value: true\n",
			expected: true,
		},
		{
			name:     "string_tag",
			payload:  "value: \"true\"\n",
			expected: true,
		},
		{
			name:     "int_tag",
			payload:  "value: 1\n",
			expected: true,
		},
		{
			name:      "string_tag_invalid",
			payload:   "value: \"notabool\"\n",
			expectErr: true,
		},
		{
			name:      "default_tag_invalid",
			payload:   "value: {}\n",
			expectErr: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var wrapper struct {
				Value yamlBool `yaml:"value"`
			}
			err := yaml.Unmarshal([]byte(testCase.payload), &wrapper)
			if testCase.expectErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if bool(wrapper.Value) != testCase.expected {
				t.Fatalf("expected %v, got %v", testCase.expected, bool(wrapper.Value))
			}
		})
	}
}

func TestYamlBoolUnmarshalYAMLDefaultTagSupportsNull(t *testing.T) {
	var value yamlBool
	node := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: ""}
	if err := value.UnmarshalYAML(node); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bool(value) {
		t.Fatalf("expected false, got true")
	}
}

func TestTenantSigningKeyReturnsCopyAndHandlesEmptyKey(t *testing.T) {
	document := FileDocument{
		Tenants: []FileTenant{
			{
				ID:                "demo",
				DisplayName:       "Demo",
				AllowedHosts:      []string{"demo.localhost"},
				GoogleWebClientID: "demo-client",
				JWTSigningKey:     "signing",
				CookieDomain:      "",
				SessionCookieName: "app_session_demo",
				RefreshCookieName: "app_refresh_demo",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
				AllowInsecureHTTP: true,
			},
		},
	}
	config, err := LoadConfigFromDocument(document)
	if err != nil {
		t.Fatalf("expected config to load: %v", err)
	}
	tenant, ok := config.TenantByID("demo")
	if !ok {
		t.Fatalf("expected tenant to exist")
	}
	key := tenant.SigningKey()
	if string(key) != "signing" {
		t.Fatalf("expected signing key")
	}
	key[0] = 'X'
	key2 := tenant.SigningKey()
	if string(key2) != "signing" {
		t.Fatalf("expected signing key to be copied")
	}

	emptyTenant := Tenant{}
	if emptyTenant.SigningKey() != nil {
		t.Fatalf("expected nil signing key for empty tenant")
	}
}

func TestConfigHostHelpersReportAmbiguity(t *testing.T) {
	sharedHostDocument := FileDocument{
		Tenants: []FileTenant{
			{
				ID:                "tenant-a",
				DisplayName:       "Tenant A",
				AllowedHosts:      []string{"shared.localhost"},
				GoogleWebClientID: "client-a",
				JWTSigningKey:     "signing-a",
				CookieDomain:      "",
				SessionCookieName: "app_session_a",
				RefreshCookieName: "app_refresh_a",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
				AllowInsecureHTTP: true,
			},
			{
				ID:                "tenant-b",
				DisplayName:       "Tenant B",
				AllowedHosts:      []string{"shared.localhost"},
				GoogleWebClientID: "client-b",
				JWTSigningKey:     "signing-b",
				CookieDomain:      "",
				SessionCookieName: "app_session_b",
				RefreshCookieName: "app_refresh_b",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
				AllowInsecureHTTP: true,
			},
		},
	}

	sharedConfig, err := LoadConfigFromDocument(sharedHostDocument)
	if err != nil {
		t.Fatalf("expected config to load: %v", err)
	}
	if owner, ok := sharedConfig.HostOwner("shared.localhost"); !ok || owner == "" {
		t.Fatalf("expected an owner")
	}
	if !sharedConfig.HostIsAmbiguous("shared.localhost") {
		t.Fatalf("expected host to be ambiguous")
	}
	if !sharedConfig.HasAmbiguousHosts() {
		t.Fatalf("expected config to have ambiguous hosts")
	}
}

func TestConfigHostOwnerFallsBackWhenHostPortInvalid(t *testing.T) {
	document := FileDocument{
		Tenants: []FileTenant{
			{
				ID:                "tenant-a",
				DisplayName:       "Tenant A",
				AllowedHosts:      []string{"demo.localhost"},
				GoogleWebClientID: "client-a",
				JWTSigningKey:     "signing-a",
				CookieDomain:      "",
				SessionCookieName: "app_session_a",
				RefreshCookieName: "app_refresh_a",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
				AllowInsecureHTTP: true,
			},
		},
	}
	config, err := LoadConfigFromDocument(document)
	if err != nil {
		t.Fatalf("expected config to load: %v", err)
	}

	if _, ok := config.HostOwner("[invalid-host"); ok {
		t.Fatalf("expected invalid host to have no owner")
	}

	if config.HostIsAmbiguous("[invalid-host") {
		t.Fatalf("expected invalid host to be non-ambiguous")
	}
}

func TestNormalizeHostPortRejectsInvalidInputs(t *testing.T) {
	testCases := []struct {
		name      string
		host      string
		expectErr bool
	}{
		{
			name:      "empty",
			host:      "  ",
			expectErr: true,
		},
		{
			name:      "ipv6_missing_bracket",
			host:      "[2001:db8::1",
			expectErr: true,
		},
		{
			name:      "invalid_port",
			host:      "demo.localhost:port",
			expectErr: true,
		},
		{
			name: "ipv6_with_port",
			host: "[2001:db8::1]:8443",
		},
		{
			name: "host_without_port",
			host: "demo.localhost",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, _, err := normalizeHostPort(testCase.host)
			if testCase.expectErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestTenantFromContextReturnsFalseForMissingOrInvalidValues(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	contextGin, _ := gin.CreateTestContext(recorder)
	if _, ok := TenantFromContext(contextGin); ok {
		t.Fatalf("expected missing tenant to return false")
	}

	contextGin.Set(contextKeyResolvedTenant, "not-a-tenant")
	if _, ok := TenantFromContext(contextGin); ok {
		t.Fatalf("expected invalid tenant type to return false")
	}
}

func TestHasAmbiguousHostsReturnsFalseWhenHostsUnique(t *testing.T) {
	document := FileDocument{
		Tenants: []FileTenant{
			{
				ID:                "demo",
				DisplayName:       "Demo",
				AllowedHosts:      []string{"demo.localhost"},
				GoogleWebClientID: "demo-client",
				JWTSigningKey:     "demo-key",
				CookieDomain:      "",
				SessionCookieName: "app_session_demo",
				RefreshCookieName: "app_refresh_demo",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
				AllowInsecureHTTP: true,
			},
		},
	}

	config, err := LoadConfigFromDocument(document)
	if err != nil {
		t.Fatalf("expected config to load: %v", err)
	}
	if config.HasAmbiguousHosts() {
		t.Fatalf("expected no ambiguous hosts")
	}
}

func TestNormalizeOriginRejectsInvalidShapes(t *testing.T) {
	testCases := []struct {
		name  string
		value string
	}{
		{name: "empty", value: ""},
		{name: "invalid_scheme", value: "ftp://example.com"},
		{name: "missing_host", value: "https://"},
		{name: "with_path", value: "https://example.com/path"},
		{name: "with_query", value: "https://example.com?x=1"},
		{name: "with_fragment", value: "https://example.com#hash"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := normalizeOrigin(testCase.value); err == nil {
				t.Fatalf("expected error")
			}
		})
	}
}

func TestExpandEnvSliceReturnsEmptyWhenInputEmpty(t *testing.T) {
	if expanded := expandEnvSlice(nil); expanded != nil {
		t.Fatalf("expected nil slice, got %#v", expanded)
	}
}

func TestTenantMiddlewareReturnsExpectedStatuses(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := loadTestConfig(t)
	resolver, err := NewResolver(config)
	if err != nil {
		t.Fatalf("expected resolver to construct: %v", err)
	}

	router := gin.New()
	router.Use(TenantMiddleware(resolver, http.StatusTeapot))
	router.GET("/probe", func(context *gin.Context) {
		context.Status(http.StatusNoContent)
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/probe", nil)
	request.Host = "unknown.example.com"
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusTeapot {
		t.Fatalf("expected teapot status for unknown tenant, got %d", recorder.Code)
	}

	uninitializedResolver := &Resolver{}
	uninitializedRouter := gin.New()
	uninitializedRouter.Use(TenantMiddleware(uninitializedResolver, 0))
	uninitializedRouter.GET("/probe", func(context *gin.Context) {
		context.Status(http.StatusNoContent)
	})
	uninitializedRecorder := httptest.NewRecorder()
	uninitializedRequest := httptest.NewRequest(http.MethodGet, "/probe", nil)
	uninitializedRequest.Host = "demo.example.com"
	uninitializedRouter.ServeHTTP(uninitializedRecorder, uninitializedRequest)
	if uninitializedRecorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for uninitialized resolver, got %d", uninitializedRecorder.Code)
	}
}

func TestNewResolverRejectsEmptyConfig(t *testing.T) {
	if _, err := NewResolver(Config{}); err == nil || !errors.Is(err, ErrResolverUninitialized) {
		t.Fatalf("expected ErrResolverUninitialized, got %v", err)
	}
}

func TestLoadConfigReturnsErrorWhenFileMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")
	if _, err := LoadConfig(path); err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestParseHostsRejectsDuplicateEntries(t *testing.T) {
	_, _, _, err := parseHosts([]string{"demo.localhost", "Demo.Localhost"}, "demo")
	if err == nil || !errors.Is(err, ErrInvalidTenantConfig) {
		t.Fatalf("expected ErrInvalidTenantConfig, got %v", err)
	}
	if !strings.Contains(err.Error(), errorCodeDuplicateHost) {
		t.Fatalf("expected duplicate host code, got %v", err)
	}
}

func TestExtractHostPortHandlesBracketedHostWithoutPort(t *testing.T) {
	request := &http.Request{Host: "[2001:db8::1]"}
	host, port := ExtractHostPort(request)
	if host != "2001:db8::1" || port != "" {
		t.Fatalf("unexpected host/port: %q %q", host, port)
	}
}

func TestLoadConfigFromDocumentRejectsEmptyTenants(t *testing.T) {
	if _, err := LoadConfigFromDocument(FileDocument{}); err == nil {
		t.Fatalf("expected error for empty tenants")
	}
}

func TestLoadConfigExpandsEnvironmentVariables(t *testing.T) {
	if err := os.Setenv("TENANT_ID", "env-demo"); err != nil {
		t.Fatalf("setenv failed: %v", err)
	}
	t.Cleanup(func() { _ = os.Unsetenv("TENANT_ID") })

	document := FileDocument{
		Tenants: []FileTenant{
			{
				ID:                "${TENANT_ID}",
				DisplayName:       "Demo",
				AllowedHosts:      []string{"demo.localhost"},
				GoogleWebClientID: "demo-client",
				JWTSigningKey:     "demo-key",
				CookieDomain:      "",
				SessionCookieName: "app_session_demo",
				RefreshCookieName: "app_refresh_demo",
				SessionTTL:        "15m",
				RefreshTTL:        "720h",
				NonceTTL:          "5m",
				AllowInsecureHTTP: true,
			},
		},
	}

	config, err := LoadConfigFromDocument(document)
	if err != nil {
		t.Fatalf("expected config to load: %v", err)
	}
	if _, ok := config.TenantByID("env-demo"); !ok {
		t.Fatalf("expected env-expanded tenant id to resolve")
	}
}

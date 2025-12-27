package tenants

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

func TestHostPortFromOriginNormalizesPortsAndIPv6(t *testing.T) {
	testCases := []struct {
		name      string
		origin    string
		host      string
		port      string
		expectErr bool
	}{
		{
			name:   "host_with_port",
			origin: "https://demo.example.com:8443",
			host:   "demo.example.com",
			port:   "8443",
		},
		{
			name:   "host_without_port",
			origin: "https://demo.example.com",
			host:   "demo.example.com",
			port:   "",
		},
		{
			name:   "ipv6_host_with_port",
			origin: "https://[2001:db8::1]:8443",
			host:   "2001:db8::1",
			port:   "8443",
		},
		{
			name:      "missing_scheme",
			origin:    "demo.example.com",
			expectErr: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			hostValue, portValue, err := hostPortFromOrigin(testCase.origin)
			if testCase.expectErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if hostValue != testCase.host || portValue != testCase.port {
				t.Fatalf("expected host %q port %q, got %q %q", testCase.host, testCase.port, hostValue, portValue)
			}
		})
	}
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
				AllowedHosts:      []string{"https://demo.localhost"},
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
	request.Header.Set("Origin", "https://unknown.example.com")
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
	uninitializedRequest.Header.Set("Origin", "https://demo.example.com")
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
	_, _, err := parseHosts([]string{"https://demo.localhost", "https://Demo.Localhost"}, "demo")
	if err == nil || !errors.Is(err, ErrInvalidTenantConfig) {
		t.Fatalf("expected ErrInvalidTenantConfig, got %v", err)
	}
	if !strings.Contains(err.Error(), errorCodeDuplicateHost) {
		t.Fatalf("expected duplicate host code, got %v", err)
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
				AllowedHosts:      []string{"https://demo.localhost"},
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

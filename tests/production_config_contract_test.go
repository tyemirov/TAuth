package productionconfig_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	poodleScannerOrigin            = "https://poodlescanner.com"
	poodleScannerCookieDomain      = "api.poodlescanner.com"
	poodleScannerSessionCookieName = "app_session_ps"
	poodleScannerRefreshCookieName = "app_refresh_ps"
	mediaOpsOrigin                 = "https://mediaops.mprlab.com"
	mediaOpsCookieDomain           = ".mprlab.com"
	mediaOpsSessionCookieName      = "app_session_mediaops"
	mediaOpsRefreshCookieName      = "app_refresh_mediaops"
	googleIdentityOrigin           = "https://accounts.google.com"
)

type doctorReport struct {
	Summary struct {
		TotalConfigs   int `json:"total_configs"`
		ValidConfigs   int `json:"valid_configs"`
		InvalidConfigs int `json:"invalid_configs"`
	} `json:"summary"`
}

type preflightReport struct {
	EffectiveConfig struct {
		Server struct {
			EnableCORS                  bool     `json:"enable_cors"`
			CORSAllowedOrigins          []string `json:"cors_allowed_origins"`
			CORSAllowedOriginExceptions []string `json:"cors_allowed_origin_exceptions"`
		} `json:"server"`
		Tenants []preflightTenant `json:"tenants"`
	} `json:"effective_config"`
}

type preflightTenant struct {
	TenantID              string   `json:"tenant_id"`
	TenantOrigins         []string `json:"tenant_origins"`
	TenantOriginsRedacted bool     `json:"tenant_origins_redacted"`
	CookieDomain          string   `json:"cookie_domain"`
	SessionCookieName     string   `json:"session_cookie_name"`
	RefreshCookieName     string   `json:"refresh_cookie_name"`
	AllowInsecureHTTP     bool     `json:"allow_insecure_http"`
	SameSiteMode          string   `json:"same_site_mode"`
}

func TestProductionConfigSupportsSplitStaticFrontends(t *testing.T) {
	repositoryRoot := testRepositoryRoot(t)
	configPath := filepath.Join(repositoryRoot, "configs", "config.tauth.yml")
	environmentSamplePath := filepath.Join(repositoryRoot, "configs", "tauth.env.sample")
	commandEnvironment := productionTestEnvironment(t, environmentSamplePath, configPath)
	binaryPath := filepath.Join(t.TempDir(), "tauth")

	testContext, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	buildCommand := exec.CommandContext(testContext, "go", "build", "-o", binaryPath, "./cmd/server")
	buildCommand.Dir = repositoryRoot
	buildOutput, buildErr := buildCommand.CombinedOutput()
	if buildErr != nil {
		t.Fatalf("build real TAuth executable: %v\n%s", buildErr, buildOutput)
	}

	doctorOutput := runTAuthCommand(t, testContext, repositoryRoot, binaryPath, commandEnvironment, "doctor", "--json", configPath)
	var doctorPayload doctorReport
	if decodeErr := json.Unmarshal(doctorOutput, &doctorPayload); decodeErr != nil {
		t.Fatalf("decode doctor report: %v\n%s", decodeErr, doctorOutput)
	}
	if doctorPayload.Summary.TotalConfigs != 1 || doctorPayload.Summary.ValidConfigs != 1 || doctorPayload.Summary.InvalidConfigs != 0 {
		t.Fatalf("expected full production config to validate, got summary %#v", doctorPayload.Summary)
	}

	preflightOutput := runTAuthCommand(t, testContext, repositoryRoot, binaryPath, commandEnvironment, "preflight", "--include-origins", "--config", configPath)
	var preflightPayload preflightReport
	if decodeErr := json.Unmarshal(preflightOutput, &preflightPayload); decodeErr != nil {
		t.Fatalf("decode preflight report: %v\n%s", decodeErr, preflightOutput)
	}
	if !preflightPayload.EffectiveConfig.Server.EnableCORS {
		t.Fatal("expected production CORS to be enabled")
	}
	if !containsString(preflightPayload.EffectiveConfig.Server.CORSAllowedOrigins, poodleScannerOrigin) {
		t.Fatalf("expected CORS origins to contain %s, got %#v", poodleScannerOrigin, preflightPayload.EffectiveConfig.Server.CORSAllowedOrigins)
	}
	if !containsString(preflightPayload.EffectiveConfig.Server.CORSAllowedOrigins, mediaOpsOrigin) {
		t.Fatalf("expected CORS origins to contain %s, got %#v", mediaOpsOrigin, preflightPayload.EffectiveConfig.Server.CORSAllowedOrigins)
	}
	if !containsString(preflightPayload.EffectiveConfig.Server.CORSAllowedOrigins, googleIdentityOrigin) {
		t.Fatalf("expected CORS origins to contain %s, got %#v", googleIdentityOrigin, preflightPayload.EffectiveConfig.Server.CORSAllowedOrigins)
	}
	if !containsString(preflightPayload.EffectiveConfig.Server.CORSAllowedOriginExceptions, googleIdentityOrigin) {
		t.Fatalf("expected CORS origin exceptions to contain %s, got %#v", googleIdentityOrigin, preflightPayload.EffectiveConfig.Server.CORSAllowedOriginExceptions)
	}

	poodleScannerTenant := requireTenant(t, preflightPayload.EffectiveConfig.Tenants, "ps")
	if poodleScannerTenant.TenantOriginsRedacted {
		t.Fatal("expected preflight --include-origins to expose tenant origins")
	}
	if len(poodleScannerTenant.TenantOrigins) != 1 || poodleScannerTenant.TenantOrigins[0] != poodleScannerOrigin {
		t.Fatalf("expected ps origin %s, got %#v", poodleScannerOrigin, poodleScannerTenant.TenantOrigins)
	}
	if poodleScannerTenant.CookieDomain != poodleScannerCookieDomain {
		t.Fatalf("expected ps cookie domain %s, got %s", poodleScannerCookieDomain, poodleScannerTenant.CookieDomain)
	}
	if poodleScannerTenant.SessionCookieName != poodleScannerSessionCookieName {
		t.Fatalf("expected ps session cookie %s, got %s", poodleScannerSessionCookieName, poodleScannerTenant.SessionCookieName)
	}
	if poodleScannerTenant.RefreshCookieName != poodleScannerRefreshCookieName {
		t.Fatalf("expected ps refresh cookie %s, got %s", poodleScannerRefreshCookieName, poodleScannerTenant.RefreshCookieName)
	}
	if poodleScannerTenant.AllowInsecureHTTP {
		t.Fatal("expected ps cookies to require HTTPS")
	}
	if poodleScannerTenant.SameSiteMode != "None" {
		t.Fatalf("expected ps cross-origin SameSite mode None, got %s", poodleScannerTenant.SameSiteMode)
	}

	mediaOpsTenant := requireTenant(t, preflightPayload.EffectiveConfig.Tenants, "mediaops")
	if len(mediaOpsTenant.TenantOrigins) != 1 || mediaOpsTenant.TenantOrigins[0] != mediaOpsOrigin {
		t.Fatalf("expected mediaops origin %s, got %#v", mediaOpsOrigin, mediaOpsTenant.TenantOrigins)
	}
	if mediaOpsTenant.CookieDomain != mediaOpsCookieDomain {
		t.Fatalf("expected mediaops cookie domain %s, got %s", mediaOpsCookieDomain, mediaOpsTenant.CookieDomain)
	}
	if mediaOpsTenant.SessionCookieName != mediaOpsSessionCookieName || mediaOpsTenant.RefreshCookieName != mediaOpsRefreshCookieName {
		t.Fatalf("unexpected mediaops cookie names: %s %s", mediaOpsTenant.SessionCookieName, mediaOpsTenant.RefreshCookieName)
	}
	if mediaOpsTenant.AllowInsecureHTTP || mediaOpsTenant.SameSiteMode != "None" {
		t.Fatalf("expected secure cross-origin mediaops cookies, got insecure=%t same_site=%s", mediaOpsTenant.AllowInsecureHTTP, mediaOpsTenant.SameSiteMode)
	}
}

func testRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, testFilename, _, available := runtime.Caller(0)
	if !available {
		t.Fatal("resolve production config test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(testFilename), ".."))
}

func productionTestEnvironment(t *testing.T, samplePath string, configPath string) []string {
	t.Helper()
	values := loadEnvironmentSample(t, samplePath)
	for name := range values {
		if strings.Contains(name, "GOOGLE_") && strings.Contains(name, "CLIENT_ID") {
			values[name] = strings.ToLower(strings.ReplaceAll(name, "_", "-")) + ".apps.googleusercontent.com"
		}
		if strings.Contains(name, "JWT_SIGNING_KEY") {
			values[name] = "test-only-" + strings.ToLower(strings.ReplaceAll(name, "_", "-"))
		}
	}
	values["TAUTH_GOOGLE_NATIVE_IOS_REDIRECT_URI_LOOPAWARE"] = "com.mprlab.loopaware.test:/oauth2redirect/google"
	values["TAUTH_GOOGLE_NATIVE_IOS_REDIRECT_URI_HECATE"] = "com.mprlab.hecate.test:/oauthredirect"
	values["TAUTH_GOOGLE_NATIVE_IOS_REDIRECT_URI_KAMU"] = "com.mprlab.kamu.test:/oauthredirect"
	values["TAUTH_APPLE_PRIVATE_KEY_BASE64_KAMU"] = generatedApplePrivateKey(t)
	values["TAUTH_DATABASE_URL"] = ""
	values["TAUTH_CONFIG_FILE"] = configPath

	for name, value := range values {
		if strings.Contains(value, "CHANGEME") {
			t.Fatalf("test environment retains placeholder %s", name)
		}
	}

	mergedValues := make(map[string]string)
	for _, entry := range os.Environ() {
		name, value, found := strings.Cut(entry, "=")
		if found {
			mergedValues[name] = value
		}
	}
	for name, value := range values {
		mergedValues[name] = value
	}

	names := make([]string, 0, len(mergedValues))
	for name := range mergedValues {
		names = append(names, name)
	}
	sort.Strings(names)
	environment := make([]string, 0, len(names))
	for _, name := range names {
		environment = append(environment, name+"="+mergedValues[name])
	}
	return environment
}

func loadEnvironmentSample(t *testing.T, samplePath string) map[string]string {
	t.Helper()
	document, readErr := os.ReadFile(samplePath)
	if readErr != nil {
		t.Fatalf("read production environment sample: %v", readErr)
	}
	values := make(map[string]string)
	for lineNumber, rawLine := range strings.Split(string(document), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, rawValue, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(name) == "" {
			t.Fatalf("parse %s line %d", samplePath, lineNumber+1)
		}
		value := strings.TrimSpace(rawValue)
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			unquotedValue, unquoteErr := strconv.Unquote(value)
			if unquoteErr != nil {
				t.Fatalf("unquote %s line %d: %v", samplePath, lineNumber+1, unquoteErr)
			}
			value = unquotedValue
		}
		values[strings.TrimSpace(name)] = os.Expand(value, func(reference string) string {
			return values[reference]
		})
	}
	return values
}

func generatedApplePrivateKey(t *testing.T) string {
	t.Helper()
	privateKey, generateErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if generateErr != nil {
		t.Fatalf("generate test Apple private key: %v", generateErr)
	}
	privateKeyBytes, marshalErr := x509.MarshalPKCS8PrivateKey(privateKey)
	if marshalErr != nil {
		t.Fatalf("marshal test Apple private key: %v", marshalErr)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes})
	return base64.StdEncoding.EncodeToString(privateKeyPEM)
}

func runTAuthCommand(t *testing.T, testContext context.Context, repositoryRoot string, binaryPath string, environment []string, arguments ...string) []byte {
	t.Helper()
	command := exec.CommandContext(testContext, binaryPath, arguments...)
	command.Dir = repositoryRoot
	command.Env = environment
	output, commandErr := command.CombinedOutput()
	if commandErr != nil {
		t.Fatalf("run tauth %s: %v\n%s", strings.Join(arguments, " "), commandErr, output)
	}
	return output
}

func requireTenant(t *testing.T, tenants []preflightTenant, tenantID string) preflightTenant {
	t.Helper()
	for _, tenant := range tenants {
		if tenant.TenantID == tenantID {
			return tenant
		}
	}
	t.Fatalf("expected tenant %s in preflight report", tenantID)
	return preflightTenant{}
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

package productionconfig_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const deployManifestRelativePath = ".mprlab/deploy/resources.yml"

func TestRepositoryOwnsVersionlessApplicationResources(t *testing.T) {
	repositoryRoot := testRepositoryRoot(t)
	manifestPath := filepath.Join(repositoryRoot, filepath.FromSlash(deployManifestRelativePath))
	manifestDocument, readErr := os.ReadFile(manifestPath)
	if readErr != nil {
		t.Fatalf("read application resource manifest: %v", readErr)
	}

	var document map[string]any
	if unmarshalErr := yaml.Unmarshal(manifestDocument, &document); unmarshalErr != nil {
		t.Fatalf("decode application resource manifest: %v", unmarshalErr)
	}
	if len(document) != 1 {
		t.Fatalf("application resource manifest must have one document root: %#v", document)
	}
	resourcesDocument, available := document["mprlab_resources"].(map[string]any)
	if !available {
		t.Fatalf("application resource manifest has no mprlab_resources mapping: %#v", document)
	}
	if owner, available := resourcesDocument["owner"].(string); !available || owner != "tauth" {
		t.Fatalf("application resource manifest has unexpected owner: %#v", resourcesDocument["owner"])
	}
	releasePolicy, available := resourcesDocument["release"].(map[string]any)
	if !available || len(releasePolicy) != 1 || stringField(t, releasePolicy, "scheme") != "semver" {
		t.Fatalf("application resource manifest has unexpected release policy: %#v", resourcesDocument["release"])
	}
	resourceKeys := make([]string, 0, len(resourcesDocument))
	for resourceKey := range resourcesDocument {
		resourceKeys = append(resourceKeys, resourceKey)
	}
	slices.Sort(resourceKeys)
	if !slices.Equal(resourceKeys, []string{"ci", "defaults", "operations", "owner", "release", "resources"}) {
		t.Fatalf("application resource manifest root is not the exact versionless contract: %#v", resourceKeys)
	}
	ciPolicy := mappingField(t, resourcesDocument, "ci")
	command := mappingField(t, ciPolicy, "command")
	if len(ciPolicy) != 2 || ciPolicy["enabled"] != true || len(command) != 2 || command["0"] != "make" || command["1"] != "ci" {
		t.Fatalf("application CI must enable the ordered make ci command: %#v", ciPolicy)
	}
	defaults := mappingField(t, resourcesDocument, "defaults")
	timeouts := mappingField(t, defaults, "timeouts")
	if len(defaults) != 1 || len(timeouts) != 5 {
		t.Fatalf("application default timeout shape is not canonical: %#v", defaults)
	}
	for _, field := range []string{"startup", "completion", "readiness", "request", "shutdown"} {
		if durationField(t, timeouts, field) <= 0 {
			t.Fatalf("application default timeout %s must be positive", field)
		}
	}
	operations := mappingField(t, resourcesDocument, "operations")
	expectedOperations := map[string][]string{
		"ci":                           {"timeouts"},
		"app-plan-release":             {"polling", "timeouts"},
		"app-plan-publish":             {"polling", "timeouts"},
		"app-plan-deploy":              {"polling", "timeouts"},
		"app-release":                  {"polling", "timeouts"},
		"app-publish":                  {"polling", "timeouts"},
		"app-deploy":                   {"polling", "timeouts"},
		"deployment.http-health":       {"polling"},
		"deployment.resource.recovery": {"polling"},
		"app_deploy.health.same_host":  {"polling"},
		"app_deploy.pages.deployment_status_poll": {"polling"},
	}
	if len(operations) != len(expectedOperations) {
		t.Fatalf("application operation policy has unexpected operations: %#v", operations)
	}
	for name, expectedFields := range expectedOperations {
		policy := mappingField(t, operations, name)
		fields := make([]string, 0, len(policy))
		for field := range policy {
			fields = append(fields, field)
		}
		slices.Sort(fields)
		if !slices.Equal(fields, expectedFields) {
			t.Fatalf("operation %s has unexpected policy fields: %#v", name, fields)
		}
		if slices.Contains(fields, "timeouts") {
			overrides := mappingField(t, policy, "timeouts")
			if len(overrides) != 1 || durationField(t, overrides, "completion") <= 0 {
				t.Fatalf("operation %s must declare a positive completion timeout: %#v", name, overrides)
			}
		}
		if slices.Contains(fields, "polling") {
			polling := mappingField(t, policy, "polling")
			initial := durationField(t, polling, "initial")
			maximum := durationField(t, polling, "maximum")
			increment := durationField(t, polling, "increment")
			multiplier, multiplierOK := polling["multiplier"].(int)
			attemptLimit, attemptLimitOK := polling["attempt_limit"].(int)
			if len(polling) != 5 || initial <= 0 || maximum < initial || increment < 0 || !multiplierOK || multiplier < 1 || !attemptLimitOK || attemptLimit < 1 {
				t.Fatalf("operation %s must declare finite positive polling: %#v", name, polling)
			}
		}
	}

	resources, available := resourcesDocument["resources"].(map[string]any)
	if !available {
		t.Fatalf("application resource manifest has no resources map: %#v", resourcesDocument["resources"])
	}
	resourceIdentities := make([]string, 0, len(resources))
	var runtimeProject map[string]any
	var browserHelperPages map[string]any
	for resourceID, resourceValue := range resources {
		resource, resourceAvailable := resourceValue.(map[string]any)
		if !resourceAvailable {
			t.Fatalf("application resource is not a mapping: %#v", resourceValue)
		}
		resourceIdentity := stringField(t, resource, "kind") + "/" + resourceID
		resourceIdentities = append(resourceIdentities, resourceIdentity)
		if resourceIdentity == "compose_project/runtime" {
			runtimeProject = resource
		}
		if resourceIdentity == "github_pages/browser-helper" {
			browserHelperPages = resource
		}
	}
	slices.Sort(resourceIdentities)
	expectedResourceIdentities := []string{
		"caddy_route/public-api",
		"compose_project/runtime",
		"github_pages/browser-helper",
		"health_check/public-health",
		"private_values/oauth-private",
		"runtime_capability/http",
		"runtime_capability/oauth",
		"runtime_capability/tenants",
		"tauth_authorization_server/oauth-server",
	}
	if !slices.Equal(resourceIdentities, expectedResourceIdentities) {
		t.Fatalf("application resource identities do not match the TAuth lifecycle: %#v", resourceIdentities)
	}
	if runtimeProject == nil {
		t.Fatal("application resource manifest has no runtime Compose project")
	}
	if browserHelperPages == nil {
		t.Fatal("application resource manifest has no canonical browser-helper Pages resource")
	}
	for fieldName, expectedValue := range map[string]string{
		"repository": "tyemirov/tauth",
		"branch":     "gh-pages",
		"domain":     "tauth.mprlab.com",
		"url":        "https://tauth.mprlab.com/",
	} {
		if actualValue := stringField(t, browserHelperPages, fieldName); actualValue != expectedValue {
			t.Fatalf("browser-helper Pages %s mismatch: got %q want %q", fieldName, actualValue, expectedValue)
		}
	}
	pagesSource, available := browserHelperPages["source"].(map[string]any)
	if !available || len(pagesSource) != 4 ||
		stringField(t, pagesSource, "kind") != "container" ||
		stringField(t, pagesSource, "context") != "." ||
		stringField(t, pagesSource, "dockerfile") != "docker/pages/Dockerfile" ||
		stringField(t, pagesSource, "target") != "pages" {
		t.Fatalf("browser-helper Pages source is not the exact site artifact: %#v", browserHelperPages["source"])
	}
	pagesVerification, available := browserHelperPages["verification"].(map[string]any)
	if !available || len(pagesVerification) != 1 || stringField(t, pagesVerification, "path") != "/.mprlab-release.json" {
		t.Fatalf("browser-helper Pages verification is not canonical: %#v", browserHelperPages["verification"])
	}
	if _, available := runtimeProject["placement"]; available {
		t.Fatalf("runtime Compose project retains obsolete project placement: %#v", runtimeProject["placement"])
	}
	if _, available := runtimeProject["profiles"]; available {
		t.Fatalf("runtime Compose project retains obsolete profiles: %#v", runtimeProject["profiles"])
	}
	services, available := runtimeProject["services"].(map[string]any)
	if !available || len(services) != 1 {
		t.Fatalf("runtime Compose project must declare exactly one service: %#v", runtimeProject["services"])
	}
	runtimeService, available := services["tauth-api"].(map[string]any)
	if !available {
		t.Fatalf("runtime Compose service is not a mapping: %#v", services["tauth-api"])
	}
	placement, available := runtimeService["placement"].(map[string]any)
	if !available || len(placement) != 2 {
		t.Fatalf("runtime Compose service must declare exact placement: %#v", runtimeService["placement"])
	}
	if group := stringField(t, placement, "group"); group != "gateway" {
		t.Fatalf("runtime Compose service has unexpected placement group: %q", group)
	}
	if cardinality := stringField(t, placement, "cardinality"); cardinality != "one" {
		t.Fatalf("runtime Compose service has unexpected placement cardinality: %q", cardinality)
	}
	if _, available := runtimeService["environment_files"]; available {
		t.Fatalf("runtime Compose service retains obsolete environment files: %#v", runtimeService["environment_files"])
	}
	retiredServices, available := runtimeProject["retired_services"].(map[string]any)
	if !available || len(retiredServices) != 1 {
		t.Fatalf("runtime Compose project must retire exactly one service: %#v", runtimeProject["retired_services"])
	}
	retiredService, available := retiredServices["mprlab-nginx-gateway/tauth-api"].(map[string]any)
	if !available || len(retiredService) != 0 {
		t.Fatalf("service retirement must use its project/service key and an empty body: %#v", retiredServices)
	}

	manifestText := string(manifestDocument)
	if strings.Contains(manifestText, "\n          visibility:") {
		t.Fatal("application image retains removed visibility field")
	}
	for _, requiredContract := range []string{
		"managed: tauth.config",
		"name: mprlab-nginx-gateway_tauth-data",
		"name: tauth.http",
		"name: tauth.tenants",
		"name: tauth.oauth",
		"alias: tauth-api",
		"alias: tauth-tenants",
		"alias: tauth-oauth",
		"hostname: tauth-api.mprlab.com",
		"url: https://tauth-api.mprlab.com/health",
	} {
		if !strings.Contains(manifestText, requiredContract) {
			t.Errorf("application resource manifest is missing %q", requiredContract)
		}
	}
	if healthPathCount := strings.Count(manifestText, "path: /health"); healthPathCount != 4 {
		t.Errorf("application resource manifest must use /health at four backend readiness boundaries, got %d", healthPathCount)
	}
	for _, obsoleteContract := range []string{
		"schema_version:",
		"dependencies:",
		"profiles:",
		"environment_files:",
		"make_workflow",
		"ansible_task_bundle",
		"dispatch_target:",
		"directory:",
		"hostname: tauth.mprlab.com",
		"path: /tauth.js",
		"url: https://tauth-api.mprlab.com/tauth.js",
	} {
		if strings.Contains(manifestText, obsoleteContract) {
			t.Errorf("application resource manifest retains obsolete contract %q", obsoleteContract)
		}
	}
}

func TestAPIImageExcludesBrowserHelper(t *testing.T) {
	repositoryRoot := testRepositoryRoot(t)
	runtimeDockerfileDocument, readErr := os.ReadFile(filepath.Join(repositoryRoot, "Dockerfile"))
	if readErr != nil {
		t.Fatalf("read API image Dockerfile: %v", readErr)
	}
	if strings.Contains(string(runtimeDockerfileDocument), "/web") {
		t.Fatalf("API image Dockerfile retains the obsolete browser-helper filesystem")
	}
}

func TestPagesArtifactAssemblesDocsAndCanonicalHelper(t *testing.T) {
	repositoryRoot := testRepositoryRoot(t)
	dockerfilePath := filepath.Join(repositoryRoot, "docker", "pages", "Dockerfile")
	dockerfileDocument, readErr := os.ReadFile(dockerfilePath)
	if readErr != nil {
		t.Fatalf("read Pages artifact Dockerfile: %v", readErr)
	}
	expectedDockerfile := strings.Join([]string{
		"# syntax=docker/dockerfile:1",
		"",
		"FROM scratch AS pages-source",
		"",
		"COPY docs/ /",
		"COPY web/tauth.js /tauth.js",
		"COPY web/app/ /app/",
		"",
		"FROM scratch AS pages",
		"",
		"COPY --from=pages-source / /",
		"",
	}, "\n")
	if string(dockerfileDocument) != expectedDockerfile {
		t.Fatalf("Pages artifact Dockerfile does not assemble the exact published site")
	}

	noJekyllPath := filepath.Join(repositoryRoot, "web", ".nojekyll")
	if _, statErr := os.Stat(noJekyllPath); !os.IsNotExist(statErr) {
		t.Fatalf("TAuth must not contain the gateway-owned Pages .nojekyll marker: %v", statErr)
	}
}

func TestPagesArtifactUsesProductionLoopAwareIdentity(t *testing.T) {
	repositoryRoot := testRepositoryRoot(t)
	const pixelURL = "https://loopaware.mprlab.com/pixel.js?site_id=fe20ae87-c3fc-4347-a76f-dcceb4143e92"
	for _, relativePath := range []string{"docs/index.html", "docs/usage.html"} {
		pageDocument, readErr := os.ReadFile(filepath.Join(repositoryRoot, filepath.FromSlash(relativePath)))
		if readErr != nil {
			t.Fatalf("read published page %s: %v", relativePath, readErr)
		}
		pageText := string(pageDocument)
		if strings.Count(pageText, "https://loopaware.mprlab.com/pixel.js") != 1 {
			t.Errorf("published page %s must contain one LoopAware pixel", relativePath)
		}
		if !strings.Contains(pageText, pixelURL) {
			t.Errorf("published page %s does not use the production TAuth site identity", relativePath)
		}
	}
}

func TestDockerBuildContextsUseCanonicalIgnoreContract(t *testing.T) {
	repositoryRoot := testRepositoryRoot(t)
	for _, relativePath := range []string{
		"Dockerfile.dockerignore",
		"docker/pages/Dockerfile.dockerignore",
	} {
		_, statErr := os.Stat(filepath.Join(repositoryRoot, filepath.FromSlash(relativePath)))
		if !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("Dockerfile-specific ignore file replaces the root contract: %s", relativePath)
		}
	}

	dockerIgnoreBytes, readErr := os.ReadFile(filepath.Join(repositoryRoot, ".dockerignore"))
	if readErr != nil {
		t.Fatalf("read Docker ignore contract: %v", readErr)
	}
	exclusions := make(map[string]struct{})
	for _, line := range strings.Split(string(dockerIgnoreBytes), "\n") {
		if strings.HasPrefix(line, "!") {
			t.Errorf("Docker ignore contract contains negation %q", line)
		}
		exclusions[line] = struct{}{}
	}
	if _, excludesPagesSource := exclusions["docs/"]; excludesPagesSource {
		t.Error("Docker ignore contract excludes the required Pages docs source")
	}
	for _, required := range []string{
		".git",
		".env*",
		"tests/",
		"tools/",
		".github/",
		"node_modules/",
		".mprlab/deploy/.env",
	} {
		if _, exists := exclusions[required]; !exists {
			t.Errorf("Docker ignore contract lacks required exclusion %q", required)
		}
	}
}

func TestRepositoryDelegatesOnlyThreeProductionLifecycleCommands(t *testing.T) {
	repositoryRoot := testRepositoryRoot(t)
	makefileDocument, readErr := os.ReadFile(filepath.Join(repositoryRoot, "Makefile"))
	if readErr != nil {
		t.Fatalf("read Makefile: %v", readErr)
	}
	makefileText := string(makefileDocument)
	for _, obsoleteTarget := range []string{
		"\ncontainer-artifacts:",
		"\npublish-release:",
		"\ndeploy-dry-run:",
	} {
		if strings.Contains(makefileText, obsoleteTarget) {
			t.Errorf("Makefile retains obsolete production target %q", obsoleteTarget)
		}
	}

	for _, forbiddenPath := range []string{
		".mprlab/release.yml",
		".env.deploy.example",
		"scripts/deploy.sh",
		"scripts/release.sh",
		"scripts/publish-release.sh",
		"scripts/release",
		"tests/releasecontract",
	} {
		_, statErr := os.Stat(filepath.Join(repositoryRoot, filepath.FromSlash(forbiddenPath)))
		if !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("application repository still owns production lifecycle path %s", forbiddenPath)
		}
	}

	trackedDeployCommand := exec.Command("git", "ls-files", ".mprlab/deploy")
	trackedDeployCommand.Dir = repositoryRoot
	trackedDeployOutput, trackedDeployErr := trackedDeployCommand.Output()
	if trackedDeployErr != nil {
		t.Fatalf("list tracked deployment files: %v", trackedDeployErr)
	}
	trackedDeployFiles := strings.Fields(string(trackedDeployOutput))
	if !slices.Equal(trackedDeployFiles, []string{deployManifestRelativePath}) {
		t.Fatalf("application repository has unexpected tracked deployment files: %#v", trackedDeployFiles)
	}
}

func stringField(t *testing.T, document map[string]any, fieldName string) string {
	t.Helper()
	value, available := document[fieldName].(string)
	if !available || value == "" {
		t.Fatalf("manifest field %s is not a non-empty string: %#v", fieldName, document[fieldName])
	}
	return value
}

func testRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, testFilename, _, available := runtime.Caller(0)
	if !available {
		t.Fatal("resolve repository contract test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(testFilename), ".."))
}

func mappingField(t *testing.T, document map[string]any, fieldName string) map[string]any {
	t.Helper()
	value, available := document[fieldName].(map[string]any)
	if !available {
		t.Fatalf("manifest field %s is not a mapping: %#v", fieldName, document[fieldName])
	}
	return value
}

func durationField(t *testing.T, document map[string]any, fieldName string) time.Duration {
	t.Helper()
	value, err := time.ParseDuration(stringField(t, document, fieldName))
	if err != nil {
		t.Fatalf("manifest field %s is not a duration: %v", fieldName, err)
	}
	return value
}

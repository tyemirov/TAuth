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

	"gopkg.in/yaml.v3"
)

const deployManifestRelativePath = ".mprlab/deploy/resources.yml"

var expectedGatewayWrapper = strings.Join([]string{
	".PHONY: release publish deploy",
	"",
	"release publish deploy:",
	"\t@application_root=\"$$(git rev-parse --show-toplevel)\"; \\",
	"\tgateway_root=\"$$(dirname \"$${application_root}\")/mprlab-gateway\"; \\",
	"\tif [ ! -d \"$${gateway_root}\" ]; then \\",
	"\t\tprintf \"required sibling gateway is missing: %s; clone mprlab-gateway at exactly %s\\n\" \\",
	"\t\t\t\"$${gateway_root}\" \"$${gateway_root}\" >&2; \\",
	"\t\texit 2; \\",
	"\tfi; \\",
	"\t$(MAKE) --no-print-directory -C \"$${gateway_root}\" \"app-$@\" \\",
	"\t\tMPRLAB_APP_ROOT=\"$${application_root}\"",
}, "\n")

func TestRepositoryOwnsSchemaV4ApplicationResources(t *testing.T) {
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
	if schemaVersion, available := resourcesDocument["schema_version"].(int); !available || schemaVersion != 4 {
		t.Fatalf("application resource manifest has unexpected schema version: %#v", resourcesDocument["schema_version"])
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
	if !slices.Equal(resourceKeys, []string{"owner", "release", "resources", "schema_version"}) {
		t.Fatalf("application resource manifest root is not the exact schema-v4 contract: %#v", resourceKeys)
	}

	resources, available := resourcesDocument["resources"].([]any)
	if !available {
		t.Fatalf("application resource manifest has no resources list: %#v", resourcesDocument["resources"])
	}
	resourceIdentities := make([]string, 0, len(resources))
	var runtimeProject map[string]any
	var browserHelperPages map[string]any
	for _, resourceValue := range resources {
		resource, resourceAvailable := resourceValue.(map[string]any)
		if !resourceAvailable {
			t.Fatalf("application resource is not a mapping: %#v", resourceValue)
		}
		resourceIdentity := stringField(t, resource, "kind") + "/" + stringField(t, resource, "id")
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
	services, available := runtimeProject["services"].([]any)
	if !available || len(services) != 1 {
		t.Fatalf("runtime Compose project must declare exactly one service: %#v", runtimeProject["services"])
	}
	runtimeService, available := services[0].(map[string]any)
	if !available {
		t.Fatalf("runtime Compose service is not a mapping: %#v", services[0])
	}
	placement, available := runtimeService["placement"].(map[string]any)
	if !available || len(placement) != 2 {
		t.Fatalf("runtime Compose service must declare exact schema-v4 placement: %#v", runtimeService["placement"])
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
	retiredServices, available := runtimeProject["retired_services"].([]any)
	if !available || len(retiredServices) != 1 {
		t.Fatalf("runtime Compose project must retire exactly one legacy service: %#v", runtimeProject["retired_services"])
	}
	retiredService, available := retiredServices[0].(map[string]any)
	if !available || len(retiredService) != 2 {
		t.Fatalf("legacy service retirement must contain only project and service: %#v", retiredServices[0])
	}
	if project := stringField(t, retiredService, "project"); project != "mprlab-nginx-gateway" {
		t.Fatalf("legacy service retirement has unexpected Compose project: %q", project)
	}
	if service := stringField(t, retiredService, "service"); service != "tauth-api" {
		t.Fatalf("legacy service retirement has unexpected service: %q", service)
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
		"schema_version: 1",
		"schema_version: 2",
		"schema_version: 3",
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
		"COPY web/.nojekyll /.nojekyll",
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
	noJekyllInfo, statErr := os.Stat(noJekyllPath)
	if statErr != nil {
		t.Fatalf("inspect Pages .nojekyll marker: %v", statErr)
	}
	if !noJekyllInfo.Mode().IsRegular() || noJekyllInfo.Size() != 0 {
		t.Fatalf("Pages .nojekyll marker must be an empty regular file: mode=%s size=%d", noJekyllInfo.Mode(), noJekyllInfo.Size())
	}

	dockerIgnoreDocument, readErr := os.ReadFile(filepath.Join(repositoryRoot, ".dockerignore"))
	if readErr != nil {
		t.Fatalf("read Docker ignore contract: %v", readErr)
	}
	if !strings.HasSuffix(string(dockerIgnoreDocument), "\n!docs/\n!docs/**\n") {
		t.Fatalf("Docker ignore contract does not expose the complete Pages docs source")
	}
}

func TestRepositoryDelegatesOnlyThreeProductionLifecycleCommands(t *testing.T) {
	repositoryRoot := testRepositoryRoot(t)
	makefileDocument, readErr := os.ReadFile(filepath.Join(repositoryRoot, "Makefile"))
	if readErr != nil {
		t.Fatalf("read Makefile: %v", readErr)
	}
	makefileText := string(makefileDocument)
	if !strings.Contains(makefileText, expectedGatewayWrapper) {
		t.Fatalf("Makefile does not expose the exact sibling-gateway wrapper")
	}
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

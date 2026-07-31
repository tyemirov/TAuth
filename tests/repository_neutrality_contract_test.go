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

func TestRepositoryOwnsSchemaV2ApplicationResources(t *testing.T) {
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
	if schemaVersion, available := resourcesDocument["schema_version"].(int); !available || schemaVersion != 2 {
		t.Fatalf("application resource manifest has unexpected schema version: %#v", resourcesDocument["schema_version"])
	}
	if owner, available := resourcesDocument["owner"].(string); !available || owner != "tauth" {
		t.Fatalf("application resource manifest has unexpected owner: %#v", resourcesDocument["owner"])
	}
	dependencies, available := resourcesDocument["dependencies"].([]any)
	if !available || len(dependencies) != 0 {
		t.Fatalf("TAuth must declare no runtime dependencies: %#v", resourcesDocument["dependencies"])
	}

	resources, available := resourcesDocument["resources"].([]any)
	if !available {
		t.Fatalf("application resource manifest has no resources list: %#v", resourcesDocument["resources"])
	}
	resourceIdentities := make([]string, 0, len(resources))
	for _, resourceValue := range resources {
		resource, resourceAvailable := resourceValue.(map[string]any)
		if !resourceAvailable {
			t.Fatalf("application resource is not a mapping: %#v", resourceValue)
		}
		resourceIdentities = append(resourceIdentities, stringField(t, resource, "kind")+"/"+stringField(t, resource, "id"))
	}
	slices.Sort(resourceIdentities)
	expectedResourceIdentities := []string{
		"caddy_route/public-api",
		"caddy_route/public-helper",
		"compose_project/runtime",
		"health_check/public-health",
		"runtime_capability/http",
		"runtime_capability/tenants",
	}
	if !slices.Equal(resourceIdentities, expectedResourceIdentities) {
		t.Fatalf("application resource identities do not match the TAuth lifecycle: %#v", resourceIdentities)
	}

	manifestText := string(manifestDocument)
	for _, requiredContract := range []string{
		"managed: tauth.config",
		"secret: tauth.runtime-environment",
		"name: mprlab-nginx-gateway_tauth-data",
		"name: tauth.http",
		"name: tauth.tenants",
		"alias: tauth-api",
		"alias: tauth-tenants",
		"hostname: tauth-api.mprlab.com",
		"hostname: tauth.mprlab.com",
		"url: https://tauth-api.mprlab.com/tauth.js",
	} {
		if !strings.Contains(manifestText, requiredContract) {
			t.Errorf("application resource manifest is missing %q", requiredContract)
		}
	}
	for _, obsoleteContract := range []string{
		"schema_version: 1",
		"make_workflow",
		"ansible_task_bundle",
		"dispatch_target:",
		"directory:",
	} {
		if strings.Contains(manifestText, obsoleteContract) {
			t.Errorf("application resource manifest retains obsolete contract %q", obsoleteContract)
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

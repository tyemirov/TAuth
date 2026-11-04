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
	manifestDocument, err := os.ReadFile(filepath.Join(repositoryRoot, filepath.FromSlash(deployManifestRelativePath)))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(manifestDocument, &document); err != nil {
		t.Fatal(err)
	}
	if len(document) != 1 {
		t.Fatal("application manifest must have one document root")
	}
	root := mappingField(t, document, "mprlab_resources")
	if root["owner"] != "tauth" || mappingField(t, root, "release")["scheme"] != "semver" {
		t.Fatal("application owner or release policy changed")
	}
	keys := make([]string, 0, len(root))
	for key := range root {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"artifacts", "environment", "lifecycle", "owner", "publications", "release", "targets"}) {
		t.Fatalf("selected manifest is not the current versionless contract: %v", keys)
	}
	environment := mappingField(t, root, "environment")
	if environment["source"] != ".mprlab/deploy/.env" {
		t.Fatal("application must select its explicit private source")
	}
	inputs := map[string]string{}
	for _, raw := range listField(t, environment, "private_inputs") {
		input := raw.(map[string]any)
		id, variable := stringField(t, input, "id"), stringField(t, input, "variable")
		if inputs[id] != "" {
			t.Fatalf("duplicate private input %s", id)
		}
		inputs[id] = variable
	}
	targets := mappingField(t, root, "targets")
	host := identifiedManifestEntry(t, listField(t, mappingField(t, targets, "access"), "hosts"), "host", "tutosh")
	if inputs[stringField(t, mappingField(t, host, "elevation_password"), "input")] != "DEPLOY_SUDO_PASSWORD_TUTOSH" {
		t.Fatal("host authentication lost its declared private input")
	}
	lifecycle := mappingField(t, root, "lifecycle")
	ci := mappingField(t, lifecycle, "ci")
	command := listField(t, ci, "command")
	if ci["enabled"] != true || len(command) != 2 || command[0] != "make" || command[1] != "ci" {
		t.Fatal("CI must enable ordered make ci")
	}
	timeouts := mappingField(t, mappingField(t, lifecycle, "defaults"), "timeouts")
	for _, name := range []string{"startup", "completion", "readiness", "request", "shutdown"} {
		if durationField(t, timeouts, name) <= 0 {
			t.Fatalf("nonpositive %s timeout", name)
		}
	}
	for _, raw := range listField(t, lifecycle, "operations") {
		operation := raw.(map[string]any)
		if rawTimeouts, ok := operation["timeouts"]; ok {
			if durationField(t, rawTimeouts.(map[string]any), "completion") <= 0 {
				t.Fatal("nonpositive operation timeout")
			}
		}
		if rawPolling, ok := operation["polling"]; ok {
			polling := rawPolling.(map[string]any)
			initial, maximum, increment := durationField(t, polling, "initial"), durationField(t, polling, "maximum"), durationField(t, polling, "increment")
			multiplier, multiplierOK := polling["multiplier"].(int)
			attempts, attemptsOK := polling["attempt_limit"].(int)
			if initial <= 0 || maximum < initial || increment < 0 || !multiplierOK || multiplier < 1 || !attemptsOK || attempts < 1 {
				t.Fatalf("invalid finite polling for %v", operation["name"])
			}
		}
	}
	artifacts := mappingField(t, root, "artifacts")
	publications := mappingField(t, root, "publications")
	image := identifiedManifestEntry(t, listField(t, mappingField(t, publications, "ghcr"), "images"), "id", "tauth-image")
	if image["repository"] != "ghcr.io/tyemirov/tauth" {
		t.Fatal("ordinary service image repository changed")
	}
	project := identifiedManifestEntry(t, listField(t, mappingField(t, targets, "docker_compose"), "projects"), "id", "runtime")
	services := listField(t, project, "services")
	if len(services) != 1 {
		t.Fatal("TAuth must retain its one runtime service")
	}
	service := identifiedManifestEntry(t, services, "id", "tauth-api")
	if mappingField(t, service, "image")["publication"] != "tauth-image" {
		t.Fatal("TAuth runtime lost its image publication")
	}
	placement := mappingField(t, service, "placement")
	if placement["group"] != "gateway" || placement["cardinality"] != "one" {
		t.Fatal("TAuth placement changed")
	}
	volume := identifiedManifestEntry(t, listField(t, project, "volumes"), "id", "data")
	if volume["name"] != "mprlab-nginx-gateway_tauth-data" || volume["retention"] != "retain" {
		t.Fatal("TAuth persistent volume changed")
	}
	asset := identifiedManifestEntry(t, listField(t, service, "assets"), "target", "/config/config.yml")
	if asset["secret"] != "tauth-native-config" {
		t.Fatal("TAuth must use its retained native configuration file")
	}
	endpoints := listField(t, service, "endpoints")
	for id, name := range map[string]string{"http": "tauth.http", "oauth": "tauth.oauth", "tenants": "tauth.tenants"} {
		endpoint := identifiedManifestEntry(t, endpoints, "id", id)
		if endpoint["name"] != name || mappingField(t, endpoint, "health")["path"] != "/health" {
			t.Fatalf("ordinary TAuth endpoint %s changed", id)
		}
	}
	site := identifiedManifestEntry(t, listField(t, mappingField(t, targets, "github_pages"), "sites"), "id", "browser-helper")
	if site["publication"] != "browser-helper" || site["url"] != "https://tauth.mprlab.com/" {
		t.Fatal("browser-helper serving destination changed")
	}
	publishedSite := identifiedManifestEntry(t, listField(t, mappingField(t, publications, "github_pages"), "sites"), "id", "browser-helper")
	if publishedSite["repository"] != "tyemirov/tauth" || publishedSite["branch"] != "gh-pages" || publishedSite["domain"] != "tauth.mprlab.com" || mappingField(t, publishedSite, "marker")["path"] != "/.mprlab-release.json" {
		t.Fatal("browser-helper publication destination changed")
	}
	web := identifiedManifestEntry(t, listField(t, artifacts, "web_bundles"), "id", "browser-helper")
	source := mappingField(t, web, "source")
	if source["kind"] != "container" || source["context"] != "." || source["dockerfile"] != "docker/pages/Dockerfile" || source["target"] != "pages" {
		t.Fatal("browser-helper build source changed")
	}
	for _, platform := range []string{"darwin-arm64", "linux-amd64"} {
		binary := identifiedManifestEntry(t, listField(t, artifacts, "binaries"), "id", "retention-audit-"+platform)
		build := mappingField(t, binary, "build")
		if build["binary"] != "tauth-retention-audit" || build["package"] != "./cmd/retentionaudit" {
			t.Fatal("retention auditor must remain a separate binary")
		}
	}
}

func listField(t *testing.T, document map[string]any, name string) []any {
	t.Helper()
	value, ok := document[name].([]any)
	if !ok {
		t.Fatalf("manifest field %s is not a list", name)
	}
	return value
}

func identifiedManifestEntry(t *testing.T, entries []any, field, identity string) map[string]any {
	t.Helper()
	for _, raw := range entries {
		entry, ok := raw.(map[string]any)
		if ok && entry[field] == identity {
			return entry
		}
	}
	t.Fatalf("manifest entry %s=%s is absent", field, identity)
	return nil
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

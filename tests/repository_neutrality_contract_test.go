package productionconfig_test

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var forbiddenVendorTokens = []string{
	"marcopoloresearchlab",
	"mpr-ui",
	"mprlab.com",
	"mprlab-release",
	"mprlab.container",
	"mprlab.release",
}

const (
	deployConfigFileName       = ".env.deploy"
	deployConfigExampleName    = ".env.deploy.example"
	deployManifestRelativePath = ".mprlab/deploy/resources.yml"
	deployScriptRelativePath   = "scripts/deploy.sh"
	fixtureDeployMakeTarget    = "apply"
	fixtureDeployMissingTarget = "missing"
)

type deploymentManifestDocument struct {
	Resources deploymentManifest `yaml:"mprlab_resources"`
}

type deploymentManifest struct {
	SchemaVersion int                          `yaml:"schema_version"`
	Repository    deploymentManifestRepository `yaml:"repo"`
	Resources     []deploymentManifestResource `yaml:"resources"`
}

type deploymentManifestRepository struct {
	ID             string `yaml:"id"`
	Directory      string `yaml:"directory"`
	DispatchTarget string `yaml:"dispatch_target"`
}

type deploymentManifestResource struct {
	Type    string                        `yaml:"type"`
	Name    string                        `yaml:"name"`
	Targets deploymentManifestMakeTargets `yaml:"targets"`
}

type deploymentManifestMakeTargets struct {
	Release string `yaml:"release"`
	Publish string `yaml:"publish"`
	Deploy  string `yaml:"deploy"`
}

func TestRepositoryExposesVanillaLocalDeploymentContract(t *testing.T) {
	repositoryRoot := testRepositoryRoot(t)
	for _, relativePath := range []string{deployConfigExampleName, deployScriptRelativePath} {
		path := filepath.Join(repositoryRoot, filepath.FromSlash(relativePath))
		_, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatalf("generic TAuth repository is missing deployment contract %s: %v", relativePath, statErr)
		}
	}

	makefilePath := filepath.Join(repositoryRoot, "Makefile")
	makefileDocument, readErr := os.ReadFile(makefilePath)
	if readErr != nil {
		t.Fatalf("read Makefile: %v", readErr)
	}
	makefileText := string(makefileDocument)
	for _, requiredContract := range []string{"\ndeploy-dry-run:", "\ndeploy:", deployScriptRelativePath} {
		if !strings.Contains(makefileText, requiredContract) {
			t.Errorf("generic TAuth Makefile is missing deployment contract %q", requiredContract)
		}
	}

	ignoreCommand := exec.Command("git", "check-ignore", "--quiet", "--no-index", deployConfigFileName)
	ignoreCommand.Dir = repositoryRoot
	if ignoreErr := ignoreCommand.Run(); ignoreErr != nil {
		t.Fatalf("local deployment config must be ignored: %v", ignoreErr)
	}
}

func TestRepositoryExposesVanillaDeploymentDiscoveryManifest(t *testing.T) {
	repositoryRoot := testRepositoryRoot(t)
	manifestPath := filepath.Join(repositoryRoot, filepath.FromSlash(deployManifestRelativePath))
	manifestDocument, readErr := os.ReadFile(manifestPath)
	if readErr != nil {
		t.Fatalf("read vanilla deployment discovery manifest: %v", readErr)
	}

	var document deploymentManifestDocument
	decoder := yaml.NewDecoder(strings.NewReader(string(manifestDocument)))
	decoder.KnownFields(true)
	if decodeErr := decoder.Decode(&document); decodeErr != nil {
		t.Fatalf("decode vanilla deployment discovery manifest: %v", decodeErr)
	}

	manifest := document.Resources
	if manifest.SchemaVersion != 1 {
		t.Errorf("unexpected deployment manifest schema version: %d", manifest.SchemaVersion)
	}
	expectedRepository := deploymentManifestRepository{
		ID:             "tauth",
		Directory:      "TAuth",
		DispatchTarget: "tauth",
	}
	if manifest.Repository != expectedRepository {
		t.Errorf("unexpected deployment manifest repository identity: %#v", manifest.Repository)
	}
	if len(manifest.Resources) != 1 {
		t.Fatalf("vanilla deployment manifest must expose exactly one lifecycle resource, got %d", len(manifest.Resources))
	}

	resource := manifest.Resources[0]
	expectedResource := deploymentManifestResource{
		Type: "make_workflow",
		Name: "tauth",
		Targets: deploymentManifestMakeTargets{
			Release: "release",
			Publish: "publish",
			Deploy:  "deploy",
		},
	}
	if resource != expectedResource {
		t.Errorf("unexpected vanilla deployment lifecycle resource: %#v", resource)
	}
}

func TestDeployDryRunRequiresLocalConfiguration(t *testing.T) {
	fixtureRoot := prepareDeploymentFixture(t)
	deployOutput, deployErr := runFixtureMake(fixtureRoot, "deploy-dry-run")
	if deployErr == nil {
		t.Fatalf("deploy dry-run accepted a missing local configuration:\n%s", deployOutput)
	}
	if !strings.Contains(string(deployOutput), "local deployment config not found") {
		t.Fatalf("deploy dry-run returned an unexpected missing-config error: %v\n%s", deployErr, deployOutput)
	}
}

func TestDeployDryRunValidatesWithoutExecutingLocalTarget(t *testing.T) {
	fixtureRoot := prepareDeploymentFixture(t)
	operatorDirectory := prepareOperatorFixture(t, fixtureRoot)
	writeDeploymentConfig(t, fixtureRoot, operatorDirectory, fixtureDeployMakeTarget)

	deployOutput, deployErr := runFixtureMake(fixtureRoot, "deploy-dry-run")
	if deployErr != nil {
		t.Fatalf("run deploy dry-run: %v\n%s", deployErr, deployOutput)
	}
	outputText := string(deployOutput)
	for _, expectedOutput := range []string{
		"deployment_config=" + filepath.Join(fixtureRoot, deployConfigFileName),
		"deployment_directory=" + operatorDirectory,
		"deployment_make_target=" + fixtureDeployMakeTarget,
	} {
		if !strings.Contains(outputText, expectedOutput) {
			t.Errorf("deploy dry-run output is missing %q:\n%s", expectedOutput, deployOutput)
		}
	}
	if _, statErr := os.Stat(filepath.Join(fixtureRoot, "dispatch.log")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("deploy dry-run executed the local target: %v", statErr)
	}
}

func TestDeployDryRunRejectsUnknownLocalTarget(t *testing.T) {
	fixtureRoot := prepareDeploymentFixture(t)
	operatorDirectory := prepareOperatorFixture(t, fixtureRoot)
	writeDeploymentConfig(t, fixtureRoot, operatorDirectory, fixtureDeployMissingTarget)

	deployOutput, deployErr := runFixtureMake(fixtureRoot, "deploy-dry-run")
	if deployErr == nil {
		t.Fatalf("deploy dry-run accepted an unknown local target:\n%s", deployOutput)
	}
	if !strings.Contains(string(deployOutput), "configured deployment Make target is unavailable") {
		t.Fatalf("deploy dry-run returned an unexpected target error: %v\n%s", deployErr, deployOutput)
	}
}

func TestDeployDryRunRejectsIncompleteLocalConfiguration(t *testing.T) {
	for _, testCase := range []struct {
		name                 string
		configurationForRoot func(string) string
		expected             string
	}{
		{
			name: "missing directory",
			configurationForRoot: func(string) string {
				return "DEPLOY_MAKE_TARGET=" + fixtureDeployMakeTarget + "\n"
			},
			expected: "DEPLOY_DIRECTORY is required",
		},
		{
			name: "missing target",
			configurationForRoot: func(fixtureRoot string) string {
				return "DEPLOY_DIRECTORY=" + fixtureRoot + "\n"
			},
			expected: "DEPLOY_MAKE_TARGET is required",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixtureRoot := prepareDeploymentFixture(t)
			writeRawDeploymentConfig(t, fixtureRoot, testCase.configurationForRoot(fixtureRoot), 0o600)

			deployOutput, deployErr := runFixtureMake(fixtureRoot, "deploy-dry-run")
			if deployErr == nil || !strings.Contains(string(deployOutput), testCase.expected) {
				t.Fatalf("deploy dry-run accepted incomplete local configuration: %v\n%s", deployErr, deployOutput)
			}
		})
	}
}

func TestDeployDryRunRejectsExecutableConfigSyntax(t *testing.T) {
	fixtureRoot := prepareDeploymentFixture(t)
	operatorDirectory := prepareOperatorFixture(t, fixtureRoot)
	executionMarker := filepath.Join(fixtureRoot, "config-executed")
	writeRawDeploymentConfig(
		t,
		fixtureRoot,
		fmt.Sprintf(
			"DEPLOY_DIRECTORY=%s\nDEPLOY_MAKE_TARGET=%s\nprintf exploited > %s\n",
			operatorDirectory,
			fixtureDeployMakeTarget,
			executionMarker,
		),
		0o600,
	)

	deployOutput, deployErr := runFixtureMake(fixtureRoot, "deploy-dry-run")
	if deployErr == nil || !strings.Contains(string(deployOutput), "invalid .env.deploy assignment") {
		t.Fatalf("deploy dry-run accepted executable config syntax: %v\n%s", deployErr, deployOutput)
	}
	if _, statErr := os.Stat(executionMarker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("deployment config was executed: %v", statErr)
	}
}

func TestDeployDryRunRejectsUnknownAndDuplicateConfigKeys(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		extra    string
		expected string
	}{
		{name: "unknown", extra: "DEPLOY_EXTRA=value\n", expected: "unknown .env.deploy key"},
		{name: "duplicate", extra: "DEPLOY_MAKE_TARGET=second-target\n", expected: "DEPLOY_MAKE_TARGET is duplicated"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixtureRoot := prepareDeploymentFixture(t)
			operatorDirectory := prepareOperatorFixture(t, fixtureRoot)
			writeRawDeploymentConfig(
				t,
				fixtureRoot,
				fmt.Sprintf(
					"DEPLOY_DIRECTORY=%s\nDEPLOY_MAKE_TARGET=%s\n%s",
					operatorDirectory,
					fixtureDeployMakeTarget,
					testCase.extra,
				),
				0o600,
			)

			deployOutput, deployErr := runFixtureMake(fixtureRoot, "deploy-dry-run")
			if deployErr == nil || !strings.Contains(string(deployOutput), testCase.expected) {
				t.Fatalf("deploy dry-run accepted %s config key: %v\n%s", testCase.name, deployErr, deployOutput)
			}
		})
	}
}

func TestDeployDryRunRejectsPermissiveLocalConfiguration(t *testing.T) {
	fixtureRoot := prepareDeploymentFixture(t)
	operatorDirectory := prepareOperatorFixture(t, fixtureRoot)
	writeDeploymentConfig(t, fixtureRoot, operatorDirectory, fixtureDeployMakeTarget)
	if chmodErr := os.Chmod(filepath.Join(fixtureRoot, deployConfigFileName), 0o644); chmodErr != nil {
		t.Fatalf("make local deployment config permissive: %v", chmodErr)
	}

	deployOutput, deployErr := runFixtureMake(fixtureRoot, "deploy-dry-run")
	if deployErr == nil || !strings.Contains(string(deployOutput), "mode 0600") {
		t.Fatalf("deploy dry-run accepted permissive local configuration: %v\n%s", deployErr, deployOutput)
	}
}

func TestDeployDryRunRejectsSymlinkedLocalConfiguration(t *testing.T) {
	fixtureRoot := prepareDeploymentFixture(t)
	operatorDirectory := prepareOperatorFixture(t, fixtureRoot)
	realConfigPath := filepath.Join(fixtureRoot, "operator.env")
	configDocument := fmt.Sprintf(
		"DEPLOY_DIRECTORY=%s\nDEPLOY_MAKE_TARGET=%s\n",
		operatorDirectory,
		fixtureDeployMakeTarget,
	)
	if writeErr := os.WriteFile(realConfigPath, []byte(configDocument), 0o600); writeErr != nil {
		t.Fatalf("write symlink target deployment config: %v", writeErr)
	}
	if symlinkErr := os.Symlink(realConfigPath, filepath.Join(fixtureRoot, deployConfigFileName)); symlinkErr != nil {
		t.Fatalf("symlink local deployment config: %v", symlinkErr)
	}

	deployOutput, deployErr := runFixtureMake(fixtureRoot, "deploy-dry-run")
	if deployErr == nil || !strings.Contains(string(deployOutput), "local deployment config not found") {
		t.Fatalf("deploy dry-run accepted symlinked local configuration: %v\n%s", deployErr, deployOutput)
	}
}

func TestDeployDispatchesThroughLocalConfiguration(t *testing.T) {
	fixtureRoot := prepareDeploymentFixture(t)
	operatorDirectory := prepareOperatorFixture(t, fixtureRoot)
	writeDeploymentConfig(t, fixtureRoot, operatorDirectory, fixtureDeployMakeTarget)

	deployOutput, deployErr := runFixtureMake(fixtureRoot, "deploy")
	if deployErr != nil {
		t.Fatalf("run local fixture deploy: %v\n%s", deployErr, deployOutput)
	}
	dispatchLogPath := filepath.Join(fixtureRoot, "dispatch.log")
	dispatchLog, readErr := os.ReadFile(dispatchLogPath)
	if readErr != nil {
		t.Fatalf("read local dispatch log: %v", readErr)
	}
	if string(dispatchLog) != "applied\n" {
		t.Fatalf("unexpected local dispatch log: %q", dispatchLog)
	}
}

func TestProductAndReleaseSurfacesAreVendorNeutral(t *testing.T) {
	repositoryRoot := testRepositoryRoot(t)
	trackedCommand := exec.Command("git", "ls-files", "--cached", "--others", "--exclude-standard")
	trackedCommand.Dir = repositoryRoot
	trackedOutput, trackedErr := trackedCommand.Output()
	if trackedErr != nil {
		t.Fatalf("list repository files: %v", trackedErr)
	}

	for _, relativePath := range strings.Fields(string(trackedOutput)) {
		if !isVendorNeutralitySurface(relativePath) {
			continue
		}
		path := filepath.Join(repositoryRoot, filepath.FromSlash(relativePath))
		file, openErr := os.Open(path)
		if openErr != nil {
			if errors.Is(openErr, os.ErrNotExist) {
				continue
			}
			t.Fatalf("open %s: %v", relativePath, openErr)
		}
		scanner := bufio.NewScanner(file)
		lineNumber := 0
		for scanner.Scan() {
			lineNumber++
			normalizedLine := strings.ToLower(scanner.Text())
			for _, forbiddenToken := range forbiddenVendorTokens {
				if strings.Contains(normalizedLine, forbiddenToken) {
					t.Errorf("vendor-specific token %q at %s:%d", forbiddenToken, relativePath, lineNumber)
				}
			}
		}
		if scanErr := scanner.Err(); scanErr != nil {
			_ = file.Close()
			t.Fatalf("scan %s: %v", relativePath, scanErr)
		}
		if closeErr := file.Close(); closeErr != nil {
			t.Fatalf("close %s: %v", relativePath, closeErr)
		}
	}
}

func isVendorNeutralitySurface(relativePath string) bool {
	if relativePath == "README.md" || relativePath == "ARCHITECTURE.md" || relativePath == "Makefile" || relativePath == deployConfigExampleName || relativePath == deployManifestRelativePath {
		return true
	}
	for _, prefix := range []string{"docs/", "examples/", "internal/", "scripts/", "tests/"} {
		if strings.HasPrefix(relativePath, prefix) {
			return relativePath != "tests/repository_neutrality_contract_test.go"
		}
	}
	return false
}

func prepareDeploymentFixture(t *testing.T) string {
	t.Helper()
	repositoryRoot := testRepositoryRoot(t)
	fixtureRoot := t.TempDir()
	fixtureScriptsDirectory := filepath.Join(fixtureRoot, "scripts")
	if makeDirectoryErr := os.MkdirAll(fixtureScriptsDirectory, 0o755); makeDirectoryErr != nil {
		t.Fatalf("create fixture scripts directory: %v", makeDirectoryErr)
	}
	copyDeploymentFixtureFile(t, filepath.Join(repositoryRoot, "Makefile"), filepath.Join(fixtureRoot, "Makefile"), 0o644)
	copyDeploymentFixtureFile(t, filepath.Join(repositoryRoot, filepath.FromSlash(deployScriptRelativePath)), filepath.Join(fixtureRoot, filepath.FromSlash(deployScriptRelativePath)), 0o755)
	return fixtureRoot
}

func prepareOperatorFixture(t *testing.T, fixtureRoot string) string {
	t.Helper()
	operatorDirectory := filepath.Join(fixtureRoot, "operator")
	if makeDirectoryErr := os.MkdirAll(operatorDirectory, 0o755); makeDirectoryErr != nil {
		t.Fatalf("create operator fixture directory: %v", makeDirectoryErr)
	}
	operatorMakefile := fmt.Sprintf(
		".PHONY: %s\n%s:\n\t@printf 'applied\\n' > %q\n",
		fixtureDeployMakeTarget,
		fixtureDeployMakeTarget,
		filepath.Join(fixtureRoot, "dispatch.log"),
	)
	if writeErr := os.WriteFile(filepath.Join(operatorDirectory, "Makefile"), []byte(operatorMakefile), 0o644); writeErr != nil {
		t.Fatalf("write operator fixture Makefile: %v", writeErr)
	}
	return operatorDirectory
}

func writeDeploymentConfig(t *testing.T, fixtureRoot string, operatorDirectory string, makeTarget string) {
	t.Helper()
	configDocument := fmt.Sprintf(
		"DEPLOY_DIRECTORY=%s\nDEPLOY_MAKE_TARGET=%s\n",
		operatorDirectory,
		makeTarget,
	)
	writeRawDeploymentConfig(t, fixtureRoot, configDocument, 0o600)
}

func writeRawDeploymentConfig(t *testing.T, fixtureRoot string, configDocument string, mode os.FileMode) {
	t.Helper()
	if writeErr := os.WriteFile(filepath.Join(fixtureRoot, deployConfigFileName), []byte(configDocument), mode); writeErr != nil {
		t.Fatalf("write local deployment config: %v", writeErr)
	}
}

func copyDeploymentFixtureFile(t *testing.T, sourcePath string, destinationPath string, fileMode os.FileMode) {
	t.Helper()
	document, readErr := os.ReadFile(sourcePath)
	if readErr != nil {
		t.Fatalf("read deployment fixture source %s: %v", sourcePath, readErr)
	}
	if writeErr := os.WriteFile(destinationPath, document, fileMode); writeErr != nil {
		t.Fatalf("write deployment fixture destination %s: %v", destinationPath, writeErr)
	}
}

func runFixtureMake(fixtureRoot string, target string) ([]byte, error) {
	makeCommand := exec.Command("make", "--no-print-directory", target)
	makeCommand.Dir = fixtureRoot
	return makeCommand.CombinedOutput()
}

func testRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, testFilename, _, available := runtime.Caller(0)
	if !available {
		t.Fatal("resolve repository contract test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(testFilename), ".."))
}

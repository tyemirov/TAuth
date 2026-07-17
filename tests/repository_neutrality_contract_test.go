package productionconfig_test

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var forbiddenVendorTokens = []string{
	"marcopoloresearchlab",
	"mpr-ui",
	"mprlab.com",
	"mprlab-release",
	"mprlab.container",
	"mprlab.release",
}

func TestRepositoryDoesNotOwnAnOperatorDeployment(t *testing.T) {
	repositoryRoot := testRepositoryRoot(t)
	for _, relativePath := range []string{
		".mprlab/deploy/resources.yml",
		"configs/config.tauth.yml",
		"configs/tauth.env.sample",
		"scripts/deploy.sh",
	} {
		path := filepath.Join(repositoryRoot, filepath.FromSlash(relativePath))
		_, statErr := os.Stat(path)
		if statErr == nil {
			t.Errorf("generic TAuth repository contains operator deployment path %s", relativePath)
			continue
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("inspect %s: %v", relativePath, statErr)
		}
	}

	makefilePath := filepath.Join(repositoryRoot, "Makefile")
	makefileDocument, readErr := os.ReadFile(makefilePath)
	if readErr != nil {
		t.Fatalf("read Makefile: %v", readErr)
	}
	makefileText := string(makefileDocument)
	for _, forbiddenContract := range []string{"\ndeploy:", "GATEWAY_DIR", "DEPLOY_ARGS"} {
		if strings.Contains(makefileText, forbiddenContract) {
			t.Errorf("generic TAuth Makefile contains operator deployment contract %q", forbiddenContract)
		}
	}

	deployCommand := exec.Command("make", "--dry-run", "deploy")
	deployCommand.Dir = repositoryRoot
	deployOutput, deployErr := deployCommand.CombinedOutput()
	if deployErr == nil {
		t.Fatalf("generic TAuth unexpectedly exposes make deploy:\n%s", deployOutput)
	}
	if !strings.Contains(string(deployOutput), "No rule to make target") {
		t.Fatalf("make deploy failed for an unexpected reason: %v\n%s", deployErr, deployOutput)
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
	if relativePath == "README.md" || relativePath == "ARCHITECTURE.md" || relativePath == "Makefile" {
		return true
	}
	for _, prefix := range []string{"docs/", "examples/", "internal/", "scripts/", "tests/"} {
		if strings.HasPrefix(relativePath, prefix) {
			return relativePath != "tests/repository_neutrality_contract_test.go"
		}
	}
	return false
}

func testRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, testFilename, _, available := runtime.Caller(0)
	if !available {
		t.Fatal("resolve repository contract test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(testFilename), ".."))
}

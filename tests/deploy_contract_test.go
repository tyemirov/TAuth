package productionconfig_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeployNoOpDoesNotRequireGatewayCheckout(t *testing.T) {
	repositoryRoot := testRepositoryRoot(t)
	testContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	deployCommand := exec.CommandContext(
		testContext,
		"bash",
		"scripts/deploy.sh",
		"--tag",
		"v0.0.0",
		"--skip-image-verify",
		"--skip-backend",
	)
	deployCommand.Dir = repositoryRoot
	missingGatewayPath := filepath.Join(t.TempDir(), "missing-gateway")
	deployCommand.Env = append(os.Environ(), "GATEWAY_DIR="+missingGatewayPath)
	deployOutput, deployErr := deployCommand.CombinedOutput()
	if deployErr != nil {
		t.Fatalf("run deployment no-op without gateway checkout: %v\n%s", deployErr, deployOutput)
	}
	if !strings.Contains(string(deployOutput), "TAuth deploy complete") {
		t.Fatalf("deployment no-op did not report completion:\n%s", deployOutput)
	}
}

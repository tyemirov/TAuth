package ci_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestGitHubWorkflowsExist(t *testing.T) {
	t.Helper()

	projectRoot := filepath.Clean(filepath.Join("..", ".."))
	workflows := []struct {
		relativePath string
		requiredSnip []byte
	}{
		{
			relativePath: filepath.Join(".github", "workflows", "go-tests.yml"),
			requiredSnip: []byte("go test ./..."),
		},
		{
			relativePath: filepath.Join(".github", "workflows", "release.yml"),
			requiredSnip: []byte("docker build"),
		},
	}

	for _, workflow := range workflows {
		fullPath := filepath.Join(projectRoot, workflow.relativePath)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			t.Fatalf("read workflow %q: %v", workflow.relativePath, err)
		}

		if !bytes.Contains(data, workflow.requiredSnip) {
			t.Fatalf("workflow %q missing required snippet %q", workflow.relativePath, string(workflow.requiredSnip))
		}
	}
}

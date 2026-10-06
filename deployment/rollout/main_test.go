package main

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Child processes use the real rollout CLI with controlled Gateway and Ansible dependencies.
func init() {
	if os.Getenv("TAUTH_ROLLOUT_CLI_FIXTURE") != "1" {
		return
	}
	switch filepath.Base(os.Args[0]) {
	case "rollout-fixture":
		main()
	case "mprlab-gateway":
		if os.Args[1] == "version" {
			fmt.Println(`{"version":"fixture","source_commit":"fixture","platform":"fixture","lifecycle_contract":4}`)
		} else {
			fmt.Println("fixture gateway:", strings.Join(os.Args[1:], " "))
		}
	case "ansible-playbook":
		if os.Getenv("TAUTH_ROLLOUT_ALL_PHASES") == "1" {
			fmt.Println("fixture phase:", strings.Join(os.Args[1:], " "))
		} else {
			fmt.Println("fixture: cutover input preflight reached")
			os.Exit(7)
		}
	default:
		os.Exit(8)
	}
	os.Exit(0)
}

func TestRolloutCurrentReleaseCLI(t *testing.T) {
	root := t.TempDir()
	if output, err := exec.Command("git", "init", "--quiet", root).CombinedOutput(); err != nil {
		t.Fatalf("initialize fixture: %v %s", err, output)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	packageRoot := t.TempDir()
	rollout := filepath.Join(packageRoot, "rollout-fixture")
	gateway := filepath.Join(packageRoot, "runtime/bin/mprlab-gateway")
	ansible := filepath.Join(packageRoot, "toolchain/bin/ansible-playbook")
	for _, path := range []string{rollout, gateway, ansible} {
		if output, err := exec.Command("mkdir", "-p", filepath.Dir(path)).CombinedOutput(); err != nil {
			t.Fatalf("create fixture directory: %v %s", err, output)
		}
		if err = os.Link(executable, path); err != nil {
			t.Fatal(err)
		}
	}
	lifecycle := filepath.Join(root, ".git/mprlab-lifecycle")
	releaseRoot := filepath.Join(lifecycle, "releases/v1.2.3")
	captureRepositoryRolloutInputs(t, filepath.Join(releaseRoot, "inputs"))
	imagePath := filepath.Join(releaseRoot, "image.oci.tar")
	image, err := os.Create(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	archive := tar.NewWriter(image)
	index := []byte(`{"manifests":[{"digest":"sha256:` + strings.Repeat("a", 64) + `"}]}`)
	if err = archive.WriteHeader(&tar.Header{Name: "index.json", Size: int64(len(index))}); err != nil {
		t.Fatal(err)
	}
	if _, err = archive.Write(index); err != nil {
		t.Fatal(err)
	}
	if err = archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err = image.Close(); err != nil {
		t.Fatal(err)
	}
	current := `{"schema_version":1,"preparation":"sealed","publication_state":"published","release":{"version":"v1.2.3","artifacts":[{"id":"tauth-image","kind":"container_image","path":"image.oci.tar","repository":"ghcr.io/example/auth"}]},"publication":{"version":"v1.2.3"}}`
	if err = writeFile(filepath.Join(lifecycle, "current-release.json"), []byte(current)); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(rollout, root, gateway)
	command.Env = append(os.Environ(), "TAUTH_ROLLOUT_CLI_FIXTURE=1", "MPRLAB_GATEWAY_OPERATOR_ROOT="+t.TempDir())
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "fixture: cutover input preflight reached") || !strings.Contains(string(output), "cutover.input_preflight:") {
		t.Fatalf("rollout did not consume the current release: %v\n%s", err, output)
	}
	operatorRoot := t.TempDir()
	if output, err := exec.Command("mkdir", "-p", filepath.Join(root, ".mprlab/deploy")).CombinedOutput(); err != nil {
		t.Fatalf("create fixture directory: %v %s", err, output)
	}
	if err = writeFile(filepath.Join(root, ".mprlab/deploy/.env"), nil); err != nil {
		t.Fatal(err)
	}
	if err = writeFile(filepath.Join(operatorRoot, "private.env"), nil); err != nil {
		t.Fatal(err)
	}
	command = exec.Command(rollout, root, gateway)
	command.Env = append(os.Environ(), "TAUTH_ROLLOUT_CLI_FIXTURE=1", "TAUTH_ROLLOUT_ALL_PHASES=1", "MPRLAB_GATEWAY_OPERATOR_ROOT="+operatorRoot, "TAUTH_TENANT_ENCRYPTION_KEY="+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	output, err = command.CombinedOutput()
	if err != nil {
		t.Fatalf("full rollout failed: %v\n%s", err, output)
	}
	oldPhase := strings.Index(string(output), "/deployment/rollout/cutover.yml")
	newPhase := strings.Index(string(output), "/deployment/rollout/console-google-client.yml")
	subjectPhase := strings.Index(string(output), "/deployment/rollout/application-subjects.yml")
	deployPhase := strings.Index(string(output), "fixture gateway: app-deploy")
	if oldPhase < 0 || newPhase <= oldPhase || subjectPhase <= newPhase || deployPhase <= subjectPhase {
		t.Fatalf("independent migration phase absent or out of order: %s", output)
	}

}

func captureRepositoryRolloutInputs(t *testing.T, destination string) {
	t.Helper()
	repositoryRoot, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("locate repository: %v", err)
	}
	// Use a disposable index to capture the next source tree, including local edits,
	// while applying the real ignore rules and leaving the user's index unchanged.
	indexPath := filepath.Join(t.TempDir(), "index")
	git := func(arguments ...string) *exec.Cmd {
		command := exec.Command("git", arguments...)
		command.Dir = strings.TrimSpace(string(repositoryRoot))
		command.Env = append(os.Environ(), "GIT_INDEX_FILE="+indexPath)
		return command
	}
	for _, arguments := range [][]string{
		{"read-tree", "HEAD"},
		{"add", "--all", "--", ":/deployment/migrations", ":/deployment/rollout"},
	} {
		if output, err := git(arguments...).CombinedOutput(); err != nil {
			t.Fatalf("capture repository inputs: %v\n%s", err, output)
		}
	}
	paths, err := git("ls-files", "-z", "--full-name", "--", ":/deployment/migrations/*.json", ":/deployment/rollout/*.yml").Output()
	if err != nil {
		t.Fatalf("list release inputs: %v", err)
	}
	command := git("checkout-index", "--prefix="+destination+string(filepath.Separator), "--stdin", "-z")
	command.Stdin = bytes.NewReader(paths)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("extract release inputs: %v\n%s", err, output)
	}
}

func TestPersistentServerKeyPreparation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.env")
	if err := writeFile(path, []byte("EXISTING='preserved'\n")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TAUTH_TENANT_ENCRYPTION_KEY", "")
	key, err := prepareKey(path, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatal("wrong key length")
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	again, err := prepareKey(path, encoded, encoded)
	if err != nil || !bytes.Equal(again, key) {
		t.Fatal("key changed", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(content), "TAUTH_TENANT_ENCRYPTION_KEY=") != 1 || !strings.Contains(string(content), "EXISTING='preserved'") {
		t.Fatal("private input overwritten")
	}
	recoveredPath := filepath.Join(t.TempDir(), "private.env")
	if err = writeFile(recoveredPath, nil); err != nil {
		t.Fatal(err)
	}
	recovered, err := prepareKey(recoveredPath, "", encoded)
	if err != nil || !bytes.Equal(recovered, key) {
		t.Fatal("remote key not recovered", err)
	}
	if _, err = prepareKey(path, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), encoded); err == nil {
		t.Fatal("key conflict accepted")
	}
	if _, err = prepareKey(recoveredPath, "", "malformed"); err == nil {
		t.Fatal("invalid recovery key accepted")
	}
	content, err = os.ReadFile(recoveredPath)
	if err != nil || strings.Contains(string(content), "malformed") {
		t.Fatal("invalid recovery key persisted", err)
	}
}

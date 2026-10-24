package main

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
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
		} else if os.Args[1] == "bootstrap-run" {
			if len(os.Args) < 8 || os.Args[2] != "--repo-root" || os.Args[3] != os.Getenv("TAUTH_ROLLOUT_APPLICATION_ROOT") || os.Args[4] != "--operation" || os.Args[5] != "app-deploy" || os.Args[6] != "--" {
				panic("unexpected captured rollout invocation: " + strings.Join(os.Args[1:], " "))
			}
			packageRoot := filepath.Dir(filepath.Dir(filepath.Dir(os.Args[0])))
			if os.Args[7] != filepath.Join(packageRoot, "toolchain/bin/ansible-playbook") {
				panic("rollout did not select packaged Ansible")
			}
			fmt.Println("fixture bootstrap:", strings.Join(os.Args[7:], " "))
			command := exec.Command(os.Args[7], os.Args[8:]...)
			command.Env = append(os.Environ(), "TAUTH_ROLLOUT_BOOTSTRAP=1")
			command.Stdout, command.Stderr = os.Stdout, os.Stderr
			if err := command.Run(); err != nil {
				var failure *exec.ExitError
				if errors.As(err, &failure) {
					os.Exit(failure.ExitCode())
				}
				panic(err)
			}
		} else {
			fmt.Println("fixture gateway:", strings.Join(os.Args[1:], " "))
		}
	case "docker":
		if marker := os.Getenv("TAUTH_ROLLOUT_DOCKER_CALL_MARKER"); marker != "" {
			if err := writeFile(marker, []byte("called")); err != nil {
				panic(err)
			}
		}
		expected := "ghcr.io/example/auth:1.2.3"
		if len(os.Args) < 9 || os.Args[7] != expected {
			panic("unexpected image extraction: " + strings.Join(os.Args, " "))
		}
		if image := os.Getenv("TAUTH_ROLLOUT_IMAGE"); image != "" {
			command := exec.Command(os.Getenv("TAUTH_ROLLOUT_REAL_DOCKER"), append(os.Args[1:7], append([]string{image}, os.Args[8:]...)...)...)
			command.Stdout, command.Stderr = os.Stdout, os.Stderr
			if err := command.Run(); err != nil {
				os.Exit(9)
			}
			break
		}
		archive := tar.NewWriter(os.Stdout)
		if name := os.Getenv("TAUTH_ROLLOUT_EXTRA_ENTRY"); name != "" {
			if err := archive.WriteHeader(&tar.Header{Name: name, Size: 1}); err != nil {
				panic(err)
			}
			if _, err := archive.Write([]byte("x")); err != nil {
				panic(err)
			}
		}
		for _, name := range os.Args[12:] {
			if name == os.Getenv("TAUTH_ROLLOUT_MISSING") {
				continue
			}
			payload, err := os.ReadFile(filepath.Join(os.Getenv("TAUTH_ROLLOUT_SOURCE"), name))
			if err != nil {
				panic(err)
			}
			if err = archive.WriteHeader(&tar.Header{Name: name, Size: int64(len(payload))}); err != nil {
				panic(err)
			}
			if _, err = archive.Write(payload); err != nil {
				panic(err)
			}
		}
		if err := archive.Close(); err != nil {
			panic(err)
		}
	case "ansible-playbook":
		if os.Getenv("TAUTH_ROLLOUT_BOOTSTRAP") != "1" {
			fmt.Fprintln(os.Stderr, "fixture: Ansible requires captured Gateway bootstrap")
			os.Exit(98)
		}
		playbook := os.Args[3]
		source := filepath.Join(os.Getenv("TAUTH_ROLLOUT_SOURCE"), "deployment/rollout", filepath.Base(playbook))
		assertPayload := func(actual, expected string) {
			contents, err := os.ReadFile(actual)
			if err != nil {
				panic(err)
			}
			reference, err := os.ReadFile(expected)
			if err != nil || !bytes.Equal(contents, reference) {
				panic("image payload differs: " + actual)
			}
		}
		assertPayload(playbook, source)
		variables, err := os.ReadFile(strings.TrimPrefix(os.Args[5], "@"))
		if err != nil {
			panic(err)
		}
		var request map[string]string
		if err := json.Unmarshal(variables, &request); err != nil {
			panic(err)
		}
		if plan := request["tauth_cutover_plan"]; plan != "" {
			assertPayload(plan, filepath.Join(os.Getenv("TAUTH_ROLLOUT_SOURCE"), "deployment/migrations", filepath.Base(plan)))
		}
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
	for _, path := range []string{rollout, gateway, ansible, filepath.Join(packageRoot, "docker")} {
		if output, err := exec.Command("mkdir", "-p", filepath.Dir(path)).CombinedOutput(); err != nil {
			t.Fatalf("create fixture directory: %v %s", err, output)
		}
		if err = os.Link(executable, path); err != nil {
			t.Fatal(err)
		}
	}
	lifecycle := filepath.Join(root, ".git/mprlab-lifecycle")
	releaseRoot := filepath.Join(lifecycle, "releases/v1.2.3")
	if output, err := exec.Command("mkdir", "-p", releaseRoot).CombinedOutput(); err != nil {
		t.Fatalf("create release: %v %s", err, output)
	}
	source, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	extractionRoot := t.TempDir()
	environment := append(os.Environ(), "PATH="+packageRoot+string(os.PathListSeparator)+os.Getenv("PATH"), "TAUTH_ROLLOUT_SOURCE="+source, "TAUTH_ROLLOUT_APPLICATION_ROOT="+root, "TMPDIR="+extractionRoot)
	assertCleanup := func() {
		t.Helper()
		entries, err := os.ReadDir(extractionRoot)
		if err != nil || len(entries) != 0 {
			t.Fatalf("extraction directory retained: %v %v", entries, err)
		}
	}
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
	current := `{"schema_version":1,"preparation":"sealed","publication_state":"published","release":{"version":"v1.2.3","artifacts":[{"id":"tauth-image","resource_id":"runtime","kind":"container_image","path":"image.oci.tar","repository":"ghcr.io/example/auth","tag":"1.2.3"}]},"publication":{"version":"v1.2.3","published_artifacts":{"runtime":[{"id":"tauth-image","kind":"container_image","identity":"ghcr.io/example/auth:1.2.3"}]}}}`
	if err = writeFile(filepath.Join(lifecycle, "current-release.json"), []byte(current)); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		name, old, replacement, diagnostic string
	}{
		{"unsealed", `"preparation":"sealed"`, `"preparation":"prepared"`, "cutover.publication_invalid"},
		{"unpublished", `"publication_state":"published"`, `"publication_state":"pending"`, "cutover.publication_invalid"},
		{"version-conflict", `"publication":{"version":"v1.2.3"`, `"publication":{"version":"v1.2.2"`, "cutover.publication_invalid"},
		{"wrong-resource", `"resource_id":"runtime"`, `"resource_id":"other-runtime"`, "cutover.image_absent"},
		{"missing-runtime", `"published_artifacts":{"runtime":[`, `"published_artifacts":{"other-runtime":[`, "cutover.image_absent"},
		{"missing-image", `"id":"tauth-image","kind":"container_image","identity"`, `"id":"other-image","kind":"container_image","identity"`, "cutover.image_absent"},
		{"wrong-kind", `"kind":"container_image","identity"`, `"kind":"github_pages_version","identity"`, "cutover.image_absent"},
		{"wrong-identity", `"identity":"ghcr.io/example/auth:1.2.3"`, `"identity":"ghcr.io/example/auth:1.2.2"`, "cutover.image_identity_invalid"},
		{"duplicate-image", `"runtime":[`, `"runtime":[{"id":"tauth-image","kind":"container_image","identity":"ghcr.io/example/auth:1.2.3"},`, "cutover.image_ambiguous"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			invalid := strings.Replace(current, scenario.old, scenario.replacement, 1)
			if invalid == current {
				t.Fatal("publication fixture was not changed")
			}
			if err := writeFile(filepath.Join(lifecycle, "current-release.json"), []byte(invalid)); err != nil {
				t.Fatal(err)
			}
			dockerCall := filepath.Join(t.TempDir(), "docker-call")
			command := exec.Command(rollout, root, gateway)
			command.Env = append(environment, "TAUTH_ROLLOUT_CLI_FIXTURE=1", "TAUTH_ROLLOUT_DOCKER_CALL_MARKER="+dockerCall)
			output, err := command.CombinedOutput()
			if _, markerErr := os.ReadFile(dockerCall); !os.IsNotExist(markerErr) {
				t.Fatalf("Docker was invoked for an invalid publication: %v\n%s", markerErr, output)
			}
			if err == nil || !strings.Contains(string(output), scenario.diagnostic) || strings.Contains(string(output), "unexpected image extraction") || strings.Contains(string(output), "input preflight reached") || strings.Contains(string(output), "app-plan-deploy") {
				t.Fatalf("invalid publication reached image or remote work: %v\n%s", err, output)
			}
			assertCleanup()
		})
	}
	if err = writeFile(filepath.Join(lifecycle, "current-release.json"), []byte(current)); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(rollout, root, gateway)
	command.Env = append(environment, "TAUTH_ROLLOUT_CLI_FIXTURE=1", "MPRLAB_GATEWAY_OPERATOR_ROOT="+t.TempDir())
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "fixture: cutover input preflight reached") || !strings.Contains(string(output), "cutover.input_preflight:") || !strings.Contains(string(output), "exit status 7") {
		t.Fatalf("rollout did not consume the current release: %v\n%s", err, output)
	}
	assertCleanup()
	for _, scenario := range []struct{ name, environment string }{
		{"missing", "TAUTH_ROLLOUT_MISSING=deployment/rollout/application-subjects.yml"},
		{"duplicate", "TAUTH_ROLLOUT_EXTRA_ENTRY=deployment/rollout/inputs.yml"},
		{"unexpected", "TAUTH_ROLLOUT_EXTRA_ENTRY=../unexpected"},
	} {
		command = exec.Command(rollout, root, gateway)
		command.Env = append(environment, "TAUTH_ROLLOUT_CLI_FIXTURE=1", scenario.environment, "TAUTH_ROLLOUT_IMAGE=")
		output, err = command.CombinedOutput()
		if err == nil || !strings.Contains(string(output), "cutover.image_payload:") || strings.Contains(string(output), "fixture phase:") || strings.Contains(string(output), "input preflight reached") || strings.Contains(string(output), "app-plan-deploy") {
			t.Fatalf("%s payload reached remote work: %v %s", scenario.name, err, output)
		}
		assertCleanup()
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
	command.Env = append(environment, "TAUTH_ROLLOUT_CLI_FIXTURE=1", "TAUTH_ROLLOUT_ALL_PHASES=1", "MPRLAB_GATEWAY_OPERATOR_ROOT="+operatorRoot, "TAUTH_TENANT_ENCRYPTION_KEY="+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	output, err = command.CombinedOutput()
	if err != nil {
		t.Fatalf("full rollout failed: %v\n%s", err, output)
	}
	inputPhase := strings.Index(string(output), "/deployment/rollout/inputs.yml")
	oldPhase := strings.Index(string(output), "/deployment/rollout/cutover.yml")
	newPhase := strings.Index(string(output), "/deployment/rollout/console-google-client.yml")
	subjectPhase := strings.Index(string(output), "/deployment/rollout/application-subjects.yml")
	deployPhase := strings.Index(string(output), "fixture gateway: app-deploy")
	if strings.Count(string(output), "fixture bootstrap:") != 4 || inputPhase < 0 || oldPhase <= inputPhase || newPhase <= oldPhase || subjectPhase <= newPhase || deployPhase <= subjectPhase {
		t.Fatalf("independent migration phase absent or out of order: %s", output)
	}

	assertCleanup()
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

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

		if expected := os.Getenv("TAUTH_ROLLOUT_EXPECTED_CHILD_KEY"); expected != "" && os.Args[1] != "version" && os.Args[1] != "private-environment-operation" {
			if os.Getenv("TAUTH_TENANT_ENCRYPTION_KEY") != expected {
				panic("Gateway child lost the validated captured encryption key")
			}
			marker, err := os.OpenFile(os.Getenv("TAUTH_ROLLOUT_CHILD_PHASES"), os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				panic(err)
			}
			if _, err = fmt.Fprintln(marker, os.Args[1]); err != nil {
				panic(err)
			}
			if err = marker.Close(); err != nil {
				panic(err)
			}
		}
		if raw := os.Getenv("TAUTH_ROLLOUT_MANAGEMENT_EXPECTED"); raw != "" {
			var expected map[string]string
			if err := json.Unmarshal([]byte(raw), &expected); err != nil {
				panic(err)
			}
			for _, name := range []string{"MPRLAB_TAUTH_MANAGEMENT_URL", "MPRLAB_TAUTH_PROVISIONING_CREDENTIALS"} {
				actual, present := os.LookupEnv(name)
				value, wanted := expected[name]
				if present != wanted || actual != value {
					panic("rollout manufactured or changed undeclared management input: " + name)
				}
			}
		}
		if os.Args[1] == "version" {
			fmt.Println(`{"version":"fixture","source_commit":"fixture","platform":"fixture","lifecycle_contract":4}`)
		} else if os.Args[1] == "private-environment-operation" {
			var request struct {
				Root string   `json:"root"`
				Keys []string `json:"keys"`
			}
			if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
				panic(err)
			}
			if request.Root != os.Getenv("TAUTH_ROLLOUT_APPLICATION_ROOT") || len(request.Keys) != 1 || request.Keys[0] != "TAUTH_TENANT_ENCRYPTION_KEY" {
				panic("unexpected private request")
			}
			if os.Getenv("MPRLAB_GATEWAY_EXECUTABLE") != os.Args[0] {
				panic("missing Gateway authority")
			}
			values := map[string]string{}
			if os.Getenv("TAUTH_ROLLOUT_CAPTURED_MISSING") != "1" {
				values["TAUTH_TENANT_ENCRYPTION_KEY"] = os.Getenv("TAUTH_ROLLOUT_CAPTURED_KEY")
			}
			if err := json.NewEncoder(os.Stdout).Encode(values); err != nil {
				panic(err)
			}
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
		if recovered := os.Getenv("TAUTH_ROLLOUT_RECOVERED_KEY"); recovered != "" && filepath.Base(playbook) == "inputs.yml" {
			if err := writeFile(request["tauth_recovered_key"], []byte(recovered)); err != nil {
				panic(err)
			}
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
	environment := append(os.Environ(), "PATH="+packageRoot+string(os.PathListSeparator)+os.Getenv("PATH"), "TAUTH_ROLLOUT_SOURCE="+source, "TAUTH_ROLLOUT_APPLICATION_ROOT="+root, "TMPDIR="+extractionRoot, "TAUTH_ROLLOUT_CAPTURED_KEY="+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
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
	selectedPrivate := "# existing fixture key remains unchanged\nEXISTING='preserved'\nTAUTH_TENANT_ENCRYPTION_KEY='" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)) + "'\n"
	if err = writeFile(filepath.Join(root, ".mprlab/deploy/.env"), []byte(selectedPrivate)); err != nil {
		t.Fatal(err)
	}
	if err = writeFile(filepath.Join(operatorRoot, "private.env"), nil); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(root, ".mprlab/deploy/.env")
	privateBefore, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct{ name, captured, recovered, missing, diagnostic string }{
		{"absent", "", "", "1", "cutover.encryption_key_required"},
		{"empty", "", "", "", "cutover.encryption_key_required"},
		{"malformed", "malformed-synthetic-key", "", "", "cutover.encryption_key_invalid"},
		{"wrong-length", base64.StdEncoding.EncodeToString([]byte("synthetic")), "", "", "cutover.encryption_key_invalid"},
		{"remote-cannot-supply-missing", "", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), "1", "cutover.encryption_key_required"},
		{"matching-existing", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), "", ""},
		{"conflicting-existing", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), "", "cutover.persistent_key_conflict"},
		{"invalid-existing-reference", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), "malformed-reference", "", "cutover.persistent_key_conflict"},
	} {
		t.Run("existing-key/"+scenario.name, func(t *testing.T) {
			dockerCall := filepath.Join(t.TempDir(), "docker-call")
			command := exec.Command(rollout, root, gateway)
			command.Env = append(environment, "TAUTH_ROLLOUT_CLI_FIXTURE=1", "TAUTH_ROLLOUT_ALL_PHASES=1", "MPRLAB_GATEWAY_OPERATOR_ROOT="+operatorRoot,
				"TAUTH_TENANT_ENCRYPTION_KEY=ambient-value-must-not-replace-capture", "TAUTH_ROLLOUT_CAPTURED_KEY="+scenario.captured,
				"TAUTH_ROLLOUT_CAPTURED_MISSING="+scenario.missing, "TAUTH_ROLLOUT_RECOVERED_KEY="+scenario.recovered,
				"TAUTH_ROLLOUT_DOCKER_CALL_MARKER="+dockerCall)
			output, commandErr := command.CombinedOutput()
			if scenario.diagnostic == "" {
				if commandErr != nil || !strings.Contains(string(output), "fixture gateway: app-deploy") {
					t.Fatalf("existing key rollout failed: %v\n%s", commandErr, output)
				}
			} else if commandErr == nil || !strings.Contains(string(output), scenario.diagnostic) {
				t.Fatalf("existing key contract: expected %s: %v\n%s", scenario.diagnostic, commandErr, output)
			}
			if scenario.diagnostic == "cutover.encryption_key_required" || scenario.diagnostic == "cutover.encryption_key_invalid" {
				if _, err := os.ReadFile(dockerCall); !os.IsNotExist(err) {
					t.Fatalf("invalid captured key reached image extraction: %v", err)
				}
				if strings.Contains(string(output), "fixture gateway:") || strings.Contains(string(output), "fixture phase:") {
					t.Fatalf("invalid captured key reached provider or migration work: %s", output)
				}
			}
			if scenario.diagnostic != "" && strings.Contains(string(output), "/deployment/rollout/cutover.yml") {
				t.Fatalf("invalid key reached database cutover: %s", output)
			}
			privateAfter, err := os.ReadFile(privatePath)
			if err != nil || !bytes.Equal(privateBefore, privateAfter) {
				t.Fatalf("rollout changed selected private key input: %v", err)
			}
			for _, secret := range []string{scenario.captured, scenario.recovered, "ambient-value-must-not-replace-capture"} {
				if secret != "" && strings.Contains(string(output), secret) {
					t.Fatal("rollout diagnostics exposed a synthetic key")
				}
			}
			assertCleanup()
		})
	}
	for _, scenario := range []struct {
		name                 string
		privateFile, ambient bool
	}{
		{"absent-file-absent-inputs", false, false},
		{"unchanged-file-absent-inputs", true, false},
		{"absent-file-hostile-inputs", false, true},
		{"unchanged-file-hostile-inputs", true, true},
	} {
		t.Run("operator-inputs/"+scenario.name, func(t *testing.T) {
			operator := t.TempDir()
			privatePath := filepath.Join(operator, "private.env")
			before := []byte("exit 94\n# fixture operator inputs remain untouched\n")
			if scenario.privateFile {
				if err := writeFile(privatePath, before); err != nil {
					t.Fatal(err)
				}
			}
			expected := map[string]string{}
			if scenario.ambient {
				expected["MPRLAB_TAUTH_MANAGEMENT_URL"] = "https://hostile-fixture.invalid"
				expected["MPRLAB_TAUTH_PROVISIONING_CREDENTIALS"] = "hostile-fixture-credentials"
			}
			command := exec.Command(rollout, root, gateway)
			for _, assignment := range environment {
				name, _, _ := strings.Cut(assignment, "=")
				if name != "MPRLAB_TAUTH_MANAGEMENT_URL" && name != "MPRLAB_TAUTH_PROVISIONING_CREDENTIALS" {
					command.Env = append(command.Env, assignment)
				}
			}
			encoded, err := json.Marshal(expected)
			if err != nil {
				t.Fatal(err)
			}
			command.Env = append(command.Env, "TAUTH_ROLLOUT_CLI_FIXTURE=1", "TAUTH_ROLLOUT_ALL_PHASES=1", "MPRLAB_GATEWAY_OPERATOR_ROOT="+operator, "TAUTH_ROLLOUT_MANAGEMENT_EXPECTED="+string(encoded))
			for name, value := range expected {
				command.Env = append(command.Env, name+"="+value)
			}
			output, commandErr := command.CombinedOutput()
			if commandErr != nil || !strings.Contains(string(output), "fixture gateway: app-deploy") {
				t.Fatalf("rollout depended on undeclared operator inputs: %v\n%s", commandErr, output)
			}
			after, readErr := os.ReadFile(privatePath)
			if scenario.privateFile {
				if readErr != nil || !bytes.Equal(before, after) {
					t.Fatalf("rollout changed operator private inputs: %v", readErr)
				}
			} else if !os.IsNotExist(readErr) {
				t.Fatalf("rollout created operator private inputs: %v", readErr)
			}
			for _, secret := range expected {
				if strings.Contains(string(output), secret) {
					t.Fatal("rollout exposed synthetic management inputs")
				}
			}
			assertCleanup()
		})
	}
	childPhases := filepath.Join(t.TempDir(), "gateway-child-phases")
	if err := writeFile(childPhases, nil); err != nil {
		t.Fatal(err)
	}
	command = exec.Command(rollout, root, gateway)
	command.Env = append(environment, "TAUTH_ROLLOUT_CLI_FIXTURE=1", "TAUTH_ROLLOUT_ALL_PHASES=1", "MPRLAB_GATEWAY_OPERATOR_ROOT="+operatorRoot, "TAUTH_TENANT_ENCRYPTION_KEY=ambient-value-must-not-replace-capture", "TAUTH_ROLLOUT_CAPTURED_KEY="+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), "TAUTH_ROLLOUT_EXPECTED_CHILD_KEY="+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), "TAUTH_ROLLOUT_CHILD_PHASES="+childPhases)
	output, err = command.CombinedOutput()
	if err != nil {
		t.Fatalf("full rollout failed: %v\n%s", err, output)
	}
	observedPhases, readErr := os.ReadFile(childPhases)
	if readErr != nil {
		t.Fatal(readErr)
	}
	expectedPhases := "app-plan-publish\nbootstrap-run\napp-plan-deploy\nbootstrap-run\nbootstrap-run\nbootstrap-run\napp-deploy\n"
	if string(observedPhases) != expectedPhases {
		t.Fatalf("captured key was not passed to every Gateway child: %s", observedPhases)
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

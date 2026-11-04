// Command rollout performs TAuth's bounded data cutover before native Gateway convergence.
package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/tyemirov/tauth/deployment/migrations"
)

const encryptionKeyEnvironment = "TAUTH_TENANT_ENCRYPTION_KEY"

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) != 2 {
		return errors.New("usage: rollout APPLICATION_ROOT GATEWAY_EXECUTABLE")
	}
	root, gateway := args[0], args[1]
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	gatewayPath, err := exec.LookPath(gateway)
	if err != nil {
		return err
	}
	gatewayPath, err = filepath.EvalSymlinks(gatewayPath)
	if err != nil {
		return err
	}
	var packageRoot string
	if filepath.Base(filepath.Dir(gatewayPath)) == "bin" && filepath.Base(filepath.Dir(filepath.Dir(gatewayPath))) == "runtime" {
		packageRoot = filepath.Dir(filepath.Dir(filepath.Dir(gatewayPath)))
	} else {
		packageRoot, err = filepath.EvalSymlinks(filepath.Join(filepath.Dir(gatewayPath), "active"))
		if err != nil {
			return fmt.Errorf("cutover.runtime_package: %w", err)
		}
	}
	native := filepath.Join(packageRoot, "runtime/bin/mprlab-gateway")
	installedIdentity, err := exec.CommandContext(ctx, gateway, "version", "--json").Output()
	if err != nil {
		return err
	}
	capturedIdentity, err := exec.CommandContext(ctx, native, "version", "--json").Output()
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(installedIdentity)) != strings.TrimSpace(string(capturedIdentity)) {
		return errors.New("cutover.runtime_identity_conflict")
	}
	if err = os.Setenv("MPRLAB_GATEWAY_RUNTIME_ROOT", filepath.Join(packageRoot, "runtime")); err != nil {
		return err
	}
	if err = os.Setenv("ANSIBLE_CONFIG", filepath.Join(packageRoot, "runtime/deploy/ansible/ansible.cfg")); err != nil {
		return err
	}
	encodedKey, err := capturedEncryptionKey(ctx, native, root)
	if err != nil {
		return err
	}
	key, err := validateExistingKey(encodedKey, "")
	if err != nil {
		return err
	}
	childEnvironment := make([]string, 0, len(os.Environ())+1)
	for _, assignment := range os.Environ() {
		if !strings.HasPrefix(assignment, encryptionKeyEnvironment+"=") {
			childEnvironment = append(childEnvironment, assignment)
		}
	}
	childEnvironment = append(childEnvironment, encryptionKeyEnvironment+"="+encodedKey)
	runGateway := func(arguments ...string) error {
		command := exec.CommandContext(ctx, native, arguments...)
		command.Env = childEnvironment
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		return command.Run()
	}
	runAnsible := func(ansible string, arguments ...string) error {
		bootstrap := []string{"bootstrap-run", "--repo-root", root, "--operation", "app-deploy", "--", ansible}
		return runGateway(append(bootstrap, arguments...)...)
	}
	// Every phase uses this captured runtime package, including source and release validation.
	if err := runGateway("app-plan-publish", "--app-root", root); err != nil {
		return fmt.Errorf("cutover.release_preflight: %w", err)
	}
	operatorRoot := os.Getenv("MPRLAB_GATEWAY_OPERATOR_ROOT")
	if operatorRoot == "" {
		operatorRoot = filepath.Join(home, ".config/mprlab-gateway")
	}
	image, releaseRoot, err := selectedImage(root)
	if err != nil {
		return err
	}
	lock, err := os.Create(filepath.Join(filepath.Dir(filepath.Dir(releaseRoot)), "tauth-cutover.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("cutover.already_running: %w", err)
	}
	localRoot, err := os.MkdirTemp("", migrations.CutoverID+"-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(localRoot)
	if err = extractDeploymentPayload(ctx, image, localRoot); err != nil {
		return fmt.Errorf("cutover.image_payload: %w", err)
	}
	planPath := filepath.Join(localRoot, "deployment/migrations/"+migrations.CutoverID+".json")
	if _, err = migrations.LoadCutoverPlan(planPath); err != nil {
		return fmt.Errorf("cutover.sealed_plan: %w", err)
	}
	consolePlanPath := filepath.Join(localRoot, "deployment/migrations/"+migrations.ConsoleGoogleClientID+".json")
	if _, err = migrations.LoadConsoleGoogleClientPlan(consolePlanPath); err != nil {
		return fmt.Errorf("console_client.sealed_plan: %w", err)
	}
	subjectPlanPath := filepath.Join(localRoot, "deployment/migrations/"+migrations.ApplicationSubjectsID+".json")
	if _, err = migrations.LoadApplicationSubjectsPlan(subjectPlanPath); err != nil {
		return fmt.Errorf("application_subjects.sealed_plan: %w", err)
	}
	ansible := filepath.Join(packageRoot, "toolchain/bin/ansible-playbook")
	inputsPath := filepath.Join(localRoot, "inputs.json")
	payload, err := json.Marshal(map[string]string{"tauth_cutover_id": migrations.CutoverID, "tauth_recovered_key": filepath.Join(localRoot, "recovered-key"), "tauth_cutover_volume": "mprlab-nginx-gateway_tauth-data"})
	if err != nil {
		return err
	}
	if err = writeFile(inputsPath, payload); err != nil {
		return err
	}
	if err = runAnsible(ansible, "-i", filepath.Join(operatorRoot, "inventory/hosts.yml"), filepath.Join(localRoot, "deployment/rollout/inputs.yml"), "--extra-vars", "@"+inputsPath); err != nil {
		return fmt.Errorf("cutover.input_preflight: %w", err)
	}
	recoveredKey := ""
	if recovered, readErr := os.ReadFile(filepath.Join(localRoot, "recovered-key")); readErr == nil {
		recoveredKey = strings.TrimSpace(string(recovered))
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	_, err = validateExistingKey(encodedKey, recoveredKey)
	if err != nil {
		return err
	}
	// Native deployment planning verifies published artifacts, placements, SSH, sudo, and all private bindings before writers stop.
	if err = runGateway("app-plan-deploy", "--app-root", root); err != nil {
		return fmt.Errorf("cutover.deployment_preflight: %w", err)
	}
	keyFile := filepath.Join(localRoot, "key")
	if err = writeFile(keyFile, []byte(base64.StdEncoding.EncodeToString(key))); err != nil {
		return err
	}
	variables := map[string]string{"tauth_cutover_image": image, "tauth_cutover_plan": planPath, "tauth_cutover_key": keyFile, "tauth_cutover_id": migrations.CutoverID, "tauth_cutover_volume": "mprlab-nginx-gateway_tauth-data"}
	variablesPath := filepath.Join(localRoot, "request.json")
	payload, err = json.Marshal(variables)
	if err != nil {
		return err
	}
	if err = writeFile(variablesPath, payload); err != nil {
		return err
	}
	if err = runAnsible(ansible, "-i", filepath.Join(operatorRoot, "inventory/hosts.yml"), filepath.Join(localRoot, "deployment/rollout/cutover.yml"), "--extra-vars", "@"+variablesPath); err != nil {
		return fmt.Errorf("cutover.migration_failed: %w", err)
	}
	variables["tauth_cutover_plan"] = consolePlanPath
	variables["tauth_cutover_id"] = migrations.ConsoleGoogleClientID
	payload, err = json.Marshal(variables)
	if err != nil {
		return err
	}
	if err = writeFile(variablesPath, payload); err != nil {
		return err
	}
	if err = runAnsible(ansible, "-i", filepath.Join(operatorRoot, "inventory/hosts.yml"), filepath.Join(localRoot, "deployment/rollout/console-google-client.yml"), "--extra-vars", "@"+variablesPath); err != nil {
		return fmt.Errorf("console_client.migration_failed: %w", err)
	}
	variables["tauth_cutover_plan"] = subjectPlanPath
	variables["tauth_cutover_id"] = migrations.ApplicationSubjectsID
	payload, err = json.Marshal(variables)
	if err != nil {
		return err
	}
	if err = writeFile(variablesPath, payload); err != nil {
		return err
	}
	if err = runAnsible(ansible, "-i", filepath.Join(operatorRoot, "inventory/hosts.yml"), filepath.Join(localRoot, "deployment/rollout/application-subjects.yml"), "--extra-vars", "@"+variablesPath); err != nil {
		return fmt.Errorf("application_subjects.migration_failed: %w", err)
	}
	return runGateway("app-deploy", "--app-root", root)
}

var deploymentPayloadPaths = []string{
	"deployment/migrations/" + migrations.CutoverID + ".json",
	"deployment/migrations/" + migrations.ConsoleGoogleClientID + ".json",
	"deployment/migrations/" + migrations.ApplicationSubjectsID + ".json",
	"deployment/rollout/inputs.yml",
	"deployment/rollout/cutover.yml",
	"deployment/rollout/console-google-client.yml",
	"deployment/rollout/application-subjects.yml",
}

func extractDeploymentPayload(ctx context.Context, image, destination string) error {
	arguments := []string{"run", "--rm", "--network", "none", "--entrypoint", "tar", image, "-cf", "-", "-C", "/usr/local/share/tauth"}
	command := exec.CommandContext(ctx, "docker", append(arguments, deploymentPayloadPaths...)...)
	payload, err := command.Output()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return fmt.Errorf("extract deployment files from %s: %w: %s", image, err, strings.TrimSpace(string(exitError.Stderr)))
		}
		return fmt.Errorf("extract deployment files from %s: %w", image, err)
	}
	pending := make(map[string]bool, len(deploymentPayloadPaths))
	for _, name := range deploymentPayloadPaths {
		pending[name] = true
	}
	archive := tar.NewReader(bytes.NewReader(payload))
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read deployment archive: %w", err)
		}
		if !pending[header.Name] || header.Typeflag != tar.TypeReg {
			return fmt.Errorf("unexpected deployment archive entry %q", header.Name)
		}
		path := filepath.Join(destination, header.Name)
		if err := exec.CommandContext(ctx, "mkdir", "-p", filepath.Dir(path)).Run(); err != nil {
			return fmt.Errorf("create deployment directory: %w", err)
		}
		file, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("create deployment file %s: %w", header.Name, err)
		}
		_, copyErr := io.Copy(file, archive)
		closeErr := file.Close()
		if err := errors.Join(copyErr, closeErr); err != nil {
			return fmt.Errorf("extract deployment file %s: %w", header.Name, err)
		}
		delete(pending, header.Name)
	}
	for _, name := range deploymentPayloadPaths {
		if pending[name] {
			return fmt.Errorf("deployment file %s absent from %s", name, image)
		}
	}
	return nil
}

func capturedEncryptionKey(ctx context.Context, gateway, root string) (string, error) {
	request, err := json.Marshal(struct {
		Root  string   `json:"root"`
		Keys  []string `json:"keys"`
		Scope string   `json:"scope"`
	}{Root: root, Keys: []string{encryptionKeyEnvironment}, Scope: "provider"})
	if err != nil {
		return "", err
	}
	command := exec.CommandContext(ctx, gateway, "private-environment-operation")
	command.Env = append(os.Environ(), "MPRLAB_GATEWAY_EXECUTABLE="+gateway)
	command.Stdin = bytes.NewReader(request)
	var diagnostic bytes.Buffer
	command.Stderr = &diagnostic
	payload, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("cutover.captured_key: %w: %s", err, strings.TrimSpace(diagnostic.String()))
	}
	var values map[string]string
	if err := json.Unmarshal(payload, &values); err != nil {
		return "", fmt.Errorf("cutover.captured_key: invalid Gateway response: %w", err)
	}
	return values[encryptionKeyEnvironment], nil
}

func validateExistingKey(encoded, recovered string) ([]byte, error) {
	if encoded == "" {
		return nil, errors.New("cutover.encryption_key_required")
	}
	if recovered != "" && encoded != recovered {
		return nil, errors.New("cutover.persistent_key_conflict")
	}
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != 32 {
		return nil, errors.New("cutover.encryption_key_invalid")
	}
	return key, nil
}

func writeFile(path string, payload []byte) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = file.Write(payload)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

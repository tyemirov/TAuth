// Command rollout performs TAuth's bounded data cutover before native Gateway convergence.
package main

import (
	"archive/tar"
	"context"
	"crypto/rand"
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

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func execute(ctx context.Context, executable string, args ...string) error {
	command := exec.CommandContext(ctx, executable, args...)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command.Run()
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
	// Every phase uses this captured runtime package, including source and release validation.
	if err := execute(ctx, native, "app-plan-publish", "--app-root", root); err != nil {
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
	planPath := filepath.Join(releaseRoot, "inputs/deployment/migrations/20260930-tenant-console.json")
	plan, err := migrations.LoadCutoverPlan(planPath)
	if err != nil {
		return fmt.Errorf("cutover.sealed_plan: %w", err)
	}
	localRoot, err := os.MkdirTemp("", migrations.CutoverID+"-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(localRoot)
	ansible := filepath.Join(packageRoot, "toolchain/bin/ansible-playbook")
	inputsPath := filepath.Join(localRoot, "inputs.json")
	payload, err := json.Marshal(map[string]string{"tauth_cutover_id": migrations.CutoverID, "tauth_recovered_key": filepath.Join(localRoot, "recovered-key"), "tauth_cutover_volume": "mprlab-nginx-gateway_tauth-data"})
	if err != nil {
		return err
	}
	if err = writeFile(inputsPath, payload); err != nil {
		return err
	}
	if err = execute(ctx, ansible, "-i", filepath.Join(operatorRoot, "inventory/hosts.yml"), filepath.Join(releaseRoot, "inputs/deployment/rollout/inputs.yml"), "--extra-vars", "@"+inputsPath); err != nil {
		return fmt.Errorf("cutover.input_preflight: %w", err)
	}
	recoveredKey := ""
	if recovered, readErr := os.ReadFile(filepath.Join(localRoot, "recovered-key")); readErr == nil {
		recoveredKey = strings.TrimSpace(string(recovered))
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	key, err := prepareKey(filepath.Join(root, ".mprlab/deploy/.env"), os.Getenv("TAUTH_TENANT_ENCRYPTION_KEY"), recoveredKey)
	if err != nil {
		return err
	}
	if err = prepareGatewayInputs(operatorRoot, plan, key); err != nil {
		return err
	}
	// Native deployment planning verifies published artifacts, placements, SSH, sudo, and all private bindings before writers stop.
	if err = execute(ctx, native, "app-plan-deploy", "--app-root", root); err != nil {
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
	if err = execute(ctx, ansible, "-i", filepath.Join(operatorRoot, "inventory/hosts.yml"), filepath.Join(releaseRoot, "inputs/deployment/rollout/cutover.yml"), "--extra-vars", "@"+variablesPath); err != nil {
		return fmt.Errorf("cutover.migration_failed: %w", err)
	}
	return execute(ctx, native, "app-deploy", "--app-root", root)
}

func prepareKey(path, encoded, recovered string) ([]byte, error) {
	if encoded != "" && recovered != "" && encoded != recovered {
		return nil, errors.New("cutover.persistent_key_conflict")
	}
	missing := encoded == ""
	if missing {
		encoded = recovered
		if encoded == "" {
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				return nil, err
			}
			encoded = base64.StdEncoding.EncodeToString(key)
		}
	}
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != 32 {
		return nil, errors.New("cutover.encryption_key_invalid")
	}
	if missing {
		if err := appendEnvironment(path, "TAUTH_TENANT_ENCRYPTION_KEY", encoded); err != nil {
			return nil, err
		}
	}
	if err = os.Setenv("TAUTH_TENANT_ENCRYPTION_KEY", encoded); err != nil {
		return nil, err
	}
	return key, nil
}

func prepareGatewayInputs(root string, plan migrations.CutoverPlan, key []byte) error {
	values := map[string]string{"MPRLAB_TAUTH_MANAGEMENT_URL": plan.ManagementURL}
	credentials, err := json.Marshal(plan.CredentialMap(key))
	if err != nil {
		return err
	}
	values["MPRLAB_TAUTH_PROVISIONING_CREDENTIALS"] = string(credentials)
	for _, name := range []string{"MPRLAB_TAUTH_MANAGEMENT_URL", "MPRLAB_TAUTH_PROVISIONING_CREDENTIALS"} {
		if os.Getenv(name) == "" {
			if err = appendEnvironment(filepath.Join(root, "private.env"), name, values[name]); err != nil {
				return err
			}
			if err = os.Setenv(name, values[name]); err != nil {
				return err
			}
		}
	}
	return nil
}

func appendEnvironment(path, name, value string) error {
	// Generated values contain no shell quotes. The command uses normal shell environment lookup on its next invocation.
	if strings.ContainsAny(value, "'\n\r") {
		return errors.New("cutover.generated_environment_invalid")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return fmt.Errorf("cutover.private_input_absent: %w", err)
	}
	_, err = fmt.Fprintf(file, "\n%s='%s'\n", name, value)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
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

func selectedImage(root string) (string, string, error) {
	gitPath, err := exec.Command("git", "-C", root, "rev-parse", "--git-path", "mprlab-lifecycle").Output()
	if err != nil {
		return "", "", err
	}
	lifecycle := strings.TrimSpace(string(gitPath))
	if !filepath.IsAbs(lifecycle) {
		lifecycle = filepath.Join(root, lifecycle)
	}
	var current struct {
		Release struct {
			Version   string                                        `json:"version"`
			Artifacts []struct{ ID, Kind, Path, Repository string } `json:"artifacts"`
		} `json:"release"`
	}
	payload, err := os.ReadFile(filepath.Join(lifecycle, "current-release.json"))
	if err != nil {
		return "", "", err
	}
	if err = json.Unmarshal(payload, &current); err != nil {
		return "", "", err
	}
	if !strings.HasPrefix(current.Release.Version, "v") || strings.ContainsAny(current.Release.Version, "/\\") {
		return "", "", errors.New("cutover.release_selection_invalid")
	}
	releaseRoot := filepath.Join(lifecycle, "releases", current.Release.Version)
	for _, artifact := range current.Release.Artifacts {
		if artifact.ID != "tauth-image" || artifact.Kind != "container_image" {
			continue
		}
		if filepath.IsAbs(artifact.Path) || strings.Contains(artifact.Path, "..") {
			return "", "", errors.New("cutover.artifact_path_invalid")
		}
		file, err := os.Open(filepath.Join(releaseRoot, artifact.Path))
		if err != nil {
			return "", "", err
		}
		defer file.Close()
		archive := tar.NewReader(file)
		for {
			header, err := archive.Next()
			if err != nil {
				return "", "", fmt.Errorf("cutover.oci_index: %w", err)
			}
			if header.Name != "index.json" {
				continue
			}
			var index struct {
				Manifests []struct{ Digest string } `json:"manifests"`
			}
			if err = json.NewDecoder(io.LimitReader(archive, 1024*1024)).Decode(&index); err != nil {
				return "", "", err
			}
			if len(index.Manifests) != 1 || !strings.HasPrefix(index.Manifests[0].Digest, "sha256:") || len(index.Manifests[0].Digest) != 71 {
				return "", "", errors.New("cutover.oci_identity_invalid")
			}
			return artifact.Repository + "@" + index.Manifests[0].Digest, releaseRoot, nil
		}
	}
	return "", "", errors.New("cutover.image_absent")
}

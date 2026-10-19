package testfixture_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tyemirov/tauth/pkg/sessionvalidator"
	"gopkg.in/yaml.v3"
)

func TestPublicFixtureCLI(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".cache"), os.ModePerm); err != nil {
		t.Fatal(err)
	}
	scratch, err := os.MkdirTemp(filepath.Join(root, ".cache"), "fixture-cli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(scratch); err != nil {
			t.Error(err)
		}
	})
	binary := filepath.Join(scratch, "tauth-test-fixture")
	build := exec.Command("make", "build-test-fixture", "TEST_FIXTURE_OUTPUT="+binary)
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("public fixture build: %v\n%s", err, output)
	}
	request := map[string]any{"schema": "tauth.test-fixture.v1", "test_only": true, "app_id": "fixture-app", "server": map[string]any{"listen_addr": ":8081"}, "tenant": map[string]any{"id": "fixture-application", "display_name": "Fixture application", "origin": "http://localhost:32123", "google_web_client_id": "fixture-web.apps.googleusercontent.com", "google_native_client_id": "fixture-native.apps.googleusercontent.com", "jwt_signing_key": "synthetic-fixture-signing-key", "session_cookie_name": "fixture_session", "refresh_cookie_name": "fixture_refresh", "session_ttl": "30m", "refresh_ttl": "720h", "nonce_ttl": "10m"}}
	invoke := func(input []byte, outputDir string) ([]byte, error) {
		t.Helper()
		inputPath := filepath.Join(scratch, "input.json")
		file, err := os.Create(inputPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(input); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(binary, "--input", inputPath, "--output-dir", outputDir)
		command.Env = append(os.Environ(), "CI=1")
		return command.CombinedOutput()
	}
	encoded, _ := json.Marshal(request)
	outputDir := filepath.Join(scratch, "prepared")
	if output, err := invoke(encoded, outputDir); err != nil {
		t.Fatalf("prepare fixture: %v\n%s", err, output)
	}
	service, err := os.ReadFile(filepath.Join(outputDir, "service.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var serviceConfig map[string]any
	if err := yaml.Unmarshal(service, &serviceConfig); err != nil {
		t.Fatal(err)
	}
	if _, exists := serviceConfig["tenants"]; exists {
		t.Fatal("fixture emitted runtime tenant YAML")
	}
	server := serviceConfig["server"].(map[string]any)
	if server["database_url"] != "sqlite:///tauth-fixture/tauth.db" || server["listen_addr"] != ":8081" {
		t.Fatalf("runtime paths: %v", server)
	}
	validatorBytes, err := os.ReadFile(filepath.Join(outputDir, "validator.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var exported struct {
		Tenants []struct {
			ID     string `yaml:"id"`
			Key    string `yaml:"jwt_signing_key"`
			Cookie string `yaml:"session_cookie_name"`
		} `yaml:"tenants"`
	}
	decoder := yaml.NewDecoder(bytes.NewReader(validatorBytes))
	decoder.KnownFields(true)
	if err := decoder.Decode(&exported); err != nil {
		t.Fatal(err)
	}
	if len(exported.Tenants) != 1 || exported.Tenants[0].ID != "fixture-application" {
		t.Fatalf("validator tenant: %v", exported)
	}
	row := exported.Tenants[0]
	validator, err := sessionvalidator.New(sessionvalidator.Config{SigningKey: []byte(row.Key), Issuer: "tauth", CookieName: row.Cookie})
	if err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := validator.ValidateRequest(r)
		if err != nil || claims.TenantID != row.ID {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(204)
	}))
	defer backend.Close()
	for _, valid := range []bool{true, false} {
		key := row.Key
		if !valid {
			key = "wrong-key"
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"iss": "tauth", "sub": "fixture-user", "tenant_id": row.ID, "user_id": "fixture-user", "exp": time.Now().Add(time.Hour).Unix()})
		signed, err := token.SignedString([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		httpRequest, _ := http.NewRequest(http.MethodGet, backend.URL, nil)
		httpRequest.AddCookie(&http.Cookie{Name: row.Cookie, Value: signed})
		response, err := http.DefaultClient.Do(httpRequest)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		expected := 401
		if valid {
			expected = 204
		}
		if response.StatusCode != expected {
			t.Fatalf("validator authorization valid=%t: %d", valid, response.StatusCode)
		}
	}
	receipt, err := os.ReadFile(filepath.Join(outputDir, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{row.Key, server["tenant_encryption_key"].(string)} {
		if bytes.Contains(receipt, []byte(secret)) {
			t.Fatal("receipt contains a secret")
		}
	}
	var receiptFields map[string]any
	if err := json.Unmarshal(receipt, &receiptFields); err != nil {
		t.Fatal(err)
	}
	if receiptFields["schema"] != "tauth.test-fixture.v1" || receiptFields["app_id"] != "fixture-app" || receiptFields["tenant_id"] != row.ID || receiptFields["mount_path"] != "/tauth-fixture" || receiptFields["build_identity"] == "" || receiptFields["input_sha256"] == "" {
		t.Fatalf("receipt identity is incomplete: %v", receiptFields)
	}
	databaseBefore, err := os.ReadFile(filepath.Join(outputDir, "tauth.db"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(databaseBefore, []byte(row.Key)) {
		t.Fatal("database contains a plaintext tenant signing key")
	}
	if output, err := invoke(encoded, outputDir); err == nil {
		t.Fatalf("existing output accepted: %s", output)
	}
	databaseAfter, _ := os.ReadFile(filepath.Join(outputDir, "tauth.db"))
	if !bytes.Equal(databaseBefore, databaseAfter) {
		t.Fatal("rejected existing output changed the database")
	}
	for _, scenario := range []string{"unknown", "schema", "test-only", "remote-origin", "reserved-tenant", "reserved-app", "reserved-app-spaces", "missing-provider", "invalid-lifetime", "trailing"} {
		t.Run(scenario, func(t *testing.T) {
			var invalid map[string]any
			json.Unmarshal(encoded, &invalid)
			tenant := invalid["tenant"].(map[string]any)
			switch scenario {
			case "unknown":
				invalid["database_url"] = "sqlite:///unowned.db"
			case "schema":
				invalid["schema"] = "other"
			case "test-only":
				invalid["test_only"] = false
			case "remote-origin":
				tenant["origin"] = "https://production.example.com"
			case "reserved-tenant":
				tenant["id"] = "tauth-console"
			case "reserved-app":
				invalid["app_id"] = "tauth-console"
			case "reserved-app-spaces":
				invalid["app_id"] = " tauth-console "
			case "missing-provider":
				delete(tenant, "google_native_client_id")
			case "invalid-lifetime":
				tenant["session_ttl"] = "0s"
			}
			payload, _ := json.Marshal(invalid)
			if scenario == "trailing" {
				payload = append(payload, []byte(" {}")...)
			}
			destination := filepath.Join(scratch, scenario)
			if output, err := invoke(payload, destination); err == nil {
				t.Fatalf("invalid fixture accepted: %s", output)
			}
			if _, err := os.Stat(destination); !os.IsNotExist(err) {
				t.Fatalf("invalid fixture left output: %v", err)
			}
		})
	}
	list := exec.Command("go", "list", "./cmd/...")
	list.Dir = root
	listed, err := list.CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(listed), "cmd/testfixture") {
		t.Fatal("fixture tool exposed by ordinary build")
	}
}

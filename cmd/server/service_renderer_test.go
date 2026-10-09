package main

import (
	"bytes"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/tyemirov/tauth/internal/appconfig"
)

func TestConsoleRendererHasNoRuntimeTenantYAML(t *testing.T) {
	data, err := os.ReadFile("../../tests/fixtures/deployment-config/browser-demo.json")
	if err != nil {
		t.Fatal(err)
	}
	command := newRootCommand()
	var output bytes.Buffer
	command.SetIn(bytes.NewReader(data))
	command.SetOut(&output)
	command.SetArgs([]string{"render-deployment-config"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "\ntenants:") {
		t.Fatal("renderer still emits runtime tenant YAML")
	}
	if !strings.Contains(output.String(), "${TAUTH_TENANT_ENCRYPTION_KEY}") {
		t.Fatal("service encryption input absent")
	}
}

func TestConsoleRendererTrustedProxyInput(t *testing.T) {
	data, err := os.ReadFile("../../tests/fixtures/deployment-config/browser-demo.json")
	if err != nil {
		t.Fatal(err)
	}
	command := newRootCommand()
	var output bytes.Buffer
	command.SetIn(bytes.NewReader(data))
	command.SetOut(&output)
	command.SetArgs([]string{"render-deployment-config"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "${TAUTH_TRUSTED_PROXY_HOSTS}") || !strings.Contains(output.String(), "trusted_proxy_hosts:") || !strings.Contains(output.String(), "${TAUTH_TRUSTED_PROXY_LOOKUP_TIMEOUT}") {
		t.Fatal("rendered service lacks managed hostname proxy trust")
	}
	if strings.Contains(output.String(), "TAUTH_TRUSTED_PROXY_CIDRS") {
		t.Fatal("managed rendering still requires an operator CIDR input")
	}
}

func TestConsoleRendererTrustedProxyValidationCLI(t *testing.T) {
	data, err := os.ReadFile("../../tests/fixtures/deployment-config/browser-demo.json")
	if err != nil {
		t.Fatal(err)
	}
	command := newRootCommand()
	var output bytes.Buffer
	command.SetIn(bytes.NewReader(data))
	command.SetOut(&output)
	command.SetArgs([]string{"render-deployment-config"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	file, err := os.CreateTemp(t.TempDir(), "proxy-config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(output.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, hostname, timeout string
		valid, trusted          bool
	}{
		{"empty", "", "", true, false},
		{"configured", "localhost", "1s", true, true},
		{"managed name absent locally", "mprlab-caddy", "1s", true, false},
		{"malformed", "https://localhost", "1s", false, false},
		{"literal address", "127.0.0.1", "1s", false, false},
		{"timeout missing", "localhost", "", false, false},
		{"timeout invalid", "localhost", "invalid", false, false},
		{"timeout zero", "localhost", "0s", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("TAUTH_TRUSTED_PROXY_HOSTS", test.hostname)
			t.Setenv("TAUTH_TRUSTED_PROXY_LOOKUP_TIMEOUT", test.timeout)
			t.Setenv("TAUTH_TRUSTED_PROXY_CIDRS", "127.0.0.1/32")
			validate := newRootCommand()
			var result bytes.Buffer
			validate.SetOut(&result)
			validate.SetErr(&result)
			validate.SetArgs([]string{"validate-service-config", file.Name()})
			err := validate.Execute()
			if (err == nil) != test.valid {
				t.Fatalf("validate valid=%v error=%v", test.valid, err)
			}
			if !test.valid {
				return
			}
			config, err := appconfig.LoadConfig(file.Name())
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest("POST", "http://auth.example/auth/password/login", nil)
			request.RemoteAddr = "127.0.0.1:12345"
			request.Header.Set("X-Forwarded-Proto", "https")
			if secure := config.TransportPolicy().IsHTTPS(request); secure != test.trusted {
				t.Fatalf("rendered trusted peer=%v want=%v", secure, test.trusted)
			}
		})
	}
}

func TestManagedProxyTrustManifest(t *testing.T) {
	payload, err := os.ReadFile("../../.mprlab/deploy/resources.yml")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Resources struct {
			Resources map[string]struct {
				Bindings map[string]string `yaml:"bindings"`
				Services map[string]struct {
					Environment map[string]struct {
						Value string `yaml:"value"`
					} `yaml:"environment"`
				} `yaml:"services"`
			} `yaml:"resources"`
		} `yaml:"mprlab_resources"`
	}
	if err := yaml.Unmarshal(payload, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, resource := range manifest.Resources.Resources {
		for _, binding := range resource.Bindings {
			if binding == "TAUTH_TRUSTED_PROXY_CIDRS" || binding == "TAUTH_TRUSTED_PROXY_HOSTS" {
				t.Fatal("proxy trust still requires a private operator input")
			}
		}
	}
	environment := manifest.Resources.Resources["runtime"].Services["tauth-api"].Environment
	if environment["TAUTH_TRUSTED_PROXY_HOSTS"].Value != "mprlab-caddy" || environment["TAUTH_TRUSTED_PROXY_LOOKUP_TIMEOUT"].Value != "1s" {
		t.Fatal("deployment does not configure managed proxy identity and bounded resolution")
	}
	if _, exists := environment["TAUTH_TRUSTED_PROXY_CIDRS"]; exists {
		t.Fatal("managed deployment still supplies manual CIDRs")
	}
}

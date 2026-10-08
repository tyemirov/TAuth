package main

import (
	"bytes"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

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
	if !strings.Contains(output.String(), "${TAUTH_TRUSTED_PROXY_CIDRS}") || !strings.Contains(output.String(), "trusted_proxy_cidrs:") {
		t.Fatal("rendered service lacks the explicit trusted proxy input")
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
		name, value    string
		valid, trusted bool
	}{
		{"empty", "", true, false},
		{"configured", "127.0.0.1/32,::1/128", true, true},
		{"malformed", "127.0.0.1/32,invalid", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("TAUTH_TRUSTED_PROXY_CIDRS", test.value)
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

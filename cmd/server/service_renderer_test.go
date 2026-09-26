package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
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

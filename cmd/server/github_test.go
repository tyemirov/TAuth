package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestGitHubOnlyDoctorPreflightAndStartup(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "github-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_, err = file.WriteString(`server:
  listen_addr: 127.0.0.1:0
  enable_cors: true
  cors_allowed_origins: [https://app.example.com]
tenants:
  - id: github
    display_name: GitHub
    tenant_origins: [https://app.example.com]
    github_oauth:
      enabled: true
      client_id: github-client
      client_secret: test-secret
      redirect_uri: https://auth.example.com/auth/github/callback
    jwt_signing_key: test-signing-key
    session_cookie_name: github_session
    refresh_cookie_name: github_refresh
    session_ttl: 30m
    refresh_ttl: 720h
`)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	for _, arguments := range [][]string{{"doctor", "--json", file.Name()}, {"--config", file.Name(), "preflight"}} {
		command := newRootCommand()
		var output bytes.Buffer
		command.SetOut(&output)
		command.SetErr(&output)
		command.SetArgs(arguments)
		if err := command.Execute(); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output.String(), "test-secret") {
			t.Fatal("GitHub secret in diagnostics")
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, output.Bytes()); err != nil {
			t.Fatal(err)
		}
		if arguments[len(arguments)-1] == "preflight" && !strings.Contains(compact.String(), `"github_oauth_enabled":true`) {
			t.Fatal("preflight omitted GitHub capability")
		}
	}
	served := false
	restore := withServeHTTPStub(func(server *http.Server) error {
		served = true
		listener := httptest.NewTLSServer(server.Handler)
		defer listener.Close()
		client := listener.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		response, err := client.Get(listener.URL + "/auth/github/start?tenant_id=github&return_to=" + url.QueryEscape("https://app.example.com/done"))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 302 {
			t.Fatalf("GitHub-only server route returned %d", response.StatusCode)
		}
		response, err = client.Get(listener.URL + "/auth/github/callback?state=invalid&code=private-code")
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 400 {
			t.Fatalf("Origin-free callback not mounted: %d", response.StatusCode)
		}
		return http.ErrServerClosed
	})
	defer restore()
	command := newRootCommand()
	command.SetArgs([]string{"--config", file.Name()})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if !served {
		t.Fatal("GitHub-only server did not start")
	}
}

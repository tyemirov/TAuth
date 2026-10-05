package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/tyemirov/tauth/internal/deploymentconfig"
	"gopkg.in/yaml.v3"
)

func TestConsoleProvisioningChallengeTokenConstraint(t *testing.T) {
	for _, kind := range []string{"tauth_tenant", "tauth_github_tenant"} {
		t.Run(kind, func(t *testing.T) {
			withManagementService(t, consoleGoogleValidator{}, func(owner consoleHTTP) {
				issued, _ := owner.request("POST", "/api/management/provisioning-credentials", map[string]any{
					"app_id": owner.fixtureApp(), "name": "Gateway", "operations": []string{"read", "configure"}, "tenant_ids": []string{}, "allow_create": true,
				}, 201, "Idempotency-Key", "challenge-credential")
				machine := owner
				client := *owner.client
				client.Jar = nil
				machine.client, machine.origin = &client, ""
				auth := []string{"Authorization", "Bearer " + issued["token"].(string)}
				_, headers := machine.request("POST", "/api/management/tenants", map[string]any{"id": "challenge-app", "name": "Challenge application"}, 201, append(auth, "Idempotency-Key", "challenge-app")...)
				path := headers.Get("Location") + "/configuration"
				_, headers = machine.request("GET", path, nil, 200, auth...)
				tenant := map[string]any{
					"id": "challenge-app", "display_name": "Challenge application", "origins": []string{"http://localhost:9291"},
					"google_web_client_id": map[string]any{"resource": "private", "output": "client"},
					"jwt_signing_key":      map[string]any{"resource": "private", "output": "key"},
					"cookie":               map[string]any{"domain": "", "session_name": "challenge_session", "refresh_name": "challenge_refresh"},
				}
				outputs := map[string]any{"google-web-client-id": map[string]any{"value": "gateway-client"}, "jwt-signing-key": map[string]any{"value": "gateway-signing-key"}}
				if kind == "tauth_github_tenant" {
					delete(tenant, "google_web_client_id")
					delete(outputs, "google-web-client-id")
					tenant["github_oauth"] = map[string]any{
						"enabled": true, "client_id": map[string]any{"resource": "private", "output": "client"},
						"client_secret": map[string]any{"resource": "private", "output": "secret"},
						"redirect_uri":  "https://auth.example.com/auth/github/callback", "scopes": []string{"read:user", "user:email"},
					}
					outputs["github-client-id"] = map[string]any{"value": "github-client"}
					outputs["github-client-secret"] = map[string]any{"value": "github-private-secret"}
				}
				contribution := map[string]any{
					"owner": "challenge-application", "id": "authentication", "kind": kind,
					"desired": map[string]any{"kind": kind, "id": "authentication", "capability": "tauth.tenants", "version": 1, "tenant": tenant}, "outputs": outputs,
				}
				for index, testCase := range []struct {
					name     string
					settings map[string]any
					status   int
				}{
					{"omitted", map[string]any{"enabled": false}, 200},
					{"disabled", map[string]any{"enabled": false, "return_challenge_tokens": false}, 200},
					{"enabled", map[string]any{"enabled": false, "return_challenge_tokens": true}, 422},
					{"null", map[string]any{"enabled": false, "return_challenge_tokens": nil}, 422},
					{"string", map[string]any{"enabled": false, "return_challenge_tokens": "false"}, 422},
					{"number", map[string]any{"enabled": false, "return_challenge_tokens": 0}, 422},
					{"object", map[string]any{"enabled": false, "return_challenge_tokens": map[string]any{}}, 422},
					{"array", map[string]any{"enabled": false, "return_challenge_tokens": []any{}}, 422},
					{"unknown", map[string]any{"enabled": false, "unknown": false}, 422},
				} {
					t.Run(testCase.name, func(t *testing.T) {
						machine.t = t
						tenant["account_management"] = testCase.settings
						payload := map[string]any{"provisioning": map[string]any{"generation": index + 1, "contribution": contribution}}
						response, updated := machine.request("PUT", path, payload, testCase.status, append(auth, "If-Match", headers.Get("ETag"))...)
						if testCase.status == 200 {
							headers = updated
							encoded, err := json.Marshal(contribution)
							if err != nil {
								t.Fatal(err)
							}
							projection, err := deploymentconfig.ResolveContribution(encoded)
							if err != nil {
								t.Fatal(err)
							}
							native, err := yaml.Marshal(projection.Tenant)
							if err != nil {
								t.Fatal(err)
							}
							if bytes.Contains(native, []byte("return_challenge_tokens")) {
								t.Fatal("deployment constraint entered persisted tenant configuration")
							}
						} else if response["code"] != "management.contribution_invalid" {
							t.Fatalf("unexpected rejection: %v", response)
						}
						_, current := machine.request("GET", path, nil, 200, auth...)
						if current.Get("ETag") != headers.Get("ETag") {
							t.Fatal("rejected contribution changed stored configuration")
						}
					})
				}
			})
		})
	}
}

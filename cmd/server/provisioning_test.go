package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestConsoleProvisioningCredentialScope(t *testing.T) {
	withManagementService(t, consoleGoogleValidator{}, func(owner consoleHTTP) {
		credentialInput := map[string]any{"app_id": owner.fixtureApp(), "name": "Gateway", "operations": []string{"read", "configure", "activate", "suspend", "proofs"}, "tenant_ids": []string{}, "allow_create": true}
		issued, issuedHeaders := owner.request("POST", "/api/management/provisioning-credentials", credentialInput, 201, "Idempotency-Key", "gateway-credential")
		token := issued["token"].(string)
		retry, _ := owner.request("POST", "/api/management/provisioning-credentials", credentialInput, 201, "Idempotency-Key", "gateway-credential")
		if _, exists := retry["token"]; exists {
			t.Fatal("credential disclosed again")
		}
		machine := owner
		isolated := *owner.client
		isolated.Jar = nil
		machine.client = &isolated
		machine.origin = ""
		auth := []string{"Authorization", "Bearer " + token}
		directoryClient := machine
		directoryClient.origin = owner.origin
		directoryClient.request("GET", "/api/management/accounts", nil, 401, auth...)
		body := map[string]any{"id": "gateway-app", "name": "Gateway application"}
		tenant, headers := machine.request("POST", "/api/management/tenants", body, 201, append(auth, "Idempotency-Key", "gateway-app")...)
		if tenant["id"] != "gateway-app" {
			t.Fatal("provisioning changed declared tenant ID")
		}
		path := headers.Get("Location")
		machine.request("PATCH", path, map[string]any{"name": "Unauthorized metadata edit"}, 403, append(auth, "If-Match", headers.Get("ETag"))...)
		_, headers = machine.request("GET", path+"/configuration", nil, 200, auth...)
		browserConfig := map[string]any{"google_web_client_id": "console-client-change", "frontend_origins": []string{"http://localhost:9291"}, "api_base_url": "http://localhost:9292", "local_development": true, "session_ttl": "15m", "refresh_ttl": "720h"}
		machine.request("PUT", path+"/configuration", browserConfig, 422, append(auth, "If-Match", headers.Get("ETag"))...)
		contribution := map[string]any{
			"owner": "test-application", "id": "authentication", "kind": "tauth_tenant",
			"desired": map[string]any{"kind": "tauth_tenant", "id": "authentication", "capability": "tauth.tenants", "version": 1, "tenant": map[string]any{"id": "gateway-app", "display_name": "Gateway application", "origins": []string{"http://localhost:9291"}, "google_web_client_id": map[string]any{"resource": "private", "output": "client"}, "jwt_signing_key": map[string]any{"resource": "private", "output": "key"}, "cookie": map[string]any{"domain": "", "session_name": "gateway_session", "refresh_name": "gateway_refresh"}}},
			"outputs": map[string]any{"google-web-client-id": map[string]any{"value": "gateway-client"}, "jwt-signing-key": map[string]any{"value": "gateway-signing-key"}},
		}
		payload := map[string]any{"provisioning": map[string]any{"generation": 1, "contribution": contribution}}
		saved, updated := machine.request("PUT", path+"/configuration", payload, 200, append(auth, "If-Match", headers.Get("ETag"))...)
		repeated, repeatedHeader := machine.request("PUT", path+"/configuration", payload, 200, append(auth, "If-Match", updated.Get("ETag"))...)
		if repeated["revision"] != saved["revision"] || repeatedHeader.Get("ETag") != updated.Get("ETag") {
			t.Fatal("identical provisioning created another revision")
		}
		machine.request("POST", path+"/activations", map[string]any{"revision": saved["revision"]}, 201, append(auth, "If-Match", updated.Get("ETag"), "Idempotency-Key", "gateway-activation")...)
		application := machine
		application.origin = "http://localhost:9291"
		application.tenant = "gateway-app"
		verifyProvisionedPolicies(application, true, true, "gateway-client")
		// Ordinary console edits invalidate the last revision controlled by Gateway.
		machine.request("PUT", path+"/configuration", browserConfig, 422, append(auth, "If-Match", updated.Get("ETag"))...)
		ownerSaved, ownerHeaders := owner.request("PUT", path+"/configuration", browserConfig, 200, "If-Match", updated.Get("ETag"))
		machine.request("PUT", path+"/configuration", browserConfig, 422, append(auth, "If-Match", ownerHeaders.Get("ETag"))...)
		browserConfig["provisioning"] = nil
		machine.request("PUT", path+"/configuration", browserConfig, 422, append(auth, "If-Match", ownerHeaders.Get("ETag"))...)
		delete(browserConfig, "provisioning")
		machine.request("PUT", path+"/configuration", payload, 412, append(auth, "If-Match", ownerHeaders.Get("ETag"))...)
		unchanged, unchangedHeaders := owner.request("GET", path+"/configuration", nil, 200)
		if unchanged["revision"] != ownerSaved["revision"] || unchangedHeaders.Get("ETag") != ownerHeaders.Get("ETag") || unchanged["google_web_client_id"] != browserConfig["google_web_client_id"] {
			t.Fatal("machine changed owner configuration")
		}
		_, tenantHeaders := owner.request("GET", path, nil, 200)
		owner.request("PATCH", path, map[string]any{"state": "suspended"}, 200, "If-Match", tenantHeaders.Get("ETag"))
		machine.request("PUT", path+"/configuration", browserConfig, 422, append(auth, "If-Match", ownerHeaders.Get("ETag"))...)

		machine.request("PUT", path+"/configuration", payload, 412, append(auth, "If-Match", updated.Get("ETag"))...)
		private, privateHeaders := owner.request("POST", "/api/management/tenants", owner.tenantInput("Console only"), 201, "Idempotency-Key", "private")
		_ = private
		machine.request("GET", privateHeaders.Get("Location"), nil, 403, auth...)
		deniedInput := map[string]any{"app_id": owner.fixtureApp(), "name": "Read only", "operations": []string{"read"}, "tenant_ids": []string{"gateway-app"}, "allow_create": false}
		denied, _ := owner.request("POST", "/api/management/provisioning-credentials", deniedInput, 201, "Idempotency-Key", "read-only")
		machine.request("POST", "/api/management/tenants", body, 403, "Authorization", "Bearer "+denied["token"].(string), "Idempotency-Key", "denied")
		machine.request("PUT", path+"/configuration", payload, 403, "Authorization", "Bearer "+denied["token"].(string), "If-Match", updated.Get("ETag"))
		owner.request("DELETE", issuedHeaders.Get("Location"), nil, 204)
		machine.request("GET", path, nil, 401, auth...)
		// Revocation is idempotent and listing contains no opaque credential.
		owner.request("DELETE", issuedHeaders.Get("Location"), nil, 204)
		listing, _ := owner.request("GET", "/api/management/provisioning-credentials", nil, 200)
		encoded, _ := json.Marshal(listing)
		if len(encoded) == 0 {
			t.Fatal("empty credential listing")
		}
	})
}

func TestConsoleActualGatewayClient(t *testing.T) {
	gateway := os.Getenv("TAUTH_GATEWAY_ROOT")
	if gateway == "" {
		t.Skip("selected by make test-gateway-provisioning")
	}
	withManagementService(t, consoleGoogleValidator{}, func(owner consoleHTTP) {
		input := map[string]any{"app_id": owner.fixtureApp(), "name": "Gateway client acceptance", "operations": []string{"read", "configure", "activate", "suspend", "proofs"}, "tenant_ids": []string{}, "allow_create": true}
		credential, _ := owner.request("POST", "/api/management/provisioning-credentials", input, 201, "Idempotency-Key", "actual-gateway")
		secondApp, _ := owner.request("POST", "/api/management/apps", map[string]any{"name": "Second Gateway App"}, 201, "Idempotency-Key", "second-gateway-app")
		secondInput := map[string]any{"app_id": secondApp["id"], "name": "Second App acceptance", "operations": []string{"read", "configure", "activate", "suspend"}, "tenant_ids": []string{}, "allow_create": true}
		secondCredential, _ := owner.request("POST", "/api/management/provisioning-credentials", secondInput, 201, "Idempotency-Key", "second-app-credential")
		credentials, err := json.Marshal(map[string]any{"gateway-fixture": map[string]any{"authentication": credential["token"], "second-authentication": secondCredential["token"]}})
		if err != nil {
			t.Fatal(err)
		}
		command := exec.Command("make", "--no-print-directory", "test-tauth-management-client")
		command.Dir = gateway
		command.Env = append(os.Environ(), "TAUTH_MANAGEMENT_TEST_URL="+owner.gatewayURL, "MPRLAB_TAUTH_MANAGEMENT_URL="+owner.gatewayURL, "MPRLAB_TAUTH_PROVISIONING_CREDENTIALS="+string(credentials))
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("Gateway client: %v\n%s", err, output)
		}
		collection, _ := owner.request("GET", "/api/management/tenants", nil, 200)
		if len(collection["items"].([]any)) != 2 {
			t.Fatal("Gateway did not create exactly two tenants")
		}
		apps := map[string]any{"gateway-acceptance": input["app_id"], "gateway-acceptance-second": secondApp["id"]}
		for _, item := range collection["items"].([]any) {
			tenant := item.(map[string]any)
			if tenant["active_revision"] != float64(2) || tenant["app_id"] != apps[tenant["id"].(string)] {
				t.Fatalf("incorrect App or revision: %v", tenant)
			}
		}
	})
}

func verifyImportedProvisioning(owner consoleHTTP, insecure, requireHeader bool) {
	owner.t.Helper()
	issued, _ := owner.request("POST", "/api/management/provisioning-credentials", map[string]any{"app_id": "imported-app", "name": "Imported Gateway", "operations": []string{"read", "configure", "activate"}, "tenant_ids": []string{"imported"}, "allow_create": false}, 201, "Idempotency-Key", "imported-gateway")
	machine := owner
	client := *owner.client
	client.Jar = nil
	machine.client = &client
	machine.origin = ""
	auth := []string{"Authorization", "Bearer " + issued["token"].(string)}
	path := "/api/management/tenants/imported"
	_, headers := machine.request("GET", path+"/configuration", nil, 200, auth...)
	outputs := map[string]any{"google-web-client-id": map[string]any{"value": "imported-client"}, "jwt-signing-key": map[string]any{"value": "imported-session-key$literal"}}
	contribution := map[string]any{"owner": "imported-application", "id": "authentication", "kind": "tauth_tenant", "desired": map[string]any{"kind": "tauth_tenant", "id": "authentication", "capability": "tauth.tenants", "version": 1, "tenant": map[string]any{"id": "imported", "display_name": "Imported application", "origins": []string{"https://customer.example.com", "http://127.0.0.1:4443"}, "google_web_client_id": map[string]any{"resource": "private", "output": "google"}, "jwt_signing_key": map[string]any{"resource": "private", "output": "key"}, "cookie": map[string]any{"domain": "", "session_name": "imported_session", "refresh_name": "imported_refresh"}}}, "outputs": outputs}
	payload := map[string]any{"provisioning": map[string]any{"generation": 1, "contribution": contribution}}
	assertPolicies := func() {
		application := machine
		application.origin = "http://127.0.0.1:4443"
		application.tenant = "imported"
		verifyProvisionedPolicies(application, insecure, requireHeader, "imported-client")
	}
	assertPolicies()
	for attempt, generation := range []int{1, 1, 2, 2} {
		payload["provisioning"].(map[string]any)["generation"] = generation
		if gateway := os.Getenv("TAUTH_GATEWAY_ROOT"); gateway != "" {
			input, err := json.Marshal(map[string]any{"contributions": []any{contribution}, "owners": []any{map[string]any{"owner": "imported-application", "generation": generation}}, "removed": []any{}})
			if err != nil {
				owner.t.Fatal(err)
			}
			command := exec.Command(filepath.Join(gateway, ".venv", "bin", "python"), "-c", `
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(os.environ["TAUTH_GATEWAY_ROOT"]) / "deploy/ansible/library"))
from mprlab_tauth_provision import Client

client = Client(os.environ["TAUTH_MANAGEMENT_TEST_URL"], os.environ["TAUTH_MANAGEMENT_TEST_TOKEN"])
print(json.dumps(client.provision(**json.load(sys.stdin))))
`)
			command.Env = append(os.Environ(), "TAUTH_MANAGEMENT_TEST_URL="+owner.gatewayURL, "TAUTH_MANAGEMENT_TEST_TOKEN="+issued["token"].(string))
			command.Stdin = bytes.NewReader(input)
			output, err := command.CombinedOutput()
			if err != nil {
				owner.t.Fatalf("Gateway imported policies: %v\n%s", err, output)
			}
			var result struct {
				Changed bool `json:"changed"`
			}
			if err := json.Unmarshal(output, &result); err != nil {
				owner.t.Fatal(err)
			}
			if result.Changed != (attempt%2 == 0) {
				owner.t.Fatalf("Gateway changed=%t on attempt %d", result.Changed, attempt)
			}
		} else {
			saved, updated := machine.request("PUT", path+"/configuration", payload, 200, append(auth, "If-Match", headers.Get("ETag"))...)
			machine.request("POST", path+"/activations", map[string]any{"revision": saved["revision"]}, 201, append(auth, "If-Match", updated.Get("ETag"), "Idempotency-Key", fmt.Sprintf("imported-activation-%d", generation))...)
		}
		saved, updated := machine.request("GET", path+"/configuration", nil, 200, auth...)
		headers = updated
		if saved["revision"] != float64(generation+1) || saved["session_cookie_name"] != "imported_session" || saved["refresh_cookie_name"] != "imported_refresh" {
			owner.t.Fatalf("imported configuration changed: %v", saved)
		}
		assertPolicies()
	}
	outputs["jwt-signing-key"] = map[string]any{"value": "replacement-not-authorized"}
	payload["provisioning"].(map[string]any)["generation"] = 3
	machine.request("PUT", path+"/configuration", payload, 409, append(auth, "If-Match", headers.Get("ETag"))...)
}

func TestConsoleProvisioningCannotReactivateSuspendedTenant(t *testing.T) {
	withManagementService(t, consoleGoogleValidator{}, func(owner consoleHTTP) {
		tenant, headers := owner.request("POST", "/api/management/tenants", owner.tenantInput("Owner controlled suspension"), 201, "Idempotency-Key", "suspension-app")
		path := headers.Get("Location")
		_, headers = owner.request("GET", path+"/configuration", nil, 200)
		saved, headers := owner.request("PUT", path+"/configuration", map[string]any{"google_web_client_id": "app-client", "frontend_origins": []string{"http://localhost:9391"}, "api_base_url": "http://localhost:9392", "local_development": true, "session_ttl": "15m", "refresh_ttl": "720h"}, 200, "If-Match", headers.Get("ETag"))
		etag := headers.Get("ETag")
		credential, _ := owner.request("POST", "/api/management/provisioning-credentials", map[string]any{"app_id": owner.fixtureApp(), "name": "Activator", "operations": []string{"read", "activate"}, "tenant_ids": []string{tenant["id"].(string)}, "allow_create": false}, 201, "Idempotency-Key", "activation-credential")
		machine := owner
		client := *owner.client
		client.Jar = nil
		machine.client = &client
		machine.origin = ""
		auth := []string{"Authorization", "Bearer " + credential["token"].(string), "If-Match", etag}
		activation := map[string]any{"revision": saved["revision"]}
		machine.request("POST", path+"/activations", activation, 201, append(auth, "Idempotency-Key", "initial-activation")...)
		_, headers = owner.request("GET", path, nil, 200)
		owner.request("PATCH", path, map[string]any{"state": "suspended"}, 200, "If-Match", headers.Get("ETag"))
		rejected, _ := machine.request("POST", path+"/activations", activation, 409, append(auth, "Idempotency-Key", "machine-recovery")...)
		if rejected["code"] != "management.tenant_suspended" {
			t.Fatalf("unexpected rejection: %v", rejected)
		}
		current, _ := owner.request("GET", path, nil, 200)
		if current["state"] != "suspended" {
			t.Fatal("machine changed suspended state")
		}
		application := owner
		application.origin = "http://localhost:9391"
		application.tenant = tenant["id"].(string)
		application.request("POST", "/auth/nonce", nil, 403)
		owner.request("POST", path+"/activations", activation, 201, "If-Match", etag, "Idempotency-Key", "owner-recovery")
		application.login("application-user", "app-client")
	})
}

func verifyProvisionedPolicies(application consoleHTTP, insecure, requireHeader bool, audience string) {
	application.t.Helper()
	tenantID := application.tenant
	application.tenant = ""
	status := http.StatusUnauthorized
	if requireHeader {
		status = http.StatusForbidden
	}
	application.request("GET", "/me", nil, status)
	application.tenant = tenantID
	application.request("GET", "/me", nil, http.StatusUnauthorized)
	nonce, _ := application.request("POST", "/auth/nonce", nil, http.StatusOK)
	claims, err := json.Marshal(map[string]any{"aud": audience, "iss": "https://accounts.google.com", "sub": "policy-probe", "email": "probe@example.com", "email_verified": true, "nonce": nonce["nonce"]})
	if err != nil {
		application.t.Fatal(err)
	}
	_, cookieHeaders := application.request("POST", "/auth/google", map[string]any{"google_id_token": string(claims), "nonce_token": nonce["nonce"]}, http.StatusOK)
	response := http.Response{Header: cookieHeaders}
	cookies := response.Cookies()
	if len(cookies) != 2 {
		application.t.Fatalf("expected session and refresh cookies, got %d", len(cookies))
	}
	for _, cookie := range cookies {
		if cookie.Secure == insecure {
			application.t.Fatalf("cookie %s: Secure=%t, allow_insecure_http=%t", cookie.Name, cookie.Secure, insecure)
		}
	}
}

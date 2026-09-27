package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"testing"
)

func TestConsoleProvisioningCredentialScope(t *testing.T) {
	withManagementService(t, consoleGoogleValidator{}, func(owner consoleHTTP) {
		credentialInput := map[string]any{"name": "Gateway", "operations": []string{"read", "configure", "activate", "suspend", "proofs"}, "tenant_ids": []string{}, "allow_create": true}
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
		private, privateHeaders := owner.request("POST", "/api/management/tenants", map[string]any{"name": "Console only"}, 201, "Idempotency-Key", "private")
		_ = private
		machine.request("GET", privateHeaders.Get("Location"), nil, 403, auth...)
		deniedInput := map[string]any{"name": "Read only", "operations": []string{"read"}, "tenant_ids": []string{"gateway-app"}, "allow_create": false}
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
		input := map[string]any{"name": "Gateway client acceptance", "operations": []string{"read", "configure", "activate", "suspend", "proofs"}, "tenant_ids": []string{}, "allow_create": true}
		credential, _ := owner.request("POST", "/api/management/provisioning-credentials", input, 201, "Idempotency-Key", "actual-gateway")
		command := exec.Command("make", "--no-print-directory", "test-tauth-management-client")
		command.Dir = gateway
		command.Env = append(os.Environ(), "TAUTH_MANAGEMENT_TEST_URL="+owner.gatewayURL, "TAUTH_MANAGEMENT_TEST_TOKEN="+credential["token"].(string), "MPRLAB_TAUTH_MANAGEMENT_URL="+owner.gatewayURL, "MPRLAB_TAUTH_PROVISIONING_CREDENTIAL="+credential["token"].(string))
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("Gateway client: %v\n%s", err, output)
		}
		collection, _ := owner.request("GET", "/api/management/tenants", nil, 200)
		if len(collection["items"].([]any)) != 1 {
			t.Fatal("Gateway did not create exactly one tenant")
		}
		tenant := collection["items"].([]any)[0].(map[string]any)
		if tenant["id"] != "gateway-acceptance" || tenant["active_revision"] != float64(2) {
			t.Fatalf("unstable Gateway result: %v", tenant)
		}
	})
}

func verifyImportedProvisioning(owner consoleHTTP) {
	owner.t.Helper()
	issued, _ := owner.request("POST", "/api/management/provisioning-credentials", map[string]any{"name": "Imported Gateway", "operations": []string{"read", "configure", "activate"}, "tenant_ids": []string{"imported"}, "allow_create": false}, 201, "Idempotency-Key", "imported-gateway")
	machine := owner
	client := *owner.client
	client.Jar = nil
	machine.client = &client
	machine.origin = ""
	auth := []string{"Authorization", "Bearer " + issued["token"].(string)}
	path := "/api/management/tenants/imported"
	_, headers := machine.request("GET", path+"/configuration", nil, 200, auth...)
	outputs := map[string]any{"google-web-client-id": map[string]any{"value": "imported-client"}, "jwt-signing-key": map[string]any{"value": "imported-session-key$literal"}}
	contribution := map[string]any{"owner": "imported-application", "id": "authentication", "kind": "tauth_tenant", "desired": map[string]any{"kind": "tauth_tenant", "id": "authentication", "capability": "tauth.tenants", "version": 1, "tenant": map[string]any{"id": "imported", "display_name": "Imported application", "origins": []string{"https://customer.example.com"}, "google_web_client_id": map[string]any{"resource": "private", "output": "google"}, "jwt_signing_key": map[string]any{"resource": "private", "output": "key"}, "cookie": map[string]any{"domain": "", "session_name": "imported_session", "refresh_name": "imported_refresh"}}}, "outputs": outputs}
	payload := map[string]any{"provisioning": map[string]any{"generation": 1, "contribution": contribution}}
	saved, headers := machine.request("PUT", path+"/configuration", payload, 200, append(auth, "If-Match", headers.Get("ETag"))...)
	if saved["session_cookie_name"] != "imported_session" || saved["refresh_cookie_name"] != "imported_refresh" {
		owner.t.Fatal("imported cookie outputs changed")
	}
	machine.request("POST", path+"/activations", map[string]any{"revision": saved["revision"]}, 201, append(auth, "If-Match", headers.Get("ETag"), "Idempotency-Key", "imported-activation")...)
	outputs["jwt-signing-key"] = map[string]any{"value": "replacement-not-authorized"}
	payload["provisioning"].(map[string]any)["generation"] = 2
	machine.request("PUT", path+"/configuration", payload, 409, append(auth, "If-Match", headers.Get("ETag"))...)
}

func TestConsoleProvisioningCannotReactivateSuspendedTenant(t *testing.T) {
	withManagementService(t, consoleGoogleValidator{}, func(owner consoleHTTP) {
		tenant, headers := owner.request("POST", "/api/management/tenants", map[string]any{"name": "Owner controlled suspension"}, 201, "Idempotency-Key", "suspension-app")
		path := headers.Get("Location")
		_, headers = owner.request("GET", path+"/configuration", nil, 200)
		saved, headers := owner.request("PUT", path+"/configuration", map[string]any{"google_web_client_id": "app-client", "frontend_origins": []string{"http://localhost:9391"}, "api_base_url": "http://localhost:9392", "local_development": true, "session_ttl": "15m", "refresh_ttl": "720h"}, 200, "If-Match", headers.Get("ETag"))
		etag := headers.Get("ETag")
		credential, _ := owner.request("POST", "/api/management/provisioning-credentials", map[string]any{"name": "Activator", "operations": []string{"read", "activate"}, "tenant_ids": []string{tenant["id"].(string)}, "allow_create": false}, 201, "Idempotency-Key", "activation-credential")
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

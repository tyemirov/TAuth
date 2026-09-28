package main

import (
	"testing"

	"github.com/tyemirov/tauth/internal/controlplane"
)

func TestConsoleTenantCreationRequiresCompleteInput(t *testing.T) {
	withManagementService(t, consoleGoogleValidator{}, func(owner consoleHTTP) {
		valid := map[string]any{"name": "Complete application", "application_origin": "http://localhost:9231", "google_web_client_id": "creation-client.apps.googleusercontent.com"}
		for _, field := range []string{"name", "application_origin", "google_web_client_id"} {
			for _, absent := range []bool{true, false} {
				body := map[string]any{}
				for key, value := range valid {
					body[key] = value
				}
				if absent {
					delete(body, field)
				} else {
					body[field] = "   "
				}
				owner.request("POST", controlplane.TenantsPath, body, 422, "Idempotency-Key", field)
				collection, _ := owner.request("GET", controlplane.TenantsPath, nil, 200)
				if len(collection["items"].([]any)) != 0 {
					t.Fatal("invalid input created a tenant")
				}
			}
		}
		for _, invalid := range []struct{ field, value string }{
			{"application_origin", "https://example.com/path"},
			{"application_origin", "http://example.com"},
			{"application_origin", "https://user@example.com"},
			{"google_web_client_id", "wrong-client"},
		} {
			body := map[string]any{}
			for key, value := range valid {
				body[key] = value
			}
			body[invalid.field] = invalid.value
			owner.request("POST", controlplane.TenantsPath, body, 422, "Idempotency-Key", "invalid-"+invalid.value)
		}
		collection, _ := owner.request("GET", controlplane.TenantsPath, nil, 200)
		if len(collection["items"].([]any)) != 0 {
			t.Fatal("malformed input created a tenant")
		}
		tenant, headers := owner.request("POST", controlplane.TenantsPath, valid, 201, "Idempotency-Key", "complete")
		if tenant["state"] != "active" || tenant["active_revision"] != float64(1) {
			t.Fatal("complete tenant was not activated")
		}
		repeat, _ := owner.request("POST", controlplane.TenantsPath, valid, 201, "Idempotency-Key", "complete")
		if repeat["id"] != tenant["id"] {
			t.Fatal("retry created another tenant")
		}
		configuration, _ := owner.request("GET", headers.Get("Location")+"/configuration", nil, 200)
		if configuration["google_web_client_id"] != valid["google_web_client_id"] {
			t.Fatal("client ID changed")
		}
		app := owner
		app.origin = valid["application_origin"].(string)
		app.tenant = tenant["id"].(string)
		app.login("new-application-user", valid["google_web_client_id"].(string))
		production := map[string]any{"name": "Production application", "application_origin": "https://creation.example.com", "google_web_client_id": "production-creation.apps.googleusercontent.com"}
		active, _ := owner.request("POST", controlplane.TenantsPath, production, 201, "Idempotency-Key", "production-complete")
		if active["state"] != "active" {
			t.Fatal("production creation required an extra activation step")
		}
		owner.request("POST", controlplane.TenantsPath, production, 409, "Idempotency-Key", "conflicting-origin")
		collection, _ = owner.request("GET", controlplane.TenantsPath, nil, 200)
		if len(collection["items"].([]any)) != 2 {
			t.Fatal("failed activation left a partial tenant")
		}

	})
}

func consoleTenantInput(name string) map[string]any {
	return map[string]any{"name": name, "application_origin": "http://localhost:19091", "google_web_client_id": "fixture-client.apps.googleusercontent.com"}
}

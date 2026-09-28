package main

import (
	"github.com/tyemirov/tauth/internal/controlplane"
	"testing"
)

func TestConsoleAppHierarchy(t *testing.T) {
	withManagementService(t, consoleGoogleValidator{}, func(owner consoleHTTP) {
		app, headers := owner.request("POST", "/api/management/apps", map[string]any{"name": "Kamu"}, 201, "Idempotency-Key", "kamu-app")
		repeated, _ := owner.request("POST", "/api/management/apps", map[string]any{"name": "Kamu"}, 201, "Idempotency-Key", "kamu-app")
		if repeated["id"] != app["id"] {
			t.Fatal("App retry changed identity")
		}
		body := consoleTenantInput("Local")
		owner.request("POST", controlplane.TenantsPath, body, 422, "Idempotency-Key", "missing-app")
		body["app_id"] = app["id"]
		tenant, _ := owner.request("POST", controlplane.TenantsPath, body, 201, "Idempotency-Key", "app-local")
		if tenant["app_id"] != app["id"] || tenant["state"] != "active" {
			t.Fatal("tenant membership or activation missing")
		}
		second, _ := owner.request("POST", "/api/management/apps", map[string]any{"name": "Other"}, 201, "Idempotency-Key", "other-app")
		page, _ := owner.request("GET", controlplane.TenantsPath+"?app_id="+second["id"].(string), nil, 200)
		if len(page["items"].([]any)) != 0 {
			t.Fatal("tenants crossed Apps")
		}
		page, _ = owner.request("GET", controlplane.TenantsPath+"?app_id="+app["id"].(string), nil, 200)
		if len(page["items"].([]any)) != 1 {
			t.Fatal("App tenant missing")
		}
		owner.request("PATCH", headers.Get("Location"), map[string]any{"name": "Kamu Tales"}, 200, "If-Match", headers.Get("ETag"))
		owner.request("PATCH", headers.Get("Location"), map[string]any{"name": "Stale"}, 412, "If-Match", headers.Get("ETag"))
		owner.login("other-owner", "console-client")
		owner.request("PUT", controlplane.OwnerPath, nil, 201)
		owner.request("GET", headers.Get("Location"), nil, 404)
		owner.request("GET", controlplane.TenantsPath+"?app_id="+app["id"].(string), nil, 404)
		owner.request("POST", controlplane.TenantsPath, body, 404, "Idempotency-Key", "foreign-app")
		owner.request("GET", controlplane.TenantsPath+"/"+tenant["id"].(string), nil, 404)
	})
}

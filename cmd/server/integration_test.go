package main

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestConsoleIntegrationAndKeyExport(t *testing.T) {
	var advance atomic.Int64
	originalClock := managementNow
	managementNow = func() time.Time { return time.Now().Add(time.Duration(advance.Load())) }
	defer func() { managementNow = originalClock }()

	withManagementService(t, consoleGoogleValidator{}, func(owner consoleHTTP) {
		_, headers := owner.request("POST", "/api/management/tenants", owner.tenantInput("Integrated application"), 201, "Idempotency-Key", "integration-tenant")
		path := headers.Get("Location")
		owner.request("GET", path+"/integration", nil, 409)
		_, headers = owner.request("GET", path+"/configuration", nil, 200)
		saved, headers := owner.request("PUT", path+"/configuration", map[string]any{"google_web_client_id": "customer-google", "frontend_origins": []string{"http://localhost:9591"}, "api_base_url": "http://localhost:9592", "local_development": true, "session_ttl": "1m", "refresh_ttl": "1h"}, 200, "If-Match", headers.Get("ETag"))
		owner.request("POST", path+"/activations", map[string]any{"revision": saved["revision"]}, 201, "If-Match", headers.Get("ETag"), "Idempotency-Key", "integration-active")
		public, activeHeaders := owner.request("GET", path+"/integration", nil, 200)
		if public["revision"] != saved["revision"] || public["api_base_url"] != "http://localhost:9592" {
			t.Fatalf("incorrect integration: %v", public)
		}
		challenge, challengeHeaders := owner.request("POST", path+"/reauthentications", map[string]any{"revision": saved["revision"], "operation": "session-key-export"}, 201, "If-Match", activeHeaders.Get("ETag"), "Idempotency-Key", "export-challenge")
		owner.request("GET", challengeHeaders.Get("Location"), nil, 200)
		claims := map[string]any{"aud": "console-client", "iss": "https://accounts.google.com", "sub": "owner", "email": "owner@example.com", "email_verified": true, "nonce": challenge["nonce"], "iat": time.Now().Add(-6 * time.Minute).Unix()}
		makeBody := func() map[string]any {
			token, _ := json.Marshal(claims)
			return map[string]any{"reauthentication_id": challenge["id"], "google_id_token": string(token)}
		}
		owner.request("POST", path+"/key-exports", makeBody(), 403, "If-Match", activeHeaders.Get("ETag"), "Idempotency-Key", "stale-export")
		claims["iat"] = time.Now().Unix()
		claims["sub"] = "different-owner"
		owner.request("POST", path+"/key-exports", makeBody(), 403, "If-Match", activeHeaders.Get("ETag"), "Idempotency-Key", "substituted-export")
		claims["sub"] = "owner"
		claims["nonce"] = "wrong-transaction"
		owner.request("POST", path+"/key-exports", makeBody(), 403, "If-Match", activeHeaders.Get("ETag"), "Idempotency-Key", "wrong-nonce")
		claims["nonce"] = challenge["nonce"]
		// A challenge cannot cross tenants, owner sessions, or credential types.
		_, otherHeaders := owner.request("POST", "/api/management/tenants", owner.tenantInput("Other integration"), 201, "Idempotency-Key", "other-integration")
		otherPath := otherHeaders.Get("Location")
		_, otherHeaders = owner.request("GET", otherPath+"/configuration", nil, 200)
		otherSaved, otherHeaders := owner.request("PUT", otherPath+"/configuration", map[string]any{"google_web_client_id": "other-google", "frontend_origins": []string{"http://localhost:9593"}, "api_base_url": "http://localhost:9594", "local_development": true, "session_ttl": "1m", "refresh_ttl": "1h"}, 200, "If-Match", otherHeaders.Get("ETag"))
		owner.request("POST", otherPath+"/activations", map[string]any{"revision": otherSaved["revision"]}, 201, "If-Match", otherHeaders.Get("ETag"), "Idempotency-Key", "other-active")
		owner.request("POST", otherPath+"/key-exports", makeBody(), 403, "If-Match", otherHeaders.Get("ETag"), "Idempotency-Key", "cross-tenant")
		outsider := owner
		outsider.client = &http.Client{Transport: owner.client.Transport}
		outsider.client.Jar, _ = cookiejar.New(nil)
		outsider.login("outsider", "console-client")
		outsider.request("PUT", "/api/management/owner-account", nil, 201)
		outsider.request("POST", path+"/key-exports", makeBody(), 404, "If-Match", activeHeaders.Get("ETag"), "Idempotency-Key", "cross-owner")
		credential, _ := owner.request("POST", "/api/management/provisioning-credentials", map[string]any{"app_id": owner.fixtureApp(), "name": "No secret export", "operations": []string{"read", "configure", "activate"}, "tenant_ids": []string{strings.TrimPrefix(path, "/api/management/tenants/")}, "allow_create": false}, 201, "Idempotency-Key", "export-denied")
		bearer := owner
		bearer.client = &http.Client{Transport: owner.client.Transport}
		bearer.origin = ""
		bearer.request("POST", path+"/key-exports", makeBody(), 403, "Authorization", "Bearer "+credential["token"].(string), "If-Match", activeHeaders.Get("ETag"), "Idempotency-Key", "bearer-export")
		exported, exportHeaders := owner.request("POST", path+"/key-exports", makeBody(), 201, "If-Match", activeHeaders.Get("ETag"), "Idempotency-Key", "fresh-export")
		key, ok := exported["session_key_base64"].(string)
		if !ok || len(key) < 32 || exportHeaders.Get("Cache-Control") != "no-store" {
			t.Fatal("export contract missing")
		}
		receipt, _ := owner.request("GET", exportHeaders.Get("Location"), nil, 200)
		retry, _ := owner.request("POST", path+"/key-exports", makeBody(), 201, "If-Match", activeHeaders.Get("ETag"), "Idempotency-Key", "fresh-export")
		owner.request("POST", path+"/key-exports", makeBody(), 409, "If-Match", activeHeaders.Get("ETag"), "Idempotency-Key", "replayed-export")
		staleChallenge, _ := owner.request("POST", path+"/reauthentications", map[string]any{"revision": saved["revision"], "operation": "session-key-export"}, 201, "If-Match", activeHeaders.Get("ETag"), "Idempotency-Key", "revision-challenge")
		next, nextHeaders := owner.request("PUT", path+"/configuration", map[string]any{"google_web_client_id": "customer-google", "frontend_origins": []string{"http://localhost:9591"}, "api_base_url": "http://localhost:9592", "local_development": true, "session_ttl": "2m", "refresh_ttl": "1h"}, 200, "If-Match", activeHeaders.Get("ETag"))
		stillActive, _ := owner.request("GET", path+"/integration", nil, 200)
		if stillActive["revision"] != next["revision"] {
			t.Fatal("public integration did not use the saved configuration")
		}
		owner.request("POST", path+"/activations", map[string]any{"revision": next["revision"]}, 201, "If-Match", nextHeaders.Get("ETag"), "Idempotency-Key", "next-active")
		challenge = staleChallenge
		claims["nonce"] = challenge["nonce"]
		owner.request("POST", path+"/key-exports", makeBody(), 412, "If-Match", activeHeaders.Get("ETag"), "Idempotency-Key", "old-etag")
		owner.request("POST", path+"/key-exports", makeBody(), 403, "If-Match", nextHeaders.Get("ETag"), "Idempotency-Key", "old-revision")
		expiring, _ := owner.request("POST", path+"/reauthentications", map[string]any{"revision": next["revision"], "operation": "session-key-export"}, 201, "If-Match", nextHeaders.Get("ETag"), "Idempotency-Key", "expiring")
		challenge = expiring
		claims["nonce"] = challenge["nonce"]
		advance.Store(int64(6 * time.Minute))
		claims["iat"] = time.Now().Add(6 * time.Minute).Unix()
		owner.request("POST", path+"/key-exports", makeBody(), 403, "If-Match", nextHeaders.Get("ETag"), "Idempotency-Key", "expired-transaction")
		audit, _ := owner.request("GET", path+"/audit-events", nil, 200)
		for _, value := range []any{public, receipt, retry, audit} {
			encoded, _ := json.Marshal(value)
			if strings.Contains(string(encoded), key) {
				t.Fatal("secret escaped export response")
			}
		}
	})
}

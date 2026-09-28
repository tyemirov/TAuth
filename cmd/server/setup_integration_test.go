package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tyemirov/tauth/internal/controlplane"
)

type setupResolver struct{ addresses atomic.Value }

func (r *setupResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return r.addresses.Load().([]net.IPAddr), nil
}

func TestConsoleSetupDestinationRestrictions(t *testing.T) {
	var mode atomic.Value
	mode.Store("redirect")
	var calls atomic.Int64
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Access-Control-Allow-Origin", "https://customer.example")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		switch mode.Load().(string) {
		case "redirect":
			w.Header().Set("Location", "http://127.0.0.1/private")
			w.WriteHeader(302)
		case "large":
			_, _ = w.Write([]byte(strings.Repeat("x", 16385)))
		case "invalid":
			_, _ = w.Write([]byte(`{"nonce":"not-issued-by-this-tenant"}`))
		}
	}))
	defer remote.Close()
	resolver := &setupResolver{}
	resolver.addresses.Store([]net.IPAddr{{IP: net.ParseIP("127.0.0.1")}})
	originalNetwork := managementSetupNetwork
	managementSetupNetwork = func() controlplane.SetupNetwork {
		address, _ := url.Parse(remote.URL)
		tlsConfig := remote.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
		tlsConfig.ServerName = "example.com"
		return controlplane.SetupNetwork{Resolver: resolver, Dialer: browserSetupDialer{address: address.Host}, TLS: tlsConfig}
	}
	defer func() { managementSetupNetwork = originalNetwork }()
	values := map[string]string{}
	originalDNS := lookupManagementTXT
	lookupManagementTXT = func(_ context.Context, name string) ([]string, error) { return []string{values[name]}, nil }
	defer func() { lookupManagementTXT = originalDNS }()
	withManagementService(t, consoleGoogleValidator{}, func(owner consoleHTTP) {
		_, headers := owner.request("POST", controlplane.TenantsPath, owner.tenantInput("Setup destination"), 201, "Idempotency-Key", "setup-destination")
		path := headers.Get("Location")
		_, headers = owner.request("GET", path+"/configuration", nil, 200)
		config, headers := owner.request("PUT", path+"/configuration", map[string]any{"google_web_client_id": "customer-google", "frontend_origins": []string{"https://customer.example"}, "api_base_url": "https://api.customer.example", "local_development": false, "session_ttl": "15m", "refresh_ttl": "720h"}, 200, "If-Match", headers.Get("ETag"))
		revision := config["revision"]
		etag := headers.Get("ETag")
		owner.request("POST", path+"/setup-checks", map[string]any{"revision": revision}, 201, "If-Match", etag, "Idempotency-Key", "active-on-save")
		for _, host := range []string{"customer.example", "api.customer.example"} {
			proof, _ := owner.request("POST", path+"/origin-proofs", map[string]any{"hostname": host, "revision": revision}, 201, "Idempotency-Key", host)
			values[proof["name"].(string)] = proof["value"].(string)
			owner.request("POST", path+"/origin-proofs/"+proof["id"].(string)+"/verifications", map[string]any{}, 201, "Idempotency-Key", "verify")
		}
		owner.request("POST", path+"/activations", map[string]any{"revision": revision}, 201, "If-Match", etag, "Idempotency-Key", "activate")
		for i, address := range []string{"127.0.0.1", "10.0.0.2", "169.254.169.254", "100.64.0.1", "::1", "fc00::1", "fe80::1", "fec0::1", "2001:db8::1", "64:ff9b::7f00:1"} {
			resolver.addresses.Store([]net.IPAddr{{IP: net.ParseIP(address)}})
			result, h := owner.request("POST", path+"/setup-checks", map[string]any{"revision": revision}, 201, "If-Match", etag, "Idempotency-Key", fmt.Sprintf("private-%d", i))
			if result["state"] != "failed" || result["evidence"].([]any)[0].(map[string]any)["code"] != "destination_denied" {
				t.Fatalf("destination restriction failed for %s: %v", address, result)
			}
			owner.request("GET", h.Get("Location"), nil, 200)
		}
		if calls.Load() != 0 {
			t.Fatal("private destination reached network")
		}
		resolver.addresses.Store([]net.IPAddr{{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP("127.0.0.1")}})
		owner.request("POST", path+"/setup-checks", map[string]any{"revision": revision}, 201, "If-Match", etag, "Idempotency-Key", "mixed-dns")
		if calls.Load() != 0 {
			t.Fatal("mixed DNS reached network")
		}
		resolver.addresses.Store([]net.IPAddr{{IP: net.ParseIP("8.8.8.8")}})
		for _, scenario := range []struct{ mode, code string }{{"redirect", "status_mismatch"}, {"large", "response_invalid"}, {"invalid", "tenant_binding_invalid"}} {
			mode.Store(scenario.mode)
			before := calls.Load()
			result, _ := owner.request("POST", path+"/setup-checks", map[string]any{"revision": revision}, 201, "If-Match", etag, "Idempotency-Key", scenario.mode)
			if result["state"] != "failed" || result["evidence"].([]any)[0].(map[string]any)["code"] != scenario.code {
				t.Fatalf("wrong bounded probe result: %v", result)
			}
			owner.request("POST", path+"/setup-checks", map[string]any{"revision": revision}, 201, "If-Match", etag, "Idempotency-Key", scenario.mode)
			if calls.Load() != before+1 {
				t.Fatal("probe followed redirect or repeated receipt")
			}
		}
		owner.request("POST", path+"/setup-checks", map[string]any{"revision": revision, "url": "https://attacker.example"}, 400, "If-Match", etag, "Idempotency-Key", "url-input")
		owner.request("POST", path+"/setup-checks", map[string]any{"revision": revision}, 412, "If-Match", `"configuration-999"`, "Idempotency-Key", "stale")
		owner.request("GET", path+"/setup-checks", nil, 200)
	})
}

package oauthserver

import (
	"fmt"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

func TestClientMetadataDocumentContract(t *testing.T) {
	clientID := "https://client.example/oauth/metadata.json"
	payload := []byte(`{
  "client_id":"https://client.example/oauth/metadata.json",
  "client_name":"MCP Client",
  "application_type":"native",
  "redirect_uris":["http://127.0.0.1:49152/callback"],
  "grant_types":["refresh_token","authorization_code"],
  "response_types":["code"],
  "token_endpoint_auth_method":"none"
}`)
	client, parseErr := parseClientMetadataDocument(clientID, payload)
	if parseErr != nil {
		t.Fatalf("parse metadata: %v", parseErr)
	}
	if client.ID != clientID || client.DisplayName != "MCP Client" || client.Source != clientSourceMetadata || !redirectMatches(client, "http://127.0.0.1:49152/callback") {
		t.Fatalf("unexpected metadata client: %#v", client)
	}

	invalidDocuments := [][]byte{
		[]byte(`{"client_id":"https://other.example/metadata","client_name":"Client","redirect_uris":["https://client.example/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none"}`),
		[]byte(`{"client_id":"https://client.example/oauth/metadata.json","client_name":"Client","redirect_uris":["http://private.example/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none"}`),
		[]byte(`{"client_id":"https://client.example/oauth/metadata.json","client_name":"Client","redirect_uris":["https://client.example/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"client_secret_basic"}`),
		[]byte(`{"client_id":"https://client.example/oauth/metadata.json","client_name":"Client","redirect_uris":["https://client.example/callback"],"grant_types":["refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}`),
		[]byte(`{"client_id":"https://client.example/oauth/metadata.json","client_name":"Client","redirect_uris":["https://client.example/callback"],"grant_types":["authorization_code","authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none"}`),
	}
	for index, invalidDocument := range invalidDocuments {
		if _, invalidErr := parseClientMetadataDocument(clientID, invalidDocument); invalidErr == nil {
			t.Fatalf("expected document %d to be rejected", index)
		}
	}
}

func TestClientMetadataNetworkAndCacheBoundaries(t *testing.T) {
	invalidClientIDs := []string{
		"http://client.example/metadata", "https://client.example/", "https://127.0.0.1/metadata",
		"https://client.example/a/../metadata", "https://client.example/metadata?version=1",
	}
	for _, clientID := range invalidClientIDs {
		if _, validationErr := validateClientIdentifierURL(clientID); validationErr == nil {
			t.Fatalf("expected invalid client id %s", clientID)
		}
	}
	for _, address := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.1", "192.0.2.1", "::1", "64:ff9b::7f00:1", "2001:db8::1", "2002:7f00:1::"} {
		if !specialUseAddress(netip.MustParseAddr(address)) {
			t.Fatalf("expected special-use address %s", address)
		}
	}
	if specialUseAddress(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("expected public address to be accepted")
	}

	appConfig, _ := loadOAuthTestConfig(t, "http://127.0.0.1:9998")
	policy := appConfig.OAuthServer().ClientMetadata()
	now := time.Date(2026, time.August, 8, 0, 0, 0, 0, time.UTC)
	headers := http.Header{"Cache-Control": {"public, max-age=7200"}}
	if ttl, cacheable := metadataCacheTTL(headers, now, policy); !cacheable || ttl != time.Hour {
		t.Fatalf("expected bounded cache ttl, got %s cacheable=%v", ttl, cacheable)
	}
	headers.Set("Cache-Control", "max-age=7200, no-store")
	if _, cacheable := metadataCacheTTL(headers, now, policy); cacheable {
		t.Fatal("expected no-store response not to be cached")
	}

	resolver := NewClientMetadataResolver(policy)
	for index := 0; index < maximumClientMetadataCacheEntries; index++ {
		clientID := fmt.Sprintf("https://client-%03d.example/metadata", index)
		resolver.cacheClient(clientID, Client{ID: clientID}, now, time.Duration(index+1)*time.Minute)
	}
	resolver.cacheClient("https://new-client.example/metadata", Client{ID: "https://new-client.example/metadata"}, now, time.Hour)
	if len(resolver.cache) != maximumClientMetadataCacheEntries {
		t.Fatalf("metadata cache exceeded its bound: %d", len(resolver.cache))
	}
	if _, exists := resolver.cache["https://client-000.example/metadata"]; exists {
		t.Fatal("metadata cache did not evict the earliest expiry")
	}
}

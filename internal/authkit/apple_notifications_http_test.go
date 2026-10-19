package authkit

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func TestAppleNotificationsDisabledHTTP(t *testing.T) {
	for _, scenario := range []string{"empty", "nil store", "nil cipher", "Apple disabled"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := newErasureHTTPFixture(t)
			var requests atomic.Int64
			provider := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
			defer provider.Close()
			fixture.config.AppleOAuth = AppleOAuthConfig{Enabled: true, ClientID: "com.example.web", JWKSURL: provider.URL}
			var credentials PasswordCredentialStore = fixture.accounts
			switch scenario {
			case "nil store":
				credentials = nil
			case "nil cipher":
				fixture.accounts.SetProviderGrantCipher(nil)
			case "Apple disabled":
				fixture.config.AppleOAuth.Enabled = false
				fixture.config.AppleOAuth.NotificationAudience = "com.example.primary"
			}
			router := gin.New()
			MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(fixture.config), fixture.accounts, fixture.refresh, nil, credentials, newTestPasswordResetDispatcher(t), nil, nil)
			fixture.server.Config.Handler = router
			for _, body := range []string{`{"payload":"untrusted"}`, `{`, `{}`} {
				response, err := fixture.client.Post(fixture.server.URL+AppleNotificationPath, "application/json", strings.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if response.StatusCode != http.StatusNotFound {
					t.Fatalf("disabled notification status=%d want=404", response.StatusCode)
				}
			}
			var receipts int64
			if err := fixture.accounts.db.Model(&databaseAppleEventReceipt{}).Count(&receipts).Error; err != nil {
				t.Fatal(err)
			}
			if receipts != 0 || requests.Load() != 0 {
				t.Fatalf("disabled effects: receipts=%d provider_requests=%d", receipts, requests.Load())
			}
		})
	}
}

func TestAppleNotificationsMixedOptInHTTP(t *testing.T) {
	fixture := newErasureHTTPFixture(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	provider := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		_ = json.NewEncoder(response).Encode(mockAppleJWKS(key, "mixed-key"))
	}))
	defer provider.Close()
	ProvideAppleOAuthHTTPClient(provider.Client())
	defer ProvideAppleOAuthHTTPClient(nil)
	enabled := fixture.config
	enabled.AppleOAuth = AppleOAuthConfig{Enabled: true, ClientID: "com.example.web", NotificationAudience: "com.example.primary", JWKSURL: provider.URL}
	disabled := fixture.config
	disabled.TenantID = "disabled"
	disabled.AppleOAuth = AppleOAuthConfig{Enabled: true, ClientID: "com.example.disabled", JWKSURL: provider.URL}
	cipher := fixture.accounts.providerGrantCipher
	for _, scenario := range []string{"store", "nil store", "nil cipher", "duplicate audience"} {
		t.Run(scenario, func(t *testing.T) {
			fixture.accounts.SetProviderGrantCipher(cipher)
			configs := map[string]ServerConfig{enabled.TenantID: enabled, disabled.TenantID: disabled}
			inactive := disabled
			inactive.TenantID = "inactive"
			inactive.AppleOAuth.Enabled = false
			inactive.AppleOAuth.NotificationAudience = "com.example.inactive"
			configs[inactive.TenantID] = inactive
			if scenario == "duplicate audience" {
				duplicate := enabled
				duplicate.TenantID = "duplicate"
				configs[duplicate.TenantID] = duplicate
			}
			var credentials PasswordCredentialStore = fixture.accounts
			if scenario == "nil store" {
				credentials = nil
			}
			if scenario == "nil cipher" {
				fixture.accounts.SetProviderGrantCipher(nil)
			}
			router := gin.New()
			MountAuthRoutesWithPassword(router, NewTenantRegistryFromMap(enabled.TenantID, configs), fixture.accounts, fixture.refresh, nil, credentials, newTestPasswordResetDispatcher(t), nil, nil)
			fixture.server.Config.Handler = router
			for _, audience := range []string{disabled.AppleOAuth.ClientID, enabled.AppleOAuth.ClientID, "com.example.unknown", inactive.AppleOAuth.NotificationAudience, enabled.AppleOAuth.NotificationAudience} {
				claims := jwt.MapClaims{"iss": appleIssuer, "aud": audience, "iat": time.Now().Unix(), "jti": scenario + audience, "events": map[string]any{"type": "email-disabled", "sub": "mixed-subject", "event_time": time.Now().Unix()}}
				token := mintMockAppleIDTokenWithClaims(t, key, "mixed-key", claims)
				body, _ := json.Marshal(map[string]string{"payload": token})
				before := requests.Load()
				var receiptsBefore int64
				if err := fixture.accounts.db.Model(&databaseAppleEventReceipt{}).Count(&receiptsBefore).Error; err != nil {
					t.Fatal(err)
				}
				response, err := fixture.client.Post(fixture.server.URL+AppleNotificationPath, "application/json", bytes.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				expected := http.StatusUnauthorized
				if audience == enabled.AppleOAuth.NotificationAudience && scenario != "duplicate audience" {
					expected = http.StatusNoContent
					if scenario == "nil store" || scenario == "nil cipher" {
						expected = http.StatusServiceUnavailable
					}
				}
				if response.StatusCode != expected {
					t.Fatalf("audience=%s status=%d want=%d", audience, response.StatusCode, expected)
				}
				var receiptsAfter int64
				if err := fixture.accounts.db.Model(&databaseAppleEventReceipt{}).Count(&receiptsAfter).Error; err != nil {
					t.Fatal(err)
				}
				if expected != http.StatusNoContent && (requests.Load() != before || receiptsBefore != receiptsAfter) {
					t.Fatalf("rejected event had effects: requests=%d receipts=%d", requests.Load()-before, receiptsAfter-receiptsBefore)
				}
				if expected == http.StatusNoContent && (requests.Load() != before+1 || receiptsAfter != receiptsBefore+1) {
					t.Fatal("enabled event was not processed")
				}
			}
		})
	}
}

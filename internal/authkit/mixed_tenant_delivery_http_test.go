package authkit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/tenants"
)

type tenantSelectiveEmailSender struct {
	requests chan EmailChallengeRequest
}

func (sender *tenantSelectiveEmailSender) SendEmailChallenge(_ context.Context, request EmailChallengeRequest) error {
	sender.requests <- request
	if request.TenantID == "token-only" {
		return errors.New("notification.pinguin.tenant_not_configured")
	}
	return nil
}

func TestHTTPMixedTenantChallengeDelivery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	modes := []struct {
		id           string
		deliverEmail bool
		returnTokens bool
	}{
		{id: "email-only", deliverEmail: true},
		{id: "token-only", returnTokens: true},
		{id: "email-and-token", deliverEmail: true, returnTokens: true},
	}
	var document strings.Builder
	document.WriteString("tenants:\n")
	for _, mode := range modes {
		fmt.Fprintf(&document, `  - id: %[1]s
    display_name: %[1]s
    tenant_origins: ["https://%[1]s.example.com"]
    google_web_client_id: client-%[1]s
    jwt_signing_key: test-signing-key-for-%[1]s
    session_cookie_name: session_%[1]s
    refresh_cookie_name: refresh_%[1]s
    session_ttl: 15m
    refresh_ttl: 1440h
    nonce_ttl: 5m
    allow_insecure_http: true
    password_auth:
      enabled: true
    account_management:
      enabled: true
      password_signup:
        enabled: true
      return_challenge_tokens: %[2]t
`, mode.id, mode.returnTokens)
		if mode.deliverEmail {
			document.WriteString(`      email_delivery:
        server_address: pinguin:50051
        api_key: fixture-key
        email_verification_url: https://ui.example.com/verify-email
        password_reset_url: https://ui.example.com/reset-password
        password_link_url: https://ui.example.com/link-password
        connection_timeout_seconds: 1
        operation_timeout_seconds: 1
`)
		}
	}
	tenantConfig := mustLoadTenantsConfigFromString(t, document.String())
	registry, registryErr := BuildTenantRegistry(newTestServerConfig(), tenantConfig, NewSameSiteResolver(false))
	if registryErr != nil {
		t.Fatalf("build mixed tenant registry: %v", registryErr)
	}
	resolver, resolverErr := tenants.NewResolver(tenantConfig, tenants.WithHeaderOverride(""))
	if resolverErr != nil {
		t.Fatalf("build tenant resolver: %v", resolverErr)
	}
	flows := []struct {
		name         string
		startPath    string
		completePath string
		tokenField   string
		kind         EmailChallengeKind
	}{
		{"signup", "/auth/password/signup", "/auth/password/verify-email", "verification_token", EmailChallengeKindVerification},
		{"reset", "/auth/password/reset/start", "/auth/password/reset/complete", "reset_token", EmailChallengeKindPasswordReset},
		{"link", "/auth/account/password/link/start", "/auth/account/password/link/verify", "verification_token", EmailChallengeKindPasswordLink},
	}
	for _, mode := range modes {
		for _, flow := range flows {
			t.Run(mode.id+"/"+flow.name, func(t *testing.T) {
				accountStore := NewMemoryPasswordCredentialStore()
				sender := &tenantSelectiveEmailSender{requests: make(chan EmailChallengeRequest, 1)}
				router := gin.New()
				router.Use(tenants.TenantMiddleware(resolver, http.StatusNotFound))
				MountAuthRoutesWithPassword(router, registry, newTestUserStore(), NewMemoryRefreshTokenStore(), nil, accountStore, sender)
				server := httptest.NewServer(router)
				defer server.Close()
				client := server.Client()

				post := func(path string, payload map[string]string, cookies []*http.Cookie, expectedStatus int) (map[string]any, []*http.Cookie) {
					t.Helper()
					body, marshalErr := json.Marshal(payload)
					if marshalErr != nil {
						t.Fatalf("encode %s request: %v", path, marshalErr)
					}
					request, requestErr := http.NewRequest(http.MethodPost, server.URL+path, bytes.NewReader(body))
					if requestErr != nil {
						t.Fatalf("build %s request: %v", path, requestErr)
					}
					request.Header.Set("Content-Type", "application/json")
					request.Header.Set("X-TAuth-Tenant", mode.id)
					for _, cookie := range cookies {
						request.AddCookie(cookie)
					}
					response, responseErr := client.Do(request)
					if responseErr != nil {
						t.Fatalf("send %s request: %v", path, responseErr)
					}
					defer response.Body.Close()
					var result map[string]any
					if decodeErr := json.NewDecoder(response.Body).Decode(&result); decodeErr != nil {
						t.Fatalf("decode %s response (status %d): %v", path, response.StatusCode, decodeErr)
					}
					if response.StatusCode != expectedStatus {
						t.Fatalf("%s: expected status %d, got %d: %#v", path, expectedStatus, response.StatusCode, result)
					}
					return result, response.Cookies()
				}

				const password = "correct horse battery staple"
				const existingEmail = "existing@example.com"
				var cookies []*http.Cookie
				if flow.name != "signup" {
					seed, seedErr := accountStore.CreatePasswordSignup(context.Background(), mode.id, AccountPasswordRequest{
						UserEmail: existingEmail,
						Password:  password,
					}, time.Now().Add(time.Hour).Unix())
					if seedErr != nil {
						t.Fatalf("seed account: %v", seedErr)
					}
					_, cookies = post("/auth/password/verify-email", map[string]string{"token": seed.Token}, nil, http.StatusOK)
				}
				email := "new@example.com"
				if flow.name == "reset" {
					email = existingEmail
				}
				payload, _ := post(flow.startPath, map[string]string{"email": email, "password": password}, cookies, http.StatusAccepted)
				var deliveryToken string
				if mode.deliverEmail {
					select {
					case delivery := <-sender.requests:
						if delivery.TenantID != mode.id || delivery.Recipient != email {
							t.Fatalf("unexpected delivery tenant or recipient: %#v", delivery)
						}
						deliveryToken = challengeTokenFromDeliveryURL(t, delivery, flow.kind)
					default:
						t.Fatal("expected a challenge email")
					}
				}
				select {
				case delivery := <-sender.requests:
					t.Fatalf("unexpected email attempt for tenant %s", delivery.TenantID)
				default:
				}
				token := deliveryToken
				if mode.returnTokens {
					returned, ok := payload[flow.tokenField].(string)
					if !ok || returned == "" {
						t.Fatalf("expected %s in response", flow.tokenField)
					}
					if mode.deliverEmail && returned != deliveryToken {
						t.Fatal("response and email contain different challenge tokens")
					}
					token = returned
				} else if _, present := payload[flow.tokenField]; present {
					t.Fatalf("response exposed %s", flow.tokenField)
				}
				post(flow.completePath, map[string]string{"token": token, "password": "replacement correct horse battery staple"}, cookies, http.StatusOK)
			})
		}
	}
}

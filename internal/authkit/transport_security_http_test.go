package authkit

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/transportsecurity"
)

func TestCredentialRoutesRejectForgedTransport(t *testing.T) {
	gin.SetMode(gin.TestMode)
	config := newTestServerConfig()
	config.AllowInsecureHTTP = false
	router := gin.New()
	MountAuthRoutes(router, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), nil, NewMemoryPasswordCredentialStore(), newTestPasswordResetDispatcher(t))
	server := httptest.NewServer(router)
	defer server.Close()
	for _, route := range router.Routes() {
		if strings.HasSuffix(route.Path, "/native/config") {
			continue
		}
		t.Run(route.Method+route.Path, func(t *testing.T) {
			for _, signal := range []string{"plain", "xfp", "forwarded", "host"} {
				request, err := http.NewRequest(route.Method, server.URL+strings.ReplaceAll(route.Path, ":identity_id", "identity"), strings.NewReader(`{}`))
				if err != nil {
					t.Fatal(err)
				}
				switch signal {
				case "xfp":
					request.Header.Set("X-Forwarded-Proto", "https")
				case "forwarded":
					request.Header.Set("Forwarded", "proto=https")
				case "host":
					request.Host = "localhost:8080"
				}
				response, err := server.Client().Do(request)
				if err != nil {
					t.Fatal(err)
				}
				body, readErr := io.ReadAll(response.Body)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if !strings.Contains(string(body), `"error":"https_required"`) {
					t.Errorf("%s: expected transport error, got %s", signal, body)
				}
				response.Body.Close()
				if response.StatusCode != http.StatusBadRequest {
					t.Errorf("%s: got %d, want 400", signal, response.StatusCode)
				}
				if len(response.Cookies()) != 0 {
					t.Errorf("%s: rejection set cookies", signal)
				}
			}
		})
	}
}

func TestPasswordResetTransportPreservesChallenge(t *testing.T) {
	config := newTestServerConfig()
	config.AllowInsecureHTTP = false
	config.AccountManagementEnabled = true
	config.PasswordAuthEnabled = true
	accounts := NewMemoryPasswordCredentialStore()
	signup, err := accounts.CreatePasswordSignup(context.Background(), config.TenantID, AccountPasswordRequest{UserEmail: "transport@example.com", Password: "correct horse battery staple"}, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := accounts.VerifyEmailChallenge(context.Background(), config.TenantID, signup.Token); err != nil {
		t.Fatal(err)
	}
	challenge, err := accounts.StartPasswordReset(context.Background(), config.TenantID, "transport@example.com", time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := newTestPasswordResetDispatcher(t)
	router := gin.New()
	MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), nil, accounts, dispatcher, nil, nil)
	plain := httptest.NewServer(router)
	defer plain.Close()
	secure := httptest.NewTLSServer(router)
	defer secure.Close()
	payload := `{"token":"` + challenge.Token + `","password":"replacement correct horse battery staple"}`
	response, err := plain.Client().Post(plain.URL+"/auth/password/reset/complete", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("plaintext reset status %d", response.StatusCode)
	}
	if _, err := accounts.AuthenticatePassword(context.Background(), config.TenantID, "transport@example.com", "correct horse battery staple"); err != nil {
		t.Fatalf("plaintext reset changed password: %v", err)
	}
	response, err = secure.Client().Post(secure.URL+"/auth/password/reset/complete", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("TLS reset status %d", response.StatusCode)
	}
	if _, err := accounts.AuthenticatePassword(context.Background(), config.TenantID, "transport@example.com", "replacement correct horse battery staple"); err != nil {
		t.Fatalf("TLS reset did not change password: %v", err)
	}
}

func TestCredentialTransportControls(t *testing.T) {
	for _, scenario := range []struct {
		name                       string
		trustProxy, localHTTP, tls bool
		status                     int
	}{
		{"strict plaintext", false, false, false, 400},
		{"trusted proxy", true, false, false, 200},
		{"tenant local HTTP", false, true, false, 200},
		{"direct TLS", false, false, true, 200},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			config := newTestServerConfig()
			config.AllowInsecureHTTP = scenario.localHTTP
			if scenario.trustProxy {
				policy, err := transportsecurity.NewPolicy([]string{"127.0.0.1/32", "::1/128"})
				if err != nil {
					t.Fatal(err)
				}
				config.TransportPolicy = policy
			}
			router := gin.New()
			MountAuthRoutes(router, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), nil, NewMemoryPasswordCredentialStore(), newTestPasswordResetDispatcher(t))
			var server *httptest.Server
			if scenario.tls {
				server = httptest.NewTLSServer(router)
			} else {
				server = httptest.NewServer(router)
			}
			defer server.Close()
			request, err := http.NewRequest(http.MethodPost, server.URL+"/auth/nonce", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("X-Forwarded-Proto", "https")
			request.Header.Set("Forwarded", "proto=http")
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != scenario.status {
				t.Fatalf("status %d want %d", response.StatusCode, scenario.status)
			}
		})
	}
}

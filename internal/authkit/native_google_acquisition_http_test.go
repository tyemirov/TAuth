package authkit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"google.golang.org/api/idtoken"
)

func TestNativeGoogleAcquisitionHTTP(t *testing.T) {
	config := newMobileNativeTestServerConfig()
	config.NativeGoogleClients[1].AcquisitionFlow = "google_credential_manager"
	router := gin.New()
	MountAuthRoutes(router, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), nil, NewMemoryPasswordCredentialStore(), newTestPasswordResetDispatcher(t))
	server := httptest.NewServer(router)
	defer server.Close()
	for _, platform := range []string{"android", "ios", ""} {
		t.Run(platform, func(t *testing.T) {
			response, err := server.Client().Get(server.URL + "/auth/google/native/config?platform=" + platform)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			var body map[string]interface{}
			if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if platform == "" {
				if response.StatusCode != http.StatusBadRequest || body["error"] != "native_google_platform_required" {
					t.Fatalf("mixed acquisition status=%d body=%v", response.StatusCode, body)
				}
				rejected, err := server.Client().Post(server.URL+"/auth/google/native", "application/json", bytes.NewBufferString(`{"google_id_token":"unused","nonce_token":"unused"}`))
				if err != nil {
					t.Fatal(err)
				}
				defer rejected.Body.Close()
				var rejection map[string]interface{}
				if err := json.NewDecoder(rejected.Body).Decode(&rejection); err != nil {
					t.Fatal(err)
				}
				if rejected.StatusCode != http.StatusBadRequest || rejection["error"] != "native_google_platform_required" || len(rejected.Cookies()) != 0 {
					t.Fatalf("mixed exchange status=%d body=%v", rejected.StatusCode, rejection)
				}
				return
			}
			if response.StatusCode != http.StatusOK || body["nonce_required"] != true {
				t.Fatalf("status=%d body=%v", response.StatusCode, body)
			}
			flow := "authorization_code"
			if platform == "android" {
				flow = "google_credential_manager"
			}
			if body["acquisition_flow"] != flow {
				t.Fatalf("expected flow %s: %v", flow, body)
			}
			clients := body["clients"].([]interface{})
			client := clients[0].(map[string]interface{})
			if client["acquisition_flow"] != flow {
				t.Fatalf("client flow: %v", client)
			}
			for _, field := range []string{"redirect_uris", "authorization_endpoint", "token_endpoint", "response_type", "pkce_required", "code_challenge_methods_supported"} {
				_, exists := body[field]
				if exists != (platform == "ios") {
					t.Errorf("field %s present=%v for %s: %v", field, exists, platform, body)
				}
			}
			if platform == "android" {
				if _, exists := client["redirect_uris"]; exists {
					t.Errorf("SDK client contains redirects: %v", client)
				}
			}
		})
	}
}

func TestNativeGoogleAndroidNonceExchangeHTTP(t *testing.T) {
	for _, flow := range []string{"", "authorization_code", "google_credential_manager"} {
		t.Run("flow="+flow, func(t *testing.T) {
			config := newTestServerConfig()
			config.GoogleNativeClientID = ""
			client := NativeGoogleClientConfig{Platform: "android", ClientID: "web-server-audience"}
			client.AcquisitionFlow = nativeGoogleAcquisitionFlow(flow)
			validRedirect := ""
			if flow != "google_credential_manager" {
				validRedirect = "com.demo:/android"
				client.RedirectURIs = []string{validRedirect}
			}
			config.NativeGoogleClients = []NativeGoogleClientConfig{client}
			validator := &fakeGoogleValidator{results: map[string]validatorResult{}}
			ProvideGoogleTokenValidator(validator)
			defer ProvideGoogleTokenValidator(nil)
			accounts := NewMemoryPasswordCredentialStore()
			router := gin.New()
			MountAuthRoutes(router, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), nil, accounts, newTestPasswordResetDispatcher(t))
			server := httptest.NewServer(router)
			defer server.Close()
			issued, err := server.Client().Post(server.URL+"/auth/nonce", "application/json", nil)
			if err != nil {
				t.Fatal(err)
			}
			var nonce struct {
				Nonce string `json:"nonce"`
			}
			if err := json.NewDecoder(issued.Body).Decode(&nonce); err != nil {
				t.Fatal(err)
			}
			issued.Body.Close()
			if issued.StatusCode != http.StatusOK || nonce.Nonce == "" {
				t.Fatalf("nonce issue failed: %d", issued.StatusCode)
			}
			for _, token := range []string{"wrong-audience", "wrong-claim", "hashed-claim", "valid"} {
				claim := nonce.Nonce
				audience := "web-server-audience"
				if token == "hashed-claim" {
					digest := sha256.Sum256([]byte(nonce.Nonce))
					claim = hex.EncodeToString(digest[:])
				}
				if token == "wrong-claim" {
					claim = "mismatched"
				}
				if token == "wrong-audience" {
					audience = "different-app"
				}
				validator.results[token] = validatorResult{expectedAudience: audience, payload: &idtoken.Payload{Claims: map[string]interface{}{"iss": googleIssuerHTTPS, "sub": "stable-google-subject", "email": "android@example.com", "email_verified": true, "nonce": claim}}}
			}
			for _, scenario := range []struct {
				token    string
				status   int
				code     string
				redirect string
			}{{"valid", 400, "invalid_redirect_uri", "com.demo:/obsolete"}, {"wrong-audience", 401, "invalid_google_token", validRedirect}, {"wrong-claim", 401, "invalid_nonce", validRedirect}, {"hashed-claim", 401, "invalid_nonce", validRedirect}, {"valid", 200, "", validRedirect}, {"valid", 401, "invalid_nonce", validRedirect}} {
				encoded, err := json.Marshal(map[string]string{"google_id_token": scenario.token, "nonce_token": nonce.Nonce, "platform": "android", "redirect_uri": scenario.redirect, "acquisition_flow": "request-cannot-override"})
				if err != nil {
					t.Fatal(err)
				}
				response, err := server.Client().Post(server.URL+"/auth/google/native", "application/json", bytes.NewReader(encoded))
				if err != nil {
					t.Fatal(err)
				}
				var body map[string]interface{}
				err = json.NewDecoder(response.Body).Decode(&body)
				response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != scenario.status {
					t.Fatalf("token=%s status=%d body=%v", scenario.token, response.StatusCode, body)
				}
				if scenario.code != "" && (body["error"] != scenario.code || len(response.Cookies()) != 0) {
					t.Fatalf("rejection changed credentials: %v cookies=%v", body, response.Cookies())
				}
				if scenario.status == http.StatusOK && len(response.Cookies()) < 2 {
					t.Fatalf("missing session/refresh cookies: %v", response.Cookies())
				}
			}
			if len(accounts.accounts[config.TenantID]) != 1 {
				t.Fatalf("expected exactly one account: %v", accounts.accounts)
			}
		})
	}
}

func TestNativeGoogleAndroidAuthorizationCodeDiscoveryHTTP(t *testing.T) {
	for _, flow := range []nativeGoogleAcquisitionFlow{"", "authorization_code"} {
		t.Run(string(flow), func(t *testing.T) {
			config := newMobileNativeTestServerConfig()
			config.NativeGoogleClients[1].AcquisitionFlow = flow
			config.NativeGoogleClients[1].RedirectURIs = []string{"com.demo:/android"}
			router := gin.New()
			MountAuthRoutes(router, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), nil, NewMemoryPasswordCredentialStore(), newTestPasswordResetDispatcher(t))
			server := httptest.NewServer(router)
			defer server.Close()
			for _, platform := range []string{"android", ""} {
				response, err := server.Client().Get(server.URL + "/auth/google/native/config?platform=" + platform)
				if err != nil {
					t.Fatal(err)
				}
				var body nativeGoogleConfigResponse
				err = json.NewDecoder(response.Body).Decode(&body)
				response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != 200 || body.AcquisitionFlow != nativeGoogleAuthorizationCode || !body.PKCERequired || !stringSliceContains(body.RedirectURIs, "com.demo:/android") {
					t.Fatalf("discovery status=%d body=%+v", response.StatusCode, body)
				}
				for _, client := range body.Clients {
					if client.AcquisitionFlow != nativeGoogleAuthorizationCode {
						t.Fatalf("client flow=%+v", client)
					}
				}
			}
		})
	}
}

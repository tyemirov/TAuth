package customerapp_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tyemirov/tauth/internal/customerapp"
)

func TestCustomerAPIConfigurationBoundary(t *testing.T) {
	config := customerapp.Config{UpstreamOrigin: "https://tauth.example", APIOrigin: "https://api.customer.example", FrontendOrigin: "https://app.customer.example", TenantID: "expected", SessionCookie: "session", SessionKeyBase64: base64.StdEncoding.EncodeToString([]byte("example-key-for-boundary-test-32-bytes"))}
	for _, scenario := range []struct {
		name, api, frontend string
		valid               bool
	}{
		{"same site", config.APIOrigin, config.FrontendOrigin, true},
		{"same origin", config.APIOrigin, config.APIOrigin, true},
		{"local ports", "http://localhost:8000", "http://localhost:9000", true},
		{"different sites", config.APIOrigin, "https://attacker.example", false},
		{"different schemes", config.APIOrigin, "http://app.customer.example", false},
		{"origin slash", config.APIOrigin + "/", config.FrontendOrigin, false},
		{"origin path", config.APIOrigin + "/path", config.FrontendOrigin, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			input := config
			input.APIOrigin = scenario.api
			input.FrontendOrigin = scenario.frontend
			handler, err := customerapp.New(input, http.DefaultTransport)
			if (err == nil) != scenario.valid {
				t.Fatalf("configuration result: %v", err)
			}
			if err != nil {
				return
			}
			server := httptest.NewServer(handler)
			defer server.Close()
			for _, requestCase := range []struct {
				path, method, origin, tenant string
				status                       int
			}{
				{"/private", "GET", input.FrontendOrigin, "", 401},
				{"/private", "GET", "https://denied.example", "", 403},
				{"/private", "GET", input.FrontendOrigin, "wrong", 403},
				{"/auth/google", "GET", input.FrontendOrigin, "", 405},
				{"/auth/password", "POST", input.FrontendOrigin, "", 404},
				{"/private", "OPTIONS", input.FrontendOrigin, input.TenantID, 204},
			} {
				request, _ := http.NewRequest(requestCase.method, server.URL+requestCase.path, nil)
				request.Header.Set("Origin", requestCase.origin)
				request.Header.Set("X-TAuth-Tenant", requestCase.tenant)
				response, err := server.Client().Do(request)
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if response.StatusCode != requestCase.status {
					t.Fatalf("%s %s = %d", requestCase.method, requestCase.path, response.StatusCode)
				}
			}
		})
	}
}

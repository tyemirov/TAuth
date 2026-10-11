package appconfig

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxyHostHTTPConfiguration(t *testing.T) {
	config, err := ParseConfig([]byte("server:\n  trusted_proxy_hosts: [localhost]\n  trusted_proxy_lookup_timeout: 1s\n"))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !config.TransportPolicy().IsHTTPS(request) {
			response.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	request, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Forwarded-Proto", "https")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("resolved proxy returned %d", response.StatusCode)
	}
}

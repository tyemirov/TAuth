package authkit

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/transportsecurity"
)

type proxyHostResolver struct {
	mu        sync.Mutex
	addresses []netip.Addr
	err       error
	wait      bool
	calls     int
}

func (resolver *proxyHostResolver) LookupNetIP(ctx context.Context, network, hostname string) ([]netip.Addr, error) {
	resolver.mu.Lock()
	resolver.calls++
	addresses, err, wait := resolver.addresses, resolver.err, resolver.wait
	resolver.mu.Unlock()
	if network != "ip" || hostname != "proxy.internal" {
		return nil, errors.New("unexpected proxy lookup")
	}
	if wait {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return addresses, err
}

func TestManagedProxyCredentialHTTPResolution(t *testing.T) {
	resolver := &proxyHostResolver{}
	policy, err := transportsecurity.NewPolicy(transportsecurity.ProxyConfig{
		Hosts: []string{"proxy.internal"}, LookupTimeout: 10 * time.Millisecond,
	}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	config := newTestServerConfig()
	config.AllowInsecureHTTP = false
	config.TransportPolicy = policy
	router := gin.New()
	MountAuthRoutes(router, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), nil, NewMemoryPasswordCredentialStore(), newTestPasswordResetDispatcher(t))
	server := httptest.NewServer(router)
	defer server.Close()
	var diagnostics strings.Builder
	originalLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&diagnostics, nil)))
	t.Cleanup(func() { slog.SetDefault(originalLogger) })
	for _, scenario := range []struct {
		name      string
		addresses []netip.Addr
		err       error
		wait      bool
		status    int
	}{
		{"current proxy", []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil, false, http.StatusOK},
		{"mapped proxy", []netip.Addr{netip.MustParseAddr("::ffff:127.0.0.1")}, nil, false, http.StatusOK},
		{"previous address no longer trusted", []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil, false, http.StatusBadRequest},
		{"resolution failed", nil, errors.New("injected DNS failure"), false, http.StatusBadRequest},
		{"empty answer", nil, nil, false, http.StatusBadRequest},
		{"bounded timeout", nil, nil, true, http.StatusBadRequest},
		{"recovered current proxy", []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil, false, http.StatusOK},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			resolver.mu.Lock()
			resolver.addresses, resolver.err, resolver.wait = scenario.addresses, scenario.err, scenario.wait
			resolver.mu.Unlock()
			request, err := http.NewRequest(http.MethodPost, server.URL+"/auth/nonce", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("X-Forwarded-Proto", "https")
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != scenario.status {
				t.Fatalf("status %d want %d: %s", response.StatusCode, scenario.status, body)
			}
			if scenario.status == http.StatusBadRequest && (!strings.Contains(string(body), `"error":"https_required"`) || len(response.Cookies()) != 0) {
				t.Fatalf("rejected proxy received credential effects: %s", body)
			}
		})
	}
	for _, diagnostic := range []string{"proxy_resolution_failed", "proxy_resolution_empty", "injected DNS failure", "context deadline exceeded"} {
		if !strings.Contains(diagnostics.String(), diagnostic) {
			t.Errorf("missing resolver diagnostic %q", diagnostic)
		}
	}
	for _, values := range [][]string{nil, {"https", "https"}, {"https,http"}, {"HTTPS"}, {"http"}} {
		resolver.mu.Lock()
		before := resolver.calls
		resolver.mu.Unlock()
		request, err := http.NewRequest(http.MethodPost, server.URL+"/auth/nonce", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = "localhost:8080"
		request.Header.Set("Forwarded", "proto=https")
		for _, value := range values {
			request.Header.Add("X-Forwarded-Proto", value)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("forged headers %v returned %d", values, response.StatusCode)
		}
		resolver.mu.Lock()
		after := resolver.calls
		resolver.mu.Unlock()
		if after != before {
			t.Fatal("invalid transport headers triggered DNS lookup")
		}
	}
	resolver.mu.Lock()
	before := resolver.calls
	resolver.err = errors.New("DNS unavailable for TLS control")
	resolver.mu.Unlock()
	tlsServer := httptest.NewTLSServer(router)
	defer tlsServer.Close()
	response, err := tlsServer.Client().Post(tlsServer.URL+"/auth/nonce", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("direct TLS returned %d", response.StatusCode)
	}
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if resolver.calls != before {
		t.Fatal("direct TLS triggered DNS lookup")
	}
}

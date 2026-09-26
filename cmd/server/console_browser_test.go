package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/controlplane"
	"github.com/tyemirov/tauth/internal/customerapp"
	"github.com/tyemirov/tauth/internal/tenants"
	"google.golang.org/api/idtoken"
)

type browserGoogleValidator struct{}

func (browserGoogleValidator) Validate(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("fixture token must have three segments")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	return (consoleGoogleValidator{}).Validate(ctx, string(payload), audience)
}

func TestConsoleBrowserWorkspace(t *testing.T) {
	if os.Getenv("TAUTH_CONSOLE_BROWSER") != "1" {
		t.Skip("selected by make test-console-browser")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	var apiOrigin string
	var activeHandler atomic.Pointer[browserHandler]
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { activeHandler.Load().handler.ServeHTTP(w, r) }))
	defer api.Close()
	apiOrigin = strings.Replace(api.URL, "127.0.0.1", "api.tauth.test", 1)
	var customerHandler atomic.Pointer[browserHandler]
	customerHandler.Store(&browserHandler{handler: http.NotFoundHandler()})
	customer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { customerHandler.Load().handler.ServeHTTP(w, r) }))
	defer customer.Close()
	customerOrigin := strings.Replace(customer.URL, "127.0.0.1", "api.customer.test", 1)
	var browserHTML atomic.Value
	browserHTML.Store("")
	application := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(browserHTML.Load().(string)))
	}))
	defer application.Close()
	applicationOrigin := strings.Replace(application.URL, "127.0.0.1", "app.customer.test", 1)
	expiredClock := &browserBackendClock{}
	restart := make(chan chan struct{})
	originalNetwork := managementSetupNetwork
	managementSetupNetwork = func() controlplane.SetupNetwork {
		tlsConfig := customer.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
		tlsConfig.ServerName = "example.com"
		address, _ := url.Parse(customer.URL)
		return controlplane.SetupNetwork{Resolver: browserSetupResolver{}, Dialer: browserSetupDialer{address: address.Host}, TLS: tlsConfig}
	}
	defer func() { managementSetupNetwork = originalNetwork }()
	var dnsMutex sync.Mutex
	dnsValues := map[string]string{}
	originalLookup := lookupManagementTXT
	lookupManagementTXT = func(_ context.Context, name string) ([]string, error) {
		dnsMutex.Lock()
		defer dnsMutex.Unlock()
		return []string{dnsValues[name]}, nil
	}
	defer func() { lookupManagementTXT = originalLookup }()
	frontend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__customer-config" && r.Method == "POST" {
			var input struct {
				TenantID      string `json:"tenant_id"`
				SessionCookie string `json:"session_cookie_name"`
				Key           string `json:"session_key_base64"`
				HTML          string `json:"browser_html"`
			}
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&input); err != nil {
				http.Error(w, "invalid installation fixture", 400)
				return
			}
			handler, err := customerapp.New(customerapp.Config{UpstreamOrigin: api.URL, APIOrigin: customerOrigin, FrontendOrigin: applicationOrigin, TenantID: input.TenantID, SessionCookie: input.SessionCookie, SessionKeyBase64: input.Key, Clock: expiredClock}, api.Client().Transport)
			if err != nil {
				http.Error(w, "invalid customer configuration", 400)
				return
			}
			customerHandler.Store(&browserHandler{handler: handler})
			browserHTML.Store(input.HTML)
			w.WriteHeader(204)
			return
		}
		if r.URL.Path == "/__expire-session" && r.Method == "POST" {
			expiredClock.expire.Store(true)
			w.WriteHeader(204)
			return
		}
		if r.URL.Path == "/__restart" && r.Method == "POST" {
			ready := make(chan struct{})
			select {
			case restart <- ready:
			case <-r.Context().Done():
				return
			}
			select {
			case <-ready:
				w.WriteHeader(204)
			case <-r.Context().Done():
			}
			return
		}
		if r.URL.Path == "/__dns" && r.Method == "POST" {
			var record struct{ Name, Value string }
			if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
				http.Error(w, "invalid DNS fixture", 400)
				return
			}
			dnsMutex.Lock()
			dnsValues[record.Name] = record.Value
			dnsMutex.Unlock()
			w.WriteHeader(204)
			return
		}
		if r.URL.Path == "/app/runtime.json" {
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(map[string]string{"api_origin": apiOrigin}); err != nil {
				t.Error(err)
			}
			return
		}
		http.FileServer(http.Dir(filepath.Join(root, "web"))).ServeHTTP(w, r)
	}))
	defer frontend.Close()
	origin := strings.Replace(frontend.URL, "127.0.0.1", "console.tauth.test", 1)
	config := &appconfig.ApplicationConfig{Server: appconfig.ServerSettings{DatabaseURL: "sqlite://" + filepath.Join(t.TempDir(), "browser.db"), TenantEncryptionKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{19}, 32)), EnableCORS: true, EnableTenantHeaderOverride: true, CORSAllowedOrigins: []string{origin}}}
	store, err := controlplane.Open(context.Background(), config.Server.DatabaseURL, config.Server.TenantEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	console := tenants.FileTenant{ID: controlplane.ConsoleTenantID, DisplayName: "Console", TenantOrigins: []string{origin}, GoogleWebClientID: "console-client", JWTSigningKey: "console-browser-signing-key", SessionCookieName: "tauth_console_session", RefreshCookieName: "tauth_console_refresh", SessionTTL: "15m", RefreshTTL: "720h", AccountManagement: tenants.FileAccountManagement{Enabled: true, EmailDelivery: tenants.FileEmailDelivery{ServerAddress: "localhost:50051", APIKey: "fixture", EmailVerificationURL: origin + "/verify", PasswordResetURL: origin + "/reset", PasswordLinkURL: origin + "/link", ConnectionTimeoutSeconds: 1, OperationTimeoutSeconds: 1}}}
	if err := store.Bootstrap(context.Background(), console); err != nil {
		t.Fatal(err)
	}
	users, err := authkit.NewDatabaseUserStore(context.Background(), config.Server.DatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := users.UpsertGoogleAccount(context.Background(), controlplane.ConsoleTenantID, authkit.GoogleAccountIdentity{Subject: "owner", UserEmail: controlplane.InitialOwnerEmail, DisplayName: "Initial owner"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Provision(context.Background(), appconfig.DefaultJWTIssuer, profile.AccountID, controlplane.InitialOwnerEmail, "Initial owner"); err != nil {
		t.Fatal(err)
	}
	imported := tenants.FileTenant{ID: "imported-browser", DisplayName: "Imported application", TenantOrigins: []string{"https://imported.example.com"}, GoogleWebClientID: "imported-client", JWTSigningKey: "imported-browser-signing-key", SessionCookieName: "imported_session", RefreshCookieName: "imported_refresh", SessionTTL: "15m", RefreshTTL: "720h"}
	if _, err := store.Import(context.Background(), "browser-import", tenants.FileDocument{Tenants: []tenants.FileTenant{imported}}); err != nil {
		t.Fatal(err)
	}
	restoreValidator := withGoogleValidatorBuilderStub(func(context.Context) (authkit.GoogleTokenValidator, error) { return browserGoogleValidator{}, nil })
	defer restoreValidator()

	type browserResult struct {
		output []byte
		err    error
	}
	result := make(chan browserResult, 1)
	started, finished := false, false
	var ready chan struct{}
	restore := withServeHTTPStub(func(server *http.Server) error {
		activeHandler.Store(&browserHandler{handler: server.Handler})
		if ready != nil {
			close(ready)
			ready = nil
		}
		if !started {
			started = true
			command := exec.Command("node", "--test", "tests/console-workspace.browser.cjs")
			command.Dir = root
			command.Env = append(os.Environ(), "TAUTH_CONSOLE_URL="+origin+"/app/", "TAUTH_CONSOLE_API="+apiOrigin, "TAUTH_CUSTOMER_FRONTEND="+applicationOrigin, "TAUTH_CUSTOMER_API="+customerOrigin, "TAUTH_BROWSER_OPERATOR_URL="+frontend.URL)
			go func() { output, err := command.CombinedOutput(); result <- browserResult{output: output, err: err} }()
		}
		select {
		case ready = <-restart:
		case completed := <-result:
			finished = true
			if completed.err != nil {
				t.Errorf("console browser: %v\n%s", completed.err, completed.output)
			} else {
				t.Log(string(completed.output))
			}
		}
		return http.ErrServerClosed
	})
	defer restore()
	for !finished {
		command := &cobra.Command{}
		command.SetContext(context.WithValue(context.Background(), appConfigContextKey, config))
		if err := runServer(command, nil); err != nil {
			t.Fatal(err)
		}
	}
}

type browserHandler struct{ handler http.Handler }
type browserBackendClock struct{ expire atomic.Bool }

func (clock *browserBackendClock) Now() time.Time {
	if clock.expire.Swap(false) {
		return time.Now().Add(2 * time.Hour)
	}
	return time.Now()
}

type browserSetupResolver struct{}

func (browserSetupResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
}

type browserSetupDialer struct{ address string }

func (dialer browserSetupDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, dialer.address)
}

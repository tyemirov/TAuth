package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/spf13/cobra"
	"github.com/tyemirov/tauth/internal/appconfig"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/controlplane"
	"github.com/tyemirov/tauth/internal/tenants"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func providerFixtureDB(owner consoleHTTP) *gorm.DB {
	owner.t.Helper()
	db, err := authkit.OpenControlDatabase(context.Background(), owner.configuration.Server.DatabaseURL)
	if err != nil {
		owner.t.Fatal(err)
	}
	raw, err := db.DB()
	if err != nil {
		owner.t.Fatal(err)
	}
	owner.t.Cleanup(func() { raw.Close() })
	return db
}
func providerFile(owner consoleHTTP, id string) tenants.FileTenant {
	owner.t.Helper()
	store, err := controlplane.OpenExisting(context.Background(), owner.configuration.Server.DatabaseURL, owner.configuration.Server.TenantEncryptionKey)
	if err != nil {
		owner.t.Fatal(err)
	}
	defer store.Close()
	document, err := store.ApplicationTenants(context.Background())
	if err != nil {
		owner.t.Fatal(err)
	}
	for _, file := range document.Tenants {
		if file.ID == id {
			return file
		}
	}
	owner.t.Fatalf("active provider tenant missing")
	return tenants.FileTenant{}
}
func providerCredential(owner consoleHTTP, app, id string, operations []string, key string) (consoleHTTP, []string, string) {
	owner.t.Helper()
	issued, headers := owner.request("POST", controlplane.CredentialsPath, map[string]any{"app_id": app, "name": key, "operations": operations, "tenant_ids": []string{id}, "allow_create": false}, 201, "Idempotency-Key", key)
	machine := owner
	client := *owner.client
	client.Jar = nil
	machine.client = &client
	machine.origin = ""
	return machine, []string{"Authorization", "Bearer " + issued["token"].(string)}, headers.Get("Location")
}
func providerGoogleSignIn(application consoleHTTP, native bool) string {
	application.t.Helper()
	nonce, _ := application.request("POST", "/auth/nonce", nil, 200)
	claims, _ := json.Marshal(map[string]any{"aud": "fixture-client.apps.googleusercontent.com", "iss": "https://accounts.google.com", "sub": "stable-provider-subject", "email": "native-member@example.com", "email_verified": true, "nonce": nonce["nonce"]})
	path := "/auth/google"
	body := map[string]any{"google_id_token": string(claims), "nonce_token": nonce["nonce"]}
	if native {
		path = "/auth/google/native"
		body["platform"] = "android"
	}
	result, _ := application.request("POST", path, body, 200)
	return result["user_id"].(string)
}
func restartProviderService(t *testing.T, configuration *appconfig.ApplicationConfig, origin, id, expectedUser string) {
	t.Helper()
	restoreValidator := withGoogleValidatorBuilderStub(func(context.Context) (authkit.GoogleTokenValidator, error) { return consoleGoogleValidator{}, nil })
	defer restoreValidator()
	restore := withServeHTTPStub(func(server *http.Server) error {
		listener := httptest.NewTLSServer(server.Handler)
		defer listener.Close()
		client := listener.Client()
		client.Jar, _ = cookiejar.New(nil)
		application := consoleHTTP{t: t, client: client, base: listener.URL, origin: origin, tenant: id}
		body, _ := application.request("GET", "/auth/google/native/config?platform=android", nil, 200)
		if body["client_id"] != "fixture-client.apps.googleusercontent.com" {
			t.Fatal("active provider revision did not survive restart")
		}
		if actual := providerGoogleSignIn(application, true); actual != expectedUser {
			t.Fatal("Google identity changed after restart")
		}
		return http.ErrServerClosed
	})
	defer restore()
	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), appConfigContextKey, configuration))
	if err := runServer(command, nil); err != nil {
		t.Fatal(err)
	}
}
func TestManagementProvidersHTTP(t *testing.T) {
	var restartConfig *appconfig.ApplicationConfig
	var restartID, restartOrigin, restartUser string
	withManagementService(t, consoleGoogleValidator{}, func(owner consoleHTTP) {
		input := owner.tenantInput("Native provider app")
		app := input["app_id"].(string)
		created, header := owner.request("POST", controlplane.TenantsPath, input, 201, "Idempotency-Key", "native-provider-app")
		id := created["id"].(string)
		path := header.Get("Location")
		providers := path + "/configuration/providers"
		initial, headers := owner.request("GET", providers, nil, 200)
		empty, emptyHeader := owner.request("PATCH", providers, map[string]any{"google_native_clients": []any{}}, 200, "If-Match", headers.Get("ETag"))
		if empty["revision"] != initial["revision"] || emptyHeader.Get("ETag") != headers.Get("ETag") {
			t.Fatal("empty native list no-op advanced revision")
		}
		originalTag := headers.Get("ETag")
		if initial["revision"] != float64(1) || initial["apple"].(map[string]any)["key_configured"] != false {
			t.Fatalf("unexpected initial providers: %v", initial)
		}
		application := owner
		application.origin = input["application_origin"].(string)
		application.tenant = id
		originalGoogleUser := providerGoogleSignIn(application, false)
		restartConfig = owner.configuration
		restartID = id
		restartOrigin = application.origin
		restartUser = originalGoogleUser
		patch := map[string]any{"google_native_clients": []any{map[string]any{"platform": "android", "client_id": "fixture-client.apps.googleusercontent.com", "acquisition_flow": "google_credential_manager"}, map[string]any{"platform": "ios", "client_id": "ios-fixture.apps.googleusercontent.com", "redirect_uris": []string{"com.example:/google"}}}}
		owner.request("PATCH", providers, patch, 428)
		owner.request("PATCH", providers, patch, 412, "If-Match", `"configuration-0"`)
		for _, body := range []any{map[string]any{"apple": nil}, map[string]any{"google_native_clients": nil}, map[string]any{"apple": map[string]any{"private_key": nil}}, map[string]any{"apple": map[string]any{"token_endpoint": "https://attacker.invalid"}}, map[string]any{"google_native_clients": []any{map[string]any{"platform": "android", "client_id": "x", "unknown": true}}}} {
			owner.request("PATCH", providers, body, 400, "If-Match", originalTag)
		}
		owner.request("PATCH", providers, map[string]any{"apple": map[string]any{"private_key": ""}}, 422, "If-Match", originalTag)
		owner.request("PATCH", providers, map[string]any{"email_delivery": map[string]any{"connection_timeout_seconds": 0}}, 422, "If-Match", originalTag)
		owner.request("PATCH", providers, map[string]any{"apple": map[string]any{"private_key": "secret-invalid-key"}}, 422, "If-Match", originalTag)
		owner.request("PATCH", providers, map[string]any{}, 403, "If-Match", originalTag, "X-TAuth-CSRF", "")
		machine, auth, credentialPath := providerCredential(owner, app, id, []string{"read", "configure"}, "provider-configurer")
		saved, updated := machine.request("PATCH", providers, patch, 200, append(auth, "If-Match", originalTag)...)
		if saved["revision"] != float64(2) {
			t.Fatalf("draft revision: %v", saved)
		}
		current, _ := owner.request("GET", path, nil, 200)
		if current["active_revision"] != float64(1) || current["state"] != "active" {
			t.Fatalf("draft activated: %v", current)
		}
		same, sameHeaders := machine.request("PATCH", providers, patch, 200, append(auth, "If-Match", updated.Get("ETag"))...)
		if same["revision"] != saved["revision"] || sameHeaders.Get("ETag") != updated.Get("ETag") {
			t.Fatal("noop advanced revision")
		}
		machine.request("PATCH", providers, patch, 412, append(auth, "If-Match", originalTag)...)
		machine.request("POST", path+"/activations", map[string]any{"revision": 2}, 403, append(auth, "If-Match", updated.Get("ETag"), "Idempotency-Key", "no-activate-grant")...)
		application.request("GET", "/auth/google/native/config?platform=android", nil, 404)
		owner.request("POST", path+"/activations", map[string]any{"revision": 2}, 201, "If-Match", updated.Get("ETag"), "Idempotency-Key", "activate-providers")
		native, _ := application.request("GET", "/auth/google/native/config?platform=android", nil, 200)
		if native["acquisition_flow"] != "google_credential_manager" {
			t.Fatal(native)
		}
		if providerGoogleSignIn(application, true) != originalGoogleUser {
			t.Fatal("native provider update changed Google subject")
		}
		// Every existing authentication boundary also covers the nested provider resource.
		machine.request("GET", providers, nil, 403, append(auth, "Cookie", "unexpected=1")...)
		browserMachine := machine
		browserMachine.origin = owner.origin
		browserMachine.request("GET", providers, nil, 403, auth...)
		reader, readAuth, _ := providerCredential(owner, app, id, []string{"read"}, "provider-reader")
		reader.request("PATCH", providers, patch, 403, append(readAuth, "If-Match", updated.Get("ETag"))...)
		other := owner
		isolated := *owner.client
		isolated.Jar, _ = cookiejar.New(nil)
		other.client = &isolated
		other.login("other-owner", "console-client")
		other.request("PUT", controlplane.OwnerPath, nil, 201)
		other.request("GET", providers, nil, 404)
		db := providerFixtureDB(owner)
		var credential struct{ ID string }
		if err := db.Table("provisioning_credentials").Where("name = ?", "provider-configurer").Take(&credential).Error; err != nil {
			t.Fatal(err)
		}
		otherApp, _ := owner.request("POST", controlplane.AppsPath, map[string]any{"name": "Another App"}, 201, "Idempotency-Key", "provider-other-app")
		if err := db.Table("provisioning_credentials").Where("id = ?", credential.ID).Update("app_id", otherApp["id"]).Error; err != nil {
			t.Fatal(err)
		}
		machine.request("GET", providers, nil, 403, auth...)
		machine.request("PATCH", providers, patch, 403, append(auth, "If-Match", updated.Get("ETag"))...)
		if err := db.Table("provisioning_credentials").Where("id = ?", credential.ID).Updates(map[string]any{"app_id": app, "tenant_ids": "[]"}).Error; err != nil {
			t.Fatal(err)
		}
		machine.request("GET", providers, nil, 403, auth...)
		owner.request("DELETE", credentialPath, nil, 204)
		machine.request("GET", providers, nil, 401, auth...)
	})
	restartProviderService(t, restartConfig, restartOrigin, restartID, restartUser)
}

func TestManagementProvidersPreserveSecretsHTTP(t *testing.T) {
	withManagementService(t, consoleGoogleValidator{}, func(owner consoleHTTP) {
		created, headers := owner.request("POST", controlplane.TenantsPath, owner.tenantInput("Preserved provider app"), 201, "Idempotency-Key", "preserve-provider-app")
		id := created["id"].(string)
		path := headers.Get("Location")
		providers := path + "/configuration/providers"
		file := providerFile(owner, id)
		hash, err := bcrypt.GenerateFromPassword([]byte("provider-fixture-password"), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		file.GoogleNativeClientID = "desktop-fixture.apps.googleusercontent.com"
		file.AllowedUsers = []string{"member@example.com", "native-member@example.com"}
		file.PasswordAuth = tenants.FilePasswordAuth{Enabled: true, Users: []tenants.FilePasswordUser{{Email: "member@example.com", PasswordHash: string(hash), DisplayName: "Retained member"}}}
		file.AccountManagement = tenants.FileAccountManagement{Enabled: true, EmailDelivery: tenants.FileEmailDelivery{ServerAddress: "localhost:50051", APIKey: "retained-delivery-key", EmailVerificationURL: "http://localhost:19091/verify", PasswordResetURL: "http://localhost:19091/reset", PasswordLinkURL: "http://localhost:19091/link", ConnectionTimeoutSeconds: 2, OperationTimeoutSeconds: 4}}
		file.NonceTTL = "3m"
		encoded, err := json.Marshal(file)
		if err != nil {
			t.Fatal(err)
		}
		store, err := controlplane.OpenExisting(context.Background(), owner.configuration.Server.DatabaseURL, owner.configuration.Server.TenantEncryptionKey)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		ref, err := controlplane.NewSecretReference(id, "configuration-1", "configuration")
		if err != nil {
			t.Fatal(err)
		}
		if err = store.SaveSecret(context.Background(), ref, encoded); err != nil {
			t.Fatal(err)
		}
		tenantConfig, err := tenants.LoadResolvedConfig(tenants.FileDocument{Tenants: []tenants.FileTenant{file}})
		if err != nil {
			t.Fatal(err)
		}
		users, err := authkit.NewDatabaseUserStore(context.Background(), owner.configuration.Server.DatabaseURL)
		if err != nil {
			t.Fatal(err)
		}
		if err = seedPasswordUsers(context.Background(), tenantConfig, users, users); err != nil {
			t.Fatal(err)
		}
		owner.request("POST", path+"/activations", map[string]any{"revision": 1}, 201, "If-Match", `"configuration-1"`, "Idempotency-Key", "fixture-active")
		application := owner
		application.origin = "http://localhost:19091"
		application.tenant = id
		beforeLogin, _ := application.request("POST", "/auth/password/login", map[string]any{"email": "member@example.com", "password": "provider-fixture-password"}, 200)
		view, headers := owner.request("GET", providers, nil, 200)
		if len(view["google_native_clients"].([]any)) != 1 {
			t.Fatal("standalone desktop audience undisclosed")
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		privateKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
		patch := map[string]any{"google_native_clients": []any{map[string]any{"platform": "android", "client_id": file.GoogleWebClientID}}, "apple": map[string]any{"enabled": true, "client_id": "com.example.web", "native_client_ids": []string{"com.example.native"}, "team_id": "TEAMID", "key_id": "KEYID", "redirect_uri": "https://apple.example.com/auth/apple/callback", "private_key": privateKey}}
		saved, headers := owner.request("PATCH", providers, patch, 200, "If-Match", headers.Get("ETag"))
		public, _ := json.Marshal(saved)
		if strings.Contains(string(public), "PRIVATE KEY") || strings.Contains(string(public), "retained-delivery-key") || strings.Contains(string(public), string(hash)) {
			t.Fatal("provider representation disclosed secret")
		}
		if saved["apple"].(map[string]any)["key_configured"] != true {
			t.Fatal("key presence absent")
		}
		// Disabling cannot silently erase omitted stored credentials under the current tenant schema.
		owner.request("PATCH", providers, map[string]any{"apple": map[string]any{"enabled": false}}, 422, "If-Match", headers.Get("ETag"))
		owner.request("PATCH", providers, map[string]any{}, 200, "If-Match", headers.Get("ETag"))
		owner.request("POST", path+"/activations", map[string]any{"revision": 2}, 201, "If-Match", headers.Get("ETag"), "Idempotency-Key", "preserved-provider-active")
		after := providerFile(owner, id)
		if after.GoogleNativeClientID != "" {
			t.Fatal("standalone native audience survived complete replacement")
		}
		after.GoogleNativeClientID = file.GoogleNativeClientID
		after.GoogleNativeClients = file.GoogleNativeClients
		after.AppleOAuth = file.AppleOAuth
		if !reflect.DeepEqual(file, after) {
			t.Fatal("unrelated provider update changed complete stored configuration")
		}
		afterLogin, _ := application.request("POST", "/auth/password/login", map[string]any{"email": "member@example.com", "password": "provider-fixture-password"}, 200)
		if beforeLogin["user_id"] != afterLogin["user_id"] {
			t.Fatal("provider update changed password subject")
		}
		db := providerFixtureDB(owner)
		for _, table := range []string{"tenant_audit_events", "management_receipts"} {
			var rows []map[string]any
			if err := db.Table(table).Find(&rows).Error; err != nil {
				t.Fatal(err)
			}
			data, _ := json.Marshal(rows)
			if strings.Contains(string(data), "PRIVATE KEY") || strings.Contains(string(data), privateKey) {
				t.Fatal("secret entered audit/receipt")
			}
		}
		owner.request("PATCH", providers, map[string]any{"email_delivery": map[string]any{"server_address": "localhost:50052"}}, 422, "If-Match", headers.Get("ETag"))
		owner.request("PATCH", providers, map[string]any{"email_delivery": map[string]any{"api_key": ""}}, 422, "If-Match", headers.Get("ETag"))
		owner.request("PATCH", providers, map[string]any{"email_delivery": map[string]any{"operation_timeout_seconds": 0}}, 422, "If-Match", headers.Get("ETag"))
		owner.request("PATCH", providers, map[string]any{"email_delivery": map[string]any{"api_key": nil}}, 400, "If-Match", headers.Get("ETag"))
		delivery, deliveryHeaders := owner.request("PATCH", providers, map[string]any{"email_delivery": map[string]any{"server_address": "localhost:50052", "api_key": "new-delivery-key"}}, 200, "If-Match", headers.Get("ETag"))
		deliveryBytes, _ := json.Marshal(delivery)
		if strings.Contains(string(deliveryBytes), "new-delivery-key") || delivery["email_delivery"].(map[string]any)["key_configured"] != true {
			t.Fatal("email credential representation unsafe")
		}
		owner.request("POST", path+"/activations", map[string]any{"revision": 3}, 201, "If-Match", deliveryHeaders.Get("ETag"), "Idempotency-Key", "delivery-provider-active")
		deliveryFile := providerFile(owner, id)
		if deliveryFile.AccountManagement.EmailDelivery.APIKey != "new-delivery-key" || deliveryFile.AccountManagement.EmailDelivery.ServerAddress != "localhost:50052" {
			t.Fatal("explicit email destination/key missing")
		}
		_, headers = owner.request("PATCH", providers, map[string]any{"email_delivery": map[string]any{"operation_timeout_seconds": 5}}, 200, "If-Match", deliveryHeaders.Get("ETag"))
		owner.request("POST", path+"/activations", map[string]any{"revision": 4}, 201, "If-Match", headers.Get("ETag"), "Idempotency-Key", "delivery-timeout-active")
		deliveryFile = providerFile(owner, id)
		if deliveryFile.AccountManagement.EmailDelivery.APIKey != "new-delivery-key" {
			t.Fatal("omitted delivery key changed")
		}
		deliveryFile.AccountManagement.EmailDelivery = file.AccountManagement.EmailDelivery
		deliveryFile.GoogleNativeClients = file.GoogleNativeClients
		deliveryFile.GoogleNativeClientID = file.GoogleNativeClientID
		deliveryFile.AppleOAuth = file.AppleOAuth
		if !reflect.DeepEqual(file, deliveryFile) {
			t.Fatal("delivery patch changed unrelated configuration")
		}
		// Suspension survives a draft-only provider update.
		_, tenantHeaders := owner.request("GET", path, nil, 200)
		owner.request("PATCH", path, map[string]any{"state": "suspended"}, 200, "If-Match", tenantHeaders.Get("ETag"))
		_, draftHeaders := owner.request("PATCH", providers, map[string]any{"apple": map[string]any{"key_id": "NEXTKEY"}}, 200, "If-Match", headers.Get("ETag"))
		current, _ := owner.request("GET", path, nil, 200)
		if current["state"] != "suspended" || current["active_revision"] != float64(4) {
			t.Fatalf("provider draft resumed suspension: %v", current)
		}
		owner.request("PATCH", providers, map[string]any{}, 200, "If-Match", draftHeaders.Get("ETag"))
		for _, table := range []string{"tenant_audit_events", "management_receipts"} {
			var rows []map[string]any
			if err := db.Table(table).Find(&rows).Error; err != nil {
				t.Fatal(err)
			}
			data, _ := json.Marshal(rows)
			for _, secret := range []string{privateKey, "PRIVATE KEY", "retained-delivery-key", "new-delivery-key", string(hash)} {
				if strings.Contains(string(data), secret) {
					t.Fatal("provider secret entered audit/receipt")
				}
			}
		}
	})
}

func TestManagementProvidersConflictsHTTP(t *testing.T) {
	withManagementService(t, consoleGoogleValidator{}, func(owner consoleHTTP) {
		input := owner.tenantInput("First provider app")
		first, headers := owner.request("POST", controlplane.TenantsPath, input, 201, "Idempotency-Key", "provider-conflict-first")
		firstPath := headers.Get("Location")
		firstID := first["id"].(string)
		patch := map[string]any{"google_native_clients": []any{map[string]any{"platform": "android", "client_id": "shared-native-audience"}}}
		_, firstHeader := owner.request("PATCH", firstPath+"/configuration/providers", patch, 200, "If-Match", `"configuration-1"`)
		owner.request("POST", firstPath+"/activations", map[string]any{"revision": 2}, 201, "If-Match", firstHeader.Get("ETag"), "Idempotency-Key", "provider-conflict-activate-first")
		input["name"] = "Second provider app"
		second, headers := owner.request("POST", controlplane.TenantsPath, input, 201, "Idempotency-Key", "provider-conflict-second")
		secondPath := headers.Get("Location")
		secondID := second["id"].(string)
		_, secondHeader := owner.request("PATCH", secondPath+"/configuration/providers", patch, 200, "If-Match", `"configuration-1"`)
		failed, _ := owner.request("POST", secondPath+"/activations", map[string]any{"revision": 2}, 422, "If-Match", secondHeader.Get("ETag"), "Idempotency-Key", "provider-conflict-activate-second")
		if failed["code"] != "management.runtime_invalid" {
			t.Fatal(failed)
		}
		current, _ := owner.request("GET", secondPath, nil, 200)
		if current["active_revision"] != float64(1) {
			t.Fatal("failed runtime changed active configuration")
		}
		application := owner
		application.origin = input["application_origin"].(string)
		application.tenant = secondID
		application.request("GET", "/auth/google/native/config?platform=android", nil, 404)
		// An unrelated pending revision cannot be incorporated or silently activated by a provider patch.
		db := providerFixtureDB(owner)
		if err := db.Table("tenant_audit_events").Where("tenant_id = ? AND revision = ? AND operation = ?", secondID, 2, "configuration.providers.saved").Update("operation", "configuration.unrelated-fixture").Error; err != nil {
			t.Fatal(err)
		}
		owner.request("PATCH", secondPath+"/configuration/providers", map[string]any{}, 409, "If-Match", secondHeader.Get("ETag"))
		// Existing contribution ownership has no credential tuple capable of authorizing a second writer.
		if err := db.Table("provisioning_bindings").Create(map[string]any{"tenant_id": firstID, "contribution_owner": "fixture-owner", "contribution_id": "authentication", "generation": 1, "revision": 2, "digest": "fixture-digest"}).Error; err != nil {
			t.Fatal(err)
		}
		owner.request("GET", firstPath+"/configuration/providers", nil, 200)
		owner.request("PATCH", firstPath+"/configuration/providers", map[string]any{}, 409, "If-Match", firstHeader.Get("ETag"))
		machine, auth, _ := providerCredential(owner, input["app_id"].(string), firstID, []string{"read", "configure"}, "bound-provider-configurer")
		machine.request("GET", firstPath+"/configuration/providers", nil, 200, auth...)
		machine.request("PATCH", firstPath+"/configuration/providers", map[string]any{}, 409, append(auth, "If-Match", firstHeader.Get("ETag"))...)
	})
}

func TestManagementProvidersAndroidCodeFlowHTTP(t *testing.T) {
	withManagementService(t, consoleGoogleValidator{}, func(owner consoleHTTP) {
		input := owner.tenantInput("Android code flow")
		_, header := owner.request("POST", controlplane.TenantsPath, input, 201, "Idempotency-Key", "android-code-flow")
		providers := header.Get("Location") + "/configuration/providers"
		_, headers := owner.request("GET", providers, nil, 200)
		invalidClients := [][]any{
			{map[string]any{"platform": "android", "client_id": "server-web", "acquisition_flow": "unknown"}},
			{map[string]any{"platform": "ios", "client_id": "server-web", "acquisition_flow": "google_credential_manager"}},
			{map[string]any{"platform": "android", "client_id": "server-web", "acquisition_flow": "google_credential_manager", "redirect_uris": []string{"com.demo:/android"}}},
			{map[string]any{"platform": "android", "client_id": "native"}, map[string]any{"platform": " Android ", "client_id": "server-web", "acquisition_flow": "google_credential_manager"}},
		}
		for _, clients := range invalidClients {
			owner.request("PATCH", providers, map[string]any{"google_native_clients": clients}, 422, "If-Match", headers.Get("ETag"))
			unchanged, current := owner.request("GET", providers, nil, 200)
			if current.Get("ETag") != headers.Get("ETag") || unchanged["revision"] != float64(1) {
				t.Fatal("invalid native flow changed draft", unchanged)
			}
		}
		for _, flow := range []string{"", "authorization_code"} {
			client := map[string]any{"platform": "android", "client_id": "android-native.apps.googleusercontent.com", "redirect_uris": []string{"com.example:/android"}}
			if flow != "" {
				client["acquisition_flow"] = flow
			}
			draft, next := owner.request("PATCH", providers, map[string]any{"google_native_clients": []any{client}}, 200, "If-Match", headers.Get("ETag"))
			if draft["google_native_clients"].([]any)[0].(map[string]any)["acquisition_flow"] != "authorization_code" {
				t.Fatal("provider view omitted effective flow", draft)
			}
			if flow != "" && next.Get("ETag") != headers.Get("ETag") {
				t.Fatal("explicit default flow advanced equivalent draft")
			}
			headers = next
		}
	})
}

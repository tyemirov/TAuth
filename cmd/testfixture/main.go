//go:build tauth_testfixture

// Command testfixture prepares isolated test data. It is not a service command.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/tyemirov/tauth/deployment/migrations"
	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/controlplane"
	"github.com/tyemirov/tauth/internal/tenants"
	"gopkg.in/yaml.v3"
)

const schema = "tauth.test-fixture.v1"
const mountPath = "/tauth-fixture"
const databaseName = "tauth.db"

// fixtureRequest is the closed input contract for an isolated application fixture.
type fixtureRequest struct {
	Schema   string `json:"schema"`
	TestOnly bool   `json:"test_only"`
	AppID    string `json:"app_id"`
	Server   struct {
		ListenAddr string `json:"listen_addr"`
	} `json:"server"`
	Tenant struct {
		ID                   string `json:"id"`
		DisplayName          string `json:"display_name"`
		Origin               string `json:"origin"`
		GoogleWebClientID    string `json:"google_web_client_id"`
		GoogleNativeClientID string `json:"google_native_client_id"`
		JWTSigningKey        string `json:"jwt_signing_key"`
		SessionCookieName    string `json:"session_cookie_name"`
		RefreshCookieName    string `json:"refresh_cookie_name"`
		SessionTTL           string `json:"session_ttl"`
		RefreshTTL           string `json:"refresh_ttl"`
		NonceTTL             string `json:"nonce_ttl"`
	} `json:"tenant"`
}

type validatorTenant struct {
	ID                string `yaml:"id"`
	JWTSigningKey     string `yaml:"jwt_signing_key"`
	SessionCookieName string `yaml:"session_cookie_name"`
}

type fixtureReceipt struct {
	Schema        string `json:"schema"`
	InputSHA256   string `json:"input_sha256"`
	BuildIdentity string `json:"build_identity"`
	AppID         string `json:"app_id"`
	TenantID      string `json:"tenant_id"`
	MountPath     string `json:"mount_path"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "test fixture:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("tauth-test-fixture", flag.ContinueOnError)
	input := flags.String("input", "", "strict test fixture JSON")
	output := flags.String("output-dir", "", "new isolated fixture directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *input == "" || *output == "" || flags.NArg() != 0 {
		return errors.New("--input and --output-dir are required without positional arguments")
	}
	directory, err := filepath.Abs(*output)
	if err != nil {
		return fmt.Errorf("resolve output directory: %w", err)
	}
	if strings.ContainsAny(directory, "#?%") {
		return errors.New("output directory path must not contain #, ?, or %")
	}
	if _, err := os.Lstat(directory); err == nil {
		return errors.New("output directory already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect output directory: %w", err)
	}
	payload, err := os.ReadFile(*input)
	if err != nil {
		return fmt.Errorf("read fixture input: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	var request fixtureRequest
	if err := decoder.Decode(&request); err != nil {
		return fmt.Errorf("decode fixture input: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("fixture input must contain one JSON document")
	}
	application, err := validateRequest(request)
	if err != nil {
		return err
	}
	return prepare(request, application, payload, directory)
}

func validateRequest(request fixtureRequest) (tenants.FileTenant, error) {
	if request.Schema != schema || !request.TestOnly {
		return tenants.FileTenant{}, errors.New("schema tauth.test-fixture.v1 and test_only true are required")
	}
	required := []struct{ name, value string }{
		{"app_id", request.AppID}, {"server.listen_addr", request.Server.ListenAddr}, {"tenant.id", request.Tenant.ID}, {"tenant.display_name", request.Tenant.DisplayName}, {"tenant.origin", request.Tenant.Origin}, {"tenant.google_web_client_id", request.Tenant.GoogleWebClientID}, {"tenant.google_native_client_id", request.Tenant.GoogleNativeClientID}, {"tenant.jwt_signing_key", request.Tenant.JWTSigningKey}, {"tenant.session_cookie_name", request.Tenant.SessionCookieName}, {"tenant.refresh_cookie_name", request.Tenant.RefreshCookieName}, {"tenant.session_ttl", request.Tenant.SessionTTL}, {"tenant.refresh_ttl", request.Tenant.RefreshTTL}, {"tenant.nonce_ttl", request.Tenant.NonceTTL},
	}
	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return tenants.FileTenant{}, fmt.Errorf("%s is required", field.name)
		}
		if field.value != strings.TrimSpace(field.value) {
			return tenants.FileTenant{}, fmt.Errorf("%s must not have outer whitespace", field.name)
		}
	}
	if request.AppID == controlplane.ConsoleTenantID || request.Tenant.ID == controlplane.ConsoleTenantID {
		return tenants.FileTenant{}, errors.New("application and tenant IDs must not be tauth-console")
	}
	origin, err := url.Parse(request.Tenant.Origin)
	if err != nil {
		return tenants.FileTenant{}, errors.New("tenant.origin must be a loopback HTTP origin")
	}
	host := origin.Hostname()
	ip := net.ParseIP(host)
	if (origin.Scheme != "http" && origin.Scheme != "https") || (host != "localhost" && (ip == nil || !ip.IsLoopback())) || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return tenants.FileTenant{}, errors.New("tenant.origin must be a loopback HTTP origin")
	}
	if port := origin.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return tenants.FileTenant{}, errors.New("tenant.origin port is invalid")
		}
	}
	_, port, err := net.SplitHostPort(request.Server.ListenAddr)
	if err != nil {
		return tenants.FileTenant{}, errors.New("server.listen_addr must be an explicit host:port or :port")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return tenants.FileTenant{}, errors.New("server.listen_addr port is invalid")
	}
	application := tenants.FileTenant{ID: request.Tenant.ID, DisplayName: request.Tenant.DisplayName, TenantOrigins: []string{request.Tenant.Origin}, GoogleWebClientID: request.Tenant.GoogleWebClientID, GoogleNativeClientID: request.Tenant.GoogleNativeClientID, JWTSigningKey: request.Tenant.JWTSigningKey, SessionCookieName: request.Tenant.SessionCookieName, RefreshCookieName: request.Tenant.RefreshCookieName, SessionTTL: request.Tenant.SessionTTL, RefreshTTL: request.Tenant.RefreshTTL, NonceTTL: request.Tenant.NonceTTL, AllowInsecureHTTP: true}
	if _, err := tenants.LoadResolvedConfig(tenants.FileDocument{Tenants: []tenants.FileTenant{application}}); err != nil {
		return tenants.FileTenant{}, fmt.Errorf("validate fixture tenant: %w", err)
	}
	return application, nil
}

func randomKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("generate fixture encryption material: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func prepare(request fixtureRequest, application tenants.FileTenant, payload []byte, directory string) (err error) {
	identity, err := buildIdentity()
	if err != nil {
		return err
	}
	key, err := randomKey()
	if err != nil {
		return err
	}
	consoleKey, err := randomKey()
	if err != nil {
		return err
	}
	if err := os.Mkdir(directory, os.ModePerm); err != nil {
		return fmt.Errorf("create new output directory: %w", err)
	}
	defer func() {
		if err != nil {
			if cleanupErr := os.RemoveAll(directory); cleanupErr != nil {
				err = errors.Join(err, fmt.Errorf("remove failed fixture: %w", cleanupErr))
			}
		}
	}()
	databaseURL := "sqlite://" + filepath.Join(directory, databaseName)
	ctx := context.Background()
	store, err := controlplane.Open(ctx, databaseURL, key)
	if err != nil {
		return fmt.Errorf("open fixture store: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, store.Close())
		}
	}()
	const consoleOrigin = "https://console.test-fixture.invalid"
	console := tenants.FileTenant{ID: controlplane.ConsoleTenantID, DisplayName: "Isolated test console", TenantOrigins: []string{consoleOrigin}, GoogleWebClientID: "test-fixture-console.apps.googleusercontent.com", JWTSigningKey: consoleKey, SessionCookieName: "tauth_console_session", RefreshCookieName: "tauth_console_refresh", SessionTTL: "15m", RefreshTTL: "720h", AccountManagement: tenants.FileAccountManagement{Enabled: true, EmailDelivery: tenants.FileEmailDelivery{ServerAddress: "localhost:50051", APIKey: "test-only", EmailVerificationURL: consoleOrigin + "/verify", PasswordResetURL: consoleOrigin + "/reset", PasswordLinkURL: consoleOrigin + "/link", ConnectionTimeoutSeconds: 1, OperationTimeoutSeconds: 1}}}
	if err := store.Bootstrap(ctx, console); err != nil {
		return fmt.Errorf("bootstrap isolated console: %w", err)
	}
	owner, _, err := store.Provision(ctx, appconfig.DefaultJWTIssuer, "isolated-test-owner", "owner@test-fixture.invalid", "Isolated test owner")
	if err != nil {
		return fmt.Errorf("create fixture owner: %w", err)
	}
	if _, err := migrations.Apply(ctx, databaseURL, key, "isolated-test-fixture", owner.ID, request.AppID, application.DisplayName, tenants.FileDocument{Tenants: []tenants.FileTenant{application}}); err != nil {
		return fmt.Errorf("activate fixture application: %w", err)
	}
	closeErr := store.Close()
	closed = true
	if closeErr != nil {
		return fmt.Errorf("close fixture store: %w", closeErr)
	}
	service := appconfig.ApplicationConfig{Server: appconfig.ServerSettings{ListenAddr: request.Server.ListenAddr, DatabaseURL: "sqlite://" + filepath.Join(mountPath, databaseName), TenantEncryptionKey: key, EnableCORS: true, CORSAllowedOrigins: []string{request.Tenant.Origin}, EnableTenantHeaderOverride: true}}
	serviceYAML, err := yaml.Marshal(service)
	if err != nil {
		return err
	}
	validatorYAML, err := yaml.Marshal(struct {
		Tenants []validatorTenant `yaml:"tenants"`
	}{[]validatorTenant{{ID: application.ID, JWTSigningKey: application.JWTSigningKey, SessionCookieName: application.SessionCookieName}}})
	if err != nil {
		return err
	}
	receipt := fixtureReceipt{Schema: schema, InputSHA256: fmt.Sprintf("%x", sha256.Sum256(payload)), BuildIdentity: identity, AppID: request.AppID, TenantID: application.ID, MountPath: mountPath}
	receiptJSON, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	for _, file := range []struct {
		name string
		data []byte
	}{{"service.yaml", serviceYAML}, {"validator.yaml", validatorYAML}, {"receipt.json", append(receiptJSON, '\n')}} {
		if err := writeFile(filepath.Join(directory, file.name), file.data); err != nil {
			return err
		}
	}
	return nil
}

func writeFile(path string, data []byte) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create fixture output %s: %w", filepath.Base(path), err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write fixture output %s: %w", filepath.Base(path), err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close fixture output %s: %w", filepath.Base(path), err)
	}
	return nil
}

func buildIdentity() (string, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", errors.New("fixture build identity is unavailable")
	}
	identity := info.Main.Path + "@" + info.Main.Version
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" || setting.Key == "vcs.modified" {
			identity += " " + setting.Key + "=" + setting.Value
		}
	}
	return identity, nil
}

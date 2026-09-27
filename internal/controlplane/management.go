package controlplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/tyemirov/tauth/internal/tenants"
	"gorm.io/gorm"
)

const TenantsPath = "/api/management/tenants"
const maxTenantsPerOwner = 100

// PreparedRuntime owns a fully built candidate and the resources it retains.
// Publish cannot fail. Drain waits for all requests from retired snapshots.
type PreparedRuntime interface {
	Publish()
	Discard()
	Drain(context.Context) error
}
type RuntimeBuilder func(context.Context, tenants.Config) (PreparedRuntime, error)

// Management serializes persistent revisions and publication in a single service instance.
type Management struct {
	store       *Store
	integration *Integration
	build       RuntimeBuilder
	lookupTXT   func(context.Context, string) ([]string, error)
	mutation    sync.Mutex
	now         func() time.Time
}

func NewManagement(store *Store, build RuntimeBuilder, lookupTXT func(context.Context, string) ([]string, error), integration *Integration, now func() time.Time) *Management {
	return &Management{integration: integration, store: store, build: build, lookupTXT: lookupTXT, now: now}
}

type apiError struct {
	Status  int
	Code    string
	Details map[string]string
}

func (e *apiError) Error() string { return e.Code }
func failure(status int, code string) error {
	return &apiError{Status: status, Code: "management." + code}
}

type configurationInput struct {
	Provisioning      *provisioningInput `json:"provisioning,omitempty"`
	GoogleWebClientID string             `json:"google_web_client_id"`
	FrontendOrigins   []string           `json:"frontend_origins"`
	APIBaseURL        string             `json:"api_base_url"`
	LocalDevelopment  bool               `json:"local_development"`
	SessionTTL        string             `json:"session_ttl"`
	RefreshTTL        string             `json:"refresh_ttl"`
}
type configurationView struct {
	configurationInput
	Provisioning      *provisioningBinding `json:"provisioning,omitempty"`
	Revision          int64                `json:"revision"`
	SessionCookieName string               `json:"session_cookie_name"`
	RefreshCookieName string               `json:"refresh_cookie_name"`
	Providers         []string             `json:"providers"`
}

func configETag(revision int64) string { return fmt.Sprintf(`"configuration-%d"`, revision) }
func tenantETag(version int64) string  { return fmt.Sprintf(`"tenant-%d"`, version) }
func requireMatch(value, expected string) error {
	if value == "" {
		return failure(428, "precondition_required")
	}
	if value != expected {
		return failure(412, "revision_conflict")
	}
	return nil
}
func (store *Store) tenant(ctx context.Context, owner, id string) (tenantRecord, error) {
	var row tenantRecord
	err := store.db.WithContext(ctx).First(&row, "id = ? AND owner_account_id = ?", id, owner).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return row, failure(404, "tenant_not_found")
	}
	return row, err
}
func (store *Store) configuration(ctx context.Context, id string, revision int64) (tenants.FileTenant, configurationRecord, error) {
	var row configurationRecord
	q := store.db.WithContext(ctx).Where("tenant_id = ?", id)
	if revision > 0 {
		q = q.Where("revision = ?", revision)
	}
	if err := q.Order("revision DESC").First(&row).Error; err != nil {
		return tenants.FileTenant{}, row, err
	}
	var ref configurationReference
	if err := json.Unmarshal([]byte(row.Configuration), &ref); err != nil {
		return tenants.FileTenant{}, row, err
	}
	secret, err := NewSecretReference(id, ref.SecretID, configurationPurpose)
	if err != nil {
		return tenants.FileTenant{}, row, err
	}
	encoded, err := store.LoadSecret(ctx, secret)
	if err != nil {
		return tenants.FileTenant{}, row, err
	}
	var file tenants.FileTenant
	err = json.Unmarshal(encoded, &file)
	if err == nil && file.ID != id {
		err = errors.New("management.configuration_tenant_mismatch")
	}
	return file, row, err
}
func publicConfiguration(file tenants.FileTenant, row configurationRecord) configurationView {
	providers := []string{}
	if file.GoogleWebClientID != "" || file.GoogleNativeClientID != "" || len(file.GoogleNativeClients) > 0 {
		providers = append(providers, "google")
	}
	if bool(file.AppleOAuth.Enabled) {
		providers = append(providers, "apple")
	}
	if bool(file.GitHubOAuth.Enabled) {
		providers = append(providers, "github")
	}
	if bool(file.PasswordAuth.Enabled) {
		providers = append(providers, "password")
	}
	return configurationView{configurationInput: configurationInput{GoogleWebClientID: file.GoogleWebClientID, FrontendOrigins: file.TenantOrigins, APIBaseURL: row.APIBaseURL, LocalDevelopment: row.LocalDevelopment, SessionTTL: file.SessionTTL, RefreshTTL: file.RefreshTTL}, Revision: row.Revision, SessionCookieName: file.SessionCookieName, RefreshCookieName: file.RefreshCookieName, Providers: providers}
}
func canonicalAddress(raw string, local bool) (*url.URL, error) {
	address, err := url.Parse(raw)
	if err != nil || address.Host == "" || address.User != nil || address.RawQuery != "" || address.Fragment != "" || address.Path != "" || address.Opaque != "" || address.Hostname() != strings.ToLower(address.Hostname()) {
		return nil, failure(422, "origin_invalid")
	}
	host := address.Hostname()
	isLocal := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if isLocal {
		if !local || address.Scheme != "http" && address.Scheme != "https" {
			return nil, failure(422, "localhost_policy_required")
		}
	} else {
		if address.Scheme != "https" || net.ParseIP(host) != nil || !strings.Contains(host, ".") || strings.HasSuffix(host, ".") {
			return nil, failure(422, "origin_invalid")
		}
	}
	return address, nil
}
func validateConfiguration(input configurationInput) error {
	if len(input.GoogleWebClientID) > 256 || len(input.FrontendOrigins) > 20 {
		return failure(422, "configuration_invalid")
	}
	seen := map[string]bool{}
	for _, raw := range append(append([]string{}, input.FrontendOrigins...), input.APIBaseURL) {
		if raw == "" {
			continue
		}
		if _, err := canonicalAddress(raw, input.LocalDevelopment); err != nil {
			return err
		}
	}
	for _, raw := range input.FrontendOrigins {
		if raw == "" || seen[raw] {
			return failure(422, "origin_invalid")
		}
		seen[raw] = true
	}
	session, err := time.ParseDuration(input.SessionTTL)
	if err != nil || session < time.Minute || session > time.Hour {
		return failure(422, "session_ttl_invalid")
	}
	refresh, err := time.ParseDuration(input.RefreshTTL)
	if err != nil || refresh < session || refresh > 90*24*time.Hour {
		return failure(422, "refresh_ttl_invalid")
	}
	return nil
}
func initialConfiguration(id, name string) tenants.FileTenant {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return tenants.FileTenant{ID: id, DisplayName: name, JWTSigningKey: hex.EncodeToString(key), SessionCookieName: "tauth_" + id + "_session", RefreshCookieName: "tauth_" + id + "_refresh", SessionTTL: "15m", RefreshTTL: "720h", NonceTTL: "5m", TenantOrigins: []string{}}
}
func (store *Store) local(tx *gorm.DB) *Store {
	return &Store{db: tx, cipher: store.cipher, keyID: store.keyID, digestKey: store.digestKey}
}
func (store *Store) audit(ctx context.Context, owner, id, operation, result string, revision int64) error {
	return store.db.WithContext(ctx).Exec("INSERT INTO tenant_audit_events (id,actor_account_id,tenant_id,operation,revision,result) VALUES (?,?,?,?,?,?)", newID(), owner, id, operation, revision, result).Error
}

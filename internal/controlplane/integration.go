package controlplane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/tenants"
	"gorm.io/gorm"
)

const exportOperation = "session-key-export"

// BrowserHelperURL is the canonical published browser helper.
const BrowserHelperURL = "https://tauth.mprlab.com/tauth.js"
const recentAuthenticationWindow = 5 * time.Minute

// GoogleAccountLookup resolves a verified identity to its stable console account.
type GoogleAccountLookup interface {
	AuthenticateGoogleAccount(context.Context, string, authkit.GoogleAccountIdentity) (authkit.AccountProfile, bool, error)
}

// Integration supplies the provider and network boundaries for owner setup.
type Integration struct {
	validator             authkit.GoogleTokenValidator
	accounts              GoogleAccountLookup
	consoleClient, issuer string
	checker               *SetupChecker
}

// NewIntegration binds the Google audience, owner lookup, and setup checker.
func NewIntegration(validator authkit.GoogleTokenValidator, accounts GoogleAccountLookup, consoleClient, issuer string, checker *SetupChecker) *Integration {
	return &Integration{checker: checker, validator: validator, accounts: accounts, consoleClient: consoleClient, issuer: issuer}
}

type reauthentication struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"tenant_id"`
	OwnerAccountID string     `json:"-"`
	Revision       int64      `json:"revision"`
	Operation      string     `json:"operation"`
	Nonce          string     `json:"nonce"`
	CreatedAt      time.Time  `json:"created_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	ConsumedAt     *time.Time `json:"consumed_at"`
}

func (reauthentication) TableName() string { return "tenant_reauthentications" }

type keyExport struct {
	ID                 string    `json:"id"`
	TenantID           string    `json:"tenant_id"`
	OwnerAccountID     string    `json:"-"`
	ReauthenticationID string    `json:"reauthentication_id"`
	Revision           int64     `json:"revision"`
	CreatedAt          time.Time `json:"created_at"`
}

func (keyExport) TableName() string { return "tenant_key_exports" }

type integrationView struct {
	TenantID             string            `json:"tenant_id"`
	Revision             int64             `json:"revision"`
	APIBaseURL           string            `json:"api_base_url"`
	FrontendOrigins      []string          `json:"frontend_origins"`
	GoogleWebClientID    string            `json:"google_web_client_id"`
	ScriptURL            string            `json:"script_url"`
	SessionCookieName    string            `json:"session_cookie_name"`
	SessionTTL           string            `json:"session_ttl"`
	BrowserHTML          string            `json:"browser_html"`
	BackendConfiguration map[string]string `json:"backend_configuration"`
	AuthRoutes           []string          `json:"auth_routes"`
}

func (store *Store) activeConfiguration(ctx context.Context, owner, id string) (tenantRecord, tenants.FileTenant, configurationRecord, error) {
	row, err := store.tenant(ctx, owner, id)
	if err != nil {
		return row, tenants.FileTenant{}, configurationRecord{}, err
	}
	if row.State != "active" || row.ActiveRevision == nil {
		return row, tenants.FileTenant{}, configurationRecord{}, failure(409, "active_configuration_required")
	}
	file, config, err := store.configuration(ctx, id, *row.ActiveRevision)
	return row, file, config, err
}
func (store *Store) integrationView(ctx context.Context, owner, id string) (resourceResult, error) {
	row, file, config, err := store.activeConfiguration(ctx, owner, id)
	if err != nil {
		return resourceResult{}, err
	}
	if config.APIBaseURL == "" || file.GoogleWebClientID == "" {
		return resourceResult{}, failure(409, "customer_api_configuration_required")
	}
	settings, _ := json.Marshal(map[string]string{"baseUrl": config.APIBaseURL, "tenantId": row.ID})
	clientID, _ := json.Marshal(file.GoogleWebClientID)
	snippet := fmt.Sprintf(`<!doctype html>
<html lang="en"><meta charset="utf-8"><title>Application sign-in</title>
<div id="google-signin"></div><p id="status" role="status"></p>
<button id="private">Call protected API</button><button id="logout">Sign out</button>
<script src="%s"></script>
<script src="https://accounts.google.com/gsi/client" async defer></script>
<script>
const settings = %s;
window.addEventListener('load', async () => {
  const status = document.getElementById('status');
  await initAuthClient({...settings,
    onAuthenticated: profile => { status.textContent = 'Signed in as ' + profile.display_name; },
    onUnauthenticated: () => { status.textContent = 'Sign in to continue.'; }
  });
  const nonce = await requestNonce();
  google.accounts.id.initialize({client_id: %s, nonce, auto_select: false,
    callback: async response => {
      try { await exchangeGoogleCredential({credential: response.credential, nonceToken: nonce}); }
      catch (error) { status.textContent = 'Sign-in failed. Reload to try again.'; }
    }
  });
  google.accounts.id.renderButton(document.getElementById('google-signin'), {type: 'standard'});
  document.getElementById('private').onclick = async () => {
    const response = await apiFetch(settings.baseUrl + '/private');
    status.textContent = response.ok ? 'Protected API accepted this session.' : 'Sign in to call this API.';
  };
  document.getElementById('logout').onclick = () => logout();
});
</script></html>`, BrowserHelperURL, settings, clientID)
	view := integrationView{TenantID: row.ID, Revision: config.Revision, APIBaseURL: config.APIBaseURL, FrontendOrigins: file.TenantOrigins, GoogleWebClientID: file.GoogleWebClientID, ScriptURL: BrowserHelperURL, SessionCookieName: file.SessionCookieName, SessionTTL: file.SessionTTL, BrowserHTML: snippet, BackendConfiguration: map[string]string{"TAUTH_TENANT_ID": row.ID, "TAUTH_SESSION_COOKIE": file.SessionCookieName, "TAUTH_SESSION_KEY_BASE64": "<install exported key in the backend secret store>", "TAUTH_API_ORIGIN": config.APIBaseURL, "TAUTH_FRONTEND_ORIGIN": file.TenantOrigins[0]}, AuthRoutes: []string{"POST /auth/nonce", "POST /auth/google", "GET /auth/session", "POST /auth/refresh", "POST /auth/logout", "GET /me"}}
	return resourceResult{Status: 200, Body: view, ETag: configETag(config.Revision)}, nil
}
func (management *Management) integrationWrite(ctx *gin.Context, store *Store, owner string, parts []string, data []byte) (resourceResult, error) {
	row, file, config, err := store.activeConfiguration(ctx.Request.Context(), owner, parts[0])
	if err != nil {
		return resourceResult{}, err
	}
	if err := requireMatch(ctx.GetHeader("If-Match"), configETag(config.Revision)); err != nil {
		return resourceResult{}, err
	}
	now := management.now().UTC()
	if parts[1] == "reauthentications" {
		var input struct {
			Revision  int64  `json:"revision"`
			Operation string `json:"operation"`
		}
		if err := decodeBody(data, &input); err != nil {
			return resourceResult{}, err
		}
		if input.Revision != config.Revision || input.Operation != exportOperation {
			return resourceResult{}, failure(422, "reauthentication_operation_invalid")
		}
		proof := reauthentication{ID: newID(), TenantID: row.ID, OwnerAccountID: owner, Revision: config.Revision, Operation: exportOperation, Nonce: newID() + newID(), CreatedAt: now, ExpiresAt: now.Add(recentAuthenticationWindow)}
		if err := store.db.Create(&proof).Error; err != nil {
			return resourceResult{}, err
		}
		if err := store.audit(ctx.Request.Context(), owner, row.ID, "reauthentication.created", "succeeded", config.Revision); err != nil {
			return resourceResult{}, err
		}
		return resourceResult{Status: 201, Body: proof, Location: TenantsPath + "/" + row.ID + "/reauthentications/" + proof.ID}, nil
	}
	var input struct {
		ReauthenticationID string `json:"reauthentication_id"`
		GoogleIDToken      string `json:"google_id_token"`
	}
	if err := decodeBody(data, &input); err != nil {
		return resourceResult{}, err
	}
	var proof reauthentication
	if err := store.db.First(&proof, "id = ? AND tenant_id = ? AND owner_account_id = ?", input.ReauthenticationID, row.ID, owner).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return resourceResult{}, failure(403, "reauthentication_required")
		}
		return resourceResult{}, err
	}
	if proof.ConsumedAt != nil {
		return resourceResult{}, failure(409, "reauthentication_consumed")
	}
	if proof.Operation != exportOperation || proof.Revision != config.Revision || !now.Before(proof.ExpiresAt) {
		return resourceResult{}, failure(403, "reauthentication_expired")
	}
	validationCtx, cancel := context.WithTimeout(ctx.Request.Context(), 5*time.Second)
	defer cancel()
	payload, err := management.integration.validator.Validate(validationCtx, input.GoogleIDToken, management.integration.consoleClient)
	if err != nil {
		return resourceResult{}, failure(403, "reauthentication_invalid")
	}
	issuer, _ := payload.Claims["iss"].(string)
	subject, _ := payload.Claims["sub"].(string)
	nonce, _ := payload.Claims["nonce"].(string)
	verified, _ := payload.Claims["email_verified"].(bool)
	issued, ok := payload.Claims["iat"].(float64)
	if (issuer != "https://accounts.google.com" && issuer != "accounts.google.com") || subject == "" || nonce != proof.Nonce || !verified || !ok || issued < float64(now.Add(-recentAuthenticationWindow).Unix()) || issued > float64(now.Add(30*time.Second).Unix()) || issued < float64(proof.CreatedAt.Unix()) {
		return resourceResult{}, failure(403, "reauthentication_invalid")
	}
	profile, found, err := management.integration.accounts.AuthenticateGoogleAccount(ctx.Request.Context(), ConsoleTenantID, authkit.GoogleAccountIdentity{Subject: subject, UserEmail: readClaimString(payload.Claims, "email")})
	if err != nil && !errors.Is(err, authkit.ErrAccountNotFound) && !errors.Is(err, authkit.ErrAccountNotActive) && !errors.Is(err, authkit.ErrAccountDisabled) {
		return resourceResult{}, fmt.Errorf("management.reauthenticate_owner: %w", err)
	}
	if err != nil || !found {
		return resourceResult{}, failure(403, "reauthentication_owner_mismatch")
	}
	bound, err := store.OwnerForSubject(ctx.Request.Context(), management.integration.issuer, profile.AccountID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return resourceResult{}, fmt.Errorf("management.read_reauthenticated_owner: %w", err)
	}
	if err != nil || bound.ID != owner {
		return resourceResult{}, failure(403, "reauthentication_owner_mismatch")
	}
	if err := store.db.Model(&proof).Update("consumed_at", now).Error; err != nil {
		return resourceResult{}, err
	}
	receipt := keyExport{ID: newID(), TenantID: row.ID, OwnerAccountID: owner, ReauthenticationID: proof.ID, Revision: config.Revision, CreatedAt: now}
	if err := store.db.Create(&receipt).Error; err != nil {
		return resourceResult{}, err
	}
	effective, err := tenants.LoadResolvedConfig(tenants.FileDocument{Tenants: []tenants.FileTenant{file}})
	if err != nil {
		return resourceResult{}, err
	}
	if err := store.audit(ctx.Request.Context(), owner, row.ID, "session-key.exported", "succeeded", config.Revision); err != nil {
		return resourceResult{}, err
	}
	return resourceResult{Status: 201, Body: struct {
		keyExport
		SessionKey string `json:"session_key_base64"`
	}{receipt, base64.StdEncoding.EncodeToString(effective.Tenants()[0].SigningKey())}, ReceiptBody: receipt, Location: TenantsPath + "/" + row.ID + "/key-exports/" + receipt.ID}, nil
}
func (store *Store) integrationResource(ctx context.Context, owner string, parts []string) (resourceResult, error) {
	if parts[1] == "integration" {
		return store.integrationView(ctx, owner, parts[0])
	}
	var target any
	switch parts[1] {
	case "reauthentications":
		target = &reauthentication{}
	case "key-exports":
		target = &keyExport{}
	}
	err := store.db.WithContext(ctx).First(target, "id = ? AND tenant_id = ? AND owner_account_id = ?", parts[2], parts[0], owner).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = failure(404, "integration_resource_not_found")
	}
	return resourceResult{Status: 200, Body: target}, err
}

func readClaimString(claims map[string]interface{}, key string) string {
	value, _ := claims[key].(string)
	return value
}

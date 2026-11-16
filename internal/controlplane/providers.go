package controlplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/tenants"
	"gorm.io/gorm"
)

const providerResourceSegment = "providers"
const providerConfigurationOperation = "configuration.providers.saved"
const providerConfigurationProvenance = "provider-configuration"

type providerPatch struct {
	GoogleNativeClients *[]tenants.FileNativeGoogleClient `json:"google_native_clients"`
	Apple               *appleProviderPatch               `json:"apple"`
	EmailDelivery       *emailDeliveryPatch               `json:"email_delivery"`
}
type appleProviderPatch struct {
	Enabled         *bool     `json:"enabled"`
	ClientID        *string   `json:"client_id"`
	NativeClientIDs *[]string `json:"native_client_ids"`
	TeamID          *string   `json:"team_id"`
	KeyID           *string   `json:"key_id"`
	RedirectURI     *string   `json:"redirect_uri"`
	PrivateKey      *string   `json:"private_key"`
}
type emailDeliveryPatch struct {
	ServerAddress            *string `json:"server_address"`
	APIKey                   *string `json:"api_key"`
	EmailVerificationURL     *string `json:"email_verification_url"`
	PasswordResetURL         *string `json:"password_reset_url"`
	PasswordLinkURL          *string `json:"password_link_url"`
	ConnectionTimeoutSeconds *int    `json:"connection_timeout_seconds"`
	OperationTimeoutSeconds  *int    `json:"operation_timeout_seconds"`
}
type emailDeliveryView struct {
	ServerAddress            string `json:"server_address"`
	KeyConfigured            bool   `json:"key_configured"`
	EmailVerificationURL     string `json:"email_verification_url"`
	PasswordResetURL         string `json:"password_reset_url"`
	PasswordLinkURL          string `json:"password_link_url"`
	ConnectionTimeoutSeconds int    `json:"connection_timeout_seconds"`
	OperationTimeoutSeconds  int    `json:"operation_timeout_seconds"`
}
type nativeProviderView struct {
	AcquisitionFlow tenants.NativeGoogleAcquisitionFlow `json:"acquisition_flow"`
	Platform        string                              `json:"platform"`
	ClientID        string                              `json:"client_id"`
	RedirectURIs    []string                            `json:"redirect_uris,omitempty"`
}
type appleProviderView struct {
	Enabled         bool     `json:"enabled"`
	ClientID        string   `json:"client_id"`
	NativeClientIDs []string `json:"native_client_ids"`
	TeamID          string   `json:"team_id"`
	KeyID           string   `json:"key_id"`
	RedirectURI     string   `json:"redirect_uri"`
	KeyConfigured   bool     `json:"key_configured"`
}
type providerView struct {
	Revision            int64                `json:"revision"`
	GoogleNativeClients []nativeProviderView `json:"google_native_clients"`
	Apple               appleProviderView    `json:"apple"`
	EmailDelivery       emailDeliveryView    `json:"email_delivery"`
}

func publicProviders(file tenants.FileTenant, revision int64) providerView {
	clients := make([]nativeProviderView, 0, len(file.GoogleNativeClients)+1)
	if id := strings.TrimSpace(file.GoogleNativeClientID); id != "" {
		clients = append(clients, nativeProviderView{AcquisitionFlow: tenants.NativeGoogleAuthorizationCode, Platform: "desktop", ClientID: id})
	}
	for _, client := range file.GoogleNativeClients {
		clients = append(clients, nativeProviderView{AcquisitionFlow: client.AcquisitionFlow.Effective(), Platform: strings.ToLower(strings.TrimSpace(client.Platform)), ClientID: strings.TrimSpace(client.ClientID), RedirectURIs: client.RedirectURIs})
	}
	email := file.AccountManagement.EmailDelivery
	apple := file.AppleOAuth
	return providerView{
		Revision:            revision,
		GoogleNativeClients: clients,
		Apple: appleProviderView{
			Enabled: bool(apple.Enabled), ClientID: apple.ClientID,
			NativeClientIDs: append([]string{}, apple.NativeClientIDs...),
			TeamID:          apple.TeamID, KeyID: apple.KeyID, RedirectURI: apple.RedirectURI,
			KeyConfigured: strings.TrimSpace(apple.PrivateKey) != "" || strings.TrimSpace(apple.PrivateKeyBase64) != "",
		},
		EmailDelivery: emailDeliveryView{
			ServerAddress: email.ServerAddress, KeyConfigured: strings.TrimSpace(email.APIKey) != "",
			EmailVerificationURL: email.EmailVerificationURL, PasswordResetURL: email.PasswordResetURL,
			PasswordLinkURL: email.PasswordLinkURL, ConnectionTimeoutSeconds: email.ConnectionTimeoutSeconds,
			OperationTimeoutSeconds: email.OperationTimeoutSeconds,
		},
	}
}
func providerAppScope(ctx *gin.Context, tenant tenantRecord) error {
	if principal := provisioningPrincipal(ctx); principal != nil && principal.AppID != tenant.AppID {
		return failure(403, "app_grant_required")
	}
	return nil
}
func (store *Store) readProviders(ctx *gin.Context, owner, id string) (resourceResult, error) {
	tenant, err := store.tenant(ctx.Request.Context(), owner, id)
	if err != nil {
		return resourceResult{}, err
	}
	if err = providerAppScope(ctx, tenant); err != nil {
		return resourceResult{}, err
	}
	file, row, err := store.configuration(ctx.Request.Context(), id, 0)
	if err != nil {
		return resourceResult{}, err
	}
	return resourceResult{Status: 200, Body: publicProviders(file, row.Revision), ETag: configETag(row.Revision)}, nil
}
func hasJSONNull(value any) bool {
	switch entry := value.(type) {
	case nil:
		return true
	case map[string]any:
		for _, child := range entry {
			if hasJSONNull(child) {
				return true
			}
		}
	case []any:
		for _, child := range entry {
			if hasJSONNull(child) {
				return true
			}
		}
	}
	return false
}

// providerConfigurationJSON compares empty optional provider collections consistently.
func providerConfigurationJSON(file tenants.FileTenant) ([]byte, error) {
	file.GoogleNativeClients = append([]tenants.FileNativeGoogleClient(nil), file.GoogleNativeClients...)
	for index := range file.GoogleNativeClients {
		file.GoogleNativeClients[index].AcquisitionFlow = file.GoogleNativeClients[index].AcquisitionFlow.Effective()
		if len(file.GoogleNativeClients[index].RedirectURIs) == 0 {
			file.GoogleNativeClients[index].RedirectURIs = nil
		}
	}
	if len(file.AppleOAuth.NativeClientIDs) == 0 {
		file.AppleOAuth.NativeClientIDs = nil
	}
	return json.Marshal(file)
}
func (store *Store) writeProviders(ctx *gin.Context, owner, id string, data []byte) (resourceResult, error) {
	tenant, err := store.tenant(ctx.Request.Context(), owner, id)
	if err != nil {
		return resourceResult{}, err
	}
	if err = providerAppScope(ctx, tenant); err != nil {
		return resourceResult{}, err
	}
	file, row, err := store.configuration(ctx.Request.Context(), id, 0)
	if err != nil {
		return resourceResult{}, err
	}
	if err = requireMatch(ctx.GetHeader("If-Match"), configETag(row.Revision)); err != nil {
		return resourceResult{}, err
	}
	var patch providerPatch
	if err = decodeBody(data, &patch); err != nil {
		return resourceResult{}, err
	}
	var raw any
	if err = json.Unmarshal(data, &raw); err != nil || hasJSONNull(raw) {
		return resourceResult{}, failure(400, "body_invalid")
	}
	var binding provisioningBinding
	if err = store.db.Where("tenant_id = ?", id).Take(&binding).Error; err == nil {
		return resourceResult{}, failure(409, "configuration_provisioning_bound")
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return resourceResult{}, err
	}
	if tenant.ActiveRevision == nil || row.Revision != *tenant.ActiveRevision {
		var count int64
		if err = store.db.Model(&auditEvent{}).Where("tenant_id = ? AND revision = ? AND operation = ?", id, row.Revision, providerConfigurationOperation).Count(&count).Error; err != nil {
			return resourceResult{}, err
		}
		if count != 1 {
			return resourceResult{}, failure(409, "configuration_draft_conflict")
		}
	}
	before, err := providerConfigurationJSON(file)
	if err != nil {
		return resourceResult{}, err
	}
	if patch.GoogleNativeClients != nil {
		file.GoogleNativeClientID = ""
		file.GoogleNativeClients = *patch.GoogleNativeClients
	}
	if apple := patch.Apple; apple != nil {
		if apple.Enabled != nil {
			if *apple.Enabled {
				file.AppleOAuth.Enabled = true
			} else {
				file.AppleOAuth.Enabled = false
			}
		}
		for _, field := range []struct {
			input  *string
			target *string
		}{{apple.ClientID, &file.AppleOAuth.ClientID}, {apple.TeamID, &file.AppleOAuth.TeamID}, {apple.KeyID, &file.AppleOAuth.KeyID}, {apple.RedirectURI, &file.AppleOAuth.RedirectURI}} {
			if field.input != nil {
				*field.target = strings.TrimSpace(*field.input)
			}
		}
		if apple.NativeClientIDs != nil {
			file.AppleOAuth.NativeClientIDs = *apple.NativeClientIDs
		}
		if apple.PrivateKey != nil {
			if strings.TrimSpace(*apple.PrivateKey) == "" {
				return resourceResult{}, failure(422, "provider_configuration_invalid")
			}
			file.AppleOAuth.PrivateKey = strings.TrimSpace(*apple.PrivateKey)
			file.AppleOAuth.PrivateKeyBase64 = ""
		}
	}
	if email := patch.EmailDelivery; email != nil {
		stored := &file.AccountManagement.EmailDelivery
		if (email.ConnectionTimeoutSeconds != nil && *email.ConnectionTimeoutSeconds <= 0) || (email.OperationTimeoutSeconds != nil && *email.OperationTimeoutSeconds <= 0) {
			return resourceResult{}, failure(422, "provider_configuration_invalid")
		}
		if email.ServerAddress != nil && strings.TrimSpace(*email.ServerAddress) != strings.TrimSpace(stored.ServerAddress) && email.APIKey == nil {
			return resourceResult{}, failure(422, "provider_configuration_invalid")
		}
		if email.APIKey != nil && strings.TrimSpace(*email.APIKey) == "" {
			return resourceResult{}, failure(422, "provider_configuration_invalid")
		}
		for _, field := range []struct {
			input  *string
			target *string
		}{{email.ServerAddress, &stored.ServerAddress}, {email.APIKey, &stored.APIKey}, {email.EmailVerificationURL, &stored.EmailVerificationURL}, {email.PasswordResetURL, &stored.PasswordResetURL}, {email.PasswordLinkURL, &stored.PasswordLinkURL}} {
			if field.input != nil {
				*field.target = strings.TrimSpace(*field.input)
			}
		}
		if email.ConnectionTimeoutSeconds != nil {
			stored.ConnectionTimeoutSeconds = *email.ConnectionTimeoutSeconds
		}
		if email.OperationTimeoutSeconds != nil {
			stored.OperationTimeoutSeconds = *email.OperationTimeoutSeconds
		}
	}
	if _, err = tenants.LoadResolvedConfig(tenants.FileDocument{Tenants: []tenants.FileTenant{file}}); err != nil {
		return resourceResult{}, failure(422, "provider_configuration_invalid")
	}
	after, err := providerConfigurationJSON(file)
	if err != nil {
		return resourceResult{}, err
	}
	if bytes.Equal(before, after) {
		return resourceResult{Status: 200, Body: publicProviders(file, row.Revision), ETag: configETag(row.Revision)}, nil
	}
	row.Revision++
	if err = store.saveConfiguration(ctx.Request.Context(), file, row.Revision, providerConfigurationProvenance); err != nil {
		return resourceResult{}, err
	}
	if err = store.db.Model(&configurationRecord{}).Where("tenant_id = ? AND revision = ?", id, row.Revision).Updates(map[string]any{"api_base_url": row.APIBaseURL, "local_development": row.LocalDevelopment, "operator_integration": row.OperatorIntegration}).Error; err != nil {
		return resourceResult{}, err
	}
	if err = store.audit(ctx.Request.Context(), owner, id, providerConfigurationOperation, "succeeded", row.Revision); err != nil {
		return resourceResult{}, err
	}
	return resourceResult{Status: 200, Body: publicProviders(file, row.Revision), ETag: configETag(row.Revision)}, nil
}

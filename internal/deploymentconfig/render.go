// Package deploymentconfig converts deployment resource contributions into
// TAuth's native configuration contract.
package deploymentconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/oauthserver"
	"github.com/tyemirov/tauth/internal/tenants"
	"gopkg.in/yaml.v3"
)

const (
	// RequestSchemaVersion is the accepted deployment-render request version.
	RequestSchemaVersion = 1

	maximumRequestBytes = 1024 * 1024

	resourceKindAuthorizationServer = "tauth_authorization_server"
	resourceKindTenant              = "tauth_tenant"

	googleWebClientOutput = "google-web-client-id"
	jwtSigningKeyOutput   = "jwt-signing-key"
	applePrivateKeyOutput = "apple-private-key"
)

var (
	errInvalidRequest = errors.New("deployment_config.invalid_request")
	errInvalidOutput  = errors.New("deployment_config.invalid_output")
	errInvalidConfig  = errors.New("deployment_config.invalid_config")
)

// Render reads one strict deployment request and returns validated TAuth YAML.
func Render(reader io.Reader) ([]byte, error) {
	request, decodeErr := decodeRequest(reader)
	if decodeErr != nil {
		return nil, decodeErr
	}

	document, buildErr := buildDocument(request)
	if buildErr != nil {
		return nil, buildErr
	}
	payload, marshalErr := yaml.Marshal(document)
	if marshalErr != nil {
		return nil, fmt.Errorf("%w: encode native config: %v", errInvalidConfig, marshalErr)
	}
	if validateErr := validateDocument(payload); validateErr != nil {
		return nil, validateErr
	}
	return payload, nil
}

type request struct {
	SchemaVersion int            `json:"schema_version"`
	Contributions []contribution `json:"contributions"`
}

type contribution struct {
	Owner   string                    `json:"owner"`
	ID      string                    `json:"id"`
	Kind    string                    `json:"kind"`
	Desired json.RawMessage           `json:"desired"`
	Outputs map[string]resourceOutput `json:"outputs"`
}

type resourceOutput struct {
	Value      string `json:"value"`
	Digest     string `json:"digest,omitempty"`
	Visibility string `json:"visibility,omitempty"`
}

type authorizationServerResource struct {
	Kind       string                      `json:"kind"`
	ID         string                      `json:"id"`
	Capability string                      `json:"capability"`
	Version    int                         `json:"version"`
	Server     authorizationServerSettings `json:"server"`
}

type authorizationServerSettings struct {
	Issuer                  string               `json:"issuer" yaml:"issuer"`
	AuthorizationEndpoint   string               `json:"authorization_endpoint" yaml:"authorization_endpoint"`
	TokenEndpoint           string               `json:"token_endpoint" yaml:"token_endpoint"`
	RevocationEndpoint      string               `json:"revocation_endpoint" yaml:"revocation_endpoint"`
	JWKSURI                 string               `json:"jwks_uri" yaml:"jwks_uri"`
	LoginEndpoint           string               `json:"login_endpoint" yaml:"login_endpoint"`
	ConsentEndpoint         string               `json:"consent_endpoint" yaml:"consent_endpoint"`
	AuthorizationRequestTTL string               `json:"authorization_request_ttl" yaml:"authorization_request_ttl"`
	AuthorizationCodeTTL    string               `json:"authorization_code_ttl" yaml:"authorization_code_ttl"`
	ActiveSigningKeyID      string               `json:"active_signing_key_id" yaml:"active_signing_key_id"`
	SigningKeys             []signingKeyResource `json:"signing_keys" yaml:"-"`
	ClientMetadata          clientMetadata       `json:"client_metadata" yaml:"client_metadata"`
}

type signingKeyResource struct {
	ID              string             `json:"id"`
	PrivateKey      *resourceReference `json:"private_key,omitempty"`
	PublicKeyBase64 string             `json:"public_key_base64,omitempty"`
}

type clientMetadata struct {
	RequestTimeout  string `json:"request_timeout" yaml:"request_timeout"`
	MaximumBytes    int64  `json:"maximum_bytes" yaml:"maximum_bytes"`
	MinimumCacheTTL string `json:"minimum_cache_ttl" yaml:"minimum_cache_ttl"`
	MaximumCacheTTL string `json:"maximum_cache_ttl" yaml:"maximum_cache_ttl"`
}

type tenantResource struct {
	Kind       string         `json:"kind"`
	ID         string         `json:"id"`
	Capability string         `json:"capability"`
	Version    int            `json:"version"`
	Tenant     tenantSettings `json:"tenant"`
}

type tenantSettings struct {
	ID                  string                    `json:"id"`
	DisplayName         string                    `json:"display_name"`
	Origins             []string                  `json:"origins"`
	GoogleWebClientID   resourceReference         `json:"google_web_client_id"`
	GoogleNativeClients []nativeClientResource    `json:"google_native_clients,omitempty"`
	AppleOAuth          *appleOAuthResource       `json:"apple_oauth,omitempty"`
	PasswordAuth        passwordAuthResource      `json:"password_auth,omitempty"`
	AccountManagement   accountManagementResource `json:"account_management,omitempty"`
	JWTSigningKey       resourceReference         `json:"jwt_signing_key"`
	Cookie              cookieSettings            `json:"cookie"`
	OAuth               *tenantOAuth              `json:"oauth,omitempty"`
}

type resourceReference struct {
	Resource string `json:"resource"`
	Output   string `json:"output"`
}

type nativeClientResource struct {
	Platform     string            `json:"platform"`
	ClientID     resourceReference `json:"client_id"`
	RedirectURIs []string          `json:"redirect_uris"`
}

type appleOAuthResource struct {
	ClientID        string            `json:"client_id"`
	NativeClientIDs []string          `json:"native_client_ids,omitempty"`
	TeamID          string            `json:"team_id"`
	KeyID           string            `json:"key_id"`
	PrivateKey      resourceReference `json:"private_key"`
	RedirectURI     string            `json:"redirect_uri"`
}

type passwordAuthResource struct {
	Enabled bool `json:"enabled"`
}

type accountManagementResource struct {
	Enabled               bool                   `json:"enabled" yaml:"enabled"`
	PasswordSignup        passwordSignup         `json:"password_signup,omitempty" yaml:"password_signup"`
	ReturnChallengeTokens bool                   `json:"return_challenge_tokens" yaml:"return_challenge_tokens"`
	EmailVerificationTTL  string                 `json:"email_verification_ttl" yaml:"email_verification_ttl"`
	EmailDelivery         *emailDeliveryResource `json:"email_delivery,omitempty"`
	PasswordResetTTL      string                 `json:"password_reset_ttl" yaml:"password_reset_ttl"`
}

type emailDeliveryResource struct {
	ServerAddress            string            `json:"server_address"`
	APIKey                   resourceReference `json:"api_key"`
	EmailVerificationURL     string            `json:"email_verification_url"`
	PasswordResetURL         string            `json:"password_reset_url"`
	PasswordLinkURL          string            `json:"password_link_url"`
	ConnectionTimeoutSeconds int               `json:"connection_timeout_seconds"`
	OperationTimeoutSeconds  int               `json:"operation_timeout_seconds"`
}

type passwordSignup struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
}

type cookieSettings struct {
	Domain      string `json:"domain"`
	SessionName string `json:"session_name"`
	RefreshName string `json:"refresh_name"`
}

type tenantOAuth struct {
	Enabled                      bool                  `json:"-" yaml:"enabled"`
	AccessTokenTTL               string                `json:"access_token_ttl" yaml:"access_token_ttl"`
	RefreshTokenTTL              string                `json:"refresh_token_ttl" yaml:"refresh_token_ttl"`
	ConsentTTL                   string                `json:"consent_ttl" yaml:"consent_ttl"`
	AllowClientMetadataDocuments bool                  `json:"allow_client_metadata_documents" yaml:"allow_client_metadata_documents"`
	Resources                    []tenantOAuthResource `json:"resources" yaml:"resources"`
	Clients                      []tenantOAuthClient   `json:"clients" yaml:"clients"`
}

type tenantOAuthResource struct {
	Identifier  string             `json:"identifier" yaml:"identifier"`
	DisplayName string             `json:"display_name" yaml:"display_name"`
	Scopes      []tenantOAuthScope `json:"scopes" yaml:"scopes"`
}

type tenantOAuthScope struct {
	Identifier  string `json:"identifier" yaml:"identifier"`
	DisplayName string `json:"display_name" yaml:"display_name"`
	Description string `json:"description" yaml:"description"`
}

type tenantOAuthClient struct {
	ID                string             `json:"id" yaml:"id"`
	DisplayName       string             `json:"display_name" yaml:"display_name"`
	ApplicationType   string             `json:"application_type" yaml:"application_type"`
	RedirectURIs      []string           `json:"redirect_uris" yaml:"redirect_uris"`
	LoopbackPortRange *loopbackPortRange `json:"loopback_port_range,omitempty" yaml:"loopback_port_range,omitempty"`
	Grants            []tenantOAuthGrant `json:"grants" yaml:"grants"`
}

type loopbackPortRange struct {
	Minimum int `json:"minimum" yaml:"minimum"`
	Maximum int `json:"maximum" yaml:"maximum"`
}

type tenantOAuthGrant struct {
	Resource string   `json:"resource" yaml:"resource"`
	Scopes   []string `json:"scopes" yaml:"scopes"`
}

type nativeDocument struct {
	Server  nativeServer       `yaml:"server"`
	OAuth   *nativeOAuthServer `yaml:"oauth,omitempty"`
	Tenants []nativeTenant     `yaml:"tenants"`
}

type nativeServer struct {
	ListenAddr                  string   `yaml:"listen_addr"`
	DatabaseURL                 string   `yaml:"database_url"`
	EnableCORS                  bool     `yaml:"enable_cors"`
	CORSAllowedOrigins          []string `yaml:"cors_allowed_origins"`
	CORSAllowedOriginExceptions []string `yaml:"cors_allowed_origin_exceptions"`
	EnableTenantHeaderOverride  bool     `yaml:"enable_tenant_header_override"`
}

type nativeOAuthServer struct {
	Enabled                     bool               `yaml:"enabled"`
	AllowInsecureHTTP           bool               `yaml:"allow_insecure_http"`
	SigningKeys                 []nativeSigningKey `yaml:"signing_keys"`
	authorizationServerSettings `yaml:",inline"`
}

type nativeSigningKey struct {
	ID               string `yaml:"id"`
	PrivateKeyBase64 string `yaml:"private_key_base64,omitempty"`
	PublicKeyBase64  string `yaml:"public_key_base64,omitempty"`
}

type nativeTenant struct {
	ID                  string                   `yaml:"id"`
	DisplayName         string                   `yaml:"display_name"`
	TenantOrigins       []string                 `yaml:"tenant_origins"`
	GoogleWebClientID   string                   `yaml:"google_web_client_id"`
	GoogleNativeClients []nativeGoogleClient     `yaml:"google_native_clients,omitempty"`
	AppleOAuth          *nativeAppleOAuth        `yaml:"apple_oauth,omitempty"`
	PasswordAuth        *nativePasswordAuth      `yaml:"password_auth,omitempty"`
	AccountManagement   *nativeAccountManagement `yaml:"account_management,omitempty"`
	OAuth               *tenantOAuth             `yaml:"oauth,omitempty"`
	JWTSigningKey       string                   `yaml:"jwt_signing_key"`
	CookieDomain        string                   `yaml:"cookie_domain"`
	SessionCookieName   string                   `yaml:"session_cookie_name"`
	RefreshCookieName   string                   `yaml:"refresh_cookie_name"`
	SessionTTL          string                   `yaml:"session_ttl"`
	RefreshTTL          string                   `yaml:"refresh_ttl"`
	NonceTTL            string                   `yaml:"nonce_ttl"`
	AllowInsecureHTTP   bool                     `yaml:"allow_insecure_http"`
}

type nativeGoogleClient struct {
	Platform     string   `yaml:"platform"`
	ClientID     string   `yaml:"client_id"`
	RedirectURIs []string `yaml:"redirect_uris"`
}

type nativeAppleOAuth struct {
	Enabled          bool     `yaml:"enabled"`
	ClientID         string   `yaml:"client_id"`
	NativeClientIDs  []string `yaml:"native_client_ids,omitempty"`
	TeamID           string   `yaml:"team_id"`
	KeyID            string   `yaml:"key_id"`
	PrivateKeyBase64 string   `yaml:"private_key_base64"`
	RedirectURI      string   `yaml:"redirect_uri"`
}

type nativeAccountManagement struct {
	Enabled               bool                 `yaml:"enabled"`
	PasswordSignup        passwordSignup       `yaml:"password_signup"`
	ReturnChallengeTokens bool                 `yaml:"return_challenge_tokens"`
	EmailVerificationTTL  string               `yaml:"email_verification_ttl"`
	EmailDelivery         *nativeEmailDelivery `yaml:"email_delivery,omitempty"`
	PasswordResetTTL      string               `yaml:"password_reset_ttl"`
}

type nativeEmailDelivery struct {
	ServerAddress            string `yaml:"server_address"`
	APIKey                   string `yaml:"api_key"`
	EmailVerificationURL     string `yaml:"email_verification_url"`
	PasswordResetURL         string `yaml:"password_reset_url"`
	PasswordLinkURL          string `yaml:"password_link_url"`
	ConnectionTimeoutSeconds int    `yaml:"connection_timeout_seconds"`
	OperationTimeoutSeconds  int    `yaml:"operation_timeout_seconds"`
}

type nativePasswordAuth struct {
	Enabled bool `yaml:"enabled"`
}

func decodeRequest(reader io.Reader) (request, error) {
	limited := io.LimitReader(reader, maximumRequestBytes+1)
	payload, readErr := io.ReadAll(limited)
	if readErr != nil {
		return request{}, fmt.Errorf("%w: read request: %v", errInvalidRequest, readErr)
	}
	if len(payload) > maximumRequestBytes {
		return request{}, fmt.Errorf("%w: request exceeds %d bytes", errInvalidRequest, maximumRequestBytes)
	}
	var decoded request
	if decodeErr := strictJSON(payload, &decoded); decodeErr != nil {
		return request{}, fmt.Errorf("%w: %v", errInvalidRequest, decodeErr)
	}
	if decoded.SchemaVersion != RequestSchemaVersion {
		return request{}, fmt.Errorf("%w: schema_version must be %d", errInvalidRequest, RequestSchemaVersion)
	}
	return decoded, nil
}

func strictJSON(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decodeErr := decoder.Decode(target); decodeErr != nil {
		return decodeErr
	}
	if decodeErr := decoder.Decode(&struct{}{}); !errors.Is(decodeErr, io.EOF) {
		if decodeErr == nil {
			return errors.New("request must contain one JSON document")
		}
		return decodeErr
	}
	return nil
}

func buildDocument(renderRequest request) (nativeDocument, error) {
	document := nativeDocument{
		Server: nativeServer{
			ListenAddr:                  ":8080",
			DatabaseURL:                 "sqlite:///data/tauth.db",
			EnableCORS:                  true,
			CORSAllowedOriginExceptions: []string{"https://accounts.google.com"},
		},
		Tenants: []nativeTenant{},
	}
	originSet := map[string]struct{}{"https://accounts.google.com": {}}
	identities := make(map[string]struct{}, len(renderRequest.Contributions))
	for _, item := range renderRequest.Contributions {
		identity := strings.TrimSpace(item.Owner) + "/" + strings.TrimSpace(item.ID)
		if strings.TrimSpace(item.Owner) == "" || strings.TrimSpace(item.ID) == "" {
			return nativeDocument{}, fmt.Errorf("%w: contribution owner and id must be nonempty", errInvalidRequest)
		}
		if _, exists := identities[identity]; exists {
			return nativeDocument{}, fmt.Errorf("%w: duplicate contribution %s", errInvalidRequest, identity)
		}
		identities[identity] = struct{}{}
		switch item.Kind {
		case resourceKindAuthorizationServer:
			if document.OAuth != nil {
				return nativeDocument{}, fmt.Errorf("%w: multiple authorization-server contributions", errInvalidRequest)
			}
			oauthServer, buildErr := buildAuthorizationServer(item)
			if buildErr != nil {
				return nativeDocument{}, buildErr
			}
			document.OAuth = &oauthServer
		case resourceKindTenant:
			tenant, buildErr := buildTenant(item)
			if buildErr != nil {
				return nativeDocument{}, buildErr
			}
			document.Tenants = append(document.Tenants, tenant)
			for _, origin := range tenant.TenantOrigins {
				originSet[origin] = struct{}{}
			}
			if len(tenant.GoogleNativeClients) > 0 || tenant.AppleOAuth != nil && len(tenant.AppleOAuth.NativeClientIDs) > 0 {
				document.Server.EnableTenantHeaderOverride = true
			}
		default:
			return nativeDocument{}, fmt.Errorf("%w: unsupported contribution kind %q", errInvalidRequest, item.Kind)
		}
	}
	sort.Slice(document.Tenants, func(left, right int) bool {
		return document.Tenants[left].ID < document.Tenants[right].ID
	})
	document.Server.CORSAllowedOrigins = make([]string, 0, len(originSet))
	for origin := range originSet {
		document.Server.CORSAllowedOrigins = append(document.Server.CORSAllowedOrigins, origin)
	}
	sort.Strings(document.Server.CORSAllowedOrigins)
	return document, nil
}

func buildAuthorizationServer(item contribution) (nativeOAuthServer, error) {
	var resource authorizationServerResource
	if decodeErr := strictJSON(item.Desired, &resource); decodeErr != nil {
		return nativeOAuthServer{}, fmt.Errorf("%w: contribution %s/%s: %v", errInvalidRequest, item.Owner, item.ID, decodeErr)
	}
	if resource.Kind != resourceKindAuthorizationServer || resource.ID != item.ID || resource.Version != 1 {
		return nativeOAuthServer{}, fmt.Errorf("%w: contribution %s/%s identity is inconsistent", errInvalidRequest, item.Owner, item.ID)
	}
	keys := make([]nativeSigningKey, 0, len(resource.Server.SigningKeys))
	for _, key := range resource.Server.SigningKeys {
		nativeKey := nativeSigningKey{ID: key.ID, PublicKeyBase64: key.PublicKeyBase64}
		if key.PrivateKey != nil {
			outputName := "signing-key-" + key.ID
			value, outputErr := requireOutput(item, outputName)
			if outputErr != nil {
				return nativeOAuthServer{}, outputErr
			}
			nativeKey.PrivateKeyBase64 = value
		}
		keys = append(keys, nativeKey)
	}
	settings := resource.Server
	settings.SigningKeys = nil
	return nativeOAuthServer{
		Enabled:                     true,
		AllowInsecureHTTP:           false,
		SigningKeys:                 keys,
		authorizationServerSettings: settings,
	}, nil
}

func buildTenant(item contribution) (nativeTenant, error) {
	var resource tenantResource
	if decodeErr := strictJSON(item.Desired, &resource); decodeErr != nil {
		return nativeTenant{}, fmt.Errorf("%w: contribution %s/%s: %v", errInvalidRequest, item.Owner, item.ID, decodeErr)
	}
	if resource.Kind != resourceKindTenant || resource.ID != item.ID || resource.Version != 1 {
		return nativeTenant{}, fmt.Errorf("%w: contribution %s/%s identity is inconsistent", errInvalidRequest, item.Owner, item.ID)
	}
	googleWebClientID, googleErr := requireOutput(item, googleWebClientOutput)
	if googleErr != nil {
		return nativeTenant{}, googleErr
	}
	jwtSigningKey, jwtErr := requireOutput(item, jwtSigningKeyOutput)
	if jwtErr != nil {
		return nativeTenant{}, jwtErr
	}
	nativeClients := make([]nativeGoogleClient, 0, len(resource.Tenant.GoogleNativeClients))
	for _, client := range resource.Tenant.GoogleNativeClients {
		clientID, outputErr := requireOutput(item, "google-native-"+client.Platform+"-client-id")
		if outputErr != nil {
			return nativeTenant{}, outputErr
		}
		nativeClients = append(nativeClients, nativeGoogleClient{
			Platform: client.Platform, ClientID: clientID, RedirectURIs: client.RedirectURIs,
		})
	}
	tenant := nativeTenant{
		ID:                  resource.Tenant.ID,
		DisplayName:         resource.Tenant.DisplayName,
		TenantOrigins:       resource.Tenant.Origins,
		GoogleWebClientID:   googleWebClientID,
		GoogleNativeClients: nativeClients,
		JWTSigningKey:       jwtSigningKey,
		CookieDomain:        resource.Tenant.Cookie.Domain,
		SessionCookieName:   resource.Tenant.Cookie.SessionName,
		RefreshCookieName:   resource.Tenant.Cookie.RefreshName,
		SessionTTL:          "15m",
		RefreshTTL:          "1440h",
		NonceTTL:            "5m",
		AllowInsecureHTTP:   false,
	}
	if resource.Tenant.AppleOAuth != nil {
		privateKey, outputErr := requireOutput(item, applePrivateKeyOutput)
		if outputErr != nil {
			return nativeTenant{}, outputErr
		}
		tenant.AppleOAuth = &nativeAppleOAuth{
			Enabled:          true,
			ClientID:         resource.Tenant.AppleOAuth.ClientID,
			NativeClientIDs:  resource.Tenant.AppleOAuth.NativeClientIDs,
			TeamID:           resource.Tenant.AppleOAuth.TeamID,
			KeyID:            resource.Tenant.AppleOAuth.KeyID,
			PrivateKeyBase64: privateKey,
			RedirectURI:      resource.Tenant.AppleOAuth.RedirectURI,
		}
	}
	if resource.Tenant.PasswordAuth.Enabled {
		tenant.PasswordAuth = &nativePasswordAuth{Enabled: true}
	}
	if resource.Tenant.AccountManagement.Enabled {
		account := resource.Tenant.AccountManagement
		if strings.TrimSpace(account.EmailVerificationTTL) == "" {
			account.EmailVerificationTTL = "30m"
		}
		if strings.TrimSpace(account.PasswordResetTTL) == "" {
			account.PasswordResetTTL = "15m"
		}
		nativeAccount := &nativeAccountManagement{
			Enabled:               account.Enabled,
			PasswordSignup:        account.PasswordSignup,
			ReturnChallengeTokens: account.ReturnChallengeTokens,
			EmailVerificationTTL:  account.EmailVerificationTTL,
			PasswordResetTTL:      account.PasswordResetTTL,
		}
		if account.EmailDelivery != nil {
			apiKey, outputErr := requireOutput(item, "email-delivery-api-key")
			if outputErr != nil {
				return nativeTenant{}, outputErr
			}
			nativeAccount.EmailDelivery = &nativeEmailDelivery{
				ServerAddress:            account.EmailDelivery.ServerAddress,
				APIKey:                   apiKey,
				EmailVerificationURL:     account.EmailDelivery.EmailVerificationURL,
				PasswordResetURL:         account.EmailDelivery.PasswordResetURL,
				PasswordLinkURL:          account.EmailDelivery.PasswordLinkURL,
				ConnectionTimeoutSeconds: account.EmailDelivery.ConnectionTimeoutSeconds,
				OperationTimeoutSeconds:  account.EmailDelivery.OperationTimeoutSeconds,
			}
		}
		tenant.AccountManagement = nativeAccount
	}
	if resource.Tenant.OAuth != nil {
		oauth := *resource.Tenant.OAuth
		oauth.Enabled = true
		tenant.OAuth = &oauth
	}
	return tenant, nil
}

func requireOutput(item contribution, name string) (string, error) {
	output, exists := item.Outputs[name]
	if !exists || strings.TrimSpace(output.Value) == "" {
		return "", fmt.Errorf("%w: contribution %s/%s requires output %s", errInvalidOutput, item.Owner, item.ID, name)
	}
	return output.Value, nil
}

func validateDocument(payload []byte) error {
	config, configErr := appconfig.ParseConfig(payload)
	if configErr != nil {
		return fmt.Errorf("%w: %v", errInvalidConfig, configErr)
	}
	tenantConfig, tenantErr := tenants.LoadConfigFromDocument(config.TenantDocument())
	if tenantErr != nil {
		return fmt.Errorf("%w: %v", errInvalidConfig, tenantErr)
	}
	if corsErr := appconfig.ValidateCORSAllowlist(config.Server, tenantConfig); corsErr != nil {
		return fmt.Errorf("%w: %v", errInvalidConfig, corsErr)
	}
	if activationErr := appconfig.ValidateOAuthActivation(config.OAuthServer(), tenantConfig); activationErr != nil {
		return fmt.Errorf("%w: %v", errInvalidConfig, activationErr)
	}
	if _, registryErr := authkit.BuildTenantRegistry(authkit.ServerConfig{AppJWTIssuer: appconfig.DefaultJWTIssuer}, tenantConfig, authkit.NewSameSiteResolver(bool(config.Server.EnableCORS))); registryErr != nil {
		return fmt.Errorf("%w: %v", errInvalidConfig, registryErr)
	}
	if config.OAuthServer().Enabled() {
		if _, registryErr := oauthserver.NewRegistry(tenantConfig); registryErr != nil {
			return fmt.Errorf("%w: %v", errInvalidConfig, registryErr)
		}
		if _, signerErr := oauthserver.NewSigner(config.OAuthServer()); signerErr != nil {
			return fmt.Errorf("%w: %v", errInvalidConfig, signerErr)
		}
	}
	return nil
}

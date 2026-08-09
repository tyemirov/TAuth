package oauthserver

import (
	"context"
	"time"
)

const (
	clientSourceRegistered = "registered"
	clientSourceMetadata   = "metadata_document"
)

// Client is validated public-client metadata used by an authorization request.
type Client struct {
	ID                  string
	DisplayName         string
	ApplicationType     string
	RedirectURIs        []string
	RedirectHost        string
	Source              string
	LoopbackPortMinimum int
	LoopbackPortMaximum int
	grants              map[string]map[string]struct{}
}

// Resource is one tenant-owned protected resource.
type Resource struct {
	Identifier  string
	DisplayName string
	Scopes      map[string]Scope
}

// Scope is one resource permission presented during consent.
type Scope struct {
	Identifier  string
	DisplayName string
	Description string
}

// TenantPolicy is the complete trusted OAuth policy for one tenant.
type TenantPolicy struct {
	TenantID                     string
	AccessTokenTTL               time.Duration
	RefreshTokenTTL              time.Duration
	ConsentTTL                   time.Duration
	AllowClientMetadataDocuments bool
	Resources                    map[string]Resource
	Clients                      map[string]Client
}

// AuthorizationRequest is one validated browser authorization transaction.
type AuthorizationRequest struct {
	TenantID      string
	ClientID      string
	ClientName    string
	ClientSource  string
	RedirectURI   string
	RedirectHost  string
	Resource      string
	ResourceName  string
	Scope         string
	State         string
	CodeChallenge string
	CreatedAtUnix int64
	ExpiresAtUnix int64
}

// ConsentKey identifies one exact user-approved client grant.
type ConsentKey struct {
	TenantID string
	UserID   string
	ClientID string
	Resource string
	Scope    string
}

// Consent is one time-bounded approval for an exact grant.
type Consent struct {
	ID string
	ConsentKey
	CreatedAtUnix int64
	ExpiresAtUnix int64
	RevokedAtUnix int64
}

// AuthorizationGrant is the immutable grant bound to a code and refresh family.
type AuthorizationGrant struct {
	ConsentID     string
	TenantID      string
	UserID        string
	ClientID      string
	RedirectURI   string
	Resource      string
	Scope         string
	CodeChallenge string
	ExpiresAtUnix int64
}

// RefreshGrant is the grant returned after refresh-token validation and rotation.
type RefreshGrant struct {
	ConsentID     string
	FamilyID      string
	TenantID      string
	UserID        string
	ClientID      string
	Resource      string
	Scope         string
	ExpiresAtUnix int64
}

// CodeExchange contains every value that must match an authorization code.
type CodeExchange struct {
	ClientID     string
	Resource     string
	CodeVerifier string
	NowUnix      int64
}

// Store owns pending requests, codes, consents, and refresh-token families.
type Store interface {
	CreateAuthorizationRequest(ctx context.Context, request AuthorizationRequest) (string, error)
	GetAuthorizationRequest(ctx context.Context, requestToken string, nowUnix int64) (AuthorizationRequest, error)
	ConsumeAuthorizationRequest(ctx context.Context, requestToken string, nowUnix int64) (AuthorizationRequest, error)
	FindConsent(ctx context.Context, key ConsentKey, nowUnix int64) (Consent, bool, error)
	SaveConsent(ctx context.Context, consent Consent) (Consent, error)
	IssueAuthorizationCode(ctx context.Context, grant AuthorizationGrant) (string, error)
	RedeemAuthorizationCode(ctx context.Context, code string, exchange CodeExchange) (AuthorizationGrant, error)
	IssueRefreshToken(ctx context.Context, grant RefreshGrant) (string, error)
	RotateRefreshToken(ctx context.Context, refreshToken string, clientID string, resource string, scope string, nowUnix int64) (RefreshGrant, string, error)
	RevokeRefreshToken(ctx context.Context, refreshToken string, clientID string, nowUnix int64) error
	RevokeConsent(ctx context.Context, consentID string, nowUnix int64) error
}

func (client Client) permits(resource string, scopes []string) bool {
	if client.Source == clientSourceMetadata {
		return true
	}
	resourceScopes := client.grants[resource]
	if len(resourceScopes) == 0 {
		return false
	}
	for _, scope := range scopes {
		if _, permitted := resourceScopes[scope]; !permitted {
			return false
		}
	}
	return true
}

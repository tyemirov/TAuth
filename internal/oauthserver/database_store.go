package oauthserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tyemirov/tauth/internal/authkit"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	oauthAuthorizationRequestsTable = "oauth_authorization_requests"
	oauthAuthorizationCodesTable    = "oauth_authorization_codes"
	oauthConsentsTable              = "oauth_consents"
	oauthRefreshTokensTable         = "oauth_refresh_tokens"
)

type databaseAuthorizationRequest struct {
	RequestHash   string `gorm:"column:request_hash;primaryKey"`
	TenantID      string `gorm:"column:tenant_id;index;not null"`
	ClientID      string `gorm:"column:client_id;index;not null"`
	ClientName    string `gorm:"column:client_name;not null"`
	ClientSource  string `gorm:"column:client_source;not null"`
	RedirectURI   string `gorm:"column:redirect_uri;not null"`
	RedirectHost  string `gorm:"column:redirect_host;not null"`
	Resource      string `gorm:"column:resource;index;not null"`
	ResourceName  string `gorm:"column:resource_name;not null"`
	Scope         string `gorm:"column:scope;not null"`
	State         string `gorm:"column:state;not null"`
	CodeChallenge string `gorm:"column:code_challenge;not null"`
	CreatedAtUnix int64  `gorm:"column:created_at_unix;not null"`
	ExpiresAtUnix int64  `gorm:"column:expires_at_unix;index;not null"`
}

func (databaseAuthorizationRequest) TableName() string { return oauthAuthorizationRequestsTable }

type databaseAuthorizationCode struct {
	CodeHash       string `gorm:"column:code_hash;primaryKey"`
	ConsentID      string `gorm:"column:consent_id;index;not null"`
	TenantID       string `gorm:"column:tenant_id;index;not null"`
	UserID         string `gorm:"column:user_id;index;not null"`
	ClientID       string `gorm:"column:client_id;index;not null"`
	RedirectURI    string `gorm:"column:redirect_uri;not null"`
	Resource       string `gorm:"column:resource;index;not null"`
	Scope          string `gorm:"column:scope;not null"`
	CodeChallenge  string `gorm:"column:code_challenge;not null"`
	ExpiresAtUnix  int64  `gorm:"column:expires_at_unix;index;not null"`
	ConsumedAtUnix int64  `gorm:"column:consumed_at_unix;not null;default:0"`
}

func (databaseAuthorizationCode) TableName() string { return oauthAuthorizationCodesTable }

type databaseConsent struct {
	ID            string `gorm:"column:consent_id;primaryKey"`
	TenantID      string `gorm:"column:tenant_id;index:idx_oauth_consent_grant,priority:1;not null"`
	UserID        string `gorm:"column:user_id;index:idx_oauth_consent_grant,priority:2;not null"`
	ClientID      string `gorm:"column:client_id;index:idx_oauth_consent_grant,priority:3;not null"`
	Resource      string `gorm:"column:resource;index:idx_oauth_consent_grant,priority:4;not null"`
	Scope         string `gorm:"column:scope;index:idx_oauth_consent_grant,priority:5;not null"`
	CreatedAtUnix int64  `gorm:"column:created_at_unix;not null"`
	ExpiresAtUnix int64  `gorm:"column:expires_at_unix;index;not null"`
	RevokedAtUnix int64  `gorm:"column:revoked_at_unix;not null;default:0"`
}

func (databaseConsent) TableName() string { return oauthConsentsTable }

type databaseOAuthRefreshToken struct {
	TokenHash     string `gorm:"column:token_hash;primaryKey"`
	ConsentID     string `gorm:"column:consent_id;index;not null"`
	FamilyID      string `gorm:"column:family_id;index;not null"`
	TenantID      string `gorm:"column:tenant_id;index;not null"`
	UserID        string `gorm:"column:user_id;index;not null"`
	ClientID      string `gorm:"column:client_id;index;not null"`
	Resource      string `gorm:"column:resource;index;not null"`
	Scope         string `gorm:"column:scope;not null"`
	ExpiresAtUnix int64  `gorm:"column:expires_at_unix;index;not null"`
	Status        string `gorm:"column:status;index;not null"`
	IssuedAtUnix  int64  `gorm:"column:issued_at_unix;not null"`
	RotatedAtUnix int64  `gorm:"column:rotated_at_unix;not null;default:0"`
	RevokedAtUnix int64  `gorm:"column:revoked_at_unix;not null;default:0"`
}

func (databaseOAuthRefreshToken) TableName() string { return oauthRefreshTokensTable }

// DatabaseStore is the durable SQLite or Postgres OAuth transaction store.
type DatabaseStore struct {
	db          *gorm.DB
	driverLabel string
}

// NewDatabaseStore opens and migrates the OAuth transaction tables.
func NewDatabaseStore(ctx context.Context, databaseURL string) (*DatabaseStore, error) {
	database, driverLabel, openErr := authkit.OpenOAuthDatabase(
		ctx,
		databaseURL,
		&databaseAuthorizationRequest{},
		&databaseAuthorizationCode{},
		&databaseConsent{},
		&databaseOAuthRefreshToken{},
	)
	if openErr != nil {
		return nil, openErr
	}
	return &DatabaseStore{db: database, driverLabel: driverLabel}, nil
}

// Driver returns the selected database adapter name.
func (store *DatabaseStore) Driver() string { return store.driverLabel }

func (store *DatabaseStore) CreateAuthorizationRequest(ctx context.Context, request AuthorizationRequest) (string, error) {
	token, digest, tokenErr := newOpaqueToken("authorization_request")
	if tokenErr != nil {
		return "", tokenErr
	}
	record := databaseAuthorizationRequest{
		RequestHash: digest, TenantID: request.TenantID, ClientID: request.ClientID, ClientName: request.ClientName,
		ClientSource: request.ClientSource, RedirectURI: request.RedirectURI, RedirectHost: request.RedirectHost,
		Resource: request.Resource, ResourceName: request.ResourceName, Scope: request.Scope, State: request.State,
		CodeChallenge: request.CodeChallenge, CreatedAtUnix: request.CreatedAtUnix, ExpiresAtUnix: request.ExpiresAtUnix,
	}
	if createErr := store.db.WithContext(ctx).Create(&record).Error; createErr != nil {
		return "", fmt.Errorf("oauth_store.request.create.%s: %w", store.driverLabel, createErr)
	}
	return token, nil
}

func (store *DatabaseStore) GetAuthorizationRequest(ctx context.Context, requestToken string, nowUnix int64) (AuthorizationRequest, error) {
	var record databaseAuthorizationRequest
	queryErr := store.db.WithContext(ctx).Where("request_hash = ? AND expires_at_unix > ?", digestToken(requestToken), nowUnix).Take(&record).Error
	if queryErr != nil {
		if errors.Is(queryErr, gorm.ErrRecordNotFound) {
			return AuthorizationRequest{}, ErrAuthorizationRequestInvalid
		}
		return AuthorizationRequest{}, fmt.Errorf("oauth_store.request.get.%s: %w", store.driverLabel, queryErr)
	}
	return authorizationRequestFromDatabase(record), nil
}

func (store *DatabaseStore) ConsumeAuthorizationRequest(ctx context.Context, requestToken string, nowUnix int64) (AuthorizationRequest, error) {
	var request AuthorizationRequest
	transactionErr := store.db.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		var record databaseAuthorizationRequest
		queryErr := transaction.Clauses(clause.Locking{Strength: "UPDATE"}).Where("request_hash = ?", digestToken(requestToken)).Take(&record).Error
		if queryErr != nil {
			if errors.Is(queryErr, gorm.ErrRecordNotFound) {
				return ErrAuthorizationRequestInvalid
			}
			return queryErr
		}
		if record.ExpiresAtUnix <= nowUnix {
			return ErrAuthorizationRequestInvalid
		}
		deleted := transaction.Where("request_hash = ?", record.RequestHash).Delete(&databaseAuthorizationRequest{})
		if deleted.Error != nil {
			return deleted.Error
		}
		if deleted.RowsAffected != 1 {
			return ErrAuthorizationRequestInvalid
		}
		request = authorizationRequestFromDatabase(record)
		return nil
	})
	if transactionErr != nil {
		if errors.Is(transactionErr, ErrAuthorizationRequestInvalid) {
			return AuthorizationRequest{}, ErrAuthorizationRequestInvalid
		}
		return AuthorizationRequest{}, fmt.Errorf("oauth_store.request.consume.%s: %w", store.driverLabel, transactionErr)
	}
	return request, nil
}

func (store *DatabaseStore) FindConsent(ctx context.Context, key ConsentKey, nowUnix int64) (Consent, bool, error) {
	var record databaseConsent
	queryErr := store.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ? AND client_id = ? AND resource = ? AND scope = ? AND revoked_at_unix = 0 AND expires_at_unix > ?", key.TenantID, key.UserID, key.ClientID, key.Resource, key.Scope, nowUnix).
		Order("created_at_unix DESC").Take(&record).Error
	if errors.Is(queryErr, gorm.ErrRecordNotFound) {
		return Consent{}, false, nil
	}
	if queryErr != nil {
		return Consent{}, false, fmt.Errorf("oauth_store.consent.find.%s: %w", store.driverLabel, queryErr)
	}
	return consentFromDatabase(record), true, nil
}

func (store *DatabaseStore) SaveConsent(ctx context.Context, consent Consent) (Consent, error) {
	if strings.TrimSpace(consent.ID) == "" {
		consentID, _, consentIDErr := newOpaqueToken("consent")
		if consentIDErr != nil {
			return Consent{}, consentIDErr
		}
		consent.ID = consentID
	}
	record := databaseConsent{
		ID: consent.ID, TenantID: consent.TenantID, UserID: consent.UserID, ClientID: consent.ClientID,
		Resource: consent.Resource, Scope: consent.Scope, CreatedAtUnix: consent.CreatedAtUnix,
		ExpiresAtUnix: consent.ExpiresAtUnix, RevokedAtUnix: consent.RevokedAtUnix,
	}
	if createErr := store.db.WithContext(ctx).Create(&record).Error; createErr != nil {
		return Consent{}, fmt.Errorf("oauth_store.consent.create.%s: %w", store.driverLabel, createErr)
	}
	return consent, nil
}

func (store *DatabaseStore) IssueAuthorizationCode(ctx context.Context, grant AuthorizationGrant) (string, error) {
	code, digest, codeErr := newOpaqueToken("authorization_code")
	if codeErr != nil {
		return "", codeErr
	}
	record := databaseAuthorizationCode{
		CodeHash: digest, ConsentID: grant.ConsentID, TenantID: grant.TenantID, UserID: grant.UserID,
		ClientID: grant.ClientID, RedirectURI: grant.RedirectURI, Resource: grant.Resource, Scope: grant.Scope,
		CodeChallenge: grant.CodeChallenge, ExpiresAtUnix: grant.ExpiresAtUnix,
	}
	if createErr := store.db.WithContext(ctx).Create(&record).Error; createErr != nil {
		return "", fmt.Errorf("oauth_store.code.create.%s: %w", store.driverLabel, createErr)
	}
	return code, nil
}

func (store *DatabaseStore) RedeemAuthorizationCode(ctx context.Context, code string, exchange CodeExchange) (AuthorizationGrant, error) {
	var grant AuthorizationGrant
	transactionErr := store.db.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		var record databaseAuthorizationCode
		queryErr := transaction.Clauses(clause.Locking{Strength: "UPDATE"}).Where("code_hash = ?", digestToken(code)).Take(&record).Error
		if queryErr != nil {
			if errors.Is(queryErr, gorm.ErrRecordNotFound) {
				return ErrAuthorizationCodeInvalid
			}
			return queryErr
		}
		if record.ConsumedAtUnix != 0 || record.ExpiresAtUnix <= exchange.NowUnix || record.ClientID != exchange.ClientID || record.Resource != exchange.Resource || !pkceVerifierMatches(record.CodeChallenge, exchange.CodeVerifier) {
			return ErrAuthorizationCodeInvalid
		}
		update := transaction.Model(&databaseAuthorizationCode{}).Where("code_hash = ? AND consumed_at_unix = 0", record.CodeHash).Update("consumed_at_unix", exchange.NowUnix)
		if update.Error != nil {
			return update.Error
		}
		if update.RowsAffected != 1 {
			return ErrAuthorizationCodeInvalid
		}
		grant = authorizationGrantFromDatabase(record)
		return nil
	})
	if transactionErr != nil {
		if errors.Is(transactionErr, ErrAuthorizationCodeInvalid) {
			return AuthorizationGrant{}, ErrAuthorizationCodeInvalid
		}
		return AuthorizationGrant{}, fmt.Errorf("oauth_store.code.redeem.%s: %w", store.driverLabel, transactionErr)
	}
	return grant, nil
}

func (store *DatabaseStore) IssueRefreshToken(ctx context.Context, grant RefreshGrant) (string, error) {
	if strings.TrimSpace(grant.FamilyID) == "" {
		familyID, _, familyErr := newOpaqueToken("refresh_family")
		if familyErr != nil {
			return "", familyErr
		}
		grant.FamilyID = familyID
	}
	token, digest, tokenErr := newOpaqueToken("refresh_token")
	if tokenErr != nil {
		return "", tokenErr
	}
	record := refreshRecordFromGrant(digest, grant, time.Now().UTC().Unix())
	if createErr := store.db.WithContext(ctx).Create(&record).Error; createErr != nil {
		return "", fmt.Errorf("oauth_store.refresh.create.%s: %w", store.driverLabel, createErr)
	}
	return token, nil
}

func (store *DatabaseStore) RotateRefreshToken(ctx context.Context, refreshToken string, clientID string, resource string, scope string, nowUnix int64) (RefreshGrant, string, error) {
	var grant RefreshGrant
	var newToken string
	reused := false
	invalid := false
	invalidScope := false
	transactionErr := store.db.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		var record databaseOAuthRefreshToken
		queryErr := transaction.Clauses(clause.Locking{Strength: "UPDATE"}).Where("token_hash = ?", digestToken(refreshToken)).Take(&record).Error
		if errors.Is(queryErr, gorm.ErrRecordNotFound) {
			invalid = true
			return nil
		}
		if queryErr != nil {
			return queryErr
		}
		if record.ClientID != clientID || record.Resource != resource || record.ExpiresAtUnix <= nowUnix {
			invalid = true
			return nil
		}
		if scope != "" && record.Scope != scope {
			invalidScope = true
			return nil
		}
		if record.Status == refreshTokenStatusRotated {
			if revokeErr := revokeRefreshFamilyDatabase(transaction, record.FamilyID, record.ConsentID, nowUnix); revokeErr != nil {
				return revokeErr
			}
			reused = true
			return nil
		}
		if record.Status != refreshTokenStatusActive {
			invalid = true
			return nil
		}
		var consent databaseConsent
		consentErr := transaction.Where("consent_id = ? AND revoked_at_unix = 0 AND expires_at_unix > ?", record.ConsentID, nowUnix).Take(&consent).Error
		if errors.Is(consentErr, gorm.ErrRecordNotFound) {
			invalid = true
			return nil
		}
		if consentErr != nil {
			return consentErr
		}
		generatedToken, generatedDigest, tokenErr := newOpaqueToken("refresh_token")
		if tokenErr != nil {
			return tokenErr
		}
		update := transaction.Model(&databaseOAuthRefreshToken{}).Where("token_hash = ? AND status = ?", record.TokenHash, refreshTokenStatusActive).
			Updates(map[string]any{"status": refreshTokenStatusRotated, "rotated_at_unix": nowUnix})
		if update.Error != nil {
			return update.Error
		}
		if update.RowsAffected != 1 {
			invalid = true
			return nil
		}
		grant = refreshGrantFromDatabase(record)
		newRecord := refreshRecordFromGrant(generatedDigest, grant, nowUnix)
		if createErr := transaction.Create(&newRecord).Error; createErr != nil {
			return createErr
		}
		newToken = generatedToken
		return nil
	})
	if transactionErr != nil {
		return RefreshGrant{}, "", fmt.Errorf("oauth_store.refresh.rotate.%s: %w", store.driverLabel, transactionErr)
	}
	if reused {
		return RefreshGrant{}, "", ErrRefreshTokenReuse
	}
	if invalidScope {
		return RefreshGrant{}, "", ErrRefreshTokenScope
	}
	if invalid {
		return RefreshGrant{}, "", ErrRefreshTokenInvalid
	}
	return grant, newToken, nil
}

func (store *DatabaseStore) RevokeRefreshToken(ctx context.Context, refreshToken string, clientID string, nowUnix int64) error {
	transactionErr := store.db.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		var record databaseOAuthRefreshToken
		queryErr := transaction.Where("token_hash = ?", digestToken(refreshToken)).Take(&record).Error
		if errors.Is(queryErr, gorm.ErrRecordNotFound) || (queryErr == nil && record.ClientID != clientID) {
			return nil
		}
		if queryErr != nil {
			return queryErr
		}
		return revokeRefreshFamilyDatabase(transaction, record.FamilyID, record.ConsentID, nowUnix)
	})
	if transactionErr != nil {
		return fmt.Errorf("oauth_store.refresh.revoke.%s: %w", store.driverLabel, transactionErr)
	}
	return nil
}

func (store *DatabaseStore) RevokeConsent(ctx context.Context, consentID string, nowUnix int64) error {
	transactionErr := store.db.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		return revokeRefreshFamilyDatabase(transaction, "", consentID, nowUnix)
	})
	if transactionErr != nil {
		return fmt.Errorf("oauth_store.consent.revoke.%s: %w", store.driverLabel, transactionErr)
	}
	return nil
}

func revokeRefreshFamilyDatabase(transaction *gorm.DB, familyID string, consentID string, nowUnix int64) error {
	query := transaction.Model(&databaseOAuthRefreshToken{})
	if familyID != "" {
		query = query.Where("family_id = ?", familyID)
	} else {
		query = query.Where("consent_id = ?", consentID)
	}
	if updateErr := query.Updates(map[string]any{"status": refreshTokenStatusRevoked, "revoked_at_unix": nowUnix}).Error; updateErr != nil {
		return updateErr
	}
	if consentID != "" {
		if updateErr := transaction.Model(&databaseConsent{}).Where("consent_id = ? AND revoked_at_unix = 0", consentID).Update("revoked_at_unix", nowUnix).Error; updateErr != nil {
			return updateErr
		}
	}
	return nil
}

func authorizationRequestFromDatabase(record databaseAuthorizationRequest) AuthorizationRequest {
	return AuthorizationRequest{
		TenantID: record.TenantID, ClientID: record.ClientID, ClientName: record.ClientName, ClientSource: record.ClientSource,
		RedirectURI: record.RedirectURI, RedirectHost: record.RedirectHost, Resource: record.Resource,
		ResourceName: record.ResourceName, Scope: record.Scope, State: record.State, CodeChallenge: record.CodeChallenge,
		CreatedAtUnix: record.CreatedAtUnix, ExpiresAtUnix: record.ExpiresAtUnix,
	}
}

func consentFromDatabase(record databaseConsent) Consent {
	return Consent{ID: record.ID, ConsentKey: ConsentKey{TenantID: record.TenantID, UserID: record.UserID, ClientID: record.ClientID, Resource: record.Resource, Scope: record.Scope}, CreatedAtUnix: record.CreatedAtUnix, ExpiresAtUnix: record.ExpiresAtUnix, RevokedAtUnix: record.RevokedAtUnix}
}

func authorizationGrantFromDatabase(record databaseAuthorizationCode) AuthorizationGrant {
	return AuthorizationGrant{ConsentID: record.ConsentID, TenantID: record.TenantID, UserID: record.UserID, ClientID: record.ClientID, RedirectURI: record.RedirectURI, Resource: record.Resource, Scope: record.Scope, CodeChallenge: record.CodeChallenge, ExpiresAtUnix: record.ExpiresAtUnix}
}

func refreshRecordFromGrant(tokenHash string, grant RefreshGrant, issuedAtUnix int64) databaseOAuthRefreshToken {
	return databaseOAuthRefreshToken{TokenHash: tokenHash, ConsentID: grant.ConsentID, FamilyID: grant.FamilyID, TenantID: grant.TenantID, UserID: grant.UserID, ClientID: grant.ClientID, Resource: grant.Resource, Scope: grant.Scope, ExpiresAtUnix: grant.ExpiresAtUnix, Status: refreshTokenStatusActive, IssuedAtUnix: issuedAtUnix}
}

func refreshGrantFromDatabase(record databaseOAuthRefreshToken) RefreshGrant {
	return RefreshGrant{ConsentID: record.ConsentID, FamilyID: record.FamilyID, TenantID: record.TenantID, UserID: record.UserID, ClientID: record.ClientID, Resource: record.Resource, Scope: record.Scope, ExpiresAtUnix: record.ExpiresAtUnix}
}

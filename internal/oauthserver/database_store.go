package oauthserver

import (
	"context"
	"errors"
	"fmt"
	"strings"

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
	DisclosurePolicy string `gorm:"column:disclosure_policy;not null;default:''"`
	RequestHash      string `gorm:"column:request_hash;primaryKey"`
	TenantID         string `gorm:"column:tenant_id;index;not null"`
	ClientID         string `gorm:"column:client_id;index;not null"`
	ClientName       string `gorm:"column:client_name;not null"`
	ClientSource     string `gorm:"column:client_source;not null"`
	RedirectURI      string `gorm:"column:redirect_uri;not null"`
	RedirectHost     string `gorm:"column:redirect_host;not null"`
	Resource         string `gorm:"column:resource;index;not null"`
	ResourceName     string `gorm:"column:resource_name;not null"`
	Scope            string `gorm:"column:scope;not null"`
	State            string `gorm:"column:state;not null"`
	CodeChallenge    string `gorm:"column:code_challenge;not null"`
	CreatedAtUnix    int64  `gorm:"column:created_at_unix;not null"`
	ExpiresAtUnix    int64  `gorm:"column:expires_at_unix;index;not null"`
}

type databaseCapacityLock struct {
	ID int `gorm:"primaryKey"`
}

func (databaseCapacityLock) TableName() string { return "oauth_capacity_lock" }

func (databaseAuthorizationRequest) TableName() string { return oauthAuthorizationRequestsTable }

type databaseAuthorizationCode struct {
	DisclosurePolicy string `gorm:"column:disclosure_policy;not null;default:''"`
	CodeHash         string `gorm:"column:code_hash;primaryKey"`
	ConsentID        string `gorm:"column:consent_id;index;not null"`
	TenantID         string `gorm:"column:tenant_id;index;not null"`
	UserID           string `gorm:"column:user_id;index;not null"`
	ClientID         string `gorm:"column:client_id;index;not null"`
	RedirectURI      string `gorm:"column:redirect_uri;not null"`
	Resource         string `gorm:"column:resource;index;not null"`
	Scope            string `gorm:"column:scope;not null"`
	CodeChallenge    string `gorm:"column:code_challenge;not null"`
	ExpiresAtUnix    int64  `gorm:"column:expires_at_unix;index;not null"`
	ConsumedAtUnix   int64  `gorm:"column:consumed_at_unix;not null;default:0"`
}

func (databaseAuthorizationCode) TableName() string { return oauthAuthorizationCodesTable }

type databaseConsent struct {
	DisclosurePolicy string `gorm:"column:disclosure_policy;not null;default:''"`
	ID               string `gorm:"column:consent_id;primaryKey"`
	TenantID         string `gorm:"column:tenant_id;index:idx_oauth_consent_grant,priority:1;not null"`
	UserID           string `gorm:"column:user_id;index:idx_oauth_consent_grant,priority:2;not null"`
	ClientID         string `gorm:"column:client_id;index:idx_oauth_consent_grant,priority:3;not null"`
	Resource         string `gorm:"column:resource;index:idx_oauth_consent_grant,priority:4;not null"`
	Scope            string `gorm:"column:scope;index:idx_oauth_consent_grant,priority:5;not null"`
	CreatedAtUnix    int64  `gorm:"column:created_at_unix;not null"`
	ExpiresAtUnix    int64  `gorm:"column:expires_at_unix;index;not null"`
	RevokedAtUnix    int64  `gorm:"column:revoked_at_unix;not null;default:0"`
}

func (databaseConsent) TableName() string { return oauthConsentsTable }

type databaseOAuthRefreshToken struct {
	DisclosurePolicy string `gorm:"column:disclosure_policy;not null;default:''"`
	TokenHash        string `gorm:"column:token_hash;primaryKey"`
	ConsentID        string `gorm:"column:consent_id;index;not null"`
	FamilyID         string `gorm:"column:family_id;index;not null"`
	TenantID         string `gorm:"column:tenant_id;index;not null"`
	UserID           string `gorm:"column:user_id;index;not null"`
	ClientID         string `gorm:"column:client_id;index;not null"`
	Resource         string `gorm:"column:resource;index;not null"`
	Scope            string `gorm:"column:scope;not null"`
	ExpiresAtUnix    int64  `gorm:"column:expires_at_unix;index;not null"`
	Status           string `gorm:"column:status;index;not null"`
	IssuedAtUnix     int64  `gorm:"column:issued_at_unix;not null"`
	RotatedAtUnix    int64  `gorm:"column:rotated_at_unix;not null;default:0"`
	RevokedAtUnix    int64  `gorm:"column:revoked_at_unix;not null;default:0"`
}

func (databaseOAuthRefreshToken) TableName() string { return oauthRefreshTokensTable }

// DatabaseStore is the durable SQLite or Postgres OAuth transaction store.
type DatabaseStore struct {
	db               *gorm.DB
	driverLabel      string
	databaseIdentity string
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
		&databaseCapacityLock{},
	)
	if openErr != nil {
		return nil, openErr
	}
	if err := database.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&databaseCapacityLock{ID: 1}).Error; err != nil {
		return nil, fmt.Errorf("oauth_store.capacity.initialize: %w", err)
	}
	return &DatabaseStore{db: database, driverLabel: driverLabel, databaseIdentity: authkit.ErasureDatabaseIdentity(databaseURL)}, nil
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
		Resource: request.Resource, ResourceName: request.ResourceName, Scope: request.Scope, DisclosurePolicy: request.DisclosurePolicy, State: request.State,
		CodeChallenge: request.CodeChallenge, CreatedAtUnix: request.CreatedAtUnix, ExpiresAtUnix: request.ExpiresAtUnix,
	}
	var capacityErr error
	createErr := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&databaseCapacityLock{}).Where("id = 1").Update("id", 1).Error; err != nil {
			return err
		}
		if err := tx.Where("expires_at_unix <= ?", request.CreatedAtUnix).Delete(&databaseAuthorizationRequest{}).Error; err != nil {
			return err
		}
		var globalCount, tenantCount int64
		if err := tx.Model(&databaseAuthorizationRequest{}).Count(&globalCount).Error; err != nil {
			return err
		}
		if err := tx.Model(&databaseAuthorizationRequest{}).Where("tenant_id = ?", request.TenantID).Count(&tenantCount).Error; err != nil {
			return err
		}
		if globalCount >= maximumPendingGlobal || tenantCount >= maximumPendingPerTenant {
			capacityErr = ErrAuthorizationCapacity
			return nil
		}
		return tx.Create(&record).Error
	})
	if createErr != nil {
		return "", fmt.Errorf("oauth_store.request.create.%s: %w", store.driverLabel, createErr)
	}
	if capacityErr != nil {
		return "", capacityErr
	}
	return token, nil
}

func (store *DatabaseStore) GetAuthorizationRequest(ctx context.Context, requestToken string, nowUnix int64) (AuthorizationRequest, error) {
	if err := store.CleanupExpired(ctx, nowUnix); err != nil {
		return AuthorizationRequest{}, err
	}
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
	if err := store.CleanupExpired(ctx, nowUnix); err != nil {
		return AuthorizationRequest{}, err
	}
	var request AuthorizationRequest
	err := store.db.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := lockOAuthCapacity(transaction); err != nil {
			return err
		}
		var err error
		request, err = consumeAuthorizationRequestDatabase(transaction, requestToken, nowUnix)
		return err
	})
	if err != nil {
		return AuthorizationRequest{}, fmt.Errorf("oauth_store.request.consume.%s: %w", store.driverLabel, err)
	}
	return request, nil
}

func consumeAuthorizationRequestDatabase(transaction *gorm.DB, requestToken string, nowUnix int64) (AuthorizationRequest, error) {
	var record databaseAuthorizationRequest
	err := transaction.Clauses(clause.Locking{Strength: "UPDATE"}).Where("request_hash = ?", digestToken(requestToken)).Take(&record).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return AuthorizationRequest{}, ErrAuthorizationRequestInvalid
	}
	if err != nil {
		return AuthorizationRequest{}, err
	}
	if record.ExpiresAtUnix <= nowUnix {
		return AuthorizationRequest{}, ErrAuthorizationRequestInvalid
	}
	deleted := transaction.Where("request_hash = ?", record.RequestHash).Delete(&databaseAuthorizationRequest{})
	if deleted.Error != nil {
		return AuthorizationRequest{}, deleted.Error
	}
	if deleted.RowsAffected != 1 {
		return AuthorizationRequest{}, ErrAuthorizationRequestInvalid
	}
	return authorizationRequestFromDatabase(record), nil
}

func (store *DatabaseStore) FindConsent(ctx context.Context, key ConsentKey, nowUnix int64) (Consent, bool, error) {
	if err := store.CleanupExpired(ctx, nowUnix); err != nil {
		return Consent{}, false, err
	}
	var record databaseConsent
	queryErr := store.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ? AND client_id = ? AND resource = ? AND scope = ? AND disclosure_policy = ? AND revoked_at_unix = 0 AND expires_at_unix > ?", key.TenantID, key.UserID, key.ClientID, key.Resource, key.Scope, key.DisclosurePolicy, nowUnix).
		Order("created_at_unix DESC").Take(&record).Error
	if errors.Is(queryErr, gorm.ErrRecordNotFound) {
		return Consent{}, false, nil
	}
	if queryErr != nil {
		return Consent{}, false, fmt.Errorf("oauth_store.consent.find.%s: %w", store.driverLabel, queryErr)
	}
	return consentFromDatabase(record), true, nil
}

// CompleteAuthorizationRequest commits the request, consent, and code together.
func (store *DatabaseStore) CompleteAuthorizationRequest(ctx context.Context, requestToken string, completion AuthorizationCompletion) (string, error) {
	if err := store.CleanupExpired(ctx, completion.NowUnix); err != nil {
		return "", err
	}
	var code string
	err := store.db.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := lockOAuthCapacity(transaction); err != nil {
			return err
		}
		if err := admitOAuthCapacity(transaction, &databaseAuthorizationCode{}, completion.Grant.TenantID, maximumPendingPerTenant, maximumPendingGlobal); err != nil {
			return err
		}
		transactionStore := &DatabaseStore{db: transaction, driverLabel: store.driverLabel}
		pending, err := consumeAuthorizationRequestDatabase(transaction, requestToken, completion.NowUnix)
		if err != nil {
			return err
		}
		if pending != completion.Request {
			return ErrAuthorizationRequestInvalid
		}
		consent := completion.Consent
		if consent.ID == "" {
			consent, err = transactionStore.SaveConsent(ctx, consent)
			if err != nil {
				return err
			}
		}
		grant := completion.Grant
		grant.ConsentID = consent.ID
		code, err = transactionStore.issueAuthorizationCode(ctx, grant)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("oauth_store.request.complete.%s: %w", store.driverLabel, err)
	}
	return code, nil
}

func (store *DatabaseStore) SaveConsent(ctx context.Context, consent Consent) (Consent, error) {
	if err := store.CleanupExpired(ctx, consent.CreatedAtUnix); err != nil {
		return Consent{}, err
	}
	if strings.TrimSpace(consent.ID) == "" {
		consentID, _, consentIDErr := newOpaqueToken("consent")
		if consentIDErr != nil {
			return Consent{}, consentIDErr
		}
		consent.ID = consentID
	}
	record := databaseConsent{
		ID: consent.ID, TenantID: consent.TenantID, UserID: consent.UserID, ClientID: consent.ClientID,
		Resource: consent.Resource, Scope: consent.Scope, DisclosurePolicy: consent.DisclosurePolicy, CreatedAtUnix: consent.CreatedAtUnix,
		ExpiresAtUnix: consent.ExpiresAtUnix, RevokedAtUnix: consent.RevokedAtUnix,
	}
	if createErr := store.createUserRecord(ctx, record.TenantID, record.UserID, &record); createErr != nil {
		return Consent{}, fmt.Errorf("oauth_store.consent.create.%s: %w", store.driverLabel, createErr)
	}
	return consent, nil
}

func (store *DatabaseStore) IssueAuthorizationCode(ctx context.Context, grant AuthorizationGrant, nowUnix int64) (string, error) {
	if err := store.CleanupExpired(ctx, nowUnix); err != nil {
		return "", err
	}
	var code string
	err := store.db.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := lockOAuthCapacity(transaction); err != nil {
			return err
		}
		if err := admitOAuthCapacity(transaction, &databaseAuthorizationCode{}, grant.TenantID, maximumPendingPerTenant, maximumPendingGlobal); err != nil {
			return err
		}
		var err error
		code, err = (&DatabaseStore{db: transaction, driverLabel: store.driverLabel}).issueAuthorizationCode(ctx, grant)
		return err
	})
	return code, err
}

func (store *DatabaseStore) issueAuthorizationCode(ctx context.Context, grant AuthorizationGrant) (string, error) {
	code, digest, codeErr := newOpaqueToken("authorization_code")
	if codeErr != nil {
		return "", codeErr
	}
	record := databaseAuthorizationCode{
		CodeHash: digest, ConsentID: grant.ConsentID, TenantID: grant.TenantID, UserID: grant.UserID,
		ClientID: grant.ClientID, RedirectURI: grant.RedirectURI, Resource: grant.Resource, Scope: grant.Scope, DisclosurePolicy: grant.DisclosurePolicy,
		CodeChallenge: grant.CodeChallenge, ExpiresAtUnix: grant.ExpiresAtUnix,
	}
	if createErr := store.createUserRecord(ctx, record.TenantID, record.UserID, &record); createErr != nil {
		return "", fmt.Errorf("oauth_store.code.create.%s: %w", store.driverLabel, createErr)
	}
	return code, nil
}

func (store *DatabaseStore) RedeemAuthorizationCode(ctx context.Context, code string, exchange CodeExchange, authorize AccountAuthorization) (AuthorizationGrant, string, error) {
	if err := store.CleanupExpired(ctx, exchange.NowUnix); err != nil {
		return AuthorizationGrant{}, "", err
	}
	var refreshToken string
	var grant AuthorizationGrant
	transactionErr := store.db.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := lockOAuthCapacity(transaction); err != nil {
			return err
		}
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
		if err := authkit.RequireActiveAccountWrite(ctx, transaction, record.TenantID, record.UserID); err != nil {
			if errors.Is(err, authkit.ErrAccountNotActive) {
				return ErrAuthorizationCodeInvalid
			}
			return err
		}
		if err := authorize(ctx, record.TenantID, record.UserID); err != nil {
			return err
		}
		if err := admitOAuthCapacity(transaction, &databaseOAuthRefreshToken{}, record.TenantID, maximumRefreshPerTenant, maximumRefreshGlobal); err != nil {
			return err
		}
		update := transaction.Model(&databaseAuthorizationCode{}).Where("code_hash = ? AND consumed_at_unix = 0", record.CodeHash).Update("consumed_at_unix", exchange.NowUnix)
		if update.Error != nil {
			return update.Error
		}
		if update.RowsAffected != 1 {
			return ErrAuthorizationCodeInvalid
		}
		grant = authorizationGrantFromDatabase(record)
		var err error
		refreshToken, err = (&DatabaseStore{db: transaction, driverLabel: store.driverLabel}).issueRefreshToken(ctx, refreshGrantForCode(grant, exchange.RefreshExpiresAtUnix), exchange.NowUnix)
		return err
	})
	if transactionErr != nil {
		if errors.Is(transactionErr, ErrAuthorizationCodeInvalid) {
			return AuthorizationGrant{}, "", ErrAuthorizationCodeInvalid
		}
		return AuthorizationGrant{}, "", fmt.Errorf("oauth_store.code.redeem.%s: %w", store.driverLabel, transactionErr)
	}
	return grant, refreshToken, nil
}

func (store *DatabaseStore) IssueRefreshToken(ctx context.Context, grant RefreshGrant, nowUnix int64) (string, error) {
	if err := store.CleanupExpired(ctx, nowUnix); err != nil {
		return "", err
	}
	var token string
	err := store.db.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := lockOAuthCapacity(transaction); err != nil {
			return err
		}
		if err := admitOAuthCapacity(transaction, &databaseOAuthRefreshToken{}, grant.TenantID, maximumRefreshPerTenant, maximumRefreshGlobal); err != nil {
			return err
		}
		var err error
		token, err = (&DatabaseStore{db: transaction, driverLabel: store.driverLabel}).issueRefreshToken(ctx, grant, nowUnix)
		return err
	})
	return token, err
}

func (store *DatabaseStore) issueRefreshToken(ctx context.Context, grant RefreshGrant, nowUnix int64) (string, error) {
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
	record := refreshRecordFromGrant(digest, grant, nowUnix)
	if createErr := store.createUserRecord(ctx, record.TenantID, record.UserID, &record); createErr != nil {
		return "", fmt.Errorf("oauth_store.refresh.create.%s: %w", store.driverLabel, createErr)
	}
	return token, nil
}

func (store *DatabaseStore) RotateRefreshToken(ctx context.Context, refreshToken string, clientID string, resource string, scope string, nowUnix int64, authorize AccountAuthorization) (RefreshGrant, string, error) {
	if err := store.CleanupExpired(ctx, nowUnix); err != nil {
		return RefreshGrant{}, "", err
	}
	var grant RefreshGrant
	var newToken string
	reused := false
	invalid := false
	invalidScope := false
	transactionErr := store.db.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := lockOAuthCapacity(transaction); err != nil {
			return err
		}
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
		if err := authkit.RequireActiveAccountWrite(ctx, transaction, record.TenantID, record.UserID); err != nil {
			if errors.Is(err, authkit.ErrAccountNotActive) {
				return ErrRefreshTokenInvalid
			}
			return err
		}
		if err := authorize(ctx, record.TenantID, record.UserID); err != nil {
			return err
		}
		if err := admitOAuthCapacity(transaction, &databaseOAuthRefreshToken{}, record.TenantID, maximumRefreshPerTenant, maximumRefreshGlobal); err != nil {
			return err
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
	if err := store.CleanupExpired(ctx, nowUnix); err != nil {
		return err
	}
	transactionErr := store.db.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := lockOAuthCapacity(transaction); err != nil {
			return err
		}
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
	if err := store.CleanupExpired(ctx, nowUnix); err != nil {
		return err
	}
	transactionErr := store.db.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := lockOAuthCapacity(transaction); err != nil {
			return err
		}
		return revokeRefreshFamilyDatabase(transaction, "", consentID, nowUnix)
	})
	if transactionErr != nil {
		return fmt.Errorf("oauth_store.consent.revoke.%s: %w", store.driverLabel, transactionErr)
	}
	return nil
}

// RevokeUser atomically revokes consents and refresh tokens and removes codes for one tenant and user.
func (store *DatabaseStore) RevokeUser(ctx context.Context, tenantID string, userID string, nowUnix int64) error {
	if err := store.CleanupExpired(ctx, nowUnix); err != nil {
		return err
	}
	transactionErr := store.db.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := lockOAuthCapacity(transaction); err != nil {
			return err
		}
		if err := transaction.Model(&databaseConsent{}).
			Where("tenant_id = ? AND user_id = ? AND revoked_at_unix = 0", tenantID, userID).
			Update("revoked_at_unix", nowUnix).Error; err != nil {
			return err
		}
		if err := transaction.Model(&databaseOAuthRefreshToken{}).
			Where("tenant_id = ? AND user_id = ?", tenantID, userID).
			Updates(map[string]any{"status": refreshTokenStatusRevoked, "revoked_at_unix": nowUnix}).Error; err != nil {
			return err
		}
		return transaction.Where("tenant_id = ? AND user_id = ?", tenantID, userID).Delete(&databaseAuthorizationCode{}).Error
	})
	if transactionErr != nil {
		return fmt.Errorf("oauth_store.user.revoke.%s: %w", store.driverLabel, transactionErr)
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
		ResourceName: record.ResourceName, Scope: record.Scope, DisclosurePolicy: record.DisclosurePolicy, State: record.State, CodeChallenge: record.CodeChallenge,
		CreatedAtUnix: record.CreatedAtUnix, ExpiresAtUnix: record.ExpiresAtUnix,
	}
}

func consentFromDatabase(record databaseConsent) Consent {
	return Consent{ID: record.ID, ConsentKey: ConsentKey{TenantID: record.TenantID, UserID: record.UserID, ClientID: record.ClientID, Resource: record.Resource, Scope: record.Scope, DisclosurePolicy: record.DisclosurePolicy}, CreatedAtUnix: record.CreatedAtUnix, ExpiresAtUnix: record.ExpiresAtUnix, RevokedAtUnix: record.RevokedAtUnix}
}

func authorizationGrantFromDatabase(record databaseAuthorizationCode) AuthorizationGrant {
	return AuthorizationGrant{ConsentID: record.ConsentID, TenantID: record.TenantID, UserID: record.UserID, ClientID: record.ClientID, RedirectURI: record.RedirectURI, Resource: record.Resource, Scope: record.Scope, DisclosurePolicy: record.DisclosurePolicy, CodeChallenge: record.CodeChallenge, ExpiresAtUnix: record.ExpiresAtUnix}
}

func refreshRecordFromGrant(tokenHash string, grant RefreshGrant, issuedAtUnix int64) databaseOAuthRefreshToken {
	return databaseOAuthRefreshToken{TokenHash: tokenHash, ConsentID: grant.ConsentID, FamilyID: grant.FamilyID, TenantID: grant.TenantID, UserID: grant.UserID, ClientID: grant.ClientID, Resource: grant.Resource, Scope: grant.Scope, DisclosurePolicy: grant.DisclosurePolicy, ExpiresAtUnix: grant.ExpiresAtUnix, Status: refreshTokenStatusActive, IssuedAtUnix: issuedAtUnix}
}

func refreshGrantFromDatabase(record databaseOAuthRefreshToken) RefreshGrant {
	return RefreshGrant{ConsentID: record.ConsentID, FamilyID: record.FamilyID, TenantID: record.TenantID, UserID: record.UserID, ClientID: record.ClientID, Resource: record.Resource, Scope: record.Scope, DisclosurePolicy: record.DisclosurePolicy, ExpiresAtUnix: record.ExpiresAtUnix}
}

// RevokeTenantGrants participates in the tenant suspension transaction.
func RevokeTenantGrants(ctx context.Context, db *gorm.DB, tenantID string, nowUnix int64) error {
	if err := db.WithContext(ctx).Model(&databaseOAuthRefreshToken{}).Where("tenant_id = ?", tenantID).Updates(map[string]any{"status": refreshTokenStatusRevoked, "revoked_at_unix": nowUnix}).Error; err != nil {
		return fmt.Errorf("oauth_store.suspend_tokens tenant=%s: %w", tenantID, err)
	}
	if err := db.WithContext(ctx).Model(&databaseConsent{}).Where("tenant_id = ?", tenantID).Update("revoked_at_unix", nowUnix).Error; err != nil {
		return fmt.Errorf("oauth_store.suspend_consents tenant=%s: %w", tenantID, err)
	}
	if err := db.WithContext(ctx).Where("tenant_id = ?", tenantID).Delete(&databaseAuthorizationCode{}).Error; err != nil {
		return fmt.Errorf("oauth_store.suspend_codes tenant=%s: %w", tenantID, err)
	}
	return nil
}

// PurgeUser atomically removes codes, consents, and refresh grants for one tenant and user.
func (store *DatabaseStore) PurgeUser(ctx context.Context, tenantID, userID string) error {
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, model := range []any{&databaseAuthorizationCode{}, &databaseOAuthRefreshToken{}, &databaseConsent{}} {
			if err := tx.Where("tenant_id = ? AND user_id = ?", tenantID, userID).Delete(model).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("oauth_store.user_purge: %w", err)
	}
	return nil
}

func (store *DatabaseStore) createUserRecord(ctx context.Context, tenantID, userID string, record any) error {
	return store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := authkit.RequireActiveAccountWrite(ctx, tx, tenantID, userID); err != nil {
			return err
		}
		return tx.Create(record).Error
	})
}

// ErasureDatabaseIdentity identifies the selected database without disclosing its URL.
func (store *DatabaseStore) ErasureDatabaseIdentity() string { return store.databaseIdentity }

// CleanupExpired commits physical removal before callers reject expired credentials.
func (store *DatabaseStore) CleanupExpired(ctx context.Context, nowUnix int64) error {
	err := store.db.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := lockOAuthCapacity(transaction); err != nil {
			return err
		}
		for _, model := range []any{&databaseAuthorizationRequest{}, &databaseOAuthRefreshToken{}} {
			if err := transaction.Where("expires_at_unix <= ?", nowUnix).Delete(model).Error; err != nil {
				return err
			}
		}
		if err := transaction.Where("expires_at_unix <= ? OR consumed_at_unix <> 0", nowUnix).Delete(&databaseAuthorizationCode{}).Error; err != nil {
			return err
		}
		codes := transaction.Model(&databaseAuthorizationCode{}).Select("consent_id").Where("expires_at_unix > ?", nowUnix)
		refresh := transaction.Model(&databaseOAuthRefreshToken{}).Select("consent_id").Where("expires_at_unix > ?", nowUnix)
		return transaction.Where("(expires_at_unix <= ? OR revoked_at_unix <> 0) AND consent_id NOT IN (?) AND consent_id NOT IN (?)", nowUnix, codes, refresh).Delete(&databaseConsent{}).Error
	})
	if err != nil {
		return fmt.Errorf("oauth_store.cleanup.%s: %w", store.driverLabel, err)
	}
	return nil
}
func lockOAuthCapacity(transaction *gorm.DB) error {
	return transaction.Model(&databaseCapacityLock{}).Where("id = 1").Update("id", 1).Error
}
func admitOAuthCapacity(transaction *gorm.DB, model any, tenantID string, tenantLimit, globalLimit int64) error {
	var tenantCount, globalCount int64
	if err := transaction.Model(model).Count(&globalCount).Error; err != nil {
		return err
	}
	if err := transaction.Model(model).Where("tenant_id = ?", tenantID).Count(&tenantCount).Error; err != nil {
		return err
	}
	if tenantCount >= tenantLimit || globalCount >= globalLimit {
		return ErrAuthorizationCapacity
	}
	return nil
}

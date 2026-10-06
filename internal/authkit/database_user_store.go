package authkit

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tyemirov/tauth/internal/web"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	userProfileTableName        = "user_profiles"
	passwordCredentialTableName = "password_credentials"
	defaultUserRole             = "user"
)

var errUserStoreRolesScanType = errors.New("user_store.roles.scan_type")

// DatabaseUserStore persists user profiles using GORM.
type DatabaseUserStore struct {
	db                   *gorm.DB
	driverLabel          string
	databaseIdentity     string
	now                  func() time.Time
	passwordHashComparer passwordHashComparer
}

// Driver returns the active database driver label.
func (store *DatabaseUserStore) Driver() string {
	return store.driverLabel
}

type roleList []string

func (roles roleList) Value() (driver.Value, error) {
	if len(roles) == 0 {
		return "[]", nil
	}
	encoded, encodeErr := json.Marshal([]string(roles))
	if encodeErr != nil {
		return nil, fmt.Errorf("%s.roles.encode: %w", userStoreErrorPrefix, encodeErr)
	}
	return string(encoded), nil
}

func (roles *roleList) Scan(source interface{}) error {
	if roles == nil {
		return fmt.Errorf("%s.roles.scan: %w", userStoreErrorPrefix, errUserStoreRolesScanType)
	}
	switch typedSource := source.(type) {
	case nil:
		*roles = nil
		return nil
	case []byte:
		decoded, decodeErr := decodeRoleList(typedSource)
		if decodeErr != nil {
			return decodeErr
		}
		*roles = decoded
		return nil
	case string:
		decoded, decodeErr := decodeRoleList([]byte(typedSource))
		if decodeErr != nil {
			return decodeErr
		}
		*roles = decoded
		return nil
	default:
		return fmt.Errorf("%s.roles.scan: %w", userStoreErrorPrefix, errUserStoreRolesScanType)
	}
}

func decodeRoleList(payload []byte) (roleList, error) {
	if len(payload) == 0 {
		return nil, nil
	}
	var decoded []string
	if decodeErr := json.Unmarshal(payload, &decoded); decodeErr != nil {
		return nil, fmt.Errorf("%s.roles.decode: %w", userStoreErrorPrefix, decodeErr)
	}
	return roleList(decoded), nil
}

type userProfileRecord struct {
	TenantID        string   `gorm:"column:tenant_id;primaryKey"`
	UserID          string   `gorm:"column:user_id;primaryKey"`
	UserEmail       string   `gorm:"column:user_email;not null"`
	UserDisplayName string   `gorm:"column:user_display_name;not null"`
	UserAvatarURL   string   `gorm:"column:user_avatar_url;not null"`
	UserRoles       roleList `gorm:"column:user_roles;type:text;not null"`
	CreatedAtUnix   int64    `gorm:"column:created_at_unix;not null"`
	LastUpdatedUnix int64    `gorm:"column:last_updated_unix;not null"`
}

func (userProfileRecord) TableName() string {
	return userProfileTableName
}

type passwordCredentialRecord struct {
	TenantID        string `gorm:"column:tenant_id;primaryKey"`
	UserEmail       string `gorm:"column:user_email;primaryKey"`
	UserID          string `gorm:"column:user_id;index;not null"`
	AccountID       string `gorm:"column:account_id;index"`
	UserDisplayName string `gorm:"column:user_display_name;not null"`
	UserAvatarURL   string `gorm:"column:user_avatar_url;not null"`
	PasswordHash    string `gorm:"column:password_hash;not null"`
	EmailVerified   bool   `gorm:"column:email_verified;not null;default:true"`
	ManagedByConfig bool   `gorm:"column:managed_by_config;not null;default:true"`
	CreatedAtUnix   int64  `gorm:"column:created_at_unix;not null"`
	LastUpdatedUnix int64  `gorm:"column:last_updated_unix;not null"`
}

func (passwordCredentialRecord) TableName() string {
	return passwordCredentialTableName
}

type databaseAccountRecord struct {
	UserID              string   `gorm:"column:user_id;not null;uniqueIndex:idx_account_public_subject"`
	TenantID            string   `gorm:"column:tenant_id;primaryKey;uniqueIndex:idx_account_public_subject"`
	AccountID           string   `gorm:"column:account_id;primaryKey"`
	UserEmail           string   `gorm:"column:user_email;not null"`
	UserDisplayName     string   `gorm:"column:user_display_name;not null"`
	DisplayNameOverride *string  `gorm:"column:display_name_override"`
	UserAvatarURL       string   `gorm:"column:user_avatar_url;not null"`
	AccountState        string   `gorm:"column:account_state;not null"`
	UserRoles           roleList `gorm:"column:user_roles;type:text;not null"`
	CreatedAtUnix       int64    `gorm:"column:created_at_unix;not null"`
	LastUpdatedUnix     int64    `gorm:"column:last_updated_unix;not null"`
}

func (databaseAccountRecord) TableName() string {
	return "accounts"
}

type databaseAccountIdentityRecord struct {
	TenantID        string `gorm:"column:tenant_id;primaryKey"`
	Provider        string `gorm:"column:provider;primaryKey"`
	ProviderID      string `gorm:"column:provider_id;primaryKey"`
	AccountID       string `gorm:"column:account_id;index;not null"`
	CreatedAtUnix   int64  `gorm:"column:created_at_unix;not null"`
	LastUpdatedUnix int64  `gorm:"column:last_updated_unix;not null"`
}

func (databaseAccountIdentityRecord) TableName() string {
	return "account_identities"
}

type databaseAccountChallengeRecord struct {
	TenantID        string `gorm:"column:tenant_id;primaryKey"`
	TokenHash       string `gorm:"column:token_hash;primaryKey"`
	AccountID       string `gorm:"column:account_id;index;not null"`
	ChallengeKind   string `gorm:"column:challenge_kind;index;not null"`
	UserEmail       string `gorm:"column:user_email;not null"`
	UserDisplayName string `gorm:"column:user_display_name;not null"`
	UserAvatarURL   string `gorm:"column:user_avatar_url;not null"`
	PasswordHash    string `gorm:"column:password_hash;not null"`
	ExpiresUnix     int64  `gorm:"column:expires_unix;not null"`
	ConsumedAtUnix  int64  `gorm:"column:consumed_at_unix;not null;default:0"`
	CreatedAtUnix   int64  `gorm:"column:created_at_unix;not null"`
}

func (databaseAccountChallengeRecord) TableName() string {
	return "account_challenges"
}

// NewDatabaseUserStore constructs a DatabaseUserStore backed by the provided database URL.
func NewDatabaseUserStore(ctx context.Context, databaseURL string) (*DatabaseUserStore, error) {
	if err := guardApplicationSubjectSchema(ctx, databaseURL); err != nil {
		return nil, err
	}
	databaseHandle, driverLabel, openErr := openDatabase(ctx, databaseURL, userStoreErrorPrefix, &userProfileRecord{}, &passwordCredentialRecord{}, &databaseAccountRecord{}, &databaseAccountIdentityRecord{}, &databaseAccountChallengeRecord{}, &databaseAccountErasure{}, &githubTransaction{}, &databaseGitHubCredential{}, &abuseBudgetRecord{}, &abuseBudgetLock{})
	if openErr != nil {
		return nil, openErr
	}
	if err := databaseHandle.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&abuseBudgetLock{ID: 1}).Error; err != nil {
		return nil, err
	}
	store := &DatabaseUserStore{
		db:                   databaseHandle,
		driverLabel:          driverLabel,
		databaseIdentity:     hashOpaque(databaseURL),
		now:                  time.Now,
		passwordHashComparer: bcrypt.CompareHashAndPassword,
	}
	if mappingErr := store.validateApplicationSubjects(ctx); mappingErr != nil {
		return nil, mappingErr
	}
	return store, nil
}

// UpsertAccountUser inserts or updates a canonical account profile.
func (store *DatabaseUserStore) UpsertAccountUser(ctx context.Context, tenantID string, accountID string, userEmail string, userDisplayName string, userAvatarURL string) (string, []string, error) {
	normalizedEmail, emailErr := normalizePasswordEmail(userEmail)
	if emailErr != nil {
		return "", nil, fmt.Errorf("%s.upsert_account.%s: %w", userStoreErrorPrefix, store.driverLabel, emailErr)
	}
	if validateOpaqueAccountID(accountID) != nil {
		return "", nil, fmt.Errorf("%s.upsert_account.%s: empty_account_id", userStoreErrorPrefix, store.driverLabel)
	}
	profile, err := store.ResolveAccountProfile(ctx, tenantID, accountID)
	if err != nil {
		return "", nil, err
	}
	return store.upsertUserProfile(ctx, tenantID, profile.UserID, normalizedEmail, userDisplayName, userAvatarURL)
}

func (store *DatabaseUserStore) upsertUserProfile(ctx context.Context, tenantID string, applicationUserID string, userEmail string, userDisplayName string, userAvatarURL string) (string, []string, error) {
	roles := []string{defaultUserRole}
	now := store.now().UTC()
	record := userProfileRecord{
		TenantID:        tenantID,
		UserID:          applicationUserID,
		UserEmail:       userEmail,
		UserDisplayName: userDisplayName,
		UserAvatarURL:   userAvatarURL,
		UserRoles:       roleList(roles),
		CreatedAtUnix:   now.Unix(),
		LastUpdatedUnix: now.Unix(),
	}
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := RequireActiveAccountWrite(ctx, tx, tenantID, applicationUserID); err != nil {
			return err
		}
		{
			profile, err := store.accountProfileForUserWithTx(ctx, tx, tenantID, applicationUserID)
			if err != nil {
				return err
			}
			record.UserEmail = profile.UserEmail
			record.UserDisplayName = profile.DisplayName
			record.UserAvatarURL = profile.AvatarURL
			record.UserRoles = roleList(profile.Roles)
			roles = profile.Roles
		}
		return tx.Clauses(clause.OnConflict{
			Columns: []clause.Column{
				{Name: "tenant_id"},
				{Name: "user_id"},
			},
			DoUpdates: clause.AssignmentColumns([]string{
				"user_email",
				"user_display_name",
				"user_avatar_url",
				"user_roles",
				"last_updated_unix",
			}),
		}).Create(&record).Error
	})
	if err != nil {
		return "", nil, fmt.Errorf("%s.upsert.%s: %w", userStoreErrorPrefix, store.driverLabel, err)
	}
	return applicationUserID, roles, nil
}

// UpsertPasswordCredential inserts or updates one password credential.
func (store *DatabaseUserStore) UpsertPasswordCredential(ctx context.Context, tenantID string, credential PasswordCredentialSeed) error {
	normalizedCredential, normalizeErr := normalizePasswordCredentialSeed(credential)
	if normalizeErr != nil {
		return fmt.Errorf("%s.password_credential.%s: %w", userStoreErrorPrefix, store.driverLabel, normalizeErr)
	}
	now := store.now().UTC()
	record := passwordCredentialRecord{
		TenantID:        tenantID,
		UserEmail:       normalizedCredential.userEmail,
		AccountID:       normalizedCredential.accountID,
		UserDisplayName: normalizedCredential.displayName,
		UserAvatarURL:   normalizedCredential.avatarURL,
		PasswordHash:    normalizedCredential.passwordHash,
		EmailVerified:   normalizedCredential.verified,
		ManagedByConfig: normalizedCredential.managedByConfig,
		CreatedAtUnix:   now.Unix(),
		LastUpdatedUnix: now.Unix(),
	}
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Reserve the writer before resolving credential and provider bindings.
		if err := tx.Model(&databaseAccountRecord{}).Where("tenant_id = ? AND account_id IN (SELECT account_id FROM password_credentials WHERE tenant_id = ? AND user_email = ? UNION SELECT account_id FROM account_identities WHERE tenant_id = ? AND provider = ? AND provider_id = ?)", tenantID, tenantID, record.UserEmail, tenantID, accountProviderPassword, record.UserEmail).Update("last_updated_unix", gorm.Expr("last_updated_unix")).Error; err != nil {
			return err
		}
		var previous passwordCredentialRecord
		lookupErr := tx.Where("tenant_id = ? AND user_email = ?", tenantID, record.UserEmail).Take(&previous).Error
		if lookupErr != nil && !errors.Is(lookupErr, gorm.ErrRecordNotFound) {
			return lookupErr
		}
		if lookupErr == nil && previous.AccountID != "" {
			record.AccountID = previous.AccountID
		}
		var retained databaseAccountIdentityRecord
		identityErr := tx.Where("tenant_id = ? AND provider = ? AND provider_id = ?", tenantID, accountProviderPassword, record.UserEmail).Take(&retained).Error
		if identityErr != nil && !errors.Is(identityErr, gorm.ErrRecordNotFound) {
			return identityErr
		}
		if identityErr == nil {
			if record.AccountID != "" && record.AccountID != retained.AccountID {
				return ErrAccountExists
			}
			record.AccountID = retained.AccountID
		}
		if record.AccountID == "" {
			id, err := store.newUniqueOpaqueAccountID(ctx, tx, tenantID)
			if err != nil {
				return err
			}
			record.AccountID = id
			account := databaseAccountRecord{TenantID: tenantID, AccountID: id, UserID: id, UserEmail: record.UserEmail, UserDisplayName: record.UserDisplayName, UserAvatarURL: record.UserAvatarURL, AccountState: accountStateActive, UserRoles: roleList{defaultUserRole}, CreatedAtUnix: now.Unix(), LastUpdatedUnix: now.Unix()}
			if err = tx.Create(&account).Error; err != nil {
				return err
			}
		} else {
			if err := validateOpaqueAccountID(record.AccountID); err != nil {
				return err
			}
			if err := lockActiveAccount(ctx, tx, tenantID, record.AccountID); err != nil {
				return err
			}
			if err := tx.Model(&databaseAccountRecord{}).Where("tenant_id = ? AND account_id = ?", tenantID, record.AccountID).
				Updates(map[string]any{"user_display_name": gorm.Expr("COALESCE(display_name_override, ?)", record.UserDisplayName), "user_avatar_url": record.UserAvatarURL, "last_updated_unix": now.Unix()}).Error; err != nil {
				return err
			}
		}
		account, err := store.accountProfileWithTx(ctx, tx, tenantID, record.AccountID)
		if err != nil {
			return err
		}
		record.UserID = account.UserID
		identity := databaseAccountIdentityRecord{TenantID: tenantID, Provider: accountProviderPassword, ProviderID: record.UserEmail, AccountID: record.AccountID, CreatedAtUnix: now.Unix(), LastUpdatedUnix: now.Unix()}
		if err = tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&identity).Error; err != nil {
			return err
		}
		var bound databaseAccountIdentityRecord
		if err = tx.Where("tenant_id = ? AND provider = ? AND provider_id = ?", tenantID, accountProviderPassword, record.UserEmail).Take(&bound).Error; err != nil {
			return err
		}
		if bound.AccountID != record.AccountID {
			return ErrAccountExists
		}
		return tx.Clauses(clause.OnConflict{
			Columns: []clause.Column{
				{Name: "tenant_id"},
				{Name: "user_email"},
			},
			DoUpdates: clause.AssignmentColumns([]string{
				"user_id",
				"account_id",
				"user_display_name",
				"user_avatar_url",
				"password_hash",
				"email_verified",
				"managed_by_config",
				"last_updated_unix",
			}),
		}).Create(&record).Error
	})
	if err != nil {
		return fmt.Errorf("%s.password_credential.%s: %w", userStoreErrorPrefix, store.driverLabel, err)
	}
	return nil
}

// ReconcilePasswordCredentials removes tenant credentials absent from the current config.
func (store *DatabaseUserStore) ReconcilePasswordCredentials(ctx context.Context, tenantID string, configuredEmails []string) error {
	configuredEmailSet, normalizeErr := normalizePasswordEmailSet(configuredEmails)
	if normalizeErr != nil {
		return fmt.Errorf("%s.password_credential_reconcile.%s: %w", userStoreErrorPrefix, store.driverLabel, normalizeErr)
	}
	configuredEmailList := make([]string, 0, len(configuredEmailSet))
	for configuredEmail := range configuredEmailSet {
		configuredEmailList = append(configuredEmailList, configuredEmail)
	}
	deleteQuery := store.db.WithContext(ctx).Where("tenant_id = ? AND managed_by_config = ?", tenantID, true)
	if len(configuredEmailList) > 0 {
		deleteQuery = deleteQuery.Where("user_email NOT IN ?", configuredEmailList)
	}
	if err := deleteQuery.Delete(&passwordCredentialRecord{}).Error; err != nil {
		return fmt.Errorf("%s.password_credential_reconcile.%s: %w", userStoreErrorPrefix, store.driverLabel, err)
	}
	return nil
}

// AuthenticatePassword verifies one password credential and returns its profile.
func (store *DatabaseUserStore) AuthenticatePassword(ctx context.Context, tenantID string, userEmail string, password string) (PasswordCredentialProfile, error) {
	normalizedEmail, emailErr := normalizePasswordEmail(userEmail)
	if emailErr != nil {
		return PasswordCredentialProfile{}, ErrPasswordCredentialInvalid
	}
	if passwordErr := validatePlainPassword(password); passwordErr != nil {
		return PasswordCredentialProfile{}, ErrPasswordCredentialInvalid
	}
	if err := store.reserveAuthenticationBudget(ctx, "password", tenantID, normalizedEmail, 5, 30); err != nil {
		return PasswordCredentialProfile{}, err
	}
	var record passwordCredentialRecord
	queryErr := store.db.WithContext(ctx).
		Where("tenant_id = ? AND user_email = ?", tenantID, normalizedEmail).
		Take(&record).Error
	if queryErr != nil {
		if errors.Is(queryErr, gorm.ErrRecordNotFound) {
			_ = store.passwordHashComparer([]byte(passwordCredentialTimingHash), []byte(password))
			return PasswordCredentialProfile{}, ErrPasswordCredentialInvalid
		}
		return PasswordCredentialProfile{}, fmt.Errorf("%s.password_auth.%s: %w", userStoreErrorPrefix, store.driverLabel, queryErr)
	}
	if compareErr := store.passwordHashComparer([]byte(record.PasswordHash), []byte(password)); compareErr != nil {
		return PasswordCredentialProfile{}, ErrPasswordCredentialInvalid
	}
	if !record.EmailVerified {
		return PasswordCredentialProfile{}, ErrAccountNotActive
	}
	if strings.TrimSpace(record.AccountID) != "" {
		accountProfile, profileErr := store.ResolveAccountProfile(ctx, tenantID, record.AccountID)
		if profileErr != nil && !errors.Is(profileErr, ErrAccountNotFound) {
			return PasswordCredentialProfile{}, profileErr
		}
		if profileErr == nil {
			if accountProfile.State == accountStateDisabled {
				return PasswordCredentialProfile{}, ErrAccountDisabled
			}
			if accountProfile.State != accountStateActive {
				return PasswordCredentialProfile{}, ErrAccountNotActive
			}
		}
	}
	return PasswordCredentialProfile{
		AccountID:   record.AccountID,
		UserEmail:   record.UserEmail,
		DisplayName: record.UserDisplayName,
		AvatarURL:   record.UserAvatarURL,
	}, nil
}

// GetUserProfile returns the stored profile for a user.
func (store *DatabaseUserStore) GetUserProfile(ctx context.Context, tenantID string, applicationUserID string) (string, string, string, []string, error) {
	var record userProfileRecord
	queryErr := store.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ?", tenantID, applicationUserID).
		Take(&record).Error
	if queryErr != nil {
		if errors.Is(queryErr, gorm.ErrRecordNotFound) {
			return "", "", "", nil, web.ErrUserNotFound
		}
		return "", "", "", nil, fmt.Errorf("%s.get.%s: %w", userStoreErrorPrefix, store.driverLabel, queryErr)
	}
	return record.UserEmail, record.UserDisplayName, record.UserAvatarURL, []string(record.UserRoles), nil
}

// CreatePasswordSignup starts a tenant-managed password signup.
func (store *DatabaseUserStore) CreatePasswordSignup(ctx context.Context, tenantID string, request AccountPasswordRequest, expiresUnix int64) (AccountChallenge, error) {
	credential, credentialErr := buildAccountPasswordCredential(request)
	if credentialErr != nil {
		return AccountChallenge{}, credentialErr
	}
	token, tokenHash, tokenErr := generateRefreshOpaque()
	if tokenErr != nil {
		return AccountChallenge{}, fmt.Errorf("%s.account_signup_token.%s: %w", userStoreErrorPrefix, store.driverLabel, tokenErr)
	}
	now := store.now().UTC().Unix()
	var accountID string
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existingCredential passwordCredentialRecord
		credentialErr := tx.WithContext(ctx).Where("tenant_id = ? AND user_email = ?", tenantID, credential.userEmail).Take(&existingCredential).Error
		if credentialErr == nil {
			return ErrAccountExists
		}
		if credentialErr != nil && !errors.Is(credentialErr, gorm.ErrRecordNotFound) {
			return credentialErr
		}
		if exists, existsErr := store.accountIdentityExists(ctx, tx, tenantID, accountProviderPassword, credential.userEmail); existsErr != nil || exists {
			if existsErr != nil {
				return existsErr
			}
			return ErrAccountExists
		}
		generatedAccountID, accountIDErr := store.newUniqueOpaqueAccountID(ctx, tx, tenantID)
		if accountIDErr != nil {
			return accountIDErr
		}
		accountID = generatedAccountID
		account := databaseAccountRecord{
			TenantID:        tenantID,
			AccountID:       accountID,
			UserID:          accountID,
			UserEmail:       credential.userEmail,
			UserDisplayName: credential.displayName,
			UserAvatarURL:   credential.avatarURL,
			AccountState:    accountStatePendingVerification,
			UserRoles:       roleList([]string{defaultUserRole}),
			CreatedAtUnix:   now,
			LastUpdatedUnix: now,
		}
		if createErr := tx.Create(&account).Error; createErr != nil {
			return createErr
		}
		passwordRecord := passwordCredentialRecord{
			TenantID:        tenantID,
			UserEmail:       credential.userEmail,
			UserID:          accountID,
			AccountID:       accountID,
			UserDisplayName: credential.displayName,
			UserAvatarURL:   credential.avatarURL,
			PasswordHash:    credential.passwordHash,
			EmailVerified:   false,
			ManagedByConfig: false,
			CreatedAtUnix:   now,
			LastUpdatedUnix: now,
		}
		if createErr := tx.Select("*").Create(&passwordRecord).Error; createErr != nil {
			return createErr
		}
		if updateErr := tx.Model(&passwordCredentialRecord{}).
			Where("tenant_id = ? AND user_email = ?", tenantID, credential.userEmail).
			Updates(map[string]interface{}{"email_verified": false, "managed_by_config": false}).Error; updateErr != nil {
			return updateErr
		}
		challenge := databaseAccountChallengeRecord{
			TenantID:        tenantID,
			TokenHash:       tokenHash,
			AccountID:       accountID,
			ChallengeKind:   accountChallengeEmailVerification,
			UserEmail:       credential.userEmail,
			UserDisplayName: credential.displayName,
			UserAvatarURL:   credential.avatarURL,
			PasswordHash:    credential.passwordHash,
			ExpiresUnix:     expiresUnix,
			CreatedAtUnix:   now,
		}
		return tx.Create(&challenge).Error
	})
	if err != nil {
		return AccountChallenge{}, fmt.Errorf("%s.account_signup.%s: %w", userStoreErrorPrefix, store.driverLabel, err)
	}
	return AccountChallenge{AccountID: accountID, Token: token, ExpiresUnix: expiresUnix}, nil
}

// CancelPasswordSignup removes a pending signup after delivery fails.
func (store *DatabaseUserStore) CancelPasswordSignup(ctx context.Context, tenantID string, accountID string) error {
	cancelErr := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var account databaseAccountRecord
		accountErr := tx.Where("tenant_id = ? AND account_id = ? AND account_state = ?", tenantID, accountID, accountStatePendingVerification).Take(&account).Error
		if accountErr != nil {
			return accountErr
		}
		if deleteErr := tx.Where("tenant_id = ? AND account_id = ? AND challenge_kind = ?", tenantID, accountID, accountChallengeEmailVerification).Delete(&databaseAccountChallengeRecord{}).Error; deleteErr != nil {
			return deleteErr
		}
		if deleteErr := tx.Where("tenant_id = ? AND account_id = ?", tenantID, accountID).Delete(&passwordCredentialRecord{}).Error; deleteErr != nil {
			return deleteErr
		}
		return tx.Where("tenant_id = ? AND account_id = ? AND account_state = ?", tenantID, accountID, accountStatePendingVerification).Delete(&databaseAccountRecord{}).Error
	})
	if cancelErr != nil {
		return fmt.Errorf("%s.account_signup_cancel.%s: %w", userStoreErrorPrefix, store.driverLabel, cancelErr)
	}
	return nil
}

// CancelAccountChallenge removes one unconsumed reset or link challenge.
func (store *DatabaseUserStore) CancelAccountChallenge(ctx context.Context, tenantID string, accountID string, token string) error {
	deleteResult := store.db.WithContext(ctx).
		Where(
			"tenant_id = ? AND account_id = ? AND token_hash = ? AND challenge_kind IN ? AND consumed_at_unix = 0",
			tenantID,
			accountID,
			hashOpaque(strings.TrimSpace(token)),
			[]string{accountChallengePasswordReset, accountChallengePasswordLink},
		).
		Delete(&databaseAccountChallengeRecord{})
	if deleteResult.Error != nil {
		return fmt.Errorf("%s.account_challenge_cancel.%s: %w", userStoreErrorPrefix, store.driverLabel, deleteResult.Error)
	}
	if deleteResult.RowsAffected != 1 {
		return fmt.Errorf("%s.account_challenge_cancel.%s: challenge_not_found", userStoreErrorPrefix, store.driverLabel)
	}
	return nil
}

// VerifyEmailChallenge activates a pending signup.
func (store *DatabaseUserStore) VerifyEmailChallenge(ctx context.Context, tenantID string, token string) (AccountProfile, error) {
	var profile AccountProfile
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		challenge, challengeErr := store.consumeDatabaseChallenge(ctx, tx, tenantID, token, accountChallengeEmailVerification)
		if challengeErr != nil {
			return challengeErr
		}
		activation := tx.Model(&databaseAccountRecord{}).Where("tenant_id = ? AND account_id = ? AND account_state = ?", tenantID, challenge.AccountID, accountStatePendingVerification).Updates(map[string]interface{}{"account_state": accountStateActive, "last_updated_unix": store.now().UTC().Unix()})
		if activation.Error != nil {
			return activation.Error
		}
		if activation.RowsAffected != 1 {
			return ErrAccountNotActive
		}

		if updateErr := tx.Model(&passwordCredentialRecord{}).
			Where("tenant_id = ? AND user_email = ?", tenantID, challenge.UserEmail).
			Updates(map[string]interface{}{"email_verified": true, "account_id": challenge.AccountID, "last_updated_unix": store.now().UTC().Unix()}).Error; updateErr != nil {
			return updateErr
		}
		identity := databaseAccountIdentityRecord{
			TenantID:        tenantID,
			Provider:        accountProviderPassword,
			ProviderID:      challenge.UserEmail,
			AccountID:       challenge.AccountID,
			CreatedAtUnix:   store.now().UTC().Unix(),
			LastUpdatedUnix: store.now().UTC().Unix(),
		}
		if createErr := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "provider"}, {Name: "provider_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"account_id", "last_updated_unix"}),
		}).Create(&identity).Error; createErr != nil {
			return createErr
		}
		accountProfile, profileErr := store.accountProfileWithTx(ctx, tx, tenantID, challenge.AccountID)
		if profileErr != nil {
			return profileErr
		}
		profile = accountProfile
		return nil
	})
	if err != nil {
		return AccountProfile{}, fmt.Errorf("%s.account_verify.%s: %w", userStoreErrorPrefix, store.driverLabel, err)
	}
	return profile, nil
}

// StartPasswordReset issues a reset challenge for an existing password identity.
func (store *DatabaseUserStore) StartPasswordReset(ctx context.Context, tenantID string, userEmail string, expiresUnix int64) (AccountChallenge, error) {
	normalizedEmail, emailErr := normalizePasswordEmail(userEmail)
	if emailErr != nil {
		return AccountChallenge{}, ErrPasswordCredentialInvalid
	}
	if err := store.reserveAuthenticationBudget(ctx, "reset", tenantID, normalizedEmail, 1, 10); err != nil {
		return AccountChallenge{}, err
	}
	token, tokenHash, tokenErr := generateRefreshOpaque()
	if tokenErr != nil {
		return AccountChallenge{}, fmt.Errorf("%s.account_reset_token.%s: %w", userStoreErrorPrefix, store.driverLabel, tokenErr)
	}
	var record passwordCredentialRecord
	queryErr := store.db.WithContext(ctx).Where("tenant_id = ? AND user_email = ? AND email_verified = ?", tenantID, normalizedEmail, true).Take(&record).Error
	if queryErr != nil {
		if errors.Is(queryErr, gorm.ErrRecordNotFound) {
			return AccountChallenge{}, ErrAccountNotFound
		}
		return AccountChallenge{}, fmt.Errorf("%s.account_reset_lookup.%s: %w", userStoreErrorPrefix, store.driverLabel, queryErr)
	}
	if strings.TrimSpace(record.AccountID) == "" {
		return AccountChallenge{}, ErrAccountNotFound
	}
	now := store.now().UTC().Unix()
	challenge := databaseAccountChallengeRecord{
		TenantID:        tenantID,
		TokenHash:       tokenHash,
		AccountID:       record.AccountID,
		ChallengeKind:   accountChallengePasswordReset,
		UserEmail:       record.UserEmail,
		UserDisplayName: record.UserDisplayName,
		UserAvatarURL:   record.UserAvatarURL,
		ExpiresUnix:     expiresUnix,
		CreatedAtUnix:   now,
	}
	var capacityExceeded bool
	createErr := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockActiveAccount(ctx, tx, tenantID, record.AccountID); err != nil {
			return err
		}
		if err := tx.Model(&abuseBudgetLock{}).Where("id = ?", 1).Update("id", 1).Error; err != nil {
			return err
		}
		if err := tx.Where("challenge_kind = ? AND (expires_unix <= ? OR (tenant_id = ? AND account_id = ?))", accountChallengePasswordReset, now, tenantID, record.AccountID).Delete(&databaseAccountChallengeRecord{}).Error; err != nil {
			return err
		}
		var count int64
		if err := tx.Model(&databaseAccountChallengeRecord{}).Where("challenge_kind = ?", accountChallengePasswordReset).Count(&count).Error; err != nil {
			return err
		}
		if count >= maximumResetChallenges {
			capacityExceeded = true
			return nil
		}
		return tx.Create(&challenge).Error
	})
	if createErr != nil {
		return AccountChallenge{}, fmt.Errorf("%s.account_reset_create.%s: %w", userStoreErrorPrefix, store.driverLabel, createErr)
	}
	if capacityExceeded {
		return AccountChallenge{}, ErrAuthenticationRateLimited
	}
	return AccountChallenge{AccountID: record.AccountID, Token: token, ExpiresUnix: expiresUnix}, nil
}

// CompletePasswordReset rotates the credential for a valid reset challenge.
func (store *DatabaseUserStore) CompletePasswordReset(ctx context.Context, tenantID string, token string, password string) (AccountProfile, error) {
	passwordHash, hashErr := HashPassword(password)
	if hashErr != nil {
		return AccountProfile{}, ErrPasswordCredentialInvalid
	}
	var profile AccountProfile
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		challenge, challengeErr := store.consumeDatabaseChallenge(ctx, tx, tenantID, token, accountChallengePasswordReset)
		if challengeErr != nil {
			return challengeErr
		}
		current, profileErr := store.accountProfileWithTx(ctx, tx, tenantID, challenge.AccountID)
		if profileErr != nil {
			return profileErr
		}
		if current.State == accountStateDisabled {
			return ErrAccountDisabled
		}
		if err := lockActiveAccount(ctx, tx, tenantID, challenge.AccountID); err != nil {
			return err
		}
		if updateErr := tx.Model(&passwordCredentialRecord{}).
			Where("tenant_id = ? AND user_email = ? AND account_id = ?", tenantID, challenge.UserEmail, challenge.AccountID).
			Updates(map[string]interface{}{"password_hash": passwordHash, "email_verified": true, "last_updated_unix": store.now().UTC().Unix()}).Error; updateErr != nil {
			return updateErr
		}
		accountProfile, profileErr := store.accountProfileWithTx(ctx, tx, tenantID, challenge.AccountID)
		if profileErr != nil {
			return profileErr
		}
		if accountProfile.State == accountStateDisabled {
			return ErrAccountDisabled
		}
		profile = accountProfile
		return nil
	})
	if err != nil {
		return AccountProfile{}, fmt.Errorf("%s.account_reset_complete.%s: %w", userStoreErrorPrefix, store.driverLabel, err)
	}
	return profile, nil
}

// ChangePassword rotates a password credential for the authenticated account.
func (store *DatabaseUserStore) ChangePassword(ctx context.Context, tenantID string, accountID string, currentPassword string, newPassword string) (AccountProfile, error) {
	passwordHash, hashErr := HashPassword(newPassword)
	if hashErr != nil {
		return AccountProfile{}, ErrPasswordCredentialInvalid
	}
	accountProfile, profileErr := store.ResolveAccountProfile(ctx, tenantID, accountID)
	if profileErr != nil {
		return AccountProfile{}, profileErr
	}
	if accountProfile.State == accountStateDisabled {
		return AccountProfile{}, ErrAccountDisabled
	}
	if accountProfile.State != accountStateActive {
		return AccountProfile{}, ErrAccountNotActive
	}
	var record passwordCredentialRecord
	queryErr := store.db.WithContext(ctx).Where("tenant_id = ? AND account_id = ? AND email_verified = ?", tenantID, accountID, true).Take(&record).Error
	if queryErr != nil {
		if errors.Is(queryErr, gorm.ErrRecordNotFound) {
			return AccountProfile{}, ErrPasswordCredentialInvalid
		}
		return AccountProfile{}, fmt.Errorf("%s.account_change_password.%s: %w", userStoreErrorPrefix, store.driverLabel, queryErr)
	}
	if compareErr := store.passwordHashComparer([]byte(record.PasswordHash), []byte(currentPassword)); compareErr != nil {
		return AccountProfile{}, ErrPasswordCredentialInvalid
	}
	updateErr := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockActiveAccount(ctx, tx, tenantID, accountID); err != nil {
			return err
		}
		return tx.Model(&passwordCredentialRecord{}).Where("tenant_id = ? AND user_email = ? AND account_id = ?", tenantID, record.UserEmail, accountID).Updates(map[string]interface{}{"password_hash": passwordHash, "last_updated_unix": store.now().UTC().Unix()}).Error
	})
	if updateErr != nil {
		return AccountProfile{}, fmt.Errorf("%s.account_change_password.%s: %w", userStoreErrorPrefix, store.driverLabel, updateErr)
	}

	return accountProfile, nil
}

// EnsurePasswordAccount resolves the verified credential's canonical account.
func (store *DatabaseUserStore) EnsurePasswordAccount(ctx context.Context, tenantID, userEmail string) (AccountProfile, error) {
	email, err := normalizePasswordEmail(userEmail)
	if err != nil {
		return AccountProfile{}, ErrPasswordCredentialInvalid
	}
	var credential passwordCredentialRecord
	err = store.db.WithContext(ctx).Where("tenant_id = ? AND user_email = ? AND email_verified = ?", tenantID, email, true).Take(&credential).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return AccountProfile{}, ErrPasswordCredentialInvalid
	}
	if err != nil {
		return AccountProfile{}, fmt.Errorf("account.password_lookup: %w", err)
	}
	profile, err := store.ResolveAccountProfile(ctx, tenantID, credential.AccountID)
	if err != nil {
		return AccountProfile{}, err
	}
	if profile.State == accountStateDisabled {
		return AccountProfile{}, ErrAccountDisabled
	}
	if profile.State != accountStateActive {
		return AccountProfile{}, ErrAccountNotActive
	}
	return profile, nil
}

// CreatePasswordLink starts linking a password identity to an existing account.
func (store *DatabaseUserStore) CreatePasswordLink(ctx context.Context, tenantID string, accountID string, request AccountPasswordRequest, expiresUnix int64) (AccountChallenge, error) {
	credential, credentialErr := buildAccountPasswordCredential(request)
	if credentialErr != nil {
		return AccountChallenge{}, credentialErr
	}
	token, tokenHash, tokenErr := generateRefreshOpaque()
	if tokenErr != nil {
		return AccountChallenge{}, fmt.Errorf("%s.account_link_password_token.%s: %w", userStoreErrorPrefix, store.driverLabel, tokenErr)
	}
	now := store.now().UTC().Unix()
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockActiveAccount(ctx, tx, tenantID, accountID); err != nil {
			return err
		}
		if _, profileErr := store.accountProfileWithTx(ctx, tx, tenantID, accountID); profileErr != nil {
			return profileErr
		}
		if exists, existsErr := store.accountIdentityExists(ctx, tx, tenantID, accountProviderPassword, credential.userEmail); existsErr != nil || exists {
			if existsErr != nil {
				return existsErr
			}
			return ErrAccountExists
		}
		challenge := databaseAccountChallengeRecord{
			TenantID:        tenantID,
			TokenHash:       tokenHash,
			AccountID:       accountID,
			ChallengeKind:   accountChallengePasswordLink,
			UserEmail:       credential.userEmail,
			UserDisplayName: credential.displayName,
			UserAvatarURL:   credential.avatarURL,
			PasswordHash:    credential.passwordHash,
			ExpiresUnix:     expiresUnix,
			CreatedAtUnix:   now,
		}
		return tx.Create(&challenge).Error
	})
	if err != nil {
		return AccountChallenge{}, fmt.Errorf("%s.account_link_password.%s: %w", userStoreErrorPrefix, store.driverLabel, err)
	}
	return AccountChallenge{AccountID: accountID, Token: token, ExpiresUnix: expiresUnix}, nil
}

// VerifyPasswordLink completes linking a password identity to the authenticated account.
func (store *DatabaseUserStore) VerifyPasswordLink(ctx context.Context, tenantID string, accountID string, token string) (AccountProfile, error) {
	var profile AccountProfile
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		challenge, challengeErr := store.consumeDatabaseChallenge(ctx, tx, tenantID, token, accountChallengePasswordLink)
		if challengeErr != nil {
			return challengeErr
		}
		if challenge.AccountID != accountID {
			return ErrAccountChallengeInvalid
		}
		if err := lockActiveAccount(ctx, tx, tenantID, accountID); err != nil {
			return err
		}
		now := store.now().UTC().Unix()
		identity := databaseAccountIdentityRecord{
			TenantID:        tenantID,
			Provider:        accountProviderPassword,
			ProviderID:      challenge.UserEmail,
			AccountID:       accountID,
			CreatedAtUnix:   now,
			LastUpdatedUnix: now,
		}
		if createErr := tx.Create(&identity).Error; createErr != nil {
			return createErr
		}
		accountProfile, profileErr := store.accountProfileWithTx(ctx, tx, tenantID, accountID)
		if profileErr != nil {
			return profileErr
		}
		credential := passwordCredentialRecord{
			TenantID:        tenantID,
			UserEmail:       challenge.UserEmail,
			UserID:          accountProfile.UserID,
			AccountID:       accountID,
			UserDisplayName: challenge.UserDisplayName,
			UserAvatarURL:   challenge.UserAvatarURL,
			PasswordHash:    challenge.PasswordHash,
			EmailVerified:   true,
			ManagedByConfig: false,
			CreatedAtUnix:   now,
			LastUpdatedUnix: now,
		}
		if createErr := tx.Select("*").Create(&credential).Error; createErr != nil {
			return createErr
		}
		profile = accountProfile
		return nil
	})
	if err != nil {
		return AccountProfile{}, fmt.Errorf("%s.account_link_password_verify.%s: %w", userStoreErrorPrefix, store.driverLabel, err)
	}
	return profile, nil
}

// AuthenticateGoogleAccount resolves an existing linked Google identity.
func (store *DatabaseUserStore) AuthenticateGoogleAccount(ctx context.Context, tenantID string, identity GoogleAccountIdentity) (AccountProfile, bool, error) {
	return store.AuthenticateProviderAccount(ctx, tenantID, googleProviderIdentity(identity))
}

// AuthenticateProviderAccount resolves an existing linked external provider identity.
func (store *DatabaseUserStore) AuthenticateProviderAccount(ctx context.Context, tenantID string, identity AccountProviderIdentity) (AccountProfile, bool, error) {
	normalizedIdentity, identityErr := normalizeAccountProviderIdentity(identity)
	if identityErr != nil {
		return AccountProfile{}, false, identityErr
	}
	var identityRecord databaseAccountIdentityRecord
	queryErr := store.db.WithContext(ctx).Where("tenant_id = ? AND provider = ? AND provider_id = ?", tenantID, normalizedIdentity.Provider, normalizedIdentity.Subject).Take(&identityRecord).Error
	if queryErr != nil {
		if errors.Is(queryErr, gorm.ErrRecordNotFound) {
			return AccountProfile{}, false, nil
		}
		return AccountProfile{}, false, fmt.Errorf("%s.account_provider_lookup.%s: %w", userStoreErrorPrefix, store.driverLabel, queryErr)
	}
	profile, profileErr := store.ResolveAccountProfile(ctx, tenantID, identityRecord.AccountID)
	if profileErr != nil {
		return AccountProfile{}, false, profileErr
	}
	if profile.State == accountStateDisabled {
		return AccountProfile{}, false, ErrAccountDisabled
	}
	if profile.State != accountStateActive {
		return AccountProfile{}, false, ErrAccountNotActive
	}
	return profile, true, nil
}

// UpsertGoogleAccount creates or updates an account for a verified Google identity.
func (store *DatabaseUserStore) UpsertGoogleAccount(ctx context.Context, tenantID string, identity GoogleAccountIdentity) (AccountProfile, error) {
	return store.UpsertProviderAccount(ctx, tenantID, googleProviderIdentity(identity))
}

// UpsertProviderAccount creates or updates an account for a verified external provider identity.
func (store *DatabaseUserStore) UpsertProviderAccount(ctx context.Context, tenantID string, identity AccountProviderIdentity) (AccountProfile, error) {
	normalized, err := normalizeAccountProviderIdentity(identity)
	if err != nil {
		return AccountProfile{}, err
	}
	candidateID, err := newOpaqueAccountID()
	if err != nil {
		return AccountProfile{}, err
	}
	now := store.now().UTC().Unix()
	accountID := candidateID
	err = store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Claim the unique provider tuple before reading. This also obtains the
		// SQLite write reservation without a deferred read-to-write upgrade.
		record := databaseAccountIdentityRecord{TenantID: tenantID, Provider: normalized.Provider, ProviderID: normalized.Subject, AccountID: candidateID, CreatedAtUnix: now, LastUpdatedUnix: now}
		result := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&record)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 1 {
			account := databaseAccountRecord{TenantID: tenantID, AccountID: candidateID, UserID: candidateID, UserEmail: normalized.UserEmail, UserDisplayName: normalized.DisplayName, UserAvatarURL: normalized.AvatarURL, AccountState: accountStateActive, UserRoles: roleList{defaultUserRole}, CreatedAtUnix: now, LastUpdatedUnix: now}
			return tx.Create(&account).Error
		}
		if err := tx.Where("tenant_id = ? AND provider = ? AND provider_id = ?", tenantID, normalized.Provider, normalized.Subject).Take(&record).Error; err != nil {
			return err
		}
		accountID = record.AccountID
		result = tx.Model(&databaseAccountRecord{}).Where("tenant_id = ? AND account_id = ? AND account_state = ?", tenantID, accountID, accountStateActive).
			Updates(map[string]interface{}{"user_email": normalized.UserEmail, "user_display_name": gorm.Expr("COALESCE(display_name_override, CASE WHEN ? = '' THEN user_display_name ELSE ? END)", strings.TrimSpace(identity.DisplayName), normalized.DisplayName), "user_avatar_url": normalized.AvatarURL, "last_updated_unix": now})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrAccountNotActive
		}
		return nil
	})
	if err != nil {
		return AccountProfile{}, fmt.Errorf("%s.account_provider_upsert.%s: %w", userStoreErrorPrefix, store.driverLabel, err)
	}
	return store.ResolveAccountProfile(ctx, tenantID, accountID)
}

// LinkGoogleIdentity links a verified Google identity to an existing account.
func (store *DatabaseUserStore) LinkGoogleIdentity(ctx context.Context, tenantID string, accountID string, identity GoogleAccountIdentity) (AccountProfile, error) {
	return store.LinkProviderIdentity(ctx, tenantID, accountID, googleProviderIdentity(identity))
}

// LinkProviderIdentity links a verified external provider identity to an existing account.
func (store *DatabaseUserStore) LinkProviderIdentity(ctx context.Context, tenantID string, accountID string, identity AccountProviderIdentity) (AccountProfile, error) {
	normalizedIdentity, err := normalizeAccountProviderIdentity(identity)
	if err != nil {
		return AccountProfile{}, err
	}
	now := store.now().UTC().Unix()
	err = store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&databaseAccountRecord{}).Where("tenant_id = ? AND account_id = ? AND account_state = ?", tenantID, accountID, accountStateActive).Update("last_updated_unix", now)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrAccountNotActive
		}
		record := databaseAccountIdentityRecord{TenantID: tenantID, Provider: normalizedIdentity.Provider, ProviderID: normalizedIdentity.Subject, AccountID: accountID, CreatedAtUnix: now, LastUpdatedUnix: now}
		result = tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&record)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 1 {
			return nil
		}
		var existing databaseAccountIdentityRecord
		if err := tx.Where("tenant_id = ? AND provider = ? AND provider_id = ?", tenantID, normalizedIdentity.Provider, normalizedIdentity.Subject).Take(&existing).Error; err != nil {
			return err
		}
		if existing.AccountID != accountID {
			return ErrAccountExists
		}
		return nil
	})
	if err != nil {
		return AccountProfile{}, fmt.Errorf("%s.account_link_provider.%s: %w", userStoreErrorPrefix, store.driverLabel, err)
	}
	return store.ResolveAccountProfile(ctx, tenantID, accountID)
}

// UnlinkIdentity removes one linked identity from an account.
func (store *DatabaseUserStore) UnlinkIdentity(ctx context.Context, tenantID string, accountID string, provider string, providerID string) (AccountProfile, error) {
	normalizedProvider := strings.ToLower(strings.TrimSpace(provider))
	normalizedProviderID := strings.TrimSpace(providerID)
	if normalizedProvider == accountProviderPassword {
		normalizedEmail, emailErr := normalizePasswordEmail(providerID)
		if emailErr != nil {
			return AccountProfile{}, ErrPasswordCredentialInvalid
		}
		normalizedProviderID = normalizedEmail
	}
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockActiveAccount(ctx, tx, tenantID, accountID); err != nil {
			return err
		}
		count, countErr := store.identityCountWithTx(ctx, tx, tenantID, accountID)
		if countErr != nil {
			return countErr
		}
		if count <= 1 {
			return ErrAccountLastIdentity
		}
		result := tx.WithContext(ctx).Where("tenant_id = ? AND account_id = ? AND provider = ? AND provider_id = ?", tenantID, accountID, normalizedProvider, normalizedProviderID).Delete(&databaseAccountIdentityRecord{})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return ErrAccountNotFound
		}
		if normalizedProvider == accountProviderPassword {
			return tx.WithContext(ctx).Where("tenant_id = ? AND user_email = ?", tenantID, normalizedProviderID).Delete(&passwordCredentialRecord{}).Error
		}
		return nil
	})
	if err != nil {
		return AccountProfile{}, fmt.Errorf("%s.account_unlink.%s: %w", userStoreErrorPrefix, store.driverLabel, err)
	}
	return store.ResolveAccountProfile(ctx, tenantID, accountID)
}

// BeginAccountDisable blocks account access and records pending credential revocation.
func (store *DatabaseUserStore) BeginAccountDisable(ctx context.Context, tenantID string, accountID string) (AccountProfile, error) {
	if err := store.updateAccountState(ctx, tenantID, accountID, []string{accountStateActive, accountStateDisabling, accountStateDisabled}, accountStateDisabling); err != nil {
		return AccountProfile{}, err
	}
	return store.ResolveAccountProfile(ctx, tenantID, accountID)
}

// CompleteAccountDisable records successful credential revocation.
func (store *DatabaseUserStore) CompleteAccountDisable(ctx context.Context, tenantID string, accountID string) (AccountProfile, error) {
	if err := store.updateAccountState(ctx, tenantID, accountID, []string{accountStateDisabling, accountStateDisabled}, accountStateDisabled); err != nil {
		return AccountProfile{}, err
	}
	return store.ResolveAccountProfile(ctx, tenantID, accountID)
}

// PendingAccountDisablements returns persisted accounts whose credential revocation is incomplete.
func (store *DatabaseUserStore) PendingAccountDisablements(ctx context.Context) ([]AccountReference, error) {
	var pending []AccountReference
	if err := store.db.WithContext(ctx).Model(&databaseAccountRecord{}).Select("tenant_id", "account_id").Where("account_state = ?", accountStateDisabling).Scan(&pending).Error; err != nil {
		return nil, fmt.Errorf("%s.account_disable_pending.%s: %w", userStoreErrorPrefix, store.driverLabel, err)
	}
	return pending, nil
}

// ReactivateAccount marks an account active.
func (store *DatabaseUserStore) ReactivateAccount(ctx context.Context, tenantID string, accountID string) (AccountProfile, error) {
	if err := store.updateAccountState(ctx, tenantID, accountID, []string{accountStateDisabled}, accountStateActive); err != nil {
		return AccountProfile{}, err
	}
	return store.ResolveAccountProfile(ctx, tenantID, accountID)
}

// ResolveAccountProfile returns an account profile by account ID.
func (store *DatabaseUserStore) ResolveAccountProfile(ctx context.Context, tenantID string, accountID string) (AccountProfile, error) {
	if validateErr := validateOpaqueAccountID(accountID); validateErr != nil {
		return AccountProfile{}, validateErr
	}
	return store.accountProfileWithTx(ctx, store.db, tenantID, accountID)
}

func (store *DatabaseUserStore) consumeDatabaseChallenge(ctx context.Context, tx *gorm.DB, tenantID string, token string, kind string) (databaseAccountChallengeRecord, error) {
	tokenHash := hashOpaque(strings.TrimSpace(token))
	var challenge databaseAccountChallengeRecord
	queryErr := tx.WithContext(ctx).Where("tenant_id = ? AND token_hash = ? AND challenge_kind = ? AND consumed_at_unix = 0", tenantID, tokenHash, kind).Take(&challenge).Error
	if queryErr != nil {
		if errors.Is(queryErr, gorm.ErrRecordNotFound) {
			return databaseAccountChallengeRecord{}, ErrAccountChallengeInvalid
		}
		return databaseAccountChallengeRecord{}, queryErr
	}
	if time.Unix(challenge.ExpiresUnix, 0).Before(store.now().UTC()) {
		return databaseAccountChallengeRecord{}, ErrAccountChallengeInvalid
	}
	updateErr := tx.WithContext(ctx).Model(&databaseAccountChallengeRecord{}).
		Where("tenant_id = ? AND token_hash = ?", tenantID, tokenHash).
		Update("consumed_at_unix", store.now().UTC().Unix()).Error
	if updateErr != nil {
		return databaseAccountChallengeRecord{}, updateErr
	}
	return challenge, nil
}

func (store *DatabaseUserStore) accountProfileWithTx(ctx context.Context, tx *gorm.DB, tenantID string, accountID string) (AccountProfile, error) {
	var account databaseAccountRecord
	queryErr := tx.WithContext(ctx).Where("tenant_id = ? AND account_id = ?", tenantID, accountID).Take(&account).Error
	if queryErr != nil {
		if errors.Is(queryErr, gorm.ErrRecordNotFound) {
			return AccountProfile{}, ErrAccountNotFound
		}
		return AccountProfile{}, queryErr
	}
	if account.DisplayNameOverride != nil {
		account.UserDisplayName = *account.DisplayNameOverride
	}
	return AccountProfile{
		AccountID:   account.AccountID,
		UserID:      account.UserID,
		UserEmail:   account.UserEmail,
		DisplayName: account.UserDisplayName,
		AvatarURL:   account.UserAvatarURL,
		Roles:       []string(account.UserRoles),
		State:       account.AccountState,
	}, nil
}

func (store *DatabaseUserStore) accountIdentityExists(ctx context.Context, tx *gorm.DB, tenantID string, provider string, providerID string) (bool, error) {
	var identity databaseAccountIdentityRecord
	queryErr := tx.WithContext(ctx).Where("tenant_id = ? AND provider = ? AND provider_id = ?", tenantID, provider, providerID).Take(&identity).Error
	if queryErr != nil {
		if errors.Is(queryErr, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, queryErr
	}
	return true, nil
}

func (store *DatabaseUserStore) identityCountWithTx(ctx context.Context, tx *gorm.DB, tenantID string, accountID string) (int64, error) {
	var count int64
	countErr := tx.WithContext(ctx).Model(&databaseAccountIdentityRecord{}).Where("tenant_id = ? AND account_id = ?", tenantID, accountID).Count(&count).Error
	if countErr != nil {
		return 0, countErr
	}
	return count, nil
}

func (store *DatabaseUserStore) updateAccountState(ctx context.Context, tenantID string, accountID string, previousStates []string, state string) error {
	result := store.db.WithContext(ctx).Model(&databaseAccountRecord{}).
		Where("tenant_id = ? AND account_id = ? AND account_state IN ?", tenantID, accountID, previousStates).
		Updates(map[string]interface{}{"account_state": state, "last_updated_unix": store.now().UTC().Unix()})
	if result.Error != nil {
		return fmt.Errorf("%s.account_state.%s: %w", userStoreErrorPrefix, store.driverLabel, result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrAccountNotActive
	}
	return nil
}

func (store *DatabaseUserStore) newUniqueOpaqueAccountID(ctx context.Context, transactionHandle *gorm.DB, tenantID string) (string, error) {
	for attempt := 0; attempt < accountIDGenerationAttempts; attempt++ {
		accountID, accountIDErr := newOpaqueAccountID()
		if accountIDErr != nil {
			return "", accountIDErr
		}
		var existingAccountCount int64
		countErr := transactionHandle.WithContext(ctx).Model(&databaseAccountRecord{}).
			Where("tenant_id = ? AND account_id = ?", tenantID, accountID).
			Count(&existingAccountCount).Error
		if countErr != nil {
			return "", countErr
		}
		if existingAccountCount == 0 {
			return accountID, nil
		}
	}
	return "", fmt.Errorf("%w: collision", ErrAccountInvalidID)
}

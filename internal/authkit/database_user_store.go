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
	googleUserIDPrefix          = "google:"
)

var errUserStoreRolesScanType = errors.New("user_store.roles.scan_type")

// DatabaseUserStore persists user profiles using GORM.
type DatabaseUserStore struct {
	db                   *gorm.DB
	driverLabel          string
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
	CreatedAtUnix   int64  `gorm:"column:created_at_unix;not null"`
	LastUpdatedUnix int64  `gorm:"column:last_updated_unix;not null"`
}

func (passwordCredentialRecord) TableName() string {
	return passwordCredentialTableName
}

type databaseAccountRecord struct {
	TenantID        string   `gorm:"column:tenant_id;primaryKey"`
	AccountID       string   `gorm:"column:account_id;primaryKey"`
	UserEmail       string   `gorm:"column:user_email;not null"`
	UserDisplayName string   `gorm:"column:user_display_name;not null"`
	UserAvatarURL   string   `gorm:"column:user_avatar_url;not null"`
	AccountState    string   `gorm:"column:account_state;not null"`
	UserRoles       roleList `gorm:"column:user_roles;type:text;not null"`
	CreatedAtUnix   int64    `gorm:"column:created_at_unix;not null"`
	LastUpdatedUnix int64    `gorm:"column:last_updated_unix;not null"`
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
	databaseHandle, driverLabel, openErr := openDatabase(ctx, databaseURL, userStoreErrorPrefix, &userProfileRecord{}, &passwordCredentialRecord{}, &databaseAccountRecord{}, &databaseAccountIdentityRecord{}, &databaseAccountChallengeRecord{})
	if openErr != nil {
		return nil, openErr
	}
	return &DatabaseUserStore{
		db:                   databaseHandle,
		driverLabel:          driverLabel,
		now:                  time.Now,
		passwordHashComparer: bcrypt.CompareHashAndPassword,
	}, nil
}

// UpsertGoogleUser inserts or updates a Google-authenticated user profile.
func (store *DatabaseUserStore) UpsertGoogleUser(ctx context.Context, tenantID string, googleSub string, userEmail string, userDisplayName string, userAvatarURL string) (string, []string, error) {
	applicationUserID := googleUserIDPrefix + googleSub
	return store.upsertUserProfile(ctx, tenantID, applicationUserID, userEmail, userDisplayName, userAvatarURL)
}

// UpsertPasswordUser inserts or updates an email/password-authenticated user profile.
func (store *DatabaseUserStore) UpsertPasswordUser(ctx context.Context, tenantID string, userEmail string, userDisplayName string, userAvatarURL string) (string, []string, error) {
	normalizedEmail, emailErr := normalizePasswordEmail(userEmail)
	if emailErr != nil {
		return "", nil, fmt.Errorf("%s.upsert_password.%s: %w", userStoreErrorPrefix, store.driverLabel, emailErr)
	}
	applicationUserID := passwordUserIDPrefix + normalizedEmail
	return store.upsertUserProfile(ctx, tenantID, applicationUserID, normalizedEmail, userDisplayName, userAvatarURL)
}

// UpsertAccountUser inserts or updates a canonical account profile.
func (store *DatabaseUserStore) UpsertAccountUser(ctx context.Context, tenantID string, accountID string, userEmail string, userDisplayName string, userAvatarURL string) (string, []string, error) {
	normalizedEmail, emailErr := normalizePasswordEmail(userEmail)
	if emailErr != nil {
		return "", nil, fmt.Errorf("%s.upsert_account.%s: %w", userStoreErrorPrefix, store.driverLabel, emailErr)
	}
	if strings.TrimSpace(accountID) == "" {
		return "", nil, fmt.Errorf("%s.upsert_account.%s: empty_account_id", userStoreErrorPrefix, store.driverLabel)
	}
	return store.upsertUserProfile(ctx, tenantID, accountID, normalizedEmail, userDisplayName, userAvatarURL)
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
	err := store.db.WithContext(ctx).Clauses(clause.OnConflict{
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
		UserID:          passwordUserIDPrefix + normalizedCredential.userEmail,
		AccountID:       normalizedCredential.accountID,
		UserDisplayName: normalizedCredential.displayName,
		UserAvatarURL:   normalizedCredential.avatarURL,
		PasswordHash:    normalizedCredential.passwordHash,
		EmailVerified:   normalizedCredential.verified,
		CreatedAtUnix:   now.Unix(),
		LastUpdatedUnix: now.Unix(),
	}
	err := store.db.WithContext(ctx).Clauses(clause.OnConflict{
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
			"last_updated_unix",
		}),
	}).Create(&record).Error
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
	deleteQuery := store.db.WithContext(ctx).Where("tenant_id = ?", tenantID)
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
	accountID := accountIDForEmail(tenantID, credential.userEmail)
	token, tokenHash, tokenErr := generateRefreshOpaque()
	if tokenErr != nil {
		return AccountChallenge{}, fmt.Errorf("%s.account_signup_token.%s: %w", userStoreErrorPrefix, store.driverLabel, tokenErr)
	}
	now := store.now().UTC().Unix()
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
		account := databaseAccountRecord{
			TenantID:        tenantID,
			AccountID:       accountID,
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
			UserID:          passwordUserIDPrefix + credential.userEmail,
			AccountID:       accountID,
			UserDisplayName: credential.displayName,
			UserAvatarURL:   credential.avatarURL,
			PasswordHash:    credential.passwordHash,
			EmailVerified:   false,
			CreatedAtUnix:   now,
			LastUpdatedUnix: now,
		}
		if createErr := tx.Select("*").Create(&passwordRecord).Error; createErr != nil {
			return createErr
		}
		if updateErr := tx.Model(&passwordCredentialRecord{}).
			Where("tenant_id = ? AND user_email = ?", tenantID, credential.userEmail).
			Update("email_verified", false).Error; updateErr != nil {
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

// VerifyEmailChallenge activates a pending signup.
func (store *DatabaseUserStore) VerifyEmailChallenge(ctx context.Context, tenantID string, token string) (AccountProfile, error) {
	var profile AccountProfile
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		challenge, challengeErr := store.consumeDatabaseChallenge(ctx, tx, tenantID, token, accountChallengeEmailVerification)
		if challengeErr != nil {
			return challengeErr
		}
		if updateErr := tx.Model(&databaseAccountRecord{}).
			Where("tenant_id = ? AND account_id = ?", tenantID, challenge.AccountID).
			Updates(map[string]interface{}{"account_state": accountStateActive, "last_updated_unix": store.now().UTC().Unix()}).Error; updateErr != nil {
			return updateErr
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
	if createErr := store.db.WithContext(ctx).Create(&challenge).Error; createErr != nil {
		return AccountChallenge{}, fmt.Errorf("%s.account_reset_create.%s: %w", userStoreErrorPrefix, store.driverLabel, createErr)
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
	if updateErr := store.db.WithContext(ctx).Model(&passwordCredentialRecord{}).
		Where("tenant_id = ? AND user_email = ?", tenantID, record.UserEmail).
		Updates(map[string]interface{}{"password_hash": passwordHash, "last_updated_unix": store.now().UTC().Unix()}).Error; updateErr != nil {
		return AccountProfile{}, fmt.Errorf("%s.account_change_password.%s: %w", userStoreErrorPrefix, store.driverLabel, updateErr)
	}
	return store.ResolveAccountProfile(ctx, tenantID, accountID)
}

// EnsurePasswordAccount links a verified seeded password credential to an account.
func (store *DatabaseUserStore) EnsurePasswordAccount(ctx context.Context, tenantID string, userEmail string) (AccountProfile, error) {
	normalizedEmail, emailErr := normalizePasswordEmail(userEmail)
	if emailErr != nil {
		return AccountProfile{}, ErrPasswordCredentialInvalid
	}
	var profile AccountProfile
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var record passwordCredentialRecord
		queryErr := tx.WithContext(ctx).Where("tenant_id = ? AND user_email = ? AND email_verified = ?", tenantID, normalizedEmail, true).Take(&record).Error
		if queryErr != nil {
			if errors.Is(queryErr, gorm.ErrRecordNotFound) {
				return ErrPasswordCredentialInvalid
			}
			return queryErr
		}
		accountID := strings.TrimSpace(record.AccountID)
		if accountID == "" {
			accountID = accountIDForEmail(tenantID, normalizedEmail)
		}
		now := store.now().UTC().Unix()
		var existingAccount databaseAccountRecord
		existingErr := tx.WithContext(ctx).Where("tenant_id = ? AND account_id = ?", tenantID, accountID).Take(&existingAccount).Error
		if existingErr != nil && !errors.Is(existingErr, gorm.ErrRecordNotFound) {
			return existingErr
		}
		if existingErr == nil {
			if existingAccount.AccountState == accountStateDisabled {
				return ErrAccountDisabled
			}
			if existingAccount.AccountState != accountStateActive {
				return ErrAccountNotActive
			}
		}
		account := databaseAccountRecord{
			TenantID:        tenantID,
			AccountID:       accountID,
			UserEmail:       record.UserEmail,
			UserDisplayName: record.UserDisplayName,
			UserAvatarURL:   record.UserAvatarURL,
			AccountState:    accountStateActive,
			UserRoles:       roleList([]string{defaultUserRole}),
			CreatedAtUnix:   now,
			LastUpdatedUnix: now,
		}
		if createErr := tx.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "tenant_id"}, {Name: "account_id"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"user_email",
				"user_display_name",
				"user_avatar_url",
				"last_updated_unix",
			}),
		}).Create(&account).Error; createErr != nil {
			return createErr
		}
		identity := databaseAccountIdentityRecord{
			TenantID:        tenantID,
			Provider:        accountProviderPassword,
			ProviderID:      normalizedEmail,
			AccountID:       accountID,
			CreatedAtUnix:   now,
			LastUpdatedUnix: now,
		}
		if createErr := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "provider"}, {Name: "provider_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"account_id", "last_updated_unix"}),
		}).Create(&identity).Error; createErr != nil {
			return createErr
		}
		if updateErr := tx.Model(&passwordCredentialRecord{}).
			Where("tenant_id = ? AND user_email = ?", tenantID, normalizedEmail).
			Updates(map[string]interface{}{"account_id": accountID, "last_updated_unix": now}).Error; updateErr != nil {
			return updateErr
		}
		accountProfile, profileErr := store.accountProfileWithTx(ctx, tx, tenantID, accountID)
		if profileErr != nil {
			return profileErr
		}
		profile = accountProfile
		return nil
	})
	if err != nil {
		return AccountProfile{}, fmt.Errorf("%s.account_password_ensure.%s: %w", userStoreErrorPrefix, store.driverLabel, err)
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
		credential := passwordCredentialRecord{
			TenantID:        tenantID,
			UserEmail:       challenge.UserEmail,
			UserID:          passwordUserIDPrefix + challenge.UserEmail,
			AccountID:       accountID,
			UserDisplayName: challenge.UserDisplayName,
			UserAvatarURL:   challenge.UserAvatarURL,
			PasswordHash:    challenge.PasswordHash,
			EmailVerified:   true,
			CreatedAtUnix:   now,
			LastUpdatedUnix: now,
		}
		if createErr := tx.Create(&credential).Error; createErr != nil {
			return createErr
		}
		accountProfile, profileErr := store.accountProfileWithTx(ctx, tx, tenantID, accountID)
		if profileErr != nil {
			return profileErr
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
	normalizedIdentity, identityErr := normalizeGoogleAccountIdentity(identity)
	if identityErr != nil {
		return AccountProfile{}, false, identityErr
	}
	var identityRecord databaseAccountIdentityRecord
	queryErr := store.db.WithContext(ctx).Where("tenant_id = ? AND provider = ? AND provider_id = ?", tenantID, accountProviderGoogle, normalizedIdentity.Subject).Take(&identityRecord).Error
	if queryErr != nil {
		if errors.Is(queryErr, gorm.ErrRecordNotFound) {
			return AccountProfile{}, false, nil
		}
		return AccountProfile{}, false, fmt.Errorf("%s.account_google_lookup.%s: %w", userStoreErrorPrefix, store.driverLabel, queryErr)
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
	normalizedIdentity, identityErr := normalizeGoogleAccountIdentity(identity)
	if identityErr != nil {
		return AccountProfile{}, identityErr
	}
	accountID := accountIDForGoogle(tenantID, normalizedIdentity.Subject)
	now := store.now().UTC().Unix()
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		account := databaseAccountRecord{
			TenantID:        tenantID,
			AccountID:       accountID,
			UserEmail:       normalizedIdentity.UserEmail,
			UserDisplayName: normalizedIdentity.DisplayName,
			UserAvatarURL:   normalizedIdentity.AvatarURL,
			AccountState:    accountStateActive,
			UserRoles:       roleList([]string{defaultUserRole}),
			CreatedAtUnix:   now,
			LastUpdatedUnix: now,
		}
		if createErr := tx.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "tenant_id"}, {Name: "account_id"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"user_email",
				"user_display_name",
				"user_avatar_url",
				"last_updated_unix",
			}),
		}).Create(&account).Error; createErr != nil {
			return createErr
		}
		identityRecord := databaseAccountIdentityRecord{
			TenantID:        tenantID,
			Provider:        accountProviderGoogle,
			ProviderID:      normalizedIdentity.Subject,
			AccountID:       accountID,
			CreatedAtUnix:   now,
			LastUpdatedUnix: now,
		}
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "provider"}, {Name: "provider_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"account_id", "last_updated_unix"}),
		}).Create(&identityRecord).Error
	})
	if err != nil {
		return AccountProfile{}, fmt.Errorf("%s.account_google_upsert.%s: %w", userStoreErrorPrefix, store.driverLabel, err)
	}
	return store.ResolveAccountProfile(ctx, tenantID, accountID)
}

// LinkGoogleIdentity links a verified Google identity to an existing account.
func (store *DatabaseUserStore) LinkGoogleIdentity(ctx context.Context, tenantID string, accountID string, identity GoogleAccountIdentity) (AccountProfile, error) {
	normalizedIdentity, identityErr := normalizeGoogleAccountIdentity(identity)
	if identityErr != nil {
		return AccountProfile{}, identityErr
	}
	now := store.now().UTC().Unix()
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, profileErr := store.accountProfileWithTx(ctx, tx, tenantID, accountID); profileErr != nil {
			return profileErr
		}
		var existing databaseAccountIdentityRecord
		queryErr := tx.WithContext(ctx).Where("tenant_id = ? AND provider = ? AND provider_id = ?", tenantID, accountProviderGoogle, normalizedIdentity.Subject).Take(&existing).Error
		if queryErr == nil && existing.AccountID != accountID {
			return ErrAccountExists
		}
		if queryErr != nil && !errors.Is(queryErr, gorm.ErrRecordNotFound) {
			return queryErr
		}
		identityRecord := databaseAccountIdentityRecord{
			TenantID:        tenantID,
			Provider:        accountProviderGoogle,
			ProviderID:      normalizedIdentity.Subject,
			AccountID:       accountID,
			CreatedAtUnix:   now,
			LastUpdatedUnix: now,
		}
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "provider"}, {Name: "provider_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"account_id", "last_updated_unix"}),
		}).Create(&identityRecord).Error
	})
	if err != nil {
		return AccountProfile{}, fmt.Errorf("%s.account_link_google.%s: %w", userStoreErrorPrefix, store.driverLabel, err)
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

// DisableAccount marks an account disabled.
func (store *DatabaseUserStore) DisableAccount(ctx context.Context, tenantID string, accountID string) (AccountProfile, error) {
	if err := store.updateAccountState(ctx, tenantID, accountID, accountStateDisabled); err != nil {
		return AccountProfile{}, err
	}
	return store.ResolveAccountProfile(ctx, tenantID, accountID)
}

// ReactivateAccount marks an account active.
func (store *DatabaseUserStore) ReactivateAccount(ctx context.Context, tenantID string, accountID string) (AccountProfile, error) {
	if err := store.updateAccountState(ctx, tenantID, accountID, accountStateActive); err != nil {
		return AccountProfile{}, err
	}
	return store.ResolveAccountProfile(ctx, tenantID, accountID)
}

// ResolveAccountProfile returns an account profile by account ID.
func (store *DatabaseUserStore) ResolveAccountProfile(ctx context.Context, tenantID string, accountID string) (AccountProfile, error) {
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
	return AccountProfile{
		AccountID:   account.AccountID,
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

func (store *DatabaseUserStore) updateAccountState(ctx context.Context, tenantID string, accountID string, state string) error {
	result := store.db.WithContext(ctx).Model(&databaseAccountRecord{}).
		Where("tenant_id = ? AND account_id = ?", tenantID, accountID).
		Updates(map[string]interface{}{"account_state": state, "last_updated_unix": store.now().UTC().Unix()})
	if result.Error != nil {
		return fmt.Errorf("%s.account_state.%s: %w", userStoreErrorPrefix, store.driverLabel, result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrAccountNotFound
	}
	return nil
}

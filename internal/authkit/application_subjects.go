package authkit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

// ResolveAccountForUser resolves one exact application subject to its internal account.
func (store *DatabaseUserStore) ResolveAccountForUser(ctx context.Context, tenantID, userID string) (AccountProfile, error) {
	return store.accountProfileForUserWithTx(ctx, store.db, tenantID, userID)
}

func (store *DatabaseUserStore) accountProfileForUserWithTx(ctx context.Context, db *gorm.DB, tenantID, userID string) (AccountProfile, error) {
	var record databaseAccountRecord
	err := db.WithContext(ctx).Where("tenant_id = ? AND user_id = ?", tenantID, userID).Take(&record).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return AccountProfile{}, ErrAccountNotFound
	}
	if err != nil {
		return AccountProfile{}, fmt.Errorf("account.public_subject: %w", err)
	}
	return store.accountProfileWithTx(ctx, db, tenantID, record.AccountID)
}

func guardApplicationSubjectSchema(ctx context.Context, databaseURL string) error {
	db, _, err := openDatabase(ctx, databaseURL, userStoreErrorPrefix)
	if err != nil {
		return err
	}
	raw, err := db.DB()
	if err != nil {
		return err
	}
	defer raw.Close()
	if db.Migrator().HasTable(&databaseAccountRecord{}) && !db.Migrator().HasColumn(&databaseAccountRecord{}, "user_id") {
		return errors.New("account.application_subject_migration_required")
	}
	if db.Migrator().HasTable(&databaseAccountErasure{}) && !db.Migrator().HasColumn(&databaseAccountErasure{}, "user_id") {
		return errors.New("account.application_subject_migration_required")
	}
	if (db.Migrator().HasTable(&userProfileRecord{}) || db.Migrator().HasTable(&passwordCredentialRecord{})) && !db.Migrator().HasTable(&databaseAccountRecord{}) {
		return errors.New("account.application_subject_migration_required")
	}
	if db.Migrator().HasTable(&databaseAccountRecord{}) {
		return (&DatabaseUserStore{db: db}).validateApplicationSubjects(ctx)
	}
	return nil
}

func (store *DatabaseUserStore) validateApplicationSubjects(ctx context.Context) error {
	var accounts []databaseAccountRecord
	if err := store.db.WithContext(ctx).Find(&accounts).Error; err != nil {
		return err
	}
	for _, account := range accounts {
		if err := validateOpaqueAccountID(account.AccountID); err != nil {
			return err
		}
		if account.UserID == "" {
			return errors.New("account.application_subject_migration_required")
		}
	}
	checks := []struct {
		model any
		query string
	}{
		{&userProfileRecord{}, "SELECT COUNT(*) FROM user_profiles AS u LEFT JOIN accounts AS a ON a.tenant_id = u.tenant_id AND a.user_id = u.user_id WHERE a.account_id IS NULL"},
		{&passwordCredentialRecord{}, "SELECT COUNT(*) FROM password_credentials AS c LEFT JOIN accounts AS a ON a.tenant_id = c.tenant_id AND a.account_id = c.account_id WHERE a.account_id IS NULL OR c.user_id <> a.user_id"},
		{&databaseAccountIdentityRecord{}, "SELECT COUNT(*) FROM account_identities AS i LEFT JOIN accounts AS a ON a.tenant_id = i.tenant_id AND a.account_id = i.account_id WHERE a.account_id IS NULL"},
		{&databaseAccountErasure{}, "SELECT COUNT(*) FROM account_erasures AS e LEFT JOIN accounts AS a ON a.tenant_id = e.tenant_id AND a.account_id = e.account_id WHERE e.account_id IS NOT NULL AND (a.account_id IS NULL OR e.user_id IS NULL OR e.user_id <> a.user_id)"},
	}
	for _, check := range checks {
		if !store.db.Migrator().HasTable(check.model) {
			continue
		}
		var unmatched int64
		if err := store.db.WithContext(ctx).Raw(check.query).Scan(&unmatched).Error; err != nil {
			return fmt.Errorf("account.application_subject_integrity: %w", err)
		}
		if unmatched != 0 {
			return errors.New("account.application_subject_migration_required")
		}
	}

	return nil
}

// MigrateApplicationSubjects establishes the canonical application subject relation.
// The deployment caller owns the database transaction and completion receipt.
func MigrateApplicationSubjects(ctx context.Context, db *gorm.DB) error {
	addedColumn := db.Migrator().HasTable(&databaseAccountRecord{}) && !db.Migrator().HasColumn(&databaseAccountRecord{}, "user_id")
	if addedColumn {
		if err := db.Exec("ALTER TABLE accounts ADD COLUMN user_id TEXT NOT NULL DEFAULT ''").Error; err != nil {
			return err
		}
		if err := db.Exec("UPDATE accounts SET user_id = account_id").Error; err != nil {
			return err
		}
	}
	if err := db.AutoMigrate(&databaseAccountRecord{}, &databaseAccountIdentityRecord{}, &userProfileRecord{}, &passwordCredentialRecord{}); err != nil {
		return err
	}
	var accounts []databaseAccountRecord
	if err := db.WithContext(ctx).Find(&accounts).Error; err != nil {
		return err
	}
	bindings := map[string]string{}
	for _, account := range accounts {
		if err := validateOpaqueAccountID(account.AccountID); err != nil {
			return fmt.Errorf("account.migration.internal_id tenant=%s: %w", account.TenantID, err)
		}
		if !addedColumn && account.UserID != "" {
			bindings[account.TenantID+"\x00"+account.AccountID] = account.UserID
		}
	}
	var profiles []userProfileRecord
	if err := db.WithContext(ctx).Order("tenant_id,user_id").Find(&profiles).Error; err != nil {
		return err
	}
	for _, profile := range profiles {
		var account databaseAccountRecord
		subjectColumn := "user_id"
		if addedColumn {
			subjectColumn = "account_id"
		}
		err := db.Where("tenant_id = ? AND "+subjectColumn+" = ?", profile.TenantID, profile.UserID).Take(&account).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			provider, subject, ok := strings.Cut(profile.UserID, ":")
			if !ok || subject == "" || (provider != "google" && provider != "apple" && provider != "github" && provider != "email") {
				return fmt.Errorf("account.migration.unbound_subject tenant=%s user=%s", profile.TenantID, profile.UserID)
			}
			if provider == "email" {
				provider = accountProviderPassword
				var credential passwordCredentialRecord
				if e := db.Where("tenant_id = ? AND user_id = ?", profile.TenantID, profile.UserID).Take(&credential).Error; e != nil {
					return fmt.Errorf("account.migration.password_binding: %w", e)
				}
				subject = credential.UserEmail
			}
			var identity databaseAccountIdentityRecord
			e := db.Where("tenant_id = ? AND provider = ? AND provider_id = ?", profile.TenantID, provider, subject).Take(&identity).Error
			if errors.Is(e, gorm.ErrRecordNotFound) {
				id, e := newOpaqueAccountID()
				if e != nil {
					return e
				}
				now := time.Now().UTC().Unix()
				account = databaseAccountRecord{TenantID: profile.TenantID, AccountID: id, UserID: profile.UserID, UserEmail: profile.UserEmail, UserDisplayName: profile.UserDisplayName, UserAvatarURL: profile.UserAvatarURL, UserRoles: profile.UserRoles, AccountState: accountStateActive, CreatedAtUnix: profile.CreatedAtUnix, LastUpdatedUnix: profile.LastUpdatedUnix}
				if e = db.Create(&account).Error; e != nil {
					return e
				}
				identity = databaseAccountIdentityRecord{TenantID: profile.TenantID, Provider: provider, ProviderID: subject, AccountID: id, CreatedAtUnix: now, LastUpdatedUnix: now}
				if e = db.Create(&identity).Error; e != nil {
					return e
				}
			} else if e != nil {
				return e
			} else if e = db.Where("tenant_id = ? AND account_id = ?", profile.TenantID, identity.AccountID).Take(&account).Error; e != nil {
				return e
			}
			if provider == accountProviderPassword {
				var credential passwordCredentialRecord
				if e := db.Where("tenant_id = ? AND user_id = ?", profile.TenantID, profile.UserID).Take(&credential).Error; e != nil {
					return e
				}
				if credential.AccountID != "" && credential.AccountID != account.AccountID {
					return errors.New("account.migration.password_identity_conflict")
				}
				if e := db.Model(&passwordCredentialRecord{}).Where("tenant_id = ? AND user_id = ?", profile.TenantID, profile.UserID).Update("account_id", account.AccountID).Error; e != nil {
					return e
				}
			}
		} else if err != nil {
			return err
		}
		key := profile.TenantID + "\x00" + account.AccountID
		if previous := bindings[key]; previous != "" && previous != profile.UserID {
			return fmt.Errorf("account.migration.subject_conflict tenant=%s account=%s", profile.TenantID, account.AccountID)
		}
		bindings[key] = profile.UserID
	}
	if err := db.Find(&accounts).Error; err != nil {
		return err
	}
	for _, account := range accounts {
		userID := bindings[account.TenantID+"\x00"+account.AccountID]
		if userID == "" {
			userID = account.AccountID
		}
		if err := db.Model(&databaseAccountRecord{}).Where("tenant_id = ? AND account_id = ?", account.TenantID, account.AccountID).Update("user_id", userID).Error; err != nil {
			return err
		}
	}
	var credentials []passwordCredentialRecord
	if err := db.Find(&credentials).Error; err != nil {
		return err
	}
	for _, credential := range credentials {
		var account databaseAccountRecord
		if credential.AccountID == "" {
			id, err := newOpaqueAccountID()
			if err != nil {
				return err
			}
			state := accountStateActive
			if !credential.EmailVerified {
				state = accountStatePendingVerification
			}
			account = databaseAccountRecord{TenantID: credential.TenantID, AccountID: id, UserID: id, UserEmail: credential.UserEmail, UserDisplayName: credential.UserDisplayName, UserAvatarURL: credential.UserAvatarURL, UserRoles: roleList{defaultUserRole}, AccountState: state, CreatedAtUnix: credential.CreatedAtUnix, LastUpdatedUnix: credential.LastUpdatedUnix}
			if err = db.Create(&account).Error; err != nil {
				return err
			}
		} else {
			if err := db.Where("tenant_id = ? AND account_id = ?", credential.TenantID, credential.AccountID).Take(&account).Error; err != nil {
				return err
			}
		}
		if credential.EmailVerified {
			var identity databaseAccountIdentityRecord
			err := db.Where("tenant_id = ? AND provider = ? AND provider_id = ?", credential.TenantID, accountProviderPassword, credential.UserEmail).Take(&identity).Error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				identity = databaseAccountIdentityRecord{TenantID: credential.TenantID, Provider: accountProviderPassword, ProviderID: credential.UserEmail, AccountID: account.AccountID, CreatedAtUnix: credential.CreatedAtUnix, LastUpdatedUnix: credential.LastUpdatedUnix}
				if err = db.Create(&identity).Error; err != nil {
					return err
				}
			} else if err != nil {
				return err
			} else if identity.AccountID != account.AccountID {
				return errors.New("account.migration.password_identity_conflict")
			}
		}
		if err := db.Model(&passwordCredentialRecord{}).Where("tenant_id = ? AND user_email = ?", credential.TenantID, credential.UserEmail).Updates(map[string]any{"account_id": account.AccountID, "user_id": account.UserID}).Error; err != nil {
			return err
		}
	}
	if db.Migrator().HasTable(&databaseAccountErasure{}) {
		if err := db.AutoMigrate(&databaseAccountErasure{}); err != nil {
			return err
		}
		if err := db.Exec("UPDATE account_erasures SET user_id = (SELECT user_id FROM accounts WHERE accounts.tenant_id = account_erasures.tenant_id AND accounts.account_id = account_erasures.account_id) WHERE account_id IS NOT NULL").Error; err != nil {
			return err
		}
		var missing int64
		if err := db.Model(&databaseAccountErasure{}).Where("account_id IS NOT NULL AND user_id IS NULL").Count(&missing).Error; err != nil {
			return err
		}
		if missing != 0 {
			return errors.New("account.migration.erasure_subject_missing")
		}
	}
	return (&DatabaseUserStore{db: db}).validateApplicationSubjects(ctx)
}

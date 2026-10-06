package authkit

import (
	"context"
	"testing"

	"gorm.io/gorm"
)

func TestApplicationSubjectMigrationCanonicalRepeat(t *testing.T) {
	ctx := context.Background()
	users, err := NewDatabaseUserStore(ctx, sqliteDatabaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	account, err := users.UpsertProviderAccount(ctx, "tenant", AccountProviderIdentity{Provider: "google", Subject: "provider-stable", UserEmail: "parent@example.com", DisplayName: "Parent"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = users.UpsertAccountUser(ctx, "tenant", account.AccountID, account.UserEmail, account.DisplayName, ""); err != nil {
		t.Fatal(err)
	}
	publicID, err := newOpaqueAccountID()
	if err != nil {
		t.Fatal(err)
	}
	if publicID == account.AccountID {
		t.Fatal("fixture requires distinct identifiers")
	}
	if err = users.db.Model(&databaseAccountRecord{}).Where("tenant_id = ? AND account_id = ?", "tenant", account.AccountID).Update("user_id", publicID).Error; err != nil {
		t.Fatal(err)
	}
	if err = users.db.Model(&userProfileRecord{}).Where("tenant_id = ? AND user_id = ?", "tenant", account.UserID).Update("user_id", publicID).Error; err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err = users.db.Transaction(func(tx *gorm.DB) error { return MigrateApplicationSubjects(ctx, tx) }); err != nil {
			t.Fatal(err)
		}
		current, err := users.ResolveAccountForUser(ctx, "tenant", publicID)
		if err != nil || current.AccountID != account.AccountID || current.UserID != publicID {
			t.Fatalf("canonical mapping changed: %+v %v", current, err)
		}
	}
	if _, err = users.ResolveAccountForUser(ctx, "tenant", account.AccountID); err == nil {
		t.Fatal("internal account ID accepted as public fallback")
	}
	if _, err = users.ResolveAccountForUser(ctx, "other", publicID); err == nil {
		t.Fatal("public subject escaped tenant")
	}
	if _, err = users.ResolveAccountProfile(ctx, "tenant", "google:provider-stable"); err == nil {
		t.Fatal("provider subject accepted as internal account ID")
	}
}

func TestApplicationSubjectStartupRejectsInconsistentBindings(t *testing.T) {
	for _, corruption := range []string{"blank-account", "dangling-account", "different-subject", "dangling-provider"} {
		t.Run(corruption, func(t *testing.T) {
			databaseURL := sqliteDatabaseURL(t)
			users, err := NewDatabaseUserStore(context.Background(), databaseURL)
			if err != nil {
				t.Fatal(err)
			}
			hash, err := HashPassword("correct horse battery staple")
			if err != nil {
				t.Fatal(err)
			}
			if err = users.UpsertPasswordCredential(context.Background(), "tenant", PasswordCredentialSeed{UserEmail: "parent@example.com", DisplayName: "Parent", PasswordHash: hash}); err != nil {
				t.Fatal(err)
			}
			var query string
			switch corruption {
			case "blank-account":
				query = "UPDATE password_credentials SET account_id = ''"
			case "dangling-account":
				query = "UPDATE password_credentials SET account_id = 'AAAAAAAAAAAAAAAAAAAAAA'"
			case "different-subject":
				query = "UPDATE password_credentials SET user_id = 'changed-subject'"
			case "dangling-provider":
				query = "UPDATE account_identities SET account_id = 'AAAAAAAAAAAAAAAAAAAAAA'"
			}
			if err = users.db.Exec(query).Error; err != nil {
				t.Fatal(err)
			}
			var before passwordCredentialRecord
			if err = users.db.Take(&before).Error; err != nil {
				t.Fatal(err)
			}
			raw, _ := users.db.DB()
			if err = raw.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err = NewDatabaseUserStore(context.Background(), databaseURL); err == nil {
				t.Fatal("startup accepted inconsistent subject relation")
			}
			db, err := OpenControlDatabase(context.Background(), databaseURL)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { raw, _ := db.DB(); raw.Close() }()
			var after passwordCredentialRecord
			if err = db.Take(&after).Error; err != nil {
				t.Fatal(err)
			}
			if after.AccountID != before.AccountID || after.UserID != before.UserID {
				t.Fatal("startup silently converted inconsistent identity")
			}
		})
	}
}

func TestApplicationSubjectMigrationRejectsConflictingPasswordBinding(t *testing.T) {
	ctx := context.Background()
	db, err := OpenControlDatabase(ctx, sqliteDatabaseURL(t), &databaseAccountRecord{}, &databaseAccountIdentityRecord{}, &userProfileRecord{}, &passwordCredentialRecord{})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := db.DB()
	t.Cleanup(func() { raw.Close() })
	first, err := newOpaqueAccountID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newOpaqueAccountID()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{first, second} {
		if err = db.Create(&databaseAccountRecord{TenantID: "tenant", AccountID: id, UserID: id, AccountState: accountStateActive}).Error; err != nil {
			t.Fatal(err)
		}
	}
	profile := userProfileRecord{TenantID: "tenant", UserID: "email:parent@example.com", UserEmail: "parent@example.com", UserRoles: roleList{defaultUserRole}}
	if err = db.Create(&profile).Error; err != nil {
		t.Fatal(err)
	}
	credential := passwordCredentialRecord{TenantID: "tenant", UserID: profile.UserID, AccountID: first, UserEmail: profile.UserEmail, EmailVerified: true}
	if err = db.Create(&credential).Error; err != nil {
		t.Fatal(err)
	}
	if err = db.Create(&databaseAccountIdentityRecord{TenantID: "tenant", Provider: accountProviderPassword, ProviderID: profile.UserEmail, AccountID: second}).Error; err != nil {
		t.Fatal(err)
	}
	// Recreate the deployed pre-migration shape, whose profiles were provider subjects.
	if err = db.Migrator().DropColumn(&databaseAccountRecord{}, "user_id"); err != nil {
		t.Fatal(err)
	}
	if err = db.Transaction(func(tx *gorm.DB) error { return MigrateApplicationSubjects(ctx, tx) }); err == nil {
		t.Fatal("conflicting credential/provider ownership accepted")
	}
	if db.Migrator().HasColumn(&databaseAccountRecord{}, "user_id") {
		t.Fatal("failed migration committed its schema change")
	}
	var unchanged passwordCredentialRecord
	if err = db.Take(&unchanged).Error; err != nil {
		t.Fatal(err)
	}
	if unchanged.AccountID != first || unchanged.UserID != profile.UserID {
		t.Fatal("failed migration reassociated credential")
	}
}

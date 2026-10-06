package authkit

import (
	"context"
	"testing"

	"gorm.io/gorm"
)

func seedApplicationSubject(t *testing.T, db *gorm.DB, tenantID, userID string) {
	t.Helper()
	if err := db.AutoMigrate(&databaseAccountRecord{}); err != nil {
		t.Fatal(err)
	}
	var count int64
	if err := db.Model(&databaseAccountRecord{}).Where("tenant_id = ? AND user_id = ?", tenantID, userID).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		return
	}
	id, err := newOpaqueAccountID()
	if err != nil {
		t.Fatal(err)
	}
	account := databaseAccountRecord{TenantID: tenantID, AccountID: id, UserID: userID, UserEmail: "fixture@example.com", UserDisplayName: "Fixture", AccountState: accountStateActive, UserRoles: roleList{defaultUserRole}}
	if err = db.WithContext(context.Background()).Create(&account).Error; err != nil {
		t.Fatal(err)
	}
}

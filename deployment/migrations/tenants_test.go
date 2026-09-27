package migrations_test

import (
	"context"
	"testing"

	"github.com/tyemirov/tauth/deployment/migrations"
	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/controlplane"
	"github.com/tyemirov/tauth/internal/testconfig"
)

type previousBootstrap struct {
	ID             string `gorm:"primaryKey"`
	Configuration  []byte `gorm:"not null"`
	Digest         string `gorm:"not null"`
	InitialOwnerID *string
	InitialOwner   *controlplane.Owner `gorm:"foreignKey:InitialOwnerID;references:ID;constraint:OnDelete:RESTRICT"`
}

func (previousBootstrap) TableName() string { return "console_bootstraps" }

func TestRemoveInitialOwnerPreservesBootstrapAndOwners(t *testing.T) {
	ctx := context.Background()
	config := testconfig.Prepare(t, appconfig.ApplicationConfig{})
	db, err := authkit.OpenControlDatabase(ctx, config.Server.DatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := db.AutoMigrate(&previousBootstrap{}); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		`UPDATE console_bootstraps SET initial_owner_id = (SELECT id FROM owner_accounts LIMIT 1)`,
	} {
		if err := db.Exec(sql).Error; err != nil {
			t.Fatal(err)
		}
	}
	type bootstrap struct {
		ID            string
		Configuration []byte
		Digest        string
	}
	var before, after bootstrap
	if err := db.Table("console_bootstraps").First(&before).Error; err != nil {
		t.Fatal(err)
	}
	for retry := 0; retry < 2; retry++ {
		if err := migrations.RemoveInitialOwner(ctx, config.Server.DatabaseURL); err != nil {
			t.Fatal(err)
		}
	}
	if db.Migrator().HasColumn("console_bootstraps", "initial_owner_id") {
		t.Fatal("obsolete first-owner column remains")
	}
	if err := db.Table("console_bootstraps").First(&after).Error; err != nil {
		t.Fatal(err)
	}
	if before.ID != after.ID || before.Digest != after.Digest || string(before.Configuration) != string(after.Configuration) {
		t.Fatal("schema cleanup changed console data")
	}
	var count int64
	if err := db.Table("owner_accounts").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("schema cleanup changed owner accounts")
	}
}

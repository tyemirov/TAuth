package authkit

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tyemirov/tauth/internal/web"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	userProfileTableName = "user_profiles"
	defaultUserRole      = "user"
	googleUserIDPrefix   = "google:"
)

var errUserStoreRolesScanType = errors.New("user_store.roles.scan_type")

// DatabaseUserStore persists user profiles using GORM.
type DatabaseUserStore struct {
	db          *gorm.DB
	driverLabel string
	now         func() time.Time
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

// NewDatabaseUserStore constructs a DatabaseUserStore backed by the provided database URL.
func NewDatabaseUserStore(ctx context.Context, databaseURL string) (*DatabaseUserStore, error) {
	databaseHandle, driverLabel, openErr := openDatabase(ctx, databaseURL, userStoreErrorPrefix, &userProfileRecord{})
	if openErr != nil {
		return nil, openErr
	}
	return &DatabaseUserStore{
		db:          databaseHandle,
		driverLabel: driverLabel,
		now:         time.Now,
	}, nil
}

// UpsertGoogleUser inserts or updates a Google-authenticated user profile.
func (store *DatabaseUserStore) UpsertGoogleUser(ctx context.Context, tenantID string, googleSub string, userEmail string, userDisplayName string, userAvatarURL string) (string, []string, error) {
	applicationUserID := googleUserIDPrefix + googleSub
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

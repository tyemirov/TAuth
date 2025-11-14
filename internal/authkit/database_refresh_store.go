package authkit

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	sqliteDialector "github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	// ErrUnsupportedDialect indicates that no GORM dialector is available for the scheme.
	ErrUnsupportedDialect = errors.New("refresh_store.unsupported_dialect")

	errEmptyOpaqueToken    = errors.New("refresh_store.empty_token")
	errEmptyDatabaseURL    = errors.New("refresh_store.empty_database_url")
	errSQLiteEmptyPath     = errors.New("refresh_store.sqlite.empty_path")
	errSQLiteInvalidURL    = errors.New("refresh_store.sqlite.invalid_url")
	errUnsupportedNoScheme = errors.New("refresh_store.unsupported_no_scheme")
)

// DatabaseRefreshTokenStore persists rotating refresh tokens using GORM.
type DatabaseRefreshTokenStore struct {
	db          *gorm.DB
	driverLabel string
}

// Driver exposes the selected database driver label.
func (store *DatabaseRefreshTokenStore) Driver() string {
	return store.driverLabel
}

type refreshTokenRecord struct {
	TokenID         string `gorm:"column:token_id;primaryKey"`
	UserID          string `gorm:"column:user_id;index;not null"`
	TokenHash       string `gorm:"column:token_hash;uniqueIndex;not null"`
	ExpiresUnix     int64  `gorm:"column:expires_unix;not null"`
	RevokedAtUnix   int64  `gorm:"column:revoked_at_unix;not null;default:0"`
	PreviousTokenID string `gorm:"column:previous_token_id;not null;default:''"`
	IssuedAtUnix    int64  `gorm:"column:issued_at_unix;not null"`
}

func (refreshTokenRecord) TableName() string {
	return "refresh_tokens"
}

// NewDatabaseRefreshTokenStore constructs a GORM-backed store.
func NewDatabaseRefreshTokenStore(ctx context.Context, databaseURL string) (*DatabaseRefreshTokenStore, error) {
	if strings.TrimSpace(databaseURL) == "" {
		return nil, fmt.Errorf("refresh_store.open: %w", errEmptyDatabaseURL)
	}
	dialector, driverLabel, err := resolveDialector(databaseURL)
	if err != nil {
		return nil, err
	}
	gormDB, openErr := gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if openErr != nil {
		return nil, fmt.Errorf("refresh_store.open.%s: %w", driverLabel, openErr)
	}
	if migrateErr := gormDB.WithContext(ctx).AutoMigrate(&refreshTokenRecord{}); migrateErr != nil {
		return nil, fmt.Errorf("refresh_store.migrate.%s: %w", driverLabel, migrateErr)
	}
	return &DatabaseRefreshTokenStore{
		db:          gormDB,
		driverLabel: driverLabel,
	}, nil
}

// Issue inserts a new refresh token record and returns its identifiers.
func (store *DatabaseRefreshTokenStore) Issue(ctx context.Context, applicationUserID string, expiresUnix int64, previousTokenID string) (string, string, error) {
	now := time.Now().UTC()
	tokenID := newRefreshTokenID(now)
	opaqueToken, hashValue, randomErr := generateRefreshOpaque()
	if randomErr != nil {
		return "", "", fmt.Errorf("refresh_store.issue.%s: %w", store.driverLabel, randomErr)
	}
	record := refreshTokenRecord{
		TokenID:         tokenID,
		UserID:          applicationUserID,
		TokenHash:       hashValue,
		ExpiresUnix:     expiresUnix,
		RevokedAtUnix:   0,
		PreviousTokenID: previousTokenID,
		IssuedAtUnix:    now.Unix(),
	}
	if err := store.db.WithContext(ctx).Create(&record).Error; err != nil {
		return "", "", fmt.Errorf("refresh_store.issue.%s: %w", store.driverLabel, err)
	}
	return tokenID, opaqueToken, nil
}

// Validate locates a refresh token by its opaque value.
func (store *DatabaseRefreshTokenStore) Validate(ctx context.Context, tokenOpaque string) (string, string, int64, error) {
	if strings.TrimSpace(tokenOpaque) == "" {
		return "", "", 0, fmt.Errorf("refresh_store.validate.%s: %w", store.driverLabel, ErrRefreshTokenEmptyOpaque)
	}
	hashValue := hashOpaque(tokenOpaque)
	var record refreshTokenRecord
	err := store.db.WithContext(ctx).Where("token_hash = ?", hashValue).Take(&record).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", "", 0, fmt.Errorf("refresh_store.validate.%s: %w", store.driverLabel, ErrRefreshTokenNotFound)
		}
		return "", "", 0, fmt.Errorf("refresh_store.validate.%s: %w", store.driverLabel, err)
	}
	now := time.Now().UTC()
	if record.RevokedAtUnix != 0 {
		return "", "", 0, fmt.Errorf("refresh_store.validate.%s: %w", store.driverLabel, ErrRefreshTokenRevoked)
	}
	if time.Unix(record.ExpiresUnix, 0).Before(now) {
		return "", "", 0, fmt.Errorf("refresh_store.validate.%s: %w", store.driverLabel, ErrRefreshTokenExpired)
	}
	return record.UserID, record.TokenID, record.ExpiresUnix, nil
}

// Revoke marks a refresh token as revoked.
func (store *DatabaseRefreshTokenStore) Revoke(ctx context.Context, tokenID string) error {
	now := time.Now().UTC()
	result := store.db.WithContext(ctx).Model(&refreshTokenRecord{}).
		Where("token_id = ? AND revoked_at_unix = 0", tokenID).
		Update("revoked_at_unix", now.Unix())
	if result.Error != nil {
		return fmt.Errorf("refresh_store.revoke.%s: %w", store.driverLabel, result.Error)
	}
	if result.RowsAffected == 0 {
		var record refreshTokenRecord
		findErr := store.db.WithContext(ctx).Where("token_id = ?", tokenID).Take(&record).Error
		if errors.Is(findErr, gorm.ErrRecordNotFound) {
			return fmt.Errorf("refresh_store.revoke.%s: %w", store.driverLabel, ErrRefreshTokenNotFound)
		}
		if findErr != nil {
			return fmt.Errorf("refresh_store.revoke.%s: %w", store.driverLabel, findErr)
		}
		if record.RevokedAtUnix != 0 {
			return fmt.Errorf("refresh_store.revoke.%s: %w", store.driverLabel, ErrRefreshTokenAlreadyRevoked)
		}
		return nil
	}
	return nil
}

func resolveDialector(databaseURL string) (gorm.Dialector, string, error) {
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		return nil, "", fmt.Errorf("refresh_store.parse_url: %w", err)
	}
	if parsed.Scheme == "" {
		return nil, "", fmt.Errorf("refresh_store.dialect: %w", errUnsupportedNoScheme)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "postgres", "postgresql":
		return postgres.Open(databaseURL), "postgres", nil
	case "sqlite", "sqlite3":
		dsn, dsnErr := buildSQLiteDSN(parsed)
		if dsnErr != nil {
			return nil, "", fmt.Errorf("refresh_store.sqlite: %w", dsnErr)
		}
		return sqliteDialector.Open(dsn), "sqlite", nil
	default:
		return nil, "", fmt.Errorf("refresh_store.dialect.%s: %w", strings.ToLower(parsed.Scheme), ErrUnsupportedDialect)
	}
}

func buildSQLiteDSN(parsed *url.URL) (string, error) {
	if parsed == nil {
		return "", errSQLiteInvalidURL
	}
	var builder strings.Builder
	switch {
	case parsed.Opaque != "":
		builder.WriteString(parsed.Opaque)
	case parsed.Host != "":
		builder.WriteString(parsed.Host)
		if parsed.Path != "" {
			if !strings.HasPrefix(parsed.Path, "/") {
				builder.WriteString("/")
			}
			builder.WriteString(parsed.Path)
		}
	default:
		builder.WriteString(parsed.Path)
	}
	if builder.Len() == 0 {
		return "", errSQLiteEmptyPath
	}
	if parsed.RawQuery != "" {
		builder.WriteString("?")
		builder.WriteString(parsed.RawQuery)
	}
	return builder.String(), nil
}

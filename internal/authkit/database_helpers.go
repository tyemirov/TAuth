package authkit

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	sqliteDialector "github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	refreshStoreErrorPrefix = "refresh_store"
	userStoreErrorPrefix    = "user_store"
	nonceStoreErrorPrefix   = "nonce_store"
)

var (
	ErrUnsupportedDialect = errors.New("refresh_store.unsupported_dialect")

	errEmptyDatabaseURL      = errors.New("refresh_store.empty_database_url")
	errSQLiteEmptyPath       = errors.New("refresh_store.sqlite.empty_path")
	errSQLiteInvalidURL      = errors.New("refresh_store.sqlite.invalid_url")
	errSQLiteUnsupportedHost = errors.New("refresh_store.sqlite.unsupported_host")
	errUnsupportedNoScheme   = errors.New("refresh_store.unsupported_no_scheme")
)

func openDatabase(ctx context.Context, databaseURL string, errorPrefix string, models ...interface{}) (*gorm.DB, string, error) {
	if strings.TrimSpace(databaseURL) == "" {
		return nil, "", fmt.Errorf("%s.open: %w", errorPrefix, errEmptyDatabaseURL)
	}
	dialector, driverLabel, resolveErr := resolveDialector(databaseURL, errorPrefix)
	if resolveErr != nil {
		return nil, "", resolveErr
	}
	databaseHandle, openErr := gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if openErr != nil {
		return nil, "", fmt.Errorf("%s.open.%s: %w", errorPrefix, driverLabel, openErr)
	}
	if len(models) > 0 {
		if migrateErr := databaseHandle.WithContext(ctx).AutoMigrate(models...); migrateErr != nil {
			return nil, "", fmt.Errorf("%s.migrate.%s: %w", errorPrefix, driverLabel, migrateErr)
		}
	}
	return databaseHandle, driverLabel, nil
}

func resolveDialector(databaseURL string, errorPrefix string) (gorm.Dialector, string, error) {
	parsed, parseErr := url.Parse(databaseURL)
	if parseErr != nil {
		return nil, "", fmt.Errorf("%s.parse_url: %w", errorPrefix, parseErr)
	}
	if parsed.Scheme == "" {
		return nil, "", fmt.Errorf("%s.dialect: %w", errorPrefix, errUnsupportedNoScheme)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "postgres", "postgresql":
		return postgres.Open(databaseURL), "postgres", nil
	case "sqlite", "sqlite3":
		dsn, dsnErr := buildSQLiteDSN(parsed)
		if dsnErr != nil {
			return nil, "", fmt.Errorf("%s.sqlite: %w", errorPrefix, dsnErr)
		}
		return sqliteDialector.Open(dsn), "sqlite", nil
	default:
		return nil, "", fmt.Errorf("%s.dialect.%s: %w", errorPrefix, strings.ToLower(parsed.Scheme), ErrUnsupportedDialect)
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
		host := parsed.Host
		normalizedHost := strings.TrimSuffix(host, ":")
		if strings.EqualFold(normalizedHost, "file") {
			return "", errSQLiteUnsupportedHost
		}
		builder.WriteString(host)
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

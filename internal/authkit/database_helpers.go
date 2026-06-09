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
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

const (
	refreshStoreErrorPrefix      = "refresh_store"
	userStoreErrorPrefix         = "user_store"
	nonceStoreErrorPrefix        = "nonce_store"
	schemaMigrationTableName     = "schema_migrations"
	schemaMigrationNameColumn    = "store_name"
	schemaMigrationVersionColumn = "version"
	schemaMigrationLookupByName  = "store_name = ?"
	schemaErrorFormat            = "%s.schema.%s: %w"
	refreshStoreSchemaVersion    = 1
	userStoreSchemaVersion       = 4
	nonceStoreSchemaVersion      = 1
)

var (
	ErrUnsupportedDialect = errors.New("refresh_store.unsupported_dialect")

	errEmptyDatabaseURL      = errors.New("refresh_store.empty_database_url")
	errSQLiteEmptyPath       = errors.New("refresh_store.sqlite.empty_path")
	errSQLiteInvalidURL      = errors.New("refresh_store.sqlite.invalid_url")
	errSQLiteUnsupportedHost = errors.New("refresh_store.sqlite.unsupported_host")
	errUnsupportedNoScheme   = errors.New("refresh_store.unsupported_no_scheme")
	errUnknownSchemaVersion  = errors.New("schema.unknown_version")
)

type schemaMigrationRecord struct {
	StoreName string `gorm:"column:store_name;primaryKey"`
	Version   int    `gorm:"column:version;not null"`
}

func (schemaMigrationRecord) TableName() string {
	return schemaMigrationTableName
}

type storeSchemaPolicy struct {
	StoreName             string
	Version               int
	AllowDestructiveReset bool
}

var storeSchemaPolicies = map[string]storeSchemaPolicy{
	refreshStoreErrorPrefix: {
		StoreName:             refreshStoreErrorPrefix,
		Version:               refreshStoreSchemaVersion,
		AllowDestructiveReset: true,
	},
	userStoreErrorPrefix: {
		StoreName:             userStoreErrorPrefix,
		Version:               userStoreSchemaVersion,
		AllowDestructiveReset: false,
	},
	nonceStoreErrorPrefix: {
		StoreName:             nonceStoreErrorPrefix,
		Version:               nonceStoreSchemaVersion,
		AllowDestructiveReset: false,
	},
}

func openDatabase(requestContext context.Context, databaseURL string, errorPrefix string, models ...interface{}) (*gorm.DB, string, error) {
	if strings.TrimSpace(databaseURL) == "" {
		return nil, "", fmt.Errorf("%s.open: %w", errorPrefix, errEmptyDatabaseURL)
	}
	dialector, driverLabel, resolveError := resolveDialector(databaseURL, errorPrefix)
	if resolveError != nil {
		return nil, "", resolveError
	}
	databaseHandle, openError := gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if openError != nil {
		return nil, "", fmt.Errorf("%s.open.%s: %w", errorPrefix, driverLabel, openError)
	}
	if len(models) > 0 {
		if resetError := ensureSchemaVersion(requestContext, databaseHandle, errorPrefix, driverLabel, models...); resetError != nil {
			return nil, "", resetError
		}
	}
	return databaseHandle, driverLabel, nil
}

// CheckDatabaseConnectivity opens the configured database and pings it without migrating schema.
func CheckDatabaseConnectivity(requestContext context.Context, databaseURL string) (string, error) {
	trimmedDatabaseURL := strings.TrimSpace(databaseURL)
	if trimmedDatabaseURL == "" {
		return "", fmt.Errorf("%s.open: %w", refreshStoreErrorPrefix, errEmptyDatabaseURL)
	}
	dialector, driverLabel, resolveError := resolveDialector(trimmedDatabaseURL, refreshStoreErrorPrefix)
	if resolveError != nil {
		return "", resolveError
	}
	databaseHandle, openError := gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if openError != nil {
		return "", fmt.Errorf("%s.open.%s: %w", refreshStoreErrorPrefix, driverLabel, openError)
	}
	rawHandle, rawError := databaseHandle.DB()
	if rawError != nil {
		return "", fmt.Errorf("%s.open.%s: %w", refreshStoreErrorPrefix, driverLabel, rawError)
	}
	pingError := rawHandle.PingContext(requestContext)
	if pingError != nil {
		return "", fmt.Errorf("%s.ping.%s: %w", refreshStoreErrorPrefix, driverLabel, pingError)
	}
	closeError := rawHandle.Close()
	if closeError != nil {
		return "", fmt.Errorf("%s.close.%s: %w", refreshStoreErrorPrefix, driverLabel, closeError)
	}
	return driverLabel, nil
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

func ensureSchemaVersion(requestContext context.Context, databaseHandle *gorm.DB, errorPrefix string, driverLabel string, models ...interface{}) error {
	storePolicy, policyError := newStoreSchemaPolicy(errorPrefix)
	if policyError != nil {
		return fmt.Errorf("%s.schema_version: %w", errorPrefix, policyError)
	}
	migrationError := databaseHandle.WithContext(requestContext).AutoMigrate(&schemaMigrationRecord{})
	if migrationError != nil {
		return fmt.Errorf(schemaErrorFormat, errorPrefix, driverLabel, migrationError)
	}
	var migrationRecord schemaMigrationRecord
	queryError := databaseHandle.WithContext(requestContext).
		Where(schemaMigrationLookupByName, storePolicy.StoreName).
		Take(&migrationRecord).Error
	if queryError != nil {
		if errors.Is(queryError, gorm.ErrRecordNotFound) {
			return applySchemaPolicy(requestContext, databaseHandle, errorPrefix, driverLabel, storePolicy, models...)
		}
		return fmt.Errorf(schemaErrorFormat, errorPrefix, driverLabel, queryError)
	}
	if migrationRecord.Version != storePolicy.Version {
		return applySchemaPolicy(requestContext, databaseHandle, errorPrefix, driverLabel, storePolicy, models...)
	}
	return nil
}

func applySchemaPolicy(requestContext context.Context, databaseHandle *gorm.DB, errorPrefix string, driverLabel string, storePolicy storeSchemaPolicy, models ...interface{}) error {
	migrationRecord := schemaMigrationRecord{
		StoreName: storePolicy.StoreName,
		Version:   storePolicy.Version,
	}
	if storePolicy.AllowDestructiveReset {
		return resetDatabaseSchema(requestContext, databaseHandle, errorPrefix, driverLabel, migrationRecord, models...)
	}
	return migrateDatabaseSchema(requestContext, databaseHandle, errorPrefix, driverLabel, migrationRecord, models...)
}

func resetDatabaseSchema(requestContext context.Context, databaseHandle *gorm.DB, errorPrefix string, driverLabel string, schemaVersion schemaMigrationRecord, models ...interface{}) error {
	migrator := databaseHandle.WithContext(requestContext).Migrator()
	dropError := migrator.DropTable(models...)
	if dropError != nil {
		return fmt.Errorf("%s.reset.%s: %w", errorPrefix, driverLabel, dropError)
	}
	migrationError := databaseHandle.WithContext(requestContext).AutoMigrate(models...)
	if migrationError != nil {
		return fmt.Errorf("%s.migrate.%s: %w", errorPrefix, driverLabel, migrationError)
	}
	migrationRecord := schemaVersion
	upsertError := databaseHandle.WithContext(requestContext).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: schemaMigrationNameColumn}},
		DoUpdates: clause.AssignmentColumns([]string{schemaMigrationVersionColumn}),
	}).Create(&migrationRecord).Error
	if upsertError != nil {
		return fmt.Errorf(schemaErrorFormat, errorPrefix, driverLabel, upsertError)
	}
	return nil
}

func migrateDatabaseSchema(requestContext context.Context, databaseHandle *gorm.DB, errorPrefix string, driverLabel string, migrationRecord schemaMigrationRecord, models ...interface{}) error {
	migrationError := databaseHandle.WithContext(requestContext).AutoMigrate(models...)
	if migrationError != nil {
		return fmt.Errorf("%s.migrate.%s: %w", errorPrefix, driverLabel, migrationError)
	}
	upsertError := databaseHandle.WithContext(requestContext).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: schemaMigrationNameColumn}},
		DoUpdates: clause.AssignmentColumns([]string{schemaMigrationVersionColumn}),
	}).Create(&migrationRecord).Error
	if upsertError != nil {
		return fmt.Errorf(schemaErrorFormat, errorPrefix, driverLabel, upsertError)
	}
	return nil
}

func newStoreSchemaPolicy(storeName string) (storeSchemaPolicy, error) {
	storePolicy, policyFound := storeSchemaPolicies[storeName]
	if !policyFound {
		return storeSchemaPolicy{}, errUnknownSchemaVersion
	}
	if storePolicy.Version < 1 {
		return storeSchemaPolicy{}, errUnknownSchemaVersion
	}
	return storePolicy, nil
}

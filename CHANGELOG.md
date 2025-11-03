# Changelog

## Unreleased

- TA-200: Introduced GORM-backed refresh token store supporting Postgres and SQLite, added mandatory `--database_url` / `APP_DATABASE_URL`, removed pgx-specific store and legacy compatibility, updated docs, and added SQLite lifecycle tests.
- TA-301: Updated `/api/me` to return stored profiles with session expiry, introduced `ErrUserProfileNotFound`, logged anomalies with stable codes, and added regression coverage for profile lookup failures.

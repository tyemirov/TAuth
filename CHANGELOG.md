# Changelog

## Unreleased

- TA-200: Introduced GORM-backed refresh token store supporting Postgres and SQLite, added mandatory `--database_url` / `APP_DATABASE_URL`, removed pgx-specific store and legacy compatibility, updated docs, and added SQLite lifecycle tests.
- TA-100: Delivered the reusable mpr-ui auth header, surfaced `avatar_url` across login and `/me` payloads, refreshed demo rendering, and documented dataset/event contracts for downstream consumers.
- TA-101: Published `pkg/sessionvalidator` with smart constructor, token/request helpers, and Gin middleware; refactored server middleware to reuse it and added focused unit tests plus docs.

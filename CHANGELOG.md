# Changelog

## Unreleased

- TA-200: Introduced GORM-backed refresh token store supporting Postgres and SQLite, added mandatory `--database_url` / `APP_DATABASE_URL`, removed pgx-specific store and legacy compatibility, updated docs, and added SQLite lifecycle tests.
- TA-100: Delivered the reusable mpr-ui auth header, surfaced `avatar_url` across login and `/me` payloads, refreshed demo rendering, and documented dataset/event contracts for downstream consumers.
- TA-101: Published `pkg/sessionvalidator` with smart constructor, token/request helpers, and Gin middleware; refactored server middleware to reuse it and added focused unit tests plus docs.
- TA-201: Added `LoadServerConfig` smart constructor invoked from Cobra `PreRunE`, validating TTLs, cookie names, and required identifiers before the server boots with structured `config.*` errors.
- TA-202: Introduced injectable Google token validator and clock providers, updated auth routes to reuse the singleton, and wrapped JWT mint failures with stable error codes for observability.
- TA-203: Standardised refresh token store error semantics by sharing sentinel errors, propagating contextual wrapping, and exposing idempotent revoke helpers across memory and database stores.
- TA-204: Wired zap logger and metrics recorder into auth routes, logging warnings/errors with stable codes and incrementing counters across login, refresh, and logout flows.
- TA-205: Added TLS-backed end-to-end Go tests covering `/auth/google → /auth/refresh → /auth/logout`, tampered sessions, and revoked-token scenarios to raise integration coverage.
- TA-206: Delivered Puppeteer Core coverage that verifies `auth-client.js` login/refresh/logout event dispatch using a mocked backend; gated on `CHROMIUM_PATH` for local runs.
- TA-300: Improved CLI configuration errors to enumerate missing keys, ensuring absent `jwt_signing_key` is reported precisely.
- TA-301: Reworked `/api/me` to source claims from the session context, return persisted profiles with expiry metadata, surface `ErrUserProfileNotFound`, and emit zap warnings for anomalies.
- TA-302: Required explicit origin lists when enabling credentialed CORS via `--cors_allowed_origins` / `APP_CORS_ALLOWED_ORIGINS`, surfacing configuration errors for empty or whitespace-only inputs.
- TA-400: Refocused README on user-facing outcomes and moved deep technical notes into `ARCHITECTURE.md`.
- TA-401: Expanded `ARCHITECTURE.md` with up-to-date flow diagrams, dependency notes, and security guidance that match the current implementation.
- TA-402: Captured the refactor roadmap in `docs/refactor-plan.md`, outlining policy gaps and prioritised remediation tasks.
- TA-403: Added broad integration/unit coverage across auth flows, CLI, and stores, delivering ~90.5% Go test coverage via black-box suites.
- TA-404: Renamed binaries, imports, and documentation artifacts to the `tauth` identifier across the project.
- TA-405: Added GitHub Actions workflows for Go tests on PRs/pushes and release builds that produce multi-platform artifacts and publish tagged releases.

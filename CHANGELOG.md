# Changelog

## Unreleased

- TA-332: Added `examples/docker-compose` with a `.env` template plus README instructions so developers can spin up TAuth locally via Docker Compose.
- TA-333: Updated the compose example to build the image from the local Dockerfile (`docker compose up --build`) so contributors can test unmerged changes.
- TA-334: Adjusted the Docker image to run as root, create `/data`, and declare it as a volume so the SQLite refresh store can write when using Docker Compose.
- TA-335: Added an integration test that starts the server with a file-based SQLite DSN (`sqlite:///...`) to guard against regressions in on-disk deployments.
- TA-330: Replaced the refresh token store’s SQLite dialector with the CGO-free `github.com/glebarez/sqlite`, refreshed tests to enforce the driver selection, and documented the change so Docker images run without enabling CGO.
- TA-200: Introduced GORM-backed refresh token store supporting Postgres and SQLite, added mandatory `--database_url` / `APP_DATABASE_URL`, removed pgx-specific store and legacy compatibility, updated docs, and added SQLite lifecycle tests.
- TA-100: Delivered the reusable mpr-ui auth header, surfaced `avatar_url` across login and `/me` payloads, refreshed demo rendering, and documented dataset/event contracts for downstream consumers.
- TA-101: Published `pkg/sessionvalidator` with smart constructor, token/request helpers, and Gin middleware; refactored server middleware to reuse it and added focused unit tests plus docs.
- TA-201: Added `LoadServerConfig` smart constructor invoked from Cobra `PreRunE`, validating TTLs, cookie names, and required identifiers before the server boots with structured `config.*` errors.
- TA-202: Introduced injectable Google token validator and clock providers, updated auth routes to reuse the singleton, and wrapped JWT mint failures with stable error codes for observability.
- TA-203: Standardised refresh token store error semantics by sharing sentinel errors, propagating contextual wrapping, and exposing idempotent revoke helpers across memory and database stores.
- TA-204: Wired zap logger and metrics recorder into auth routes, logging warnings/errors with stable codes and incrementing counters across login, refresh, and logout flows.
- TA-205: Added TLS-backed end-to-end Go tests covering `/auth/google → /auth/refresh → /auth/logout`, tampered sessions, and revoked-token scenarios to raise integration coverage.
- TA-206: Delivered Puppeteer Core coverage that verifies `auth-client.js` login/refresh/logout event dispatch using a mocked backend; gated on `CHROMIUM_PATH` for local runs.
- TA-207: Adopted the mpr-ui footer component in the demo, exposed `renderFooter`/`mprFooter` helpers, and hydrated the footer using the CDN-hosted library.
- TA-208: Enforced nonce issuance/validation for Google Sign-In via `/auth/nonce`, injected the issued nonce into Google Identity Services initializers (mpr-ui bundles + demo), refreshed docs/examples, expanded Node coverage for nonce provisioning/failure paths, and dropped the bundled `mpr-ui.js` in favour of the CDN-hosted build.
- TA-210: Reauthored the demo page with LoopAware’s footer contract, reused the Bootstrap 5.3 + Icons stack and public theme script, mirrored the product catalogue, and strengthened Node/browser tests around theme persistence and dropup ARIA semantics.
- TA-300: Improved CLI configuration errors to enumerate missing keys, ensuring absent `jwt_signing_key` is reported precisely.
- TA-301: Reworked `/api/me` to source claims from the session context, return persisted profiles with expiry metadata, surface `ErrUserProfileNotFound`, and emit zap warnings for anomalies.
- TA-302: Required explicit origin lists when enabling credentialed CORS via `--cors_allowed_origins` / `APP_CORS_ALLOWED_ORIGINS`, surfacing configuration errors for empty or whitespace-only inputs.
- TA-406: Accepted comma-separated `APP_CORS_ALLOWED_ORIGINS` values so environment variables mirror CLI flag behavior and keep whitespace-free origins when enabling credentialed CORS.
- TA-400: Refocused README on user-facing outcomes and moved deep technical notes into `ARCHITECTURE.md`.
- TA-401: Expanded `ARCHITECTURE.md` with up-to-date flow diagrams, dependency notes, and security guidance that match the current implementation.
- TA-402: Captured the refactor roadmap in `docs/refactor-plan.md`, outlining policy gaps and prioritised remediation tasks.
- TA-403: Added broad integration/unit coverage across auth flows, CLI, and stores, delivering ~90.5% Go test coverage via black-box suites.
- TA-404: Renamed binaries, imports, and documentation artifacts to the `tauth` identifier across the project.
- TA-405: Added GitHub Actions workflows for Go tests on PRs/pushes and release builds that produce multi-platform artifacts and publish tagged releases.

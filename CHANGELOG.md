# Changelog

## [Unreleased]

### Bug Fixes 🐛
- Ensure `initAuthClient` clears stale auth state when a peer refresh broadcast arrives without a profile, with regression coverage.

### Improvements ⚙️
- Renamed tenant origin configuration from `allowed_hosts` to `tenant_origins` and aligned preflight output and flags.
- Default session validator issuer to `tauth` when omitted so clients do not need to configure it explicitly.

### Testing 🧪
- Added a browser integration test that signs in via the demo helper, clicks sign out, and asserts the header resets.

### Docs 📚
- Documented `cors_allowed_origin_exceptions` usage (including GIS) and updated example configs to match validation rules.
- Clarified sessionvalidator guidance to omit issuer configuration.

## [v0.9.5]

### Features ✨
- `tauth.js` exposes nonce issuance and Google credential exchange helpers for client integrations.
- Require explicit base URL in `initAuthClient`; remove script-origin inference in the auth client.
- Added GitHub Pages deployment workflow for the `web/` directory.
- Rebuilt the docs landing page with a new neon layout, deep dive sections, palette suggestions, and GitHub/Docs/Community footer links.

### Improvements ⚙️
- Renamed browser helper from `auth-client.js` to `tauth.js` and serve it at `/tauth.js` for better GitHub Pages compatibility.
- Static browser helpers no longer infer the API host from the script origin.
- Updated docs, examples, and tests to reflect the rename and new base URL requirements.
- Improved shared database helpers and persistent stores for users and nonces with database storage enabled.
- `/me` endpoint now uses JWT claims and better handles refresh flow failures.
- Added test coverage for auth-client nonce and credential exchange helpers.
- Relaxed origin checks for static auth-client serving on shared hosts to support Safari/WebKit.
- Removed the legacy `/mpr-sites.js` asset and demo HTML from service assets so only `/tauth.js` ships with the API.

### Bug Fixes 🐛
- Removed legacy auth-client server route.
- Allowed static auth-client serving on shared hosts even when Origin headers are missing.
- Enforced nonce requirement for Google Sign-In exchanges; mismatched nonces cause authentication failure.
- Tenant resolution now keys off request origins only; host-based routing is removed and `tenant_origins` must be schemeful origins.
- Require `X-TAuth-Tenant` overrides to match request origins and require explicit overrides when Origin is missing.
- Reject missing Origin at the origin gate unless a valid `X-TAuth-Tenant` override is supplied.
- Enforce CORS allowlists to match tenant origins unless explicitly permitted via `cors_allowed_origin_exceptions`.
- Removed UI framework assets from the server package; the demo now loads mpr-ui from the CDN while TAuth serves only `/tauth.js`.
- Removed UI-specific headers from `tauth.js` so the helper remains frontend-agnostic.
- Removed forced `crossorigin` on demo script loaders and set a default demo client ID so the mpr-ui header renders in local demo runs.
- Ensured the tauth demo loads tauth.js before the mpr-ui bundle and GIS so header auth wiring stays consistent.
- Aligned the demo CORS allowlist with the Docker Compose frontend port (8080) so preflight OPTIONS requests succeed.
- Restored the demo baseline styling (font + margins) using mpr-ui tokens so the page matches the expected mpr-ui look.
- Cleared stale auth-client profiles when session bootstrap fails so mpr-ui logout reliably resets state.
- Added a cache-busting query string for local demo tauth.js loads so updated bundles are picked up during development.
- Aligned tools/mpr-ui docs and demo wiring with `/tauth.js`, and updated the mpr-ui auth header to prefer tauth.js helpers with a base-url fallback.

### Testing 🧪
- Added coverage for database-backed user/nonce stores.
- Added regression tests for refresh cookie duplication, overlapping cookie scopes, and cross-type cookie collisions.
- Added regression coverage for tenant configuration validation related to cookie name collisions.
- Added auth-client tests for nonce and credential exchange helpers.
- Added a GitHub Actions workflow that runs frontend tests and type checks on frontend changes.
- Added regression coverage for the tauth demo config bootstrap sequencing.
- Added regression coverage for demo CORS and tenant origin configuration.
- Added regression coverage for clearing cached profiles when refresh fails.
- Added regression coverage for the demo tauth.js cache-busting loader.

### Docs 📚
- Updated README and ARCHITECTURE.md to replace `auth-client.js` references with `tauth.js`.
- Documented the explicit base URL requirement for `tauth.js` initialization.
- Updated issue tracker with new features and bug fixes related to auth client renaming and API changes.
- Enhanced usage guides and examples to reflect new deployment and integration workflows.
- Removed stale `/demo` endpoint documentation; demos now live solely in repository assets.

## [v0.9.0]

### Features ✨
- Introduced WebAssetsVolume configuration and landing page updates with footer integration and layout improvements.
- Added EmbeddedAuthServer for mounting auth routes and auth endpoint helpers with automatic base URL resolution.
- Added pre-start configuration report and validation via `tauth preflight` with redacted effective-config report for external validation.

### Improvements ⚙️
- Migrated preflight package to reusable `github.com/tyemirov/utils/preflight`; enhanced Viper adapter to support YAML + env bindings.
- Auth client now auto-detects base URL and exposes `getAuthEndpoints()`; sessionvalidator loader supports tenant config from `config.yaml`.
- Updated Dockerfile to add `/web` volume for web assets; updated dependencies and module namespace.
- Added GitHub Pages landing page with dark neon theme, presentation layout, and a refreshed footer.
- Increased test coverage to 95%, adding sandbox-safe integration tests and expanded coverage on multiple modules.

### Bug Fixes 🐛
- Cleaned host collision rules and fixed multi-tenant hygiene validation in preflight.
- Fixed config loading and validation including env variable placeholder support and handling missing env vars gracefully.

### Testing 🧪
- Added extensive unit and integration tests for sessionvalidator, config loaders, tenant runtime, preflight reports, and server coverage.
- Integration tests use in-memory servers for end-to-end tenant routing and auth flow validation.

### Docs 📚
- Documented new `tauth preflight` command and effective-config report format; updated migration guides.
- Added detailed architecture and usage guides, including server-only endpoint contracts and sessionvalidator configuration.
- Provided migration documentation for GAuss to TAuth and updated README with deployment tips and preflight usage.
- Added landing page documentation and demo HTML with updated footer and UI components.

## [v0.0.8]

### Features ✨
- TA-212: Switched tenant configuration format from JSON to YAML to improve readability. Updated loader to parse YAML, and all documentation/examples now reference `tenants.yaml`.
- TA-101: Added the `internal/tenants` domain model plus JSON loader that validates tenant IDs, hosts, cookies, and TTLs ahead of the multi-tenant routing work.
- TA-102: Introduced the tenant resolver + gin middleware with optional `X-TAuth-Tenant` overrides plus comprehensive tests so upcoming auth routes can bind per-tenant configs safely.
- TA-103: Scoped refresh tokens, nonce pools, and the in-memory user store by tenant ID, embedded `tenant_id` inside JWT claims, and enforced tenant-aware `RequireSession` validation to block cross-tenant cookie replay.
- TA-104: Wired multi-tenant routing end-to-end (`--tenants_file`, optional header overrides, `TenantRegistry`), so each request uses the correct per-tenant cookie domains/TTLs and host mismatches fallback cleanly.
- TA-106: Made the tenants JSON file mandatory for every deployment, rewired CLI/tests, and refreshed docs so single-tenant and multi-tenant setups share the same configuration workflow.
- TA-105: Added the `tenantId` option to `auth-client.js`, updated documentation so front-ends know when to use the override header, and expanded Node tests covering two tenants + header-based refresh flows.
- TA-107: `auth-client.js` now derives its base URL from the script origin and exposes `getAuthEndpoints()`; `pkg/sessionvalidator` can now load tenant signing keys, issuer, and cookie names from `config.yaml` for downstream JWT validation.
- TA-108: Added `tauth preflight` to emit a redacted effective-config report and validate dependencies before launch, plus build metadata in the report for external validators.
- TA-109: Generalized preflight reporting with `github.com/tyemirov/utils/preflight`, added a Viper-based adapter for YAML + env bindings, and refactored TAuth preflight to reuse the shared schema.

### Improvements ⚙️
- TA-411: Moved the preflight package to `github.com/tyemirov/utils/preflight` to make it reusable outside the TAuth module.

### Docs 📚
- TA-100: Captured the multi-tenant implementation roadmap and opened follow-up issues (TA-101-TA-105) to track tenant modelling, routing, storage isolation, runtime wiring, and documentation updates.
- TA-110: Added a GitHub Pages landing page at `docs/index.html` with the new presentation layout and CTAs.
- TA-111: Swapped the landing page footer to a custom component.
- TA-112: Removed the palette suggestions section from the landing page.

### Improvements ⚙️
- TA-113: Added `/web` as a Docker volume and copied web assets into the image.

### Bug Fixes 🐛
- TA-339: Expanded the tenant config loader to replace `${VAR}`/`$VAR` placeholders (even when configs are embedded), added regression tests for both document and YAML entry points, and documented the behavior so missing env vars collapse to empty strings without panicking.
- TA-333: Fixed `clearCookie` path mismatch during logout; refresh cookies (Path `/auth`) are now correctly cleared alongside session cookies.
- TA-334: Fixed `/demo/config.js` serving default tenant config; now correctly resolves the tenant from the request context to return the appropriate Google Client ID.
- Accept `X-TAuth-Tenant` overrides that provide a frontend origin and teach `auth-client.js` to fall back to the page origin when no tenant ID is supplied so multi-tenant localhost setups stay logged in on both apps; refreshed resolver/JS tests and documentation to match.
- Added optional `session_cookie_name` / `refresh_cookie_name` fields to tenant config plus documentation so legacy backends (e.g., Gravity) can continue reading `app_session` cookies while multi-tenant setups keep unique cookie names.

## [v0.0.6]

### Features ✨
- Support dev cookies over HTTP in server configuration for development ease.

### Improvements ⚙️
- Added comprehensive usage documentation with an authoritative guide in `docs/usage.md`.
- Introduced `.gitignore` enhancements to manage environment files and IDE artifacts.
- Refined server CORS and cookie SameSite handling with a new `devInsecureHTTP` flag.
- Enhanced integration tests in `internal/authkit/routes_integration_test.go`.
- Updated README to link to the new usage guide for easier onboarding.

### Bug Fixes 🐛
- Fixed handling of development cookies to support HTTP environments.

### Testing 🧪
- Expanded integration test coverage for auth routes to improve reliability.

### Docs 📚
- Created a detailed usage guide covering setup, session management, and client integration.
- Removed obsolete docs (`loopaware-footer.md` and `refactor-plan.md`) to streamline documentation.
- Improved README with updated references to new documentation resources.

## [v0.0.5]

- TA-332: Added `examples/docker-compose` with a `.env` template plus README instructions so developers can spin up TAuth locally via Docker Compose.
- TA-333: Updated the compose example to build the image from the local Dockerfile (`docker compose up --build`) so contributors can test unmerged changes.
- TA-334: Adjusted the Docker image to run as root, create `/data`, and declare it as a volume so the SQLite refresh store can write when using Docker Compose.
- TA-335: Added an integration test that starts the server with a file-based SQLite DSN (`sqlite:///...`) to guard against regressions in on-disk deployments.
- TA-335: Restored the Docker Compose quick-start (single TAuth service + `.env` template) and documented the workflow for local testing.
- TA-335: Restored the `examples/docker-compose` quick-start (compose stack + `.env` template), added README guidance, and ignored local `.env.tauth` overrides so developers can spin up TAuth locally.
- TA-334: Reconfigured the Docker image to run as root, pre-create `/data`, and declare the data volume so SQLite-backed refresh stores can write without permission errors when running under Docker Compose.
- TA-330: Replaced the refresh token store’s SQLite dialector with the CGO-free `github.com/glebarez/sqlite`, refreshed tests to enforce the driver selection, and documented the change so Docker images run without enabling CGO.
- TA-200: Introduced GORM-backed refresh token store supporting Postgres and SQLite, added mandatory `--database_url` / `APP_DATABASE_URL`, removed pgx-specific store and legacy compatibility, updated docs, and added SQLite lifecycle tests.
- TA-100: Delivered a reusable auth header, surfaced `avatar_url` across login and `/me` payloads, refreshed demo rendering, and documented dataset/event contracts for downstream consumers.
- TA-101: Published `pkg/sessionvalidator` with smart constructor, token/request helpers, and Gin middleware; refactored server middleware to reuse it and added focused unit tests plus docs.
- TA-201: Added `LoadServerConfig` smart constructor invoked from Cobra `PreRunE`, validating TTLs, cookie names, and required identifiers before the server boots with structured `config.*` errors.
- TA-202: Introduced injectable Google token validator and clock providers, updated auth routes to reuse the singleton, and wrapped JWT mint failures with stable error codes for observability.
- TA-203: Standardised refresh token store error semantics by sharing sentinel errors, propagating contextual wrapping, and exposing idempotent revoke helpers across memory and database stores.
- TA-204: Wired zap logger and metrics recorder into auth routes, logging warnings/errors with stable codes and incrementing counters across login, refresh, and logout flows.
- TA-205: Added TLS-backed end-to-end Go tests covering `/auth/google → /auth/refresh → /auth/logout`, tampered sessions, and revoked-token scenarios to raise integration coverage.
- TA-206: Delivered Puppeteer Core coverage that verifies `auth-client.js` login/refresh/logout event dispatch using a mocked backend; gated on `CHROMIUM_PATH` for local runs.
- TA-207: Adopted a shared footer component in the demo, exposed helper hooks, and hydrated the footer using the CDN-hosted library.
- TA-208: Enforced nonce issuance/validation for Google Sign-In via `/auth/nonce`, injected the issued nonce into Google Identity Services initializers, refreshed docs/examples, expanded Node coverage for nonce provisioning/failure paths, and dropped the bundled UI helper in favour of the CDN-hosted build.
- TA-210: Reauthored the demo page with LoopAware’s footer contract, reused the Bootstrap 5.3 + Icons stack and public theme script, mirrored the product catalogue, and strengthened Node/browser tests around theme persistence and dropup ARIA semantics.
- TA-300: Improved CLI configuration errors to enumerate missing keys, ensuring absent tenant `jwt_signing_key` values are reported precisely.
- TA-301: Reworked `/api/me` to source claims from the session context, return persisted profiles with expiry metadata, surface `ErrUserProfileNotFound`, and emit zap warnings for anomalies.
- TA-302: Required explicit origin lists when enabling credentialed CORS via `--cors_allowed_origins` / `APP_CORS_ALLOWED_ORIGINS`, surfacing configuration errors for empty or whitespace-only inputs.
- TA-406: Accepted comma-separated `APP_CORS_ALLOWED_ORIGINS` values so environment variables mirror CLI flag behavior and keep whitespace-free origins when enabling credentialed CORS.
- TA-400: Refocused README on user-facing outcomes and moved deep technical notes into `ARCHITECTURE.md`.
- TA-401: Expanded `ARCHITECTURE.md` with up-to-date flow diagrams, dependency notes, and security guidance that match the current implementation.
- TA-402: Captured the refactor roadmap in `docs/refactor-plan.md`, outlining policy gaps and prioritised remediation tasks.
- TA-403: Added broad integration/unit coverage across auth flows, CLI, and stores, delivering ~90.5% Go test coverage via black-box suites.
- TA-404: Renamed binaries, imports, and documentation artifacts to the `tauth` identifier across the project.
- TA-405: Added GitHub Actions workflows for Go tests on PRs/pushes and release builds that produce multi-platform artifacts and publish tagged releases.

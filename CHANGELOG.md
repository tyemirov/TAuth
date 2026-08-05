# Changelog

## Unreleased

### Features
- Added tenant-enabled Sign in with Apple using `/auth/apple/start` and `/auth/apple/callback`, including signed state, nonce validation, Apple client-secret JWT generation, JWKS-backed ID-token validation, allowlist enforcement, account-management support, and the `tauth.js` Apple login helpers.
- Added full tenant-gated account management for first-party email/password accounts, including signup, email verification, reset, password change, Google/password linking, unlinking, account disablement, persisted opaque account IDs, and account-level refresh revocation.
- Added tenant-enabled email/password login via `POST /auth/password/login`, with bcrypt-hashed configured users, persistent credential storage, and the `exchangePasswordCredential` browser helper.

### Bug Fixes
- Accepted the explicit zero-tenant aggregate during forward deployment bootstrap: `tauth doctor` validates it, `/health` remains available, and auth routes stay inactive until an application contributes a tenant.
- Made `https://tauth.mprlab.com/tauth.js` the sole browser-helper location, removed the backend's embedded helper route and obsolete `/web` image payload so `tauth-api.mprlab.com/tauth.js` returns 404, and added the independent `/health` readiness endpoint.
- Preserved the complete documentation site in the canonical Pages artifact and disabled Jekyll so the gateway verification marker remains publicly addressable.
- Fixed deploy image verification when `latest` matches a normalized SemVer image tag such as `1.1.1` rather than the literal Git release tag `v1.1.1`.
- Preserved literal bcrypt hashes during YAML environment expansion so `$2a$`, `$2b$`, and `$2y$` hashes are not mistaken for shell variables.
- Reconciled password credential rows during startup seeding so users removed from `password_auth.users` cannot continue authenticating from persistent stores.
- Masked password credential lookup timing by running a dummy bcrypt comparison when a normalized email has no stored credential.
- Added `GET /auth/session` for browser bootstrap so stale restore hints return profile JSON or `204 No Content` instead of emitting expected `/me` or `/auth/refresh` 401s.
- Require browser `/auth/google` ID tokens to carry a nonce claim matching the submitted TAuth nonce token or its opaque hash.
- Generate persisted opaque 128-bit base64url account-management subjects instead of deterministic tenant/provider/email hashes, migrate stored account references once, and revoke refresh tokens tied to the old account subjects.

### Improvements
- Declared a canonical container-built GitHub Pages resource that assembles the documentation site and `web/tauth.js` in the schema-v3 lifecycle manifest, and removed the obsolete `tauth.mprlab.com` Caddy route.
- Declare the complete schema-v3 TAuth runtime, service placement, retained data, gateway-managed tenant config, `tauth.http` and `tauth.tenants` capabilities, public routes, and health check for the sibling gateway lifecycle.
- Declare bounded retirement of the legacy `mprlab-nginx-gateway/tauth-api` container while preserving its retained data volume during the schema-v3 cutover.
- Delegate only `make release`, `make publish`, and `make deploy` to the exact sibling `../mprlab-gateway`, removing the app-owned release, publication, deployment, and local-controller implementations.
- Documented Apple OAuth tenant configuration, browser redirect flow, callback endpoints, and provider-generic account identity behavior.
- Documented the password-auth tenant config, helper flow, persistence table, and endpoint behavior across README, architecture, and usage docs.
- Updated `tauth.js` hinted restore to use `/auth/session` while preserving `/auth/refresh` for protected `apiFetch` retries.

## [v1.1.12] - 2026-07-29

- Merge pull request #138 from tyemirov/gix/mark-example-env-files-as-documentation-only-clarify
- test: use non-operational origins in demo env and update related assertions
- chore(deploy): update deploy.sh guidance for .env.deploy creation
- docs(example): clarify tauth-demo .env file as non-operational sample
- docs: clarify .env.deploy.example usage and update setup instructions
- docs: clarify creation of local deployment config in README
- docs: clarify .env.deploy.example is documentation-only with dummy values
- Merge pull request #137 from tyemirov/bugfix/B044-data-only-deploy-binding
- Fix B044 data-only deployment binding

## [v1.1.11] - 2026-07-17

- Merge pull request #136 from tyemirov/bugfix/TA-450-restore-deploy-discovery-manifest
- fix(deploy): restore canonical vendor-neutral deployment discovery manifest

## [v1.1.10] - 2026-07-17

- Merge pull request #135 from tyemirov/bugfix/TA-449-restore-vanilla-deploy-contract
- fix: restore neutral deploy lifecycle with local operator binding

## [v1.1.9] - 2026-07-17

- Merge pull request #134 from tyemirov/bugfix/TA-448-vendor-neutral-deployment
- Remove operator deployment knowledge from TAuth
- Merge pull request #133 from tyemirov/improvement/TA-447-add-mediaops-tenant
- Scope MediaOps TAuth cookies
- Add TA-447 MediaOps production tenant

## [v1.1.8] - 2026-07-11

- Merge pull request #132 from tyemirov/gix/refactor-policies-and-workflows-remove-legacy-ci-and
- test: remove --skip-ci argument from deploy_contract_test deployment command
- docs(issues): resolve B043 with updated deploy contract test alignment
- Merge remote-tracking branch 'origin/master' into gix/refactor-policies-and-workflows-remove-legacy-ci-and
- test: add release contract test to verify repository-owned release tooling
- refactor(scripts): modularize release/publish flow and remove legacy scripts
- docs: remove CNAME file from documentation
- chore(deploy): remove obsolete Ansible resources.yml
- docs: update README to clarify deployment and helper script serving
- build(makefile): update release and publish targets for container artifact flow
- docs: update agent and issue management policies, add recurring maintenance runbooks
- ci: remove GitHub Actions workflows for frontend deploy and release
- Merge pull request #131 from tyemirov/tyemirov/improvement/TA-446-production-config-ownership
- feat(config): own shared TAuth production deployment contract

## [v1.1.7] - 2026-06-24

### Features ✨
- Introduced persisted opaque 128-bit base64url account IDs for enhanced uniqueness and security in account management.
- Full tenant-gated account management now uses these opaque account IDs for sessions, supporting signup, email verification, reset, password change, identity linking/unlinking, and account disablement.

### Improvements ⚙️
- Refactored account ID handling to remove "account:" prefix and use bare opaque IDs consistently.
- Updated documentation across AGENTS.md, ARCHITECTURE.md, README.md, and usage docs to clarify the new opaque account ID format and session subject usage.
- Added Ansible resource definitions for TAuth deployment.

### Bug Fixes 🐛
- Fixed account management to generate and persist opaque account IDs for sessions, migrating existing references and revoking refresh tokens tied to old subjects.
- Enforced rejection of non-opaque account subjects at runtime to maintain contract integrity.

### Testing 🧪
- Focused tests on account ID persistence and session handling in internal authkit packages.

### Docs 📚
- Updated AGENTS.md with forward-only contract discipline emphasizing no backward compatibility.
- Clarified account ID formats and session subject details in multiple docs including changelog, usage, and issue tracker descriptions.
- Fixed wording in changelog regarding account subject format changes.

## [v1.1.6] - 2026-06-09

### Features ✨
- Add tenant-enabled Sign in with Apple support, including OAuth provider, start and callback routes, and session handling.
- Implement full tenant-gated account management for email/password accounts with signup, verification, reset, change, linking, unlinking, and disable endpoints.
- Enforce active account sessions and restrict password reset by allowed users.

### Improvements ⚙️
- Unify external provider handling in authkit for Apple OAuth support.
- Allow Apple OAuth paths to bypass origin and tenant middleware for proper callback handling.
- Update package description and documentation to include Apple and password authentication features.
- Enhance tauth.js with Apple login helpers and account management support.
- Preserve self-service password credentials across config reconciliation and recheck live account state for account-management routes.

### Bug Fixes 🐛
- Fix password reset completion to recheck allowed users before revoking sessions or minting new cookies, returning 403 when user is not allowed.
- Reject disabled account sessions on `/me`, treat as anonymous on `/auth/session`, and prevent refresh into fresh JWTs.
- Post-review fixes for Apple login flow to carry validated return URLs, redirect properly after cookie minting, and record helper restore hints.

### Testing 🧪
- Add comprehensive tests for tenant-aware Apple login URL, account management helpers, and disable account helper.
- Cover stale disabled-account sessions and persistent credential reconciliation with regression tests.
- Black-box HTTP regression coverage for Apple routes and password reset flows.
- Validate with focused authkit tests, black-box memory/persistent store coverage, and full CI runs.

### Docs 📚
- Update documentation with Sign in with Apple support, configuration details, and account management HTTP API endpoints.
- Add detailed planning and resolution notes for account management features (TA-500).
- Update README and ISSUES.md with Apple Sign-in and account management fixes and feature details.

## [v1.1.5] - 2026-06-08

### Features ✨
- Added `GET /auth/session` endpoint for browser bootstrap to return current or refreshed session profile or `204 No Content` for anonymous/expired sessions.
- Enforced Google ID token nonce claim requirement on `/auth/google` to cryptographically bind sign-in attempts.
- Added nonce enforcement and clean session restore in the authkit.

### Improvements ⚙️
- Updated `tauth.js` to use `/auth/session` for hinted session restore, avoiding browser-visible 401 errors.
- Refactored to replace `meEndpoint` with `sessionEndpoint` for session fetch in the auth client.
- Updated deployment make target in `deploy.sh` for backend deployment.
- Added local `make release`, `make publish`, and `make deploy` wrappers to satisfy shared MPR workflows.
- Updated documentation and README to reflect new `/auth/session` endpoint and bootstrap behavior.

### Bug Fixes 🐛
- Fixed branch refresh command in release script to use `sync` instead of `cd`.
- Required Google ID tokens to carry valid nonce claims, rejecting missing or mismatched nonces with `401 invalid_nonce`.
- Cleaned session restore flow to avoid console noise from expected 401 errors during stale session restoration.

### Testing 🧪
- Updated auth client tests to use `/auth/session` endpoint.
- Added HTTP and browser-client regression tests for anonymous, authenticated, refresh-backed, and expired session states.

### Docs 📚
- Updated usage and API documentation for the new `/auth/session` endpoint.
- Documented client session flow changes and nonce enforcement.
- Updated README to reflect `/auth/session` usage and bootstrap behavior.

## [v1.1.4] - 2026-05-14

### Features ✨
- Added tenant-enabled email/password authentication with `POST /auth/password/login` endpoint.
- Included bcrypt-hashed user credential storage and password hash verification.
- Introduced `exchangePasswordCredential` helper in the browser client for password login.
  
### Improvements ⚙️
- Added tenant-scoped password auth config contract and backend support.
- Implemented startup seeding with removed-user reconciliation for password users.
- Enhanced session and token handling for password authentication flows.
- Updated documentation covering password credential reconciliation and usage.
  
### Bug Fixes 🐛
- Masked timing during password credential lookup to prevent information leaks.

### Testing 🧪
- Added black-box and integration tests covering password login and credential stores.
- Extended existing tests for multi-tenant password auth scenarios.

### Docs 📚
- Documented password credential reconciliation, password auth config, and login usage.
- Updated architecture and usage docs to include password authentication flows.

## [v1.1.3] - 2026-05-14

### Features ✨
- `tauth.js` client now defaults to `bootstrapMode: "restore-if-hinted"`, reporting anonymous visitors without probing protected endpoints on first load.
- Added non-secret local session restore hints keyed by `baseUrl` and tenant ID to enable silent session restoration for returning users.
- Introduced `getAuthState()` method reporting auth states: `unknown`, `anonymous`, `restoring`, `authenticated`, or `error`.
- Added `onAuthError` callback hook to handle 403, 404, network errors, and server failures during session restore attempts.

### Improvements ⚙️
- Modified `initAuthClient` to support explicit tenant-scoped restore hints, avoiding cross-tenant bootstrap probes on shared origins.
- Updated client bootstrap modes: `restore-if-hinted` (default), `eager` (legacy probe-first), and `passive` (no automatic restore).
- Enhanced backend multi-tenant support by scoping restore hints by tenant, ensuring secure tenant isolation during bootstrap.
- Documentation updated for clearer guidance on bootstrap modes, tenant selection, and bootstrap behavior.

### Bug Fixes 🐛
- Fixed issue where public shared header loads generated noisy 401 errors in browser console for logged-out users by skipping `/me` and `/auth/refresh` probes without prior session hints.
- Session restore hint is cleared on unauthenticated `401` responses during hinted restores, preventing stale restore attempts.

### Testing 🧪
- Added comprehensive tests for new bootstrap modes verifying anonymous initial state, hinted restores with `/me`, passive bootstrap, one-time refresh-on-401 during restore, and proper clearing of restore hints on unauthorized responses.

### Docs 📚
- Updated usage and architecture documentation to explain the new bootstrap behavior, restore hint mechanism, and tenant scoped bootstrap management.
- Clarified helper globals and default parameters in `tauth.js`.
- Improved README side notes detailing bootstrap modes and tenant overrides.

## [v1.1.2] - 2026-05-08

### Features ✨
- _No changes._

### Improvements ⚙️
- Added local `make release`, `make publish`, and `make deploy` wrappers to satisfy shared MPR deployed-app workflow contract.
- Updated release workflow to tag images with both `vX.Y.Z` and `X.Y.Z` aliases for better image consistency.
- Deployment scripts now accept `latest` as a valid release alias when matching image tags during verification.

### Bug Fixes 🐛
- Fixed deploy image verification to correctly accept `latest` tag digest matching any of the normalized SemVer aliases (e.g., `1.1.1`) instead of only the literal Git tag (e.g., `v1.1.1`).
- Resolved issue where local publish and GitHub workflows could divergent tag images leading to false deploy verification errors.

### Testing 🧪
- Verified deploy image matching using extensive timeout-controlled local and CI runs including gateway workflow verification.

### Docs 📚
- Updated documentation to remove references to deprecated `/demo` endpoint and reflect auth client readiness changes in the demo.
- Improved ISSUE tracking heuristics and added notes on deploy image verification behavior.

## [v1.1.1] - 2026-05-08

### Features ✨
- Add repo-local `make release`, `make publish`, and `make deploy` scripts for TAuth to enable streamlined GHCR image publishing and backend deployment.
- Implement native mobile Google sign-in support for Expo iOS and Android clients with platform-specific redirect URIs and audience validation.

### Improvements ⚙️
- Improve documentation and configuration handling across modules, updating README, ARCHITECTURE, and usage docs with detailed Expo client recipe.
- Refactor repository layout to use `.mprlab/` folder for autonomous flow and issue tracking files.
- Enhance Google OAuth client configurations, including platform audiences and mobile-specific client IDs.

### Bug Fixes 🐛
- _No changes._

### Testing 🧪
- Add black-box tests covering Google authorization flows, including mobile redirect handling, nonce validation, audience verification, and session refresh/logout.
- Validation and compatibility tested with `make ci` and integration against sibling gateway workflows.

### Docs 📚
- Update documentation to include native mobile OAuth flow details and configuration.
- Clarify usage instructions and repo deployment workflows in README and related docs.

## [v1.1.0] - 2026-04-11

### Features ✨
- Added native system-browser login flow for installed apps via `GET /auth/google/native/config` and `POST /auth/google/native`.
- Introduced support for native OAuth desktop/installed-app clients in tenant configuration (`google_native_client_id`).
- Enabled native clients to authenticate using PKCE and local loopback redirect without embedding Google sign-in in a web view.

### Improvements ⚙️
- Updated tenant configuration schema to include optional native client IDs for isolated tenant sessions.
- Enhanced documentation with native installed-app login instructions and updated architecture overview.
- Improved configuration validation and testing to cover native client ID parsing and uniqueness.
- Refined auth routes to handle native login flow with ID token and nonce validation.

### Bug Fixes 🐛
- _No changes._

### Testing 🧪
- Added tests verifying native client ID parsing in configuration.
- Expanded integration and HTTP route tests to cover native OAuth flow and error cases.

### Docs 📚
- Documented native system-browser exchange flow including tenant config, API endpoints, and client usage.
- Updated README and usage guides to describe native installed-app login alongside web popup flow.
- Clarified tenant config requirements and API error semantics for native login endpoints.

## [v1.0.1] - 2026-03-20

### Features ✨
- Support multi-arch linux/arm64 Docker images and GitHub workflow.
- Added a detailed YouTube scopes feasibility report.
- New comprehensive usage.html page rendered from usage.md for GitHub Pages.

### Improvements ⚙️
- Deploy docs site to GitHub Pages, copying tauth.js to site root.
- Added Google Analytics tags to docs pages.
- Update documentation to clarify TAuth does not implement OAuth2 authorization flows or manage Google API tokens.
- Enhance Dockerfile to support target OS/architecture build arguments.
- Streamlined GitHub Pages workflow to publish docs and web folders.

### Bug Fixes 🐛
- Fixed `usage.html` properly loading `usage.md`.

### Testing 🧪
- _No changes._

### Docs 📚
- Major docs update including new usage.html and youtube-scopes-feasibility.md.
- Added Google tag script to main docs pages.
- Clarified TAuth's authentication-only scope and limitation regarding OAuth2 tokens in README and usage.md.

## [v1.0.0]

### Features ✨
- Introduce store schema policy and store schema version constructor with validation moved to edge.
- Add database connectivity probe for health checks.
- Optional tenant override header (`X-TAuth-Tenant`) support for web clients; structured tenant resolution errors added.
- Add `tauth doctor` command for comprehensive configuration validation, including cross-configuration checks and database connectivity.
- Fixtures and assets added for test scaffolding.
- Multi-tenant configuration is now fully functional.

### Improvements ⚙️
- Default `tauth.js` to only send tenant override header when tenant ID is explicitly configured.
- Refine tenant resolution to rely primarily on browser Origin headers, with optional override for non-browser or shared-origin clients.
- Prevent destructive refresh token schema resets; register schema versions safely to avoid data loss.
- Improved configuration docs, examples, and test fixtures for multi-tenant setups.
- Docker build optimized by ignoring unnecessary files.
- `tauth doctor` supports JSON output for CI/CD pipelines.

### Bug Fixes 🐛
- Fix database schema and fixture issues.
- Fix schema version record alignment.
- Enforce empty `allowed_users` lists to deny all logins.
- Prevent migration during database connectivity checks in `tauth doctor`.
- Reset incompatible refresh token schemas only once per schema version to avoid repeated drops.
- Correct origin validation and error handling for multi-tenant authentication.

### Testing 🧪
- Add extensive tests for `tauth doctor` command including config validation and cross-validation.
- Add HTTP tests for authentication reject logic based on allowlist.
- Add tests for multi-tenant configuration loading.
- Add multiple new database-related and store tests.

### Docs 📚
- Update README and ARCHITECTURE.md with tenant override header usage and validation details.
- Document `tauth doctor` usage, features, and examples.
- Clarify multi-tenant origin resolution in usage and readme files.
- Add test fixtures and example configurations for multi-tenant support.

## [v0.9.9]

### Features ✨
- Introduced `allowed_users` allowlist for tenants to restrict Google sign-ins by email.
- Enforce `allowed_users` allowlist semantics at edge, rejecting disallowed emails with HTTP 403 `user_not_allowed` error.

### Improvements ⚙️
- Updated documentation and examples to include `allowed_users` configuration and behavior.
- Clarified `allowed_users` behavior: absent means allow all, empty deny all, and presence restricts to listed emails.
- Renamed tenant origin config from `allowed_hosts` to `tenant_origins`.
- Defaulted `tauth.js` to Origin-only routing; `X-TAuth-Tenant` is now sent only when a tenant id is explicitly configured.
- Added structured tenant resolution error payloads (error codes + hints) to simplify diagnosing missing/unknown/ambiguous Origin and override issues.

### Bug Fixes 🐛
- Enforced empty `allowed_users` list as deny-all, preventing unintended unrestricted access.
- Fixed origin validation and error handling for multi-tenant authentication.
- Reset incompatible refresh token schemas on upgrade by dropping and recreating store tables once per schema version.
- Prevented `tauth doctor --check-database` from migrating or resetting refresh token schemas.
- Avoided dropping user store tables when schema migration records are missing by registering versions without destructive resets.

### Testing 🧪
- Added comprehensive HTTP tests for authentication rejecting users not on the allowlist.
- Included tests for empty `allowed_users` list resulting in denied logins.

### Docs 📚
- Documented `allowed_users` behavior in README, usage guide, and architecture notes.
- Added usage examples for tenant `allowed_users` in multi-tenant configs.

## [v0.9.8]

### Features ✨
- Introduced `SessionValidatorIssuer` guidance and moved session validation to edge.
- Added default `SessionValidatorIssuer` to simplify client configuration.
- Introduced `tenant_origins` schema replacing `allowed_hosts` for tenant origin configuration.
- Added per-tenant `allowed_users` allowlists to restrict Google sign-ins by email.

### Improvements ⚙️
- Renamed tenant origin config from `allowed_hosts` to `tenant_origins` and aligned validation and preflight outputs.
- Defaulted session validator issuer to `tauth` when omitted.
- Updated example configs and documentation to reflect `tenant_origins` usage and validation.

### Bug Fixes 🐛
- Fixed configuration and origin validation rules for multi-tenant setups.
- Improved error handling for authentication and header issues in the demo.
- Enforced empty `allowed_users` as deny-all instead of disabling allowlist enforcement.

### Testing 🧪
- Added browser integration tests covering demo sign-out and header reset flows.
- Updated demo-related tests to use fixtures, reducing impact of asset changes.

### Docs 📚
- Documented `cors_allowed_origin_exceptions` usage including Google Identity Services.
- Clarified documentation and examples to align with tenant origin validation and session validator defaults.

## [v0.9.7]

### Features ✨

- Decoupled demo test fixtures and moved tenant origin validation to edge.
- Restored demo bootstrap assets and improved demo hosting to use computercat.mprlab.com and port 8081.
- Added tenant ID to the example env sample for better demo configuration.
- Implemented enhanced demo frontend app supporting Google sign-in and session status display.

### Improvements ⚙️

- Updated demo to pin mpr-ui assets to v3.3.0 to ensure Google site ID attributes are honored.
- Aligned demo origins with documented 8080 frontend ports and clarified tenant origin validation error messages.
- Switched demo server to use HTTPS with mounted TLS certificates and surfaced auth errors in the demo app.
- Updated mpr-header to use an updated DSL with TAuth and restored header auth attributes in demo.
- Changed demo compose file to mount required 3rd party tools and use computercat host.

### Bug Fixes 🐛

- Fixed demo environment fixture tracking issues.
- Restored Google sign-in on HTTPS demo ensuring functional sign-in button rendering.
- Cleared stale auth state after empty peer refresh broadcasts to avoid stale profile retention.
- Improved error surfacing for authentication and header issues within demo.
- Fixed configuration and origin validation rules for multi-tenant setup.

### Improvements ⚙️
- Renamed tenant origin configuration from `allowed_hosts` to `tenant_origins` and aligned preflight output and flags.
- Default session validator issuer to `tauth` when omitted so clients do not need to configure it explicitly.

### Testing 🧪

- Added browser integration test covering demo sign-out flow verifying header reset after logout.
- Introduced GitHub Actions workflow for frontend tests and type checking on frontend changes.
- Moved demo-related tests to fixtures to isolate asset changes from test scaffolding.

### Docs 📚

- Documented `cors_allowed_origin_exceptions` for non-tenant CORS origins including Google Identity Services.
- Updated example configs to align with stricter tenant origin validation rules.
- Improved issue tracker documentation with relevant features and bug fixes related to demo and tenant handling.

## [v0.9.6]

### Bug Fixes 🐛

- Clear stale auth state in `initAuthClient` after an empty peer refresh broadcast, preventing stale profile retention.
- Enriched tenant origin validation errors with the expected format and specific failure reasons.
- Restored the tauth demo bootstrap scripts and aligned demo origins with the documented 8080 frontend ports.
- Restored mpr-ui header auth attributes in the demo so the Google sign-in button renders.
- Pinned demo and fixture mpr-ui assets to v3.3.0 so google-site-id attributes are honored.
- Surfaced mpr-ui authentication and header errors in the demo status panel and moved the entrypoint to `app.js`.
- Mounted computercat TLS certificates in the demo compose file and switched ghttp to serve HTTPS.

### Testing 🧪

- Added browser integration test covering the demo sign-out flow to verify header reset after logout.
- Introduced a GitHub Actions workflow to run frontend tests and type checks on frontend changes.
- Moved demo-related tests onto fixtures so demo asset changes do not affect test scaffolding.

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

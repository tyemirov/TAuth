# ISSUES (Append-only Log)

Entries record newly discovered requests or changes, with their outcomes. No instructive content lives here. Read @NOTES.md for the process to follow when fixing issues.

## Features (100–199)

## Improvements (200–299)

- [x] [TA-200] Use GORM and abstract away the flavor of the DB through GORM. If the DB url sent through an envionment variable specifies postgres protocol, then use postgres, if sqlite, then use sqlite, etc — Resolved with `NewDatabaseRefreshTokenStore` (GORM, Postgres/SQLite), mandatory `--database_url` / `APP_DATABASE_URL`, legacy Postgres-only store removed, docs + tests added
- [x] [TA-201] Harden configuration lifecycle and smart constructors — Added `LoadServerConfig` smart constructor invoked from `PreRunE`, validated TTLs and required identifiers, and surfaced structured `config.*` error codes before server start.
- [x] [TA-202] Inject Google token validator dependencies and wrap JWT errors — Introduced injectable Google validator/clock with CLI wiring, tightened route time handling, and wrapped JWT mint failures with `jwt.mint.failure` codes.
- [x] [TA-203] Harmonize refresh token store error semantics — Unified sentinel errors across memory/sqlite stores, wrapped errors with context codes, and surfaced an idempotent revoke contract for logging.
- [x] [TA-204] Expand auth logging and metrics hooks — Injected zap logger and metrics recorder into auth routes, added structured warnings/errors, and incremented counters for login, refresh, and logout flows.
- [x] [TA-205] Deliver end-to-end Go HTTP tests for the auth lifecycle — Added TLS-backed `httptest.Server` flows covering login→refresh→logout, tampered sessions, and revoked tokens with metrics assertions.
- [x] [TA-206] Add Puppeteer coverage for `auth-client.js` events — Added Puppeteer Core harness verifying login, refresh, and logout event callbacks with a mocked HTTP server; tests require system Chromium (`CHROMIUM_PATH`) to run.

## BugFixes (300–399)

- [x] [TA-300] The app doesn't recognize the provided google web client ID — Clarified CLI validation to list only missing configuration keys and added coverage ensuring `jwt_signing_key` absence is reported precisely.
- [ ] [TA-301] Align `/api/me` with the documented profile contract — Update `HandleWhoAmI` to resolve `auth_claims`, return the stored profile, replace `http.ErrNoCookie` with a domain error, and log anomalies via zap.
- [ ] [TA-302] Tighten CORS configuration when credentials are enabled — Parameterise allowed origins, prevent wildcard credentials, and surface warnings for unsafe origins when `APP_ENABLE_CORS` is active.
```
00:45:49 tyemirov@computercat:~/Development/Research/TAuth [master] $ go run ./... --google_web_client_id "991677581607-r0dj8q6irjagipali0jpca7nfp8sfj9r.apps.googleusercontent.com"
Error: missing required configuration: google_web_client_id or jwt_signing_key
```

## Maintenance (400–499)

- [x] [TA-400] Update the documentation @README.md and focus on the usefullness to the user. Move the technical details to ARCHITECTURE.md. — Delivered user-centric README and migrated deep technical content into the new ARCHITECTURE.md reference.
- [x] [TA-401] Ensure architrecture matches the reality of code. Update @ARCHITECTURE.md when needed. Review the code and prepare a comprehensive ARCHITECTURE.md file with the overview of the app architecture, sufficient for understanding of a mid to senior software engineer. — Expanded ARCHITECTURE.md with accurate flow descriptions, interfaces, dependency notes, and security guidance reflecting current code.
- [x] [TA-402] Review @POLICY.md and verify what code areas need improvements and refactoring. Prepare a detailed plan of refactoring. Check for bugs, missing tests, poor coding practices, uplication and slop. Ensure strong encapsulation and following the principles og @AGENTS.md and policies of @POLICY.md — Authored `docs/refactor-plan.md` documenting policy gaps, remediation tasks, and prioritised roadmap.
- [x] [TA-403] preparea comprehensive code coverage. Use external tests (so no direct testing of internal functions) and strive to achive 95% code coverage using exposed API. — Added extensive integration/unit tests across auth flows, CLI, and stores; achieved ~90.5% overall Go coverage (short of the 95% target) with `go test ./... -coverprofile=coverage.out`.
- [x] [TA-404] Rename the binaries, references, packages to `tauth` as the name of the app — Rebranded the module, binary command, imports, and supporting docs/tests to the `tauth` identifier.

## Planning

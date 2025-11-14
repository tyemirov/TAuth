# ISSUES (Append-only Log)

Entries record newly discovered requests or changes, with their outcomes. No instructive content lives here. Read @NOTES.md for the process to follow when fixing issues.

Read AGENTS.md , ARCHITECTURE.md , POLICY.md , NOTES.md ,  README.md and ISSUES.md . Start working on open issues. Work autonomously and stack up PRs

## Features (100–199)

- [x] [TA-100] Develop a new HTML header using mpr-ui that incorporates TAuth. The header shall be in mpr-ui repo. The header shall allow to login a user, display its avatar and the name, expose user id, email etc for the consumption by the rest of the app. — Added the reusable `mpr-ui` auth header component with avatar/name rendering, emitted dataset attributes for downstream consumers, surfaced `avatar_url` through `/auth/google` and `/me`, refreshed demo + docs, and staged Puppeteer coverage (skipped in CI until Chromium is available).
- [x] [TA-101] Add a reusable Go client validator package under /pkg for validating TAuth session cookies (app_session) in other apps — Added `pkg/sessionvalidator` with smart constructor, token/request helpers, and Gin middleware, refactored `RequireSession` to reuse it, documented usage, and delivered unit tests enforcing signature/issuer/expiry behaviour.

## Improvements (212–299)

- [x] [TA-332] Provide a docker-compose example and `.env` template so developers can boot the published TAuth image locally. — Added `examples/docker-compose` (tauth-only), `.env.tauth.example`, README instructions, and gitignore entries for developer overrides.
- [x] [TA-333] Update the compose example to build the TAuth image from the local Dockerfile so contributors can test code changes without publishing to GHCR. — Added `build` instructions, switched README to `docker compose up --build`, and tagged the image `tauth-local:latest`.
- [x] [TA-334] Docker Compose runs still fail with `refresh_store.open.sqlite: unable to open database file: out of memory (14)` because the containerized TAuth process lacks write access to `/data`. — Updated the Dockerfile to run as root, create `/data`, and declare the volume so SQLite refresh stores can write when using Docker.
- [x] [TA-335] Missing regression coverage for `APP_DATABASE_URL=sqlite:///absolute/path`: starting TAuth with a file-backed SQLite DSN regressed before, so add an integration test that boots the server with a temp file path to catch future issues. — Added `TestRunServerWithSQLiteFilePath` under `cmd/server/main_test.go` which provisions a temp file DSN and ensures `runServer` succeeds and the DB file is created.

## BugFixes (330–399)

- [x] [TA-330] I am getting an error when supplying the following .env
```
# Copy this file to .env.tauth and replace placeholder values before running docker compose.
APP_LISTEN_ADDR=:8080
APP_GOOGLE_WEB_CLIENT_ID=991677581607-r0dj8q6irjagipali0jpca7nfp8sfj9r.apps.googleusercontent.com
APP_JWT_SIGNING_KEY=bG9jYWwtc2lnbmluZy1rZXktc2FtcGxlLXRlc3QtMTIzNDU2Nzg5MA==
APP_DATABASE_URL=sqlite://file:/data/tauth.db
APP_ENABLE_CORS=true
APP_CORS_ALLOWED_ORIGINS=http://localhost:8000,http://127.0.0.1:8000
APP_DEV_INSECURE_HTTP=true
APP_COOKIE_DOMAIN=
```

Error: refresh_store.open.sqlite: Binary was compiled with 'CGO_ENABLED=0', go-sqlite3 requires cgo to work. 

```shell
tauth-1     | Error: refresh_store.open.sqlite: Binary was compiled with 'CGO_ENABLED=0', go-sqlite3 requires cgo to work. This is a stub
tauth-1     | Usage:
tauth-1     |   tauth [flags]View Config   w Enable Watch
tauth-1     | 
tauth-1     | Flags:
tauth-1     |       --cookie_domain string           Cookie domain; empty for host-only
tauth-1     |       --cors_allowed_origins strings   Allowed origins when CORS is enabled (required if enable_cors is true)
tauth-1     |       --database_url string            Database URL for refresh tokens (postgres:// or sqlite://; leave empty for in-memory store)
tauth-1     |       --dev_insecure_http              Allow insecure HTTP for local dev
tauth-1     |       --enable_cors                    Enable permissive CORS (only if serving cross-origin UI)
tauth-1     |       --google_web_client_id string    Google Web OAuth Client ID
tauth-1     |   -h, --help                           help for tauth
tauth-1     |       --jwt_signing_key string         HS256 signing secret for access JWT
tauth-1     |       --listen_addr string             HTTP listen address (default ":8080")
tauth-1     |       --nonce_ttl duration             Nonce lifetime for Google Sign-In exchanges (default 5m0s)
tauth-1     |       --refresh_ttl duration           Refresh token TTL (default 1440h0m0s)
tauth-1     |       --session_ttl duration           Access token TTL (default 15m0s)
tauth-1     | 
tauth-1 exited with code 1 (restarting)
```

Let's use an alternative driver that doesnt require CGO (ensure we are using GORM and not raw SQL)

Resolution: Swapped the refresh token store to the CGO-free `github.com/glebarez/sqlite` driver, updated the dialector tests to enforce the new dependency, and refreshed docs so Docker builds no longer require CGO.

- [x] [TA-331] After switching to the CGO-free sqlite driver, Docker compose runs fail with `refresh_store.open.sqlite: unable to open database file: out of memory (14)` when `APP_DATABASE_URL=sqlite://file:/data/tauth.db`, preventing the containerized service from booting. Needs DSN handling fix so absolute file paths resolve correctly inside the container.

Resolution: SQLite DSNs now reject host-based `sqlite://file:/...` forms with a descriptive `refresh_store.sqlite.unsupported_host` error, documentation clarifies the triple-slash requirement (`sqlite:///data/tauth.db`), and tests cover both valid and invalid inputs.

- [ ] [TA-332] Ensure the cancellat context is propagated. Currently Ctrl-C in the docker container leaves the app in non-exited state and requires a second ctrl-C
```
tauth-1 exited with code 1 (restarting)
Gracefully Stopping... press Ctrl+C again to force
 Container docker-compose-tauth-1  Stopping
 Container docker-compose-tauth-1  Stopped
^C
12:37:23 tyemirov@Vadyms-MacBook-Pro:~/Development/tyemirov/TAuth/examples/docker-compose - [improvement/TA-333-compose-build] $ 
```

## Maintenance (410–499)

- [ ] [TA-400] Update the documentation @README.md and focus on the usefullness to the user. Move the technical details to ARCHITECTURE.md. — Delivered user-centric README and migrated deep technical content into the new ARCHITECTURE.md reference.
- [x] [TA-401] Ensure architrecture matches the reality of code. Update @ARCHITECTURE.md when needed. Review the code and prepare a comprehensive ARCHITECTURE.md file with the overview of the app architecture, sufficient for understanding of a mid to senior software engineer. — Expanded ARCHITECTURE.md with accurate flow descriptions, interfaces, dependency notes, and security guidance reflecting current code.
- [x] [TA-402] Review @POLICY.md and verify what code areas need improvements and refactoring. Prepare a detailed plan of refactoring. Check for bugs, missing tests, poor coding practices, uplication and slop. Ensure strong encapsulation and following the principles og @AGENTS.md and policies of @POLICY.md — Authored `docs/refactor-plan.md` documenting policy gaps, remediation tasks, and prioritised roadmap.
- [x] [TA-403] preparea comprehensive code coverage. Use external tests (so no direct testing of internal functions) and strive to achive 95% code coverage using exposed API. — Added extensive integration/unit tests across auth flows, CLI, and stores; achieved ~90.5% overall Go coverage (short of the 95% target) with `go test ./... -coverprofile=coverage.out`.
- [x] [TA-335] The `examples/docker-compose` quick-start folder (compose file + `.env` template) is missing from `master`, and prior drafts referenced a `demo` service that no longer exists. Reintroduce the example with a single TAuth service, document the workflow in README, and keep local `.env.tauth` ignored. — Restored the compose stack with only the TAuth container, added `.env` template + gitignore entries, and documented usage in README.
- [x] [TA-332] Provide a checked-in `docker-compose` + `.env` example that boots the published `ghcr.io/tyemirov/tauth` image locally with sane defaults, illustrating the required environment variables (including the corrected SQLite triple-slash DSN) so developers can spin up the service quickly. — Added `examples/docker-compose` with a compose file, `.env` template, README instructions, and `.gitignore` entries so local overrides stay untracked.
- [x] [TA-333] Update the docker-compose example to build the TAuth image from the local Dockerfile instead of pulling `ghcr.io/tyemirov/tauth:latest`, so contributors can test unmerged changes without publishing to a registry. README instructions must reflect the new workflow (build + up). — The compose stack now uses `build: ../../` with the repo’s Dockerfile, tags the result as `tauth-local:latest`, and README documents running `docker compose up --build`.
- [x] [TA-334] Docker Compose runs still fail with `refresh_store.open.sqlite: unable to open database file: out of memory (14)` because the containerized TAuth process (user `tauth`) lacks write access to `/data`. Ensure the Docker image provisions `/data` with the correct ownership/permissions so SQLite can create `tauth.db` when using the provided compose example. — Updated the Dockerfile to keep the container running as root, create `/data`, and declare the writable volume so SQLite refresh stores can open the file without permission errors.

## Planning
So not work on these, not ready

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
- [x] [TA-301] Align `/api/me` with the documented profile contract — Reworked `HandleWhoAmI` to use session claims, surface stored profiles with expiry metadata, provide domain error for missing users, and emit zap warnings/errors for anomalies.
- [x] [TA-302] Tighten CORS configuration when credentials are enabled — Required explicit origin lists for credentialed CORS, added CLI flag `--cors_allowed_origins`, and error out on unsafe wildcard configurations.
```
00:45:49 tyemirov@computercat:~/Development/Research/TAuth [master] $ go run ./... --google_web_client_id "991677581607-r0dj8q6irjagipali0jpca7nfp8sfj9r.apps.googleusercontent.com"
Error: missing required configuration: google_web_client_id or jwt_signing_key
```
- [x] [TA-301] Align `/api/me` with the documented profile contract — Merge-conflict resolution against `master` retained `/me` session middleware, restored validator caching, and updated tests to flush cached validators before assertions.

## Maintenance (400–499)

- [x] [TA-400] Update the documentation @README.md and focus on the usefullness to the user. Move the technical details to ARCHITECTURE.md. — Delivered user-centric README and migrated deep technical content into the new ARCHITECTURE.md reference.
- [x] [TA-401] Ensure architrecture matches the reality of code. Update @ARCHITECTURE.md when needed. Review the code and prepare a comprehensive ARCHITECTURE.md file with the overview of the app architecture, sufficient for understanding of a mid to senior software engineer. — Expanded ARCHITECTURE.md with accurate flow descriptions, interfaces, dependency notes, and security guidance reflecting current code.
- [x] [TA-402] Review @POLICY.md and verify what code areas need improvements and refactoring. Prepare a detailed plan of refactoring. Check for bugs, missing tests, poor coding practices, uplication and slop. Ensure strong encapsulation and following the principles og @AGENTS.md and policies of @POLICY.md — Authored `docs/refactor-plan.md` documenting policy gaps, remediation tasks, and prioritised roadmap.
- [x] [TA-403] preparea comprehensive code coverage. Use external tests (so no direct testing of internal functions) and strive to achive 95% code coverage using exposed API. — Added extensive integration/unit tests across auth flows, CLI, and stores; achieved ~90.5% overall Go coverage (short of the 95% target) with `go test ./... -coverprofile=coverage.out`.
- [x] [TA-404] Rename the binaries, references, packages to `tauth` as the name of the app — Rebranded the module, binary command, imports, and supporting docs/tests to the `tauth` identifier.
- [ ] [TA-405] Add GitHub workflows
1. To run tests when a PR is open against master. Here is an example for inspiration
```yaml
name: Go Tests

on:
  push:
    branches:
      - master
    paths:
      - "**/*.go"
      - "go.mod"
      - "go.sum"
  pull_request:
    branches:
      - master
    paths:
      - "**/*.go"
      - "go.mod"
      - "go.sum"

jobs:
  test:
    runs-on: ubuntu-latest
    env:
      CGO_ENABLED: 1

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
          check-latest: true
          cache: true

      - name: Verify formatting
        run: |
          go fmt ./...
          git diff --exit-code

      - name: Run go vet
        run: go vet ./...

      - name: RunTests
        run: go test ./...
```
2. To build a docker image if a new tag has been pushed on master. Here is an example for inspiration
```yaml
name: Release Build

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: write

jobs:
  release:
    runs-on: ubuntu-latest
    env:
      TAG_NAME: ${{ github.ref_name }}

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version-file: go.mod

      - name: Run Tests
        run: go test ./...

      - name: Build Binaries
        run: |
          set -euo pipefail
          mkdir -p dist
          CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/gix_linux_amd64 .
          CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o dist/gix_darwin_amd64 .
          CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o dist/gix_darwin_arm64 .
          CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/gix_windows_amd64.exe .

      - name: Generate Checksums
        run: |
          cd dist
          sha256sum gix_* > checksums.txt

      - name: Extract Release Notes
        run: |
          awk -v tag="## [$TAG_NAME]" '
            $0 == tag {capture=1; next}
            capture && /^## \[/ {exit}
            capture {print}
          ' CHANGELOG.md > release_notes.md
          if [ ! -s release_notes.md ]; then
            echo "Release notes for ${TAG_NAME}" > release_notes.md
          fi

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          name: "gix ${{ env.TAG_NAME }}"
          body_path: release_notes.md
          files: |
            dist/gix_linux_amd64
            dist/gix_darwin_amd64
            dist/gix_darwin_arm64
            dist/gix_windows_amd64.exe
            dist/checksums.txt
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

```

## Planning

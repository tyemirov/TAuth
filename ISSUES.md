# ISSUES (Append-only Log)

Entries record newly discovered requests or changes, with their outcomes. No instructive content lives here. Read @NOTES.md for the process to follow when fixing issues.

Read AGENTS.md , ARCHITECTURE.md , POLICY.md , NOTES.md ,  README.md and ISSUES.md . Start working on open issues. Work autonomously and stack up PRs

## Features (100–199)

- [x] [TA-100] Make TAuth multitenant. Deliver implementation plan and document it as open issues in @ISSUES.md — Captured the roadmap (tenant config, resolver, storage isolation, routing changes, docs/tests) and opened TA-101 through TA-105 to track each implementation slice.
- [x] [TA-101] Introduce tenant domain model and config loader so operators can declare multiple tenants (id, hostnames, Google client IDs, cookie domains, TTLs) in a single file. — Added `internal/tenants` with smart constructors + JSON loader, full validation (ids, unique hosts, TTL parsing), README/ARCHITECTURE docs, and tests defining the file contract.
- [x] [TA-102] Implement tenant resolution middleware that maps inbound hosts (and optional `X-TAuth-Tenant` header for local/dev) to a resolved tenant, rejects unknown hosts early, and injects the tenant into the request context. — Added `tenants.NewResolver`, optional header override wiring, gin middleware/context helpers, README/ARCH updates, and resolver/middleware tests.
- [x] [TA-103] Scope stateful stores by tenant: refresh tokens gain a `tenant_id` column + indexes in Postgres/SQLite, nonce stores and in-memory user stores are namespaced per tenant, and JWT claims add `tenant_id` so cookies cannot be replayed across tenants. — Refresh/db stores now require tenant IDs, nonce + user stores are namespaced, JWTs/middleware enforce `tenant_id`, and docs/tests cover the new contracts.
- [x] [TA-104] Rework `cmd/server` + `authkit` routing to run per-tenant configs (per-tenant ServerConfig, cookie attributes, SameSite mode), keep backward compatibility for single-tenant flags, and unit-test the host-routing fallbacks. — Added `--tenants_file` support with tenant registry + Gin middleware, updated auth routes/middleware to consume per-tenant configs, and refreshed tests/docs to cover fallback routing.
- [x] [TA-105] Update `web/auth-client.js`, README, ARCHITECTURE, and usage docs to explain how front-ends select a tenant (document host mapping, new `initAuthClient({ tenantId })` option for shared hosts), and add integration tests that exercise two tenants end-to-end. — Added the `tenantId` option (propagated to `X-TAuth-Tenant` headers), refreshed docs with shared-host guidance, and expanded Node tests to cover the override flow.
- [x] [TA-106] Unify configuration by requiring a tenants JSON file for every deployment (single or multi-tenant), remove remaining legacy env/flag references, and update docs/tests so multi-tenancy is documented as the default operating mode rather than upcoming work. — CLI now requires `--tenants_file`, docs/examples were rewritten around the JSON schema (with Docker templates), and `cmd/server` tests cover the new loader and registry behaviour.
- [x] [TA-107] TAuth requires certain endpoints in the consuming application. Can these endpoints be automatically supplied by the TAuth client instead of a consuming application implementing these steps itself?
Core endpoints are /auth/nonce, /auth/google, /auth/refresh, /auth/logout, and /me. If we can supply them, even partially, that would ease the burden of integration with TAuth further. In case we can implement it, update @docs/migration.md documentation — Added auth-client base URL auto-detection + `getAuthEndpoints()`, updated migration guidance, expanded auth-client regression tests, and ensured the demo footer/persistence flows stay compatible with the legacy mpr-ui bundle during browser automation.
- [x] [TA-107] Reopen: embed the auth endpoints in Gin apps so backend clients can mount `/auth/*` + `/me` without reimplementing them. — Added `pkg/tauthserver` with option wiring, shared tenant registry builder, and integration-style tests that exercise the mounted endpoints.
- [x] [TA-107] Correction: remove endpoint-embedding packages, keep `/auth/*` + `/me` server-only, and expand `pkg/sessionvalidator` to load issuer/cookie names from `config.yaml`; docs now state the endpoint contract explicitly.
- [x] [TA-108] Add preflight validation + redacted effective-config report so external validators can verify orchestrated services before launch. — Scope is pre-start only (no runtime endpoints). Required output includes: service metadata (version/build/config schema version), effective server settings (CORS + allowed origins, tenant header override), per-tenant effective settings (tenant id/display name, allowed_hosts optionally redacted, google_web_client_id, cookie_domain, session_cookie_name/refresh_cookie_name, session/refresh/nonce TTLs, allow_insecure_http, derived SameSite mode, jwt_issuer), and secret fingerprints only (jwt_signing_key_fingerprint, never raw keys). External validator responsibilities: compare issuer/cookie names/cookie domain expectations, verify JWT signing key match via fingerprint comparison, validate multi-tenant hygiene (no cookie collisions on shared hosts, ambiguity rules), and validate CORS origin requirements (notably accounts.google.com). Deliverable includes stable error codes + a versioned JSON schema for the report. — Added `tauth preflight` output/report builder with redacted host mode, dependency checks, and documentation.
- [x] [TA-109] Generalize preflight implementation for Viper-based services with YAML + env bindings. — Added `tools/utils/preflight` builder interfaces, Viper config adapter with redaction hooks, refactored TAuth preflight to reuse the shared schema, and documented the generic preflight contract.
- [x] [TA-110] Add a GitHub Pages landing page under `docs/index.html` with a dark neon theme, hero CTA + code snippet, feature cards, deep-dive sections, docs links, and palette suggestions. — Added `docs/index.html` with the requested structure, copy, and palette guidance for GitHub Pages hosting.
- [x] [TA-111] Integrate the mpr-ui footer component into the GitHub Pages landing page. — Replaced the static footer with `<mpr-footer>` and added the mpr-ui stylesheet/script.

- [ ] [TA-109] Build a presentational web site as a polished landing page for a platform service TAuth
  Style it visually and structurally.
  Follow these principles:
  • Hero section with bold product tagline, subheading, primary CTA, and screenshot/code example
  • Value-props as three or four concise feature blocks with icons
  • Clean documentation links or “Get Started” area
  • Two or three deeper feature sections with side-by-side text + screenshots/code
  • Dark theme with neon accent
  • Monospace for headings and code snippets
  • Strong visual hierarchy, wide spacing, minimal borders
  • Footer with GitHub/Docs/Community links
  Provide me with:
 
  A rewritten layout structure
 
  Restyled copy in the tone of top developer platforms
 
  Matching CSS (no frameworks unless requested)
 
  Light/dark palette suggestions
  Keep everything production-grade and concise.
  Use GitHub as a hosting solution (an index.html file under docs/)

## Improvements (212–299)

- [x] [TA-212] Switch tenant configuration format from JSON to YAML. Update loader to parse YAML, validation remains the same. Update all docs, tests, and examples to use YAML. — Switched loader to `gopkg.in/yaml.v3`, updated tests/examples/docs to use YAML format and `tenants.yaml`.
- [x] [TA-340] Collapse CLI/env configuration into a single YAML file. — Replaced the Viper-based flag/env matrix with `config.yaml`, added a dedicated loader (`--config` / `TAUTH_CONFIG_FILE`), updated Compose examples, docs, and tests to consume the unified file, and exposed `tenants.LoadConfigFromDocument` for embedding.
- [x] [TA-112] Remove the palette suggestions section from the landing page. — Removed the palette section and navigation link from `docs/index.html`.
- [x] [TA-213] Expose nonce issuance and Google credential exchange helpers in `tauth.js` so consuming apps can delegate the `/auth/nonce` and `/auth/google` flows. — Added helper functions + tests for nonce and credential exchange with tenant headers.

## BugFixes (330–399)

- [x] [TA-332] Ensure the cancellat context is propagated. Currently Ctrl-C in the docker container leaves the app in non-exited state and requires a second ctrl-C — Server now shares a signal-aware context across validator and database initialization, runs shutdown with a single 10s timeout path, and exits cleanly on first context cancellation (covered by `TestRunServerHonorsContextCancellation`).
- [x] [TA-333] Fix ineffective logout for refresh cookies. The `clearCookie` helper uses path `/` for all cookies, but the refresh cookie is scoped to `/auth`. Logout must clear the refresh cookie using the correct path. — Updated `clearCookie` to accept a path argument and ensured `/auth/logout` clears the refresh cookie with `Path=/auth`.
- [x] [TA-334] Fix `demo/config.js` using default tenant config. The demo configuration endpoint currently serves the default tenant's Google Client ID regardless of the resolved tenant, breaking the demo on multi-tenant setups. It must use `tenants.TenantFromContext`. — Updated `/demo/config.js` handler to resolve tenant from context and serve the correct Google Client ID.
- [x] [TA-335] `apiFetch` leaks `X-TAuth-Tenant` to every downstream API. The helper is supposed to keep tenant overrides scoped to TAuth endpoints only, but the current `apiFetch` implementation injects the header on arbitrary requests and breaks tests/users expecting isolation. Strip the header from generic API calls and keep it for `/auth/*` refresh flows. — Updated `web/auth-client.js` to only apply the tenant header for auth endpoints, refreshed tests (`tests/auth-client.test.js`) to ensure generic API calls stay header-free, and reran `npm test -- auth-client.test.js`.
- [x] [TA-336] `setAuthTenantId` and script `data-tenant-id` never propagate to outbound requests. The runtime only reads `runtime.options.tenantId`, so calling `setAuthTenantId("tenant-a")` (or configuring the script tag) does nothing until `initAuthClient` reruns with the same value. Ensure the runtime stores the detected tenant ID and uses it for headers even when options are omitted, and update tests. — Synced the runtime + options tenant ID handling, taught `setAuthTenantId` to update future requests, and added regression coverage for detected/script + setter flows.
- [x] [TA-337] IPv6 tenant hosts cannot be resolved. `internal/tenants/resolver.go` strips ports by splitting on the first colon, which truncates IPv6 literals (`[2001:db8::1]` becomes `[2001`). Update `extractHost` to handle bracketed IPv6 hosts (with or without ports) and add coverage. — Normalized IPv6 literals properly in the resolver/config, added a dedicated test (`TestResolverSupportsIPv6Hosts`), and verified `go test ./internal/tenants`.
- [x] [TA-338] Docs/flags still reference `tenants.json` after the YAML migration. CLI help and README/ARCHITECTURE bullets instruct operators to point at a JSON file, contradicting TA-212 and causing config errors. Update user-facing strings (and sample tests) to reference `tenants.yaml`. — Updated CLI flag help, README, ARCHITECTURE, and sample tenant fixtures/tests to consistently point at `tenants.yaml`.
- [x] [TA-339] Expand environment variables inside tenants YAML. Local orchestration needs `${VAR}` placeholders (e.g., cookie domains, client IDs) to hydrate from env without templating. Loader currently treats values literally, so `${HOST}` appears verbatim. Update the loader to expand env vars (supporting `${VAR}`/`$VAR`), document the behavior, and add tests ensuring missing vars stay empty rather than causing crashes. — Added a document-level env expander so every tenant loader path (YAML or embedded configs) supports `${VAR}`/`$VAR`, covered both env and missing-var scenarios in `internal/tenants` tests, and updated README/CHANGELOG to call out the behavior.
- [x] [TA-341] Multi-tenant sessions evict each other when the UI relies on origin-only routing; `/me` and `/auth/*` lack `X-TAuth-Tenant` hints so ambiguous hosts fall back to the wrong tenant. Allow the resolver to treat header overrides as either tenant IDs or frontend origins and teach `auth-client.js` to fall back to `window.location.origin` when no explicit `tenantId` is configured. Added JS/Go regression tests and refreshed docs to explain the new behavior.
- [x] [TA-342] Legacy frontends (e.g., Gravity) still expect `app_session` / `app_refresh` cookie names, so the new per-tenant cookie names broke existing integrations. Add optional `session_cookie_name` / `refresh_cookie_name` overrides to the tenant schema, propagate them through the registry, document the fields, and update the multi-tenant example so Gravity keeps its original cookie names without reintroducing cross-tenant collisions.
- [x] [TA-343] Refresh token churn and nonce mismatches log users out under multi-tenant load. Persist user + nonce stores when database storage is enabled, stop clearing cookies on refresh failures, switch `/me` to claim-backed responses, add auth-client broadcast sync, and expand integration coverage for concurrent multi-tenant refresh.
- [x] [TA-346] Duplicate refresh cookies can mask valid tokens and overlapping cookie scopes allow collisions across tenants. Try all refresh cookie candidates and reject overlapping cookie-name reuse during tenant config validation; add regression tests for both scenarios.
- [x] [TA-347] Cross-type cookie name collisions (session vs refresh) on overlapping scopes can overwrite cookies. Reject cross-type cookie-name reuse during tenant config validation and add regression coverage.
- [x] [TA-345] Enforce unique cookie names across overlapping tenant cookie scopes (shared hosts or cookie domains) to prevent refresh/session collisions. — Added cookie scope validation in tenant config loading and regression tests for shared host, domain-domain, and domain-host overlaps.
- [x] [TA-348] Static auth-client.js requests on shared hosts fail when Origin is missing, blocking Safari/WebKit auth flows. — Relaxed static host gating to allow missing Origin for allowed hosts and refreshed server tests.
- [x] [TA-349] auth-client.js should require an explicit API base URL instead of inferring it from the script origin; update tests and documentation. — Removed script-origin fallback, enforced explicit base URL hints, updated docs/changelog, and refreshed Node tests.

## Maintenance (410–499)

- [x] [TA-410] Increase test coverage to 95%. Analyze coverage gaps in `pkg/sessionvalidator`, `internal/web`, `internal/tenants`, `cmd/server`, and `internal/authkit`. Add unit and integration tests to cover edge cases and error paths. — Added unit/integration coverage for sandbox-safe HTTP flows (no listener sockets), raised total coverage to 95%+, and verified with `go fmt ./... && go vet ./... && go test ./...`.
- [x] [TA-400] Update the documentation @README.md and focus on the usefullness to the user. Move the technical details to ARCHITECTURE.md. — README now surfaces the hosted + local deployments, points custom flows at ARCHITECTURE.md, and the detailed GIS/nonce handshake (with sample code) was moved under `ARCHITECTURE.md#google-sign-in-exchange`.
- [x] [TA-411] Move the preflight package from `pkg/preflight` to `tools/utils/preflight` and update references. — Relocated the preflight module into the shared utils repo, rewired imports, and updated documentation references.
- [x] [TA-412] Replace local utils replaces with remote module usage so only `github.com/tyemirov/utils/preflight` is required. — Removed the local replace, pinned the utils module version, and updated documentation references.
- [x] [TA-113] Mount the `web/` folder as a separate Docker volume in the image. — Added `/web` as a Docker volume and copied the web assets into the image.
- [x] [TA-413] Update the demo TAuth base URL to prefer `https://tauth.mprlab.com` on hosted domains, dynamically load `auth-client.js`, and remove the hardcoded localhost script tag so hosted deployments stay aligned.

## Planning
So not work on these, not ready
- [x] [TA-344] Refresh could fail when duplicate refresh cookies exist; validate all matching cookies and log candidate count; add regression test. — `/auth/refresh` now validates all matching cookies and logs candidate counts, with regression coverage and refreshed staticcheck tool.

## Updates (350–399)

- [x] [TA-350] Move the hosted helper to `/tauth.js` (and `/mpr-sites.js`), remove base URL hint fallbacks in favor of explicit `initAuthClient` configuration, update demos/docs/tests, and add GitHub Pages deployment for `web/`.

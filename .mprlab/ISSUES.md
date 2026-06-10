# ISSUES (Append-only Log)

Entries record newly discovered requests or changes, with their outcomes. No instructive content lives here. Read @NOTES.md for the process to follow when fixing issues.

Read @AGENTS.md, @README.md and ARCHITECTURE.md and follow the links to documentation. Read @issues.md/POLICY.md, @issues.md/PLANNING.md, @issues.md/NOTES.md, and @issues.md/ISSUES.md. Start working on open issues. Prioritize bugfixes and maintenance. Work autonomously and stack up PRs.

## Features (112–200)

- [x] [TA-200] Add Apple Sign in as an additional identity provider while keeping TAuth session cookies/JWT model.
  Add a per-tenant Apple provider block (client_id, team_id, key_id, private_key, redirect_uri, optional scopes, and optional mockable endpoint overrides). Implement `GET /auth/apple/start` to issue state + nonce and redirect to Apple, plus `GET`/`POST /auth/apple/callback` to validate state, exchange the authorization code with Apple using a client-secret JWT, verify the returned Apple ID token against Apple's JWKS, enforce nonce/email/allowed_users, and mint the same `app_session` + `app_refresh` cookies/profile JSON. Apple callback tenant resolution must use the signed state payload because provider callbacks may omit `Origin`. Add account-management support so Apple identities resolve/link as provider `apple`, add `tauth.js` helpers, document configuration and errors, and cover the flow with black-box tests using a mock Apple server.
  Resolved: added tenant-level `apple_oauth` config validation, Apple start/callback routes with signed state, nonce checks, ES256 client-secret JWT generation, token exchange, JWKS ID-token validation, allowed-user enforcement, standard session finalization, provider-generic account identities, `tauth.js` Apple login helpers, Apple-only tenant support, one-line `private_key_base64` config support for env-file deployments, preflight redaction fields, docs, and mock-Apple black-box coverage. Validation passed with `npm run verify`, `npm test`, `go test ./...`, and `make ci`; the Apple-only/base64 follow-up also passed `make ci`.
  Post-review fix (2026-06-09): Apple browser login now carries a validated `return_to` URL through signed state, redirects back to the caller with `303 See Other` after cookies are minted, and records the helper restore hint before leaving the product page. Added invalid-return and callback-redirect coverage plus helper/docs updates. Validation passed with focused Apple route coverage, focused browser-helper coverage, and `timeout -k 350s -s SIGKILL 350s make ci`.
- [x] [TA-199] Add email/password authentication as an additional identity provider while keeping TAuth session cookies/JWT model.
  Implement a scoped login-first password provider: tenant-level enablement, persistent password credential storage, password hash verification, `POST /auth/password/login`, `tauth.js` helper support, and docs/tests. The first slice does not include public self-service signup, email verification, reset-password, or account-linking UI.
  Added tenant-scoped password auth config, memory/database credential stores, startup seeding with removed-user reconciliation, timing-masked credential misses, `/auth/password/login`, `exchangePasswordCredential`, docs, and black-box coverage; validated with `make ci`.
- [x] [TA-100] Make TAuth multitenant.
  Deliver implementation plan and document it as open issues in @ISSUES.md
  Captured the roadmap (tenant config, resolver, storage isolation, routing changes, docs/tests) and opened TA-101 through TA-105 to track each implementation slice.
- [x] [TA-101] Introduce tenant domain model and config loader so operators can declare multiple tenants (id, hostnames, Google client IDs, cookie domains, TTLs) in a single file.
  Added `internal/tenants` with smart constructors + JSON loader, full validation (ids, unique hosts, TTL parsing), README/ARCHITECTURE docs, and tests defining the file contract.
- [x] [TA-102] Implement tenant resolution middleware that maps inbound hosts (and optional `X-TAuth-Tenant` header for local/dev) to a resolved tenant, rejects unknown hosts early, and injects the tenant into the request context.
  Added `tenants.NewResolver`, optional header override wiring, gin middleware/context helpers, README/ARCH updates, and resolver/middleware tests.
- [x] [TA-103] Scope stateful stores by tenant: refresh tokens gain a `tenant_id` column + indexes in Postgres/SQLite, nonce stores and in-memory user stores are namespaced per tenant, and JWT claims add `tenant_id` so cookies cannot be replayed across tenants.
  Refresh/db stores now require tenant IDs, nonce + user stores are namespaced, JWTs/middleware enforce `tenant_id`, and docs/tests cover the new contracts.
- [x] [TA-104] Rework `cmd/server` + `authkit` routing to run per-tenant configs (per-tenant ServerConfig, cookie attributes, SameSite mode), keep backward compatibility for single-tenant flags, and unit-test the host-routing fallbacks.
  Added `--tenants_file` support with tenant registry + Gin middleware, updated auth routes/middleware to consume per-tenant configs, and refreshed tests/docs to cover fallback routing.
- [x] [TA-105] Update `web/auth-client.js`, README, ARCHITECTURE, and usage docs to explain how front-ends select a tenant (document host mapping, new `initAuthClient({ tenantId })` option for shared hosts), and add integration tests that exercise two tenants end-to-end.
  Added the `tenantId` option (propagated to `X-TAuth-Tenant` headers), refreshed docs with shared-host guidance, and expanded Node tests to cover the override flow.
- [x] [TA-106] Unify configuration by requiring a tenants JSON file for every deployment (single or multi-tenant), remove remaining legacy env/flag references, and update docs/tests so multi-tenancy is documented as the default operating mode rather than upcoming work.
  CLI now requires `--tenants_file`, docs/examples were rewritten around the JSON schema (with Docker templates), and `cmd/server` tests cover the new loader and registry behaviour.
- [x] [TA-107] Correction: remove endpoint-embedding packages, keep `/auth/*` + `/me` server-only, and expand `pkg/sessionvalidator` to load issuer/cookie names from `config.yaml`; docs now state the endpoint contract explicitly.
- [x] [TA-108] Add preflight validation + redacted effective-config report so external validators can verify orchestrated services before launch.
  Scope is pre-start only (no runtime endpoints). Required output includes: service metadata (version/build/config schema version), effective server settings (CORS + allowed origins, tenant header override), per-tenant effective settings (tenant id/display name, allowed_hosts optionally redacted, google_web_client_id, cookie_domain, session_cookie_name/refresh_cookie_name, session/refresh/nonce TTLs, allow_insecure_http, derived SameSite mode, jwt_issuer), and secret fingerprints only (jwt_signing_key_fingerprint, never raw keys). External validator responsibilities: compare issuer/cookie names/cookie domain expectations, verify JWT signing key match via fingerprint comparison, validate multi-tenant hygiene (no cookie collisions on shared hosts, ambiguity rules), and validate CORS origin requirements (notably accounts.google.com). Deliverable includes stable error codes + a versioned JSON schema for the report. — Added `tauth preflight` output/report builder with redacted host mode, dependency checks, and documentation.
- [x] [TA-109] Build a presentational web site as a polished landing page for a platform service TAuth.
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
  Use GitHub as a hosting solution (an index.html file under docs/) — Rebuilt docs landing layout, copy, and neon styling with palette suggestions, updated footer links, and added a Puppeteer regression test for the new sections.
- [x] [TA-110] Add a GitHub Pages landing page under `docs/index.html` with a dark neon theme, hero CTA + code snippet, feature cards, deep-dive sections, docs links, and palette suggestions.
  Added `docs/index.html` with the requested structure, copy, and palette guidance for GitHub Pages hosting.
- [x] [TA-111] Integrate the mpr-ui footer component into the GitHub Pages landing page.
  Replaced the static footer with `<mpr-footer>` and added the mpr-ui stylesheet/script.


## Improvements (420–640)

- [x] [TA-112] Remove the palette suggestions section from the landing page.
  Removed the palette section and navigation link from `docs/index.html`.
- [x] [TA-212] Switch tenant configuration format from JSON to YAML.
  Update loader to parse YAML, validation remains the same. Update all docs, tests, and examples to use YAML.
  Switched loader to `gopkg.in/yaml.v3`, updated tests/examples/docs to use YAML format and `tenants.yaml`.
- [x] [TA-213] Expose nonce issuance and Google credential exchange helpers in `tauth.js` so consuming apps can delegate the `/auth/nonce` and `/auth/google` flows.
  Added helper functions + tests for nonce and credential exchange with tenant headers.
- [x] [TA-340] Collapse CLI/env configuration into a single YAML file.
  Replaced the Viper-based flag/env matrix with `config.yaml`, added a dedicated loader (`--config` / `TAUTH_CONFIG_FILE`), updated Compose examples, docs, and tests to consume the unified file, and exposed `tenants.LoadConfigFromDocument` for embedding.
- [x] [TA-354] Style demos exclusively with mpr-ui components loaded from the CDN.
  Rebuilt `examples/tauth-demo/index.html` with semantic markup + mpr-ui elements, adjusted demo scripts to load the bundle after `tauth.js`, and updated demo tests to match the new component structure.
- [x] [TA-419] Document CORS origin exceptions and align example configs with the enforced allowlist rules.
  Added `cors_allowed_origin_exceptions` guidance (including GIS), updated demo/multi-tenant configs, and added regression checks in the JS test suite.


## BugFixes (361–399)

- [x] [TA-444] (P0) Require browser Google ID tokens to carry the issued nonce claim.
  Summary: The current browser `/auth/google` path accepts an issued `nonce_token` even when Google omits the ID-token `nonce` claim. That protects replay of the same TAuth exchange body, but it does not cryptographically bind the Google ID token to the nonce-bearing sign-in attempt. Shared browser UI now needs TAuth to reject missing or mismatched Google nonce claims so downstream apps cannot rely on a weaker no-GIS-nonce contract.
  Expected: `/auth/google` accepts only ID tokens whose `nonce` claim equals the submitted TAuth nonce or its opaque hash; missing or mismatched nonce claims return `401 {"error":"invalid_nonce"}` without finalizing login.
  Resolved 2026-06-07: browser nonce consumption now requires the Google ID-token `nonce` claim to equal the submitted TAuth nonce or its opaque hash before the issued nonce is consumed. Missing, empty, stale, or mismatched nonce claims return invalid nonce responses without finalizing login. Replaced permissive tests with strict missing/empty/stale nonce rejection coverage. Tests: focused `go test ./internal/authkit ...`; `make ci`.

- [x] [TA-443] Console-clean background session restore for stale browser hints.
  Public apps that embed TAuth through shared UI can keep a prior-session restore hint after cookies expire. Current restore flows probe `/me` and `/auth/refresh`, producing browser-visible 401 resource errors for an expected anonymous state before the client can classify it. Add a non-error session status endpoint that returns profile JSON for valid/restored sessions and `204 No Content` for anonymous or expired sessions, so UI bootstrap does not use protected-endpoint failures as control flow.
  Resolved: added `GET /auth/session` for profile-or-204 session status, including refresh-cookie restoration without browser-visible expected 401s; updated `tauth.js` hinted restore to call that endpoint and clear stale hints from 204 responses. Added HTTP and browser-client regressions for anonymous, authenticated, refresh-backed, and expired hinted sessions. Validation passed with `make ci`.

- [x] [TA-442] Avoid logged-out bootstrap 401 noise in `tauth.js`.
  Public shared-header loads currently call `/me` and then `/auth/refresh` immediately, so anonymous visitors produce browser console 401s even though logged-out state is expected. Change the browser helper to restore only when a non-secret prior-session hint exists, preserve an eager compatibility mode, and keep protected endpoint 401s meaningful for real authorization boundaries.
  Resolved: `tauth.js` now defaults to restore-if-hinted bootstrap, stores a non-secret restore hint after successful auth/refresh, skips `/me` and `/auth/refresh` on fresh anonymous loads, exposes `getAuthState()` and `onAuthError`, preserves `bootstrapMode: "eager"`/`"passive"`, and keeps `apiFetch` refresh-on-401 for protected app calls. Validation passed with `npm run verify`, `npm test -- auth-client.test.js`, and `make ci`.
- [x] [TA-441] Deploy image verification rejects valid GitHub release workflow images when tag aliases differ.
  `make deploy` compares `ghcr.io/tyemirov/tauth:latest` to the literal `v*` release tag, but the GitHub release workflow publishes SemVer aliases such as `1.1.1` and `latest`. A local `v1.1.1` image can therefore differ from the workflow-published `1.1.1`/`latest` image even though the gateway will pull the correct `latest` image for the release.
  Resolved: deploy verification now accepts `latest` when it matches a release alias for the current tag, preferring the normalized SemVer alias (`1.1.1`) for `v*` releases; local publish and the GitHub release workflow now tag both `vX.Y.Z` and `X.Y.Z` so future release images keep both aliases aligned. Validation passed with `timeout -k 120s -s SIGKILL 120s bash scripts/deploy.sh --tag v1.1.1 --skip-ci --skip-backend`, `timeout -k 350s -s SIGKILL 350s make ci`, and the sibling gateway `timeout -k 1200s -s SIGKILL 1200s make verify-app-workflows`.
- [x] [TA-253] Demo bootstrap now waits for tauth.js readiness before wiring GIS; docs no longer describe a `/demo` endpoint.
  Added an auth client readiness handle for the tauth demo, refreshed config tests, and removed `/demo` endpoint references from usage/architecture docs.
- [x] [TA-332] Ensure the cancellat context is propagated.
  Currently Ctrl-C in the docker container leaves the app in non-exited state and requires a second ctrl-C
  Server now shares a signal-aware context across validator and database initialization, runs shutdown with a single 10s timeout path, and exits cleanly on first context cancellation (covered by `TestRunServerHonorsContextCancellation`).
- [x] [TA-333] Fix ineffective logout for refresh cookies.
  The `clearCookie` helper uses path `/` for all cookies, but the refresh cookie is scoped to `/auth`. Logout must clear the refresh cookie using the correct path.
  Updated `clearCookie` to accept a path argument and ensured `/auth/logout` clears the refresh cookie with `Path=/auth`.
- [x] [TA-334] Fix `demo/config.js` using default tenant config.
  The demo configuration endpoint currently serves the default tenant's Google Client ID regardless of the resolved tenant, breaking the demo on multi-tenant setups. It must use `tenants.TenantFromContext`.
  Updated `/demo/config.js` handler to resolve tenant from context and serve the correct Google Client ID.
- [x] [TA-335] `apiFetch` leaks `X-TAuth-Tenant` to every downstream API.
  The helper is supposed to keep tenant overrides scoped to TAuth endpoints only, but the current `apiFetch` implementation injects the header on arbitrary requests and breaks tests/users expecting isolation. Strip the header from generic API calls and keep it for `/auth/*` refresh flows.
  Updated `web/auth-client.js` to only apply the tenant header for auth endpoints, refreshed tests (`tests/auth-client.test.js`) to ensure generic API calls stay header-free, and reran `npm test -- auth-client.test.js`.
- [x] [TA-336] `setAuthTenantId` and script `data-tenant-id` never propagate to outbound requests.
  The runtime only reads `runtime.options.tenantId`, so calling `setAuthTenantId("tenant-a")` (or configuring the script tag) does nothing until `initAuthClient` reruns with the same value. Ensure the runtime stores the detected tenant ID and uses it for headers even when options are omitted, and update tests.
  Synced the runtime + options tenant ID handling, taught `setAuthTenantId` to update future requests, and added regression coverage for detected/script + setter flows.
- [x] [TA-337] IPv6 tenant hosts cannot be resolved.
  `internal/tenants/resolver.go` strips ports by splitting on the first colon, which truncates IPv6 literals (`[2001:db8::1]` becomes `[2001`). Update `extractHost` to handle bracketed IPv6 hosts (with or without ports) and add coverage.
  Normalized IPv6 literals properly in the resolver/config, added a dedicated test (`TestResolverSupportsIPv6Hosts`), and verified `go test ./internal/tenants`.
- [x] [TA-338] Docs/flags still reference `tenants.json` after the YAML migration.
  CLI help and README/ARCHITECTURE bullets instruct operators to point at a JSON file, contradicting TA-212 and causing config errors. Update user-facing strings (and sample tests) to reference `tenants.yaml`.
  Updated CLI flag help, README, ARCHITECTURE, and sample tenant fixtures/tests to consistently point at `tenants.yaml`.
- [x] [TA-339] Expand environment variables inside tenants YAML.
  Local orchestration needs `${VAR}` placeholders (e.g., cookie domains, client IDs) to hydrate from env without templating. Loader currently treats values literally, so `${HOST}` appears verbatim. Update the loader to expand env vars (supporting `${VAR}`/`$VAR`), document the behavior, and add tests ensuring missing vars stay empty rather than causing crashes.
  Added a document-level env expander so every tenant loader path (YAML or embedded configs) supports `${VAR}`/`$VAR`, covered both env and missing-var scenarios in `internal/tenants` tests, and updated README/CHANGELOG to call out the behavior.
- [x] [TA-341] Multi-tenant sessions evict each other when the UI relies on origin-only routing; `/me` and `/auth/*` lack `X-TAuth-Tenant` hints so ambiguous hosts fall back to the wrong tenant.
  Allow the resolver to treat header overrides as either tenant IDs or frontend origins and teach `auth-client.js` to fall back to `window.location.origin` when no explicit `tenantId` is configured. Added JS/Go regression tests and refreshed docs to explain the new behavior.
- [x] [TA-342] Legacy frontends (e.g., Gravity) still expect `app_session` / `app_refresh` cookie names, so the new per-tenant cookie names broke existing integrations.
  Add optional `session_cookie_name` / `refresh_cookie_name` overrides to the tenant schema, propagate them through the registry, document the fields, and update the multi-tenant example so Gravity keeps its original cookie names without reintroducing cross-tenant collisions.
- [x] [TA-343] Refresh token churn and nonce mismatches log users out under multi-tenant load.
  Persist user + nonce stores when database storage is enabled, stop clearing cookies on refresh failures, switch `/me` to claim-backed responses, add auth-client broadcast sync, and expand integration coverage for concurrent multi-tenant refresh.
- [x] [TA-344] Refresh could fail when duplicate refresh cookies exist; validate all matching cookies and log candidate count; add regression test.
  `/auth/refresh` now validates all matching cookies and logs candidate counts, with regression coverage and refreshed staticcheck tool.
- [x] [TA-345] Enforce unique cookie names across overlapping tenant cookie scopes (shared hosts or cookie domains) to prevent refresh/session collisions.
  Added cookie scope validation in tenant config loading and regression tests for shared host, domain-domain, and domain-host overlaps.
- [x] [TA-346] Duplicate refresh cookies can mask valid tokens and overlapping cookie scopes allow collisions across tenants.
  Try all refresh cookie candidates and reject overlapping cookie-name reuse during tenant config validation; add regression tests for both scenarios.
- [x] [TA-347] Cross-type cookie name collisions (session vs refresh) on overlapping scopes can overwrite cookies.
  Reject cross-type cookie-name reuse during tenant config validation and add regression coverage.
- [x] [TA-348] Static auth-client.js requests on shared hosts fail when Origin is missing, blocking Safari/WebKit auth flows.
  Relaxed static host gating to allow missing Origin for allowed hosts and refreshed server tests.
- [x] [TA-349] auth-client.js should require an explicit API base URL instead of inferring it from the script origin; update tests and documentation.
  Removed script-origin fallback, enforced explicit base URL hints, updated docs/changelog, and refreshed Node tests.
- [x] [TA-351] Remove host-based tenant resolution and enforce origin-only routing.
  The tenant resolver should use only `Origin` (or `X-TAuth-Tenant`) and require schemeful origins in `allowed_hosts`; docs/examples/tests must match the origin-only contract.
  Removed host-based matching, required schemeful origins, updated middleware/docs/examples/tests, and refreshed resolver coverage.
- [x] [TA-352] Normalize auth-client helper errors and align demo/tests with latest mpr-ui custom elements.
  Added nonce JSON parse normalization, refreshed helper/docs coverage, and moved the demo/browser tests to mpr-ui@3.1.0 custom elements with updated CDN harnesses.
- [x] [TA-353] Serve only the API endpoints and `/tauth.js` from TAuth; remove demo assets and site catalog helpers.
  Dropped `/mpr-sites.js`, removed `web/demo.html`, moved demo browser tests to the `examples/tauth-demo` page, and documented that demos are hosted separately.
- [x] [TA-355] Remove UI-specific markers from tauth.js.
  Dropped the `X-Client` header and any mpr-ui identifiers so the helper stays UI-agnostic.
- [x] [TA-356] Demo header failed to render when GIS/tauth.js scripts were blocked.
  Added a default demo Google client ID and removed the forced `crossorigin` attribute so mpr-ui and GIS load without CORS errors.
- [x] [TA-357] Demo CORS allowlist excluded the ghttp port used by the Docker Compose demo.
  Aligned the demo tenant `allowed_hosts` and CORS env origins to port 8080, and added regression coverage for the demo config files.
- [x] [TA-358] Demo base styling did not apply, leaving default margins and serif fonts.
  Added a local demo stylesheet using mpr-ui tokens to set the page baseline (font, margin, background) and styled the status panel using semantic selectors.
- [x] [TA-359] mpr-ui logout left stale session state in tauth.js.
  Removed the cached-profile fallback so `initAuthClient` clears stale sessions after logout, and added regression coverage for the refresh-fail bootstrap path.
- [x] [TA-360] Demo cached an outdated tauth.js bundle, preventing logout state updates.
  Added a cache-busting query string for local demo tauth.js loads and regression coverage for the demo loader script.


## Maintenance (438–499)

- [x] [TA-440] Add the deployed-app release/publish/deploy contract for TAuth.
  `make release && make publish` currently fails at `make release` because TAuth has no repo-local deployment workflow targets. Add the shared MPR deployment surface (`make release`, `make publish`, `make deploy`) so TAuth can publish its GHCR image and hand backend deployment to `mprlab-gateway`, and register the app with the gateway verifier.
  Resolved: added `make release`, `make publish`, and `make deploy` wrappers backed by `scripts/release.sh`, `scripts/publish.sh`, and `scripts/deploy.sh`; `publish` builds/pushes only the TAuth GHCR image, and `deploy` verifies the release/latest image before handing off to `mprlab-gateway` with `TARGET=tauth`. Validation passed with `timeout -k 350s -s SIGKILL 350s make ci` and the sibling gateway `timeout -k 1200s -s SIGKILL 1200s make verify-app-workflows`.
- [x] [TA-113] Mount the `web/` folder as a separate Docker volume in the image.
  Added `/web` as a Docker volume and copied the web assets into the image.
- [x] [TA-400] Update the documentation @README.md and focus on the usefullness to the user.
  Move the technical details to ARCHITECTURE.md.
  README now surfaces the hosted + local deployments, points custom flows at ARCHITECTURE.md, and the detailed GIS/nonce handshake (with sample code) was moved under `ARCHITECTURE.md#google-sign-in-exchange`.
- [x] [TA-410] Increase test coverage to 95%.
  Analyze coverage gaps in `pkg/sessionvalidator`, `internal/web`, `internal/tenants`, `cmd/server`, and `internal/authkit`. Add unit and integration tests to cover edge cases and error paths.
  Added unit/integration coverage for sandbox-safe HTTP flows (no listener sockets), raised total coverage to 95%+, and verified with `go fmt ./... && go vet ./... && go test ./...`.
- [x] [TA-411] Move the preflight package from `pkg/preflight` to `tools/utils/preflight` and update references.
  Relocated the preflight module into the shared utils repo, rewired imports, and updated documentation references.
- [x] [TA-412] Replace local utils replaces with remote module usage so only `github.com/tyemirov/utils/preflight` is required.
  Removed the local replace, pinned the utils module version, and updated documentation references.
- [x] [TA-413] Update the demo TAuth base URL to prefer `https://tauth.mprlab.com` on hosted domains, dynamically load `auth-client.js`, and remove the hardcoded localhost script tag so hosted deployments stay aligned.
- [x] [TA-414] CRUCIAL: Constrain `X-TAuth-Tenant` overrides so they cannot bypass origin routing.
  Require overrides to match the resolved origin tenant (when Origin is present) and require an explicit override when Origin is missing.
  Matched overrides to origin owners, required header when Origin is missing, added resolver regression tests, and ran go test ./..., go vet, staticcheck, ineffassign.
- [x] [TA-415] CRUCIAL: Tighten origin gating for non-browser clients.
  Missing Origin should be rejected unless a validated override is supplied; update docs/tests to make the requirement explicit.
  Required valid `X-TAuth-Tenant` override when Origin is missing, added origin gate regression coverage, and noted the change in CHANGELOG.
- [x] [TA-416] CRUCIAL: Align CORS allowlist with tenant origins (or explicit exception list) to avoid credentialed CORS for non-tenant origins; enforce via validation and document the policy.
  Added CORS allowlist validation against tenant origins/exception list, introduced exception config field, expanded server/preflight tests, and noted the policy in CHANGELOG.
- [x] [TA-417] Add frontend to CI.
  add a trigger for the frontend changes to github workflow. run npm tests and linters when fronted files change
  Added a frontend test workflow that runs `npm run verify` and `npm test` on frontend path changes.
- [x] [TA-418] Add a browser integration test to cover demo sign-out.
  Extended the demo test server with stateful auth responses and added a Puppeteer flow that signs in via tauth.js, clicks sign out, and asserts the header returns to unauthenticated state.
- [x] [TA-420] Clarify tenant origin validation failures with expected format and specific reasons.
  Enriched `tenant.invalid_origin` errors with a concise expectation string and reason details (missing scheme, missing host, invalid scheme, or path/query/fragment).
- [x] [TA-421] Restore tauth demo bootstrap assets and align demo origins with documented ports.
  Reintroduced `demo-config.js`/`tauth-config.js`, wired the demo HTML to load them, and realigned demo config/env/compose origins with `http://localhost:8080` to satisfy the JS test suite.
- [x] [TA-422] Correction: decouple demo-related tests from repo assets by using fixture copies for docs, multi-tenant configs, and `tauth.js`.
  Added fixture assets and repointed tests/servers to them so demo and docs changes no longer affect test scaffolding.
- [x] [TA-423] Restore demo header auth attributes so the Google sign-in button renders.
  Replaced the stale `tauth-*` attributes with the mpr-ui `base-url`/`site-id`/auth path attributes in the demo header.
- [x] [TA-424] Surface demo auth/header errors and rename the demo entrypoint to app.js.
  Switched the demo script to `app.js` and added error handling for `mpr-ui:auth:error`/`mpr-ui:header:error` plus header attribute checks.
- [x] [TA-425] Serve the demo frontend over HTTPS using the computercat TLS certificates.
  Mounted the host certs into the ghttp container and updated the demo to reference the HTTPS frontend origin.
- [x] [TA-426] Pin demo mpr-ui assets to v3.3.0 and surface Google sign-in errors so google-site-id attributes are honored.
- [x] [TA-427] Track the demo env fixture so tests can validate CORS origins.
  Added the missing `.env.tauth.example` fixture under `tests/fixtures/tauth-demo` and unignored it for git so CI can read it.
- [x] [TA-428] Correction: Rename tenant configuration `allowed_hosts` to `tenant_origins` and align preflight output and flags.
  Updated tenant config schema, preflight report fields/flag, tests, examples, and documentation to use `tenant_origins` and `tenant_origin_hashes`.
- [x] [TA-429] Default session validator issuer to `tauth` when omitted.
  Updated `pkg/sessionvalidator` to fall back to the shared default issuer and refreshed validator tests.
- [x] [TA-430] Add per-tenant allowed_users login allowlist.
  Added allowed_users config parsing + enforcement in auth login, updated docs/examples, and added tests.
- [x] [TA-431] Enforce empty allowed_users as deny-all.
  Treated explicit empty allowlists as deny-all, added tests, and documented the 403 user_not_allowed behavior.
- [x] [TA-432] Production CORS preflight 405 error.
  Root cause: Gravity frontend was calling `tauth.mprlab.com` but the Caddyfile only had `tauth-api.mprlab.com`. DNS for `tauth.mprlab.com` pointed to the Caddy server, but Caddy had no site block for it, causing requests to fail before reaching TAuth (hence no backend logs). Fix: Updated Gravity's `authBaseUrl` to `tauth-api.mprlab.com` and consolidated production config to JSON-only (Gravity PR #181).
- [ ] [TA-433] (P0) Add GitHub as an additional identity provider (OAuth2 Authorization Code + PKCE) while keeping TAuth session cookies/JWT model.
  Add a per-tenant GitHub provider block (client_id, client_secret, scopes, callback URL/origin constraints, and email requirements). Implement `GET /auth/github/start` (issue state + PKCE verifier, redirect/popup URL), `GET /auth/github/callback` (validate state + PKCE, exchange code for access token, fetch user identity + verified email via GitHub API, enforce per-tenant allowed_users against the resolved verified email), then mint the same `app_session` + `app_refresh` cookies and return the same profile shape. Note: GitHub requires a redirect round-trip; support popup mode by completing auth on a TAuth-served callback page that communicates success to the opener (postMessage/BroadcastChannel) and closes. Tenant resolution for callback must not rely on `Origin` (GitHub callback requests may omit it); instead encode the tenant in the signed `state` payload (or use tenant-specific callback paths) and re-validate it against config. Document error codes/hints for common failures (missing/invalid state, PKCE mismatch, code exchange failure, missing verified email when email is private, user_not_allowed, misconfigured callback URL, issuer/signing-key mismatch on downstream services). Add integration tests covering the full GitHub flow with a mock GitHub server (no external network) and table-driven cases.
- [ ] [TA-434] (P1) Add `tauth doctor` to proactively diagnose auth misconfiguration.
  Provide a CLI command that reads `config.yaml` and prints a focused, actionable report (and stable error codes) for common “can’t authenticate” issues: origin not configured/unknown, ambiguous origins requiring tenant override, CORS allowlist missing the frontend origin, cookie scope collisions, cookie_domain/localhost pitfalls, missing/incorrect `enable_tenant_header_override` for shared-origin clients, and JWT validation parameters to sync with downstream services (issuer, session cookie name, tenant signing key fingerprints). Include a dedicated check/hint for issuer mismatch with common downstream validators (e.g. expecting `mprlab-auth` vs TAuth issuer `tauth`).
- [x] [TA-435] Avoid destructive schema resets during `tauth doctor --check-database`.
  Switched doctor to a non-migrating connectivity probe and added coverage ensuring legacy refresh tokens are preserved.
- [x] [TA-436] Align demo fixture `tauth.js` with shipped tenant-header behavior.
  Updated fixture assets to match the current auth client so demo/browser tests no longer send `X-TAuth-Tenant` when no tenant is configured.
- [x] [TA-437] Avoid dropping user store tables when schema migrations are missing.
  Non-destructive migrations now register missing user/nonce store schema versions without dropping tables, with regression coverage for legacy user profiles.
- [x] [TA-438] (P1) Add Google OAuth scope support (YouTube channel access) to TAuth.
  Request: TAuth currently verifies Google ID tokens only (GIS) and cannot obtain OAuth access/refresh tokens needed for YouTube Data API calls such as `channels.list(mine=true)`. Implement a Google OAuth2 Authorization Code (offline) flow, store per-tenant/per-user Google refresh tokens server-side, and expose a session-protected endpoint that returns authenticated YouTube channel metadata without putting Google tokens in browser storage. Feasibility analysis captured in `docs/youtube-scopes-feasibility.md`.
  Resolved (2026-02-10): Declined. TAuth remains authentication-only and will not implement third-party authorization/token custody (YouTube/Drive/etc).
- [x] [TA-439] (P0) Finalize and implement native mobile Google sign-in support for Expo iOS and Android clients.
  PromptDew Mobile needs `Mine` and future create/edit flows to authenticate through a system-browser OAuth flow without a WebView. The existing native installed-app endpoints (`GET /auth/google/native/config` and `POST /auth/google/native`) are enabled for desktop PromptDew and production returns a single `google_native_client_id`, but the mobile contract is not yet explicit for Expo AuthSession redirects, platform-specific Google client IDs, or credential persistence across `tauth-api.mprlab.com` and downstream API hosts. Define the mobile contract and implement the required TAuth changes: support custom-scheme and/or app-link redirects suitable for iOS and Android, model platform-specific accepted Google audiences or an explicit native client audience list in tenant config, keep nonce + PKCE validation semantics, and document whether mobile clients should reuse TAuth cookies or receive a mobile-safe session/refresh credential for API calls. Add black-box tests using mocked Google authorization/token validation paths for iOS and Android redirect/audience cases, missing/invalid nonce, wrong audience, missing Origin with tenant override, refresh/logout behavior, and downstream session validation compatibility. Update README, ARCHITECTURE, and usage docs with a concrete Expo client recipe.
  Added platform-specific `google_native_clients` with redirect URI metadata, expanded native config/login responses for Expo iOS/Android, kept cookie-based mobile sessions, and covered platform audiences, redirects, tenant override, refresh/logout, and downstream session validation. Verified with `make ci`.


## Planning (500–59999)
*do not implement yet*

- [x] [TA-500] (P1) Build full account management for first-party email/password identities.
  Resolved (2026-06-08): Implemented tenant-gated account management with stable account IDs, password signup/verification/reset/change, Google/password identity linking, unlink last-identity protection, account disablement, account-level refresh revocation, redacted preflight fields, `tauth.js` helpers, documentation, and black-box memory/persistent store coverage. Production challenge delivery and admin/audit surfaces are tracked separately in TA-501. Verified with `make ci`.
  Post-review fix (2026-06-09): Preserved self-service password credentials across config reconciliation, rechecked live account state for account-management routes, and covered stale disabled-account sessions plus persistent credential reconciliation with regression tests.
  Post-review fix (2026-06-09): Password reset completion now rechecks `allowed_users` before revoking refresh sessions or minting new cookies, returning `403 user_not_allowed` when an existing reset token outlives allowlist membership. Added black-box HTTP regression coverage and verified with focused authkit tests plus `make ci`.
  Post-review fix (2026-06-09): TAuth-owned account-session surfaces now resolve live account state after JWT validation, so disabled account sessions are rejected on `/me`, treated as anonymous by `/auth/session`, and cannot be refreshed into fresh JWTs. Added stale-session black-box coverage and verified with focused authkit tests plus `make ci`.

  Original technical plan:
  1. Define the canonical account model before changing routes. Introduce a stable tenant-scoped account identifier as the canonical session subject, plus lifecycle states such as `pending_verification`, `active`, and `disabled`. Move provider-specific identities into linked identity records so `google:<sub>` and `email:<normalized-email>` can both resolve to one account. Make the session `user_id` cutover explicit; if downstream services cannot accept a stable account ID yet, record that blocker before implementing account linking.
  2. Add storage through smart-constructed domain types and edge-only validation. Required persistent records: `accounts`, `account_identities`, password credentials keyed by account ID, email verification challenges, password reset challenges, and account audit events. Store only bcrypt password hashes and hashed one-time challenge tokens. Tokens must be single-use, tenant-scoped, TTL-bound, and never returned after creation except in the delivery payload.
  3. Add tenant configuration gates for account management rather than enabling public signup by default. Suggested fields: `account_management.enabled`, `password_signup.enabled`, verification/reset TTLs, allowed email domains or allowed email list behavior, rate-limit settings, and an email delivery adapter configuration. Validate all settings in the config loader and expose safe redacted state in preflight/doctor output.
  4. Implement public password account flows as black-box HTTP contracts: `POST /auth/password/signup` creates a pending account and sends verification, `POST /auth/password/verify-email` verifies the challenge and may mint the standard session, `POST /auth/password/reset/start` returns the same accepted response for known and unknown emails, `POST /auth/password/reset/complete` rotates the credential and revokes existing refresh sessions, and `POST /auth/password/change` requires an authenticated session plus current-password proof.
  5. Implement explicit account linking and unlinking. Linking must require an authenticated session and proof of control of the identity being linked: verified Google identity for Google, verified email/password challenge for password. Unlinking must reject the last remaining login method and must revoke sessions when the removed identity was used for the current credential.
  6. Add operational controls for account disable/reactivate, account-level refresh-token revocation, audit-event inspection, and safe credential rotation. Prefer CLI/admin-only surfaces first unless a product UI explicitly requires public admin endpoints.
  7. Extend `tauth.js` with helpers for signup, email verification, reset start/complete, password change, and identity linking. Keep raw passwords and challenge tokens out of client state and preserve the current cookie/JWT session model.
  8. Add documentation and inverted-pyramid tests. Go tests should exercise the real HTTP routes with memory and persistent stores, tenant isolation, challenge expiry/reuse, timing-masked reset starts, account disablement, linked identity login, unlink rejection, and session revocation. JS/browser tests should cover helper requests, user-visible auth state transitions, and error-code propagation. Final validation must pass `make ci`.

  Out of scope for this issue unless explicitly re-scoped: MFA, passkeys/WebAuthn, organization membership and role administration beyond the existing role claim, public profile editing, marketing pages, Google API authorization scopes, and third-party token custody.

- [ ] [TA-501] (P1) Add production challenge delivery and admin audit controls for account management.
  TA-500 introduced the core account lifecycle and hashed one-time challenges, but this repository still has no production delivery adapter or admin control plane. Add an edge-only challenge delivery boundary for email/webhook providers, tenant config for provider selection and templates, delivery failure observability, retry-safe audit records, and admin-only controls for account reactivation, account-level refresh revocation, challenge inspection without raw token exposure, and audit-event retrieval. Keep raw verification/reset tokens out of persistent storage and logs. Add black-box tests with fake delivery providers and persistent audit tables before enabling production signup/reset without `return_challenge_tokens`.

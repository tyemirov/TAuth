# ISSUES (Append-only Log)

Entries record newly discovered requests or changes, with their outcomes. No instructive content lives here. Read @NOTES.md for the process to follow when fixing issues.

Read @AGENTS.md, @README.md and ARCHITECTURE.md and follow the links to documentation. Read @issues.md/POLICY.md, @issues.md/PLANNING.md, @issues.md/NOTES.md, and @issues.md/ISSUES.md. Start working on open issues. Prioritize bugfixes and maintenance. Work autonomously and stack up PRs.

## Features (112–199)

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
- [ ] [TA-112] Here is how imagine the proper way of TAuth configuration
 
  1. Tauth supplies a backend client which reads the .env configuration local to the client. 
  2. The backend client mounts an endpoint to expose this configuration
  3. tauth.js reads this configuration on initialization
  4. This is the only available way of configuring tauth front end client

  The problem is that I cant think of a way making it secure

- [x] [TA-113] Add tauth doctor command. Move all the functionality from tools/mprlab-gateway/cmd to TAuth. I want the TAuth configuration of multiple project to be validated by TAUth doctor command, where TAuth will be the authorative source on the correctness of the configuration. after the execution, the mprlab-gateway shall have an open PR which will move all TAuth validation to Tauth but leave pinguin validation intact for now. The other PR will be the TAuth pr that will add TAuth doctor command.
  Added `tauth doctor` command that validates TAuth configurations with comprehensive checks for tenant requirements (TTLs, signing keys, origins), CORS alignment, and cookie scope isolation. The command supports multiple config files with cross-config validation (`--cross-validate`), database connectivity checks (`--check-database`), and JSON output for CI/CD (`--json`). TAuth is now the authoritative source for configuration validation.

## Improvements (341–640)

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


## BugFixes (352–399)

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
- [x] [TA-253] Unable to log into Google using examples/tauth-demo
JS Console
```
Feature Policy: Skipping unsupported feature name “identity-credentials-get”. client:271:37
Feature Policy: Skipping unsupported feature name “identity-credentials-get”. client:272:336
Feature Policy: Skipping unsupported feature name “identity-credentials-get”. mpr-ui.js:2103:22
Loading failed for the <script> with source “http://localhost:8082/tauth.js”. localhost:8000:1:1
Content-Security-Policy warnings 5
[GSI_LOGGER]: The given origin is not allowed for the given client ID. m=credential_button_library:75:89
Opening multiple popups was blocked due to lack of user activation. client:83:240
Storage access automatically granted for origin “https://accounts.google.com” on “http://localhost:8000”.
```
Backend log
```
Attaching to mpr-frontend-1, tauth-1
tauth-1  | {"level":"info","ts":1766959084.2432458,"caller":"server/main.go:182","msg":"using persistent refresh token store","driver":"sqlite"}
tauth-1  | {"level":"info","ts":1766959084.2435384,"caller":"server/main.go:291","msg":"listening","addr":":8082"}
mpr-frontend-1  | Serving HTTP on 0.0.0.0 port 8000 (http://localhost:8000/) ...
tauth-1         | {"level":"info","ts":1766959087.029027,"caller":"server/main.go:353","msg":"http","method":"GET","path":"/tauth.js","status":404,"ip":"192.168.65.1","elapsed":0.00114603}
tauth-1         | {"level":"info","ts":1766959087.0502923,"caller":"server/main.go:353","msg":"http","method":"POST","path":"/auth/nonce","status":403,"ip":"192.168.65.1","elapsed":0.000038473}
tauth-1         | {"level":"info","ts":1766959094.2427735,"caller":"server/main.go:353","msg":"http","method":"POST","path":"/auth/nonce","status":403,"ip":"192.168.65.1","elapsed":0.000038485}
tauth-1         | {"level":"info","ts":1766959094.253639,"caller":"server/main.go:353","msg":"http","method":"POST","path":"/auth/nonce","status":403,"ip":"192.168.65.1","elapsed":0.000017546}
```
Resolved: aligned demo tenant allowed_hosts with the frontend origin ports and synced the demo Google client ID from `/demo/config.js` so the header uses the backend-configured client ID.
Analyze the issue and deploy the fix

- [x] [TA-253] Demo header rendering fails when the mpr-ui bundle loads before the demo config.
  Added `/demo/config.json`, delayed the mpr-ui bundle load until config + tauth.js are ready, and added regression coverage for the demo bootstrap.
- [x] [TA-253] TAuth should not expose demo-specific endpoints.
  Removed demo config routes from the server and moved demo configuration into the example assets.
- [x] [TA-253] TAuth should not depend on mpr-ui.
  Removed mpr-ui assets/tests/docs wiring and switched demos to plain tauth.js + Google Identity Services wiring.
- [x] [TA-253] Demo bootstrap now waits for tauth.js readiness before wiring GIS; docs no longer describe a `/demo` endpoint.
  Added an auth client readiness handle for the tauth demo, refreshed config tests, and removed `/demo` endpoint references from usage/architecture docs.
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
- [x] [TA-344] Refresh could fail when duplicate refresh cookies exist; validate all matching cookies and log candidate count; add regression test.
  `/auth/refresh` now validates all matching cookies and logs candidate counts, with regression coverage and refreshed staticcheck tool.

## Maintenance (418–499)

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
- [x] [TA-418] Update the mpr-ui docs/demo/code in tools/mpr-ui/ to align with tauth.js
  Updated docs and demo HTML to load `/tauth.js` (no `crossorigin`), documented base-url requirements, and taught the mpr-ui auth header to prefer `tauth.js` helpers (nonce/exchange/logout) while falling back
  to direct fetches; `initAuthClient` now receives the page origin when `base-url` is omitted.
- [x] [TA-428] Rename tenant configuration  to  and align preflight output and flags.
  Updated tenant config schema, preflight report fields/flag, tests, examples, and documentation to use  and .
- [x] [TA-428] Correction: Rename tenant configuration `allowed_hosts` to `tenant_origins` and align preflight output and flags.
  Updated tenant config schema, preflight report fields/flag, tests, examples, and documentation to use `tenant_origins` and `tenant_origin_hashes`.

- [x] [TA-420] Clarify tenant origin validation failures with expected format and specific reasons.
  Enriched `tenant.invalid_origin` errors with a concise expectation string and reason details (missing scheme, missing host, invalid scheme, or path/query/fragment).
- [x] [TA-421] Restore tauth demo bootstrap assets and align demo origins with documented ports.
  Reintroduced `demo-config.js`/`tauth-config.js`, wired the demo HTML to load them, and realigned demo config/env/compose origins with `http://localhost:8080` to satisfy the JS test suite.
- [x] [TA-422] Decouple demo-related tests from the example demo assets.
  Added self-contained fixtures and pointed demo/browser tests at them so demo changes no longer affect test scaffolding.
- [x] [TA-423] Restore demo header auth attributes so the Google sign-in button renders.
  Replaced the stale `tauth-*` attributes with the mpr-ui `base-url`/`site-id`/auth path attributes in the demo header.
- [x] [TA-424] Surface demo auth/header errors and rename the demo entrypoint to app.js.
  Switched the demo script to `app.js` and added error handling for `mpr-ui:auth:error`/`mpr-ui:header:error` plus header attribute checks.
- [x] [TA-425] Serve the demo frontend over HTTPS using the computercat TLS certificates.
  Mounted the host certs into the ghttp container and updated the demo to reference the HTTPS frontend origin.

- [x] [TA-426] Pin demo mpr-ui assets to v3.3.0 and surface Google sign-in errors so google-site-id attributes are honored.
- [x] [TA-427] Track the demo env fixture so tests can validate CORS origins.
  Added the missing `.env.tauth.example` fixture under `tests/fixtures/tauth-demo` and unignored it for git so CI can read it.
- [x] [TA-418] Clear stale auth state when a peer refresh broadcast arrives without a profile.
  `initAuthClient` now treats peer refreshes that fail to load `/me` as unauthenticated, and regression coverage reproduces the broadcast-without-profile case.

- [x] [TA-418] Add a browser integration test to cover demo sign-out.
  Extended the demo test server with stateful auth responses and added a Puppeteer flow that signs in via tauth.js, clicks sign out, and asserts the header returns to unauthenticated state.

- [x] [TA-428] Rename tenant configuration  to  and align preflight output and flags.
  Updated tenant config schema, preflight report fields/flag, tests, examples, and documentation to use  and .
- [x] [TA-428] Correction: Rename tenant configuration `allowed_hosts` to `tenant_origins` and align preflight output and flags.
  Updated tenant config schema, preflight report fields/flag, tests, examples, and documentation to use `tenant_origins` and `tenant_origin_hashes`.
- [x] [TA-429] Default session validator issuer to `tauth` when omitted.
  Updated `pkg/sessionvalidator` to fall back to the shared default issuer and refreshed validator tests.
- [x] [TA-430] Add per-tenant allowed_users login allowlist.
  Added allowed_users config parsing + enforcement in auth login, updated docs/examples, and added tests.
- [x] [TA-431] Enforce empty allowed_users as deny-all.
  Treated explicit empty allowlists as deny-all, added tests, and documented the 403 user_not_allowed behavior.
- [ ] [TA-432] I am getting this error in production. Can you help diagnose and understadn what is happening:
JS Console
```
[Error] Preflight response is not successful. Status code: 405
[Error] Fetch API cannot load https://tauth.mprlab.com/auth/nonce due to access control checks.
[Error] Failed to load resource: Preflight response is not successful. Status code: 405 (nonce, line 0)
[Error] Failed to request auth nonce – TypeError: Load failed
TypeError: Load failed
	exchangeCredentialWithTAuth (app.js:398)
```
There are no new logs on the backend.
The production configuration can be found at tools/mprlab-gateway

The network console in Safari shows:
```
Summary
URL: https://tauth.mprlab.com/auth/nonce
Status: —
Source: —
Initiator: 
tauth.js:265

Request
Accept: */*
Cache-Control: no-cache
Content-Type: application/json
Origin: https://gravity.mprlab.com
Pragma: no-cache
Referer: https://gravity.mprlab.com/
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-site
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Safari/605.1.15
X-Requested-With: XMLHttpRequest
X-TAuth-Tenant: gravity

Response
No response headers
```
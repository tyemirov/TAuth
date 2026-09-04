# ISSUES

Entries record newly discovered requests or changes, with their outcomes. No instructive content lives here. Read @NOTES.md for the process to follow when fixing issues.

Read @AGENTS.md, @README.md and ARCHITECTURE.md and follow the links to documentation. Read @issues.md/POLICY.md, @issues.md/PLANNING.md, @issues.md/NOTES.md, and @issues.md/ISSUES.md. Start working on open issues. Prioritize bugfixes and maintenance. Work autonomously and stack up PRs.

## Features

- [x] [F002] (P0) Add native Sign in with Apple authentication.
  Goal:
  TAuth accepts Apple ID tokens from iOS clients and issues the same tenant session as other identity providers.
  This contract gives one Apple identity the same TAuth user ID in native and browser sessions.
  Requirements:
  - Add explicit native Apple client IDs to each enabled Apple provider.
  - Reject a native client ID that another tenant owns.
  - Add `GET /auth/apple/native/config` and `POST /auth/apple/native`.
  - Validate Apple signature, issuer, audience, expiration, verified email, and nonce claims.
  - Consume the TAuth nonce after successful token validation.
  - Enforce HTTPS, tenant resolution, allowed users, and account state.
  - Issue the canonical TAuth session cookies and profile payload.
  - Keep the existing Apple browser flow on its Services ID.
  - Keep Apple provider tokens inside TAuth.
  Deliverables:
  - Add config domain types, route handlers, API documentation, and tests.
  - Add a public native client procedure for Expo iOS.
  Validation:
  - Verify success with the configured iOS bundle ID.
  - Verify missing config, invalid input, wrong audience, wrong issuer, expired token, invalid nonce, and nonce replay.
  - Verify tenant isolation, allowed-user policy, account management, cookies, and profile output.
  - Pass focused tenant, HTTP, preflight, doctor, and gateway image tests.
  - Run aggregate CI through the release lifecycle.

  Resolution 2026-08-13:
  - Added tenant-specific native Apple client IDs and public native endpoints.
  - Added Apple claim, audience, nonce, replay, tenant, and account tests.
  - Added the native Expo iOS procedure and provider association guidance.
  - Focused tenant, HTTP, preflight, doctor, and static checks passed.
  - The local image passed the gateway candidate test.
  - ASD-STE100 checks found no errors in the changed text.
  - The Governor check reports existing managed content drift in `.mprlab/POLICY.md`.

- [x] [F001] (P1) Add an OAuth 2.1 authorization server for first-party resource clients.
  Goal:
  TAuth can authorize remote clients for first-party MPR resources after a user
  authenticates through an existing TAuth identity provider.
  TAuth issues resource-bound access tokens without exposing upstream provider
  tokens or changing resource-server ownership.
  Current contract:
  - TAuth issues first-party session and refresh cookies after authentication.
  - Native clients also receive cookies and do not receive OAuth bearer tokens.
  - TAuth has no authorization-server metadata, public JWKS, resource scopes,
    client metadata contract, consent grants, or OAuth token endpoint.
  - LLM Proxy F021 requires this capability for authenticated remote MCP access.
  Requirements:
  - Implement the current OAuth 2.1 authorization code grant for public clients.
  - Require PKCE with `S256` for every authorization request.
  - Reject a missing verifier, a plain challenge, and a mismatched verifier.
  - Serve RFC 8414 authorization-server metadata and a public JWKS endpoint.
  - Add authorization, token, and revocation endpoints under one canonical
    issuer.
  - Read the issuer and public endpoint URLs from validated operator
    configuration.
  - Validate each redirect URI against the client's exact registered value.
  - Permit bounded loopback-port variation only for a declared native client.
  - Issue a short-lived, one-time authorization code.
  - Bind each code to the client, user, redirect URI, resource, scope, and PKCE
    challenge.
  - Require an RFC 8707 resource indicator during authorization and token
    exchange.
  - Use the exact resource identifier as the access-token audience.
  - Require each TAuth tenant to declare its permitted resource identifiers and
    scopes.
  - Reject each undeclared resource, scope, client, and redirect URI.
  - Sign OAuth access tokens with asymmetric keys.
  - Publish only the public verification keys through JWKS.
  - Keep OAuth signing keys separate from the existing cookie-session signing
    keys.
  - Include `iss`, `sub`, `aud`, `exp`, `iat`, `client_id`, `scope`, and
    `tenant_id` claims in each access token.
  - Use the same stable account subject that the current TAuth session contains.
  - Make the access-token lifetime explicit and bounded in tenant
    configuration.
  - Issue an opaque rotating refresh token for an approved client grant.
  - Store only a refresh-token digest and the minimum grant metadata.
  - Bind each refresh-token family to one client, user, resource, and scope set.
  - Revoke the full family after reuse of a rotated refresh token.
  - Revoke refresh-token families and consent grants through the OAuth
    revocation endpoint.
  - Bound remaining access after revocation with the short access-token
    lifetime.
  - Keep browser authentication and consent on TAuth-owned browser routes.
  - Show the client identity, resource, and requested scopes before approval.
  - Require an explicit approval or denial for each new consent grant.
  - Support explicitly registered clients and MCP Client ID Metadata Documents.
  - Validate metadata documents with strict HTTPS, size, redirect, cache, and
    network-address rules.
  - Do not implement Dynamic Client Registration.
  - Publish a reusable Go validator for issuer, signature, audience, expiry,
    and scope checks at a protected resource.
  - Keep protected-resource metadata and domain authorization in each resource
    server.
  - Keep Google, Apple, GitHub, and other provider access tokens outside this
    contract.
  - Never place an OAuth access token or refresh token in browser storage, DOM,
    logs, redirect queries, or TAuth session cookies.
  - Return standard OAuth errors without account data, token data, code data,
    or signing-key data.
  - Keep the generic TAuth product free of a hard-coded LLM Proxy resource or
    scope.
  - Add the authorization-server capability to OpenAPI, documentation, and
    runtime configuration.
  Deliverables:
  - Add validated OAuth resource, scope, client, key, token, and consent domain
    types.
  - Add the authorization-code, grant, refresh-token, and consent stores.
  - Add metadata, JWKS, authorization, token, revocation, login, and consent
    HTTP routes.
  - Add the asymmetric access-token signer and the reusable Go validator.
  - Add OpenAPI, configuration, security, and client-integration documentation.
  - Add black-box HTTP and browser coverage through public entry points.
  Validation:
  - Run the real TAuth server with a fake protected resource and seeded users.
  - Complete authorization code plus PKCE through the TAuth browser flow.
  - Verify metadata, JWKS, consent approval, token claims, token refresh, and
    revocation.
  - Verify authorization-code replay, PKCE failure, redirect mismatch, and
    consent denial.
  - Verify unknown clients, resources, scopes, metadata documents, and signing
    keys.
  - Verify wrong-issuer, wrong-audience, wrong-scope, expired, and revoked access
    tokens at the protected resource.
  - Verify refresh rotation, family reuse detection, expiry, and cross-client
    isolation.
  - Verify user and TAuth-tenant isolation for codes, grants, tokens, and
    consent.
  - Verify explicitly registered clients and valid MCP metadata documents.
  - Verify that browser content, logs, errors, and redirects contain no token,
    code, signing key, or provider credential.
  - Run existing cookie-session login, refresh, logout, and downstream validator
    regression scenarios.
  - Run the required baseline and final
    `timeout -k 350s -s SIGKILL 350s make ci` pair.
  Progress (2026-08-08):
  - Added the validated issuer, tenant resource, scope, client, key, token,
    consent, and metadata-document contracts.
  - Added discovery, JWKS, authorization, login, consent, token, and revocation
    routes. Added memory and database stores with atomic consumption and
    refresh-family reuse revocation.
  - Added ES256 access-token signing and the public `pkg/oauthvalidator`
    protected-resource validator.
  - Added TAuth-owned Google and password browser authentication. Google-only
    OAuth tenants now use the existing Google identity provider without
    exposing provider credentials to clients or logs.
  - Aligned authorization-code exchange and client metadata with the current
    OAuth 2.1 and MCP contracts. Revocation treats each token type value as a
    hint, and token exchange reports an invalid resource as `invalid_target`.
  - The token endpoint now validates each stored grant against the current
    resource and client policy.
  - The validator now limits JWKS requests for unknown key identifiers. It gives
    `ErrInsufficientScope` for a valid access token with insufficient scope.
  - Added public HTTP and package tests for policy changes, concurrent JWKS
    requests, and insufficient scopes.
  - Added HTTP, browser, store, isolation, key-rotation, security, and
    regression coverage. Added OpenAPI, examples, operator documentation, and
    the generic `tauth.oauth` runtime capability.
  - Changed files: `.mprlab/TERMINOLOGY.md`,
    `.mprlab/deploy/resources.yml`, `ARCHITECTURE.md`, `CHANGELOG.md`,
    `README.md`, `docs/openapi.yaml`, `docs/usage.md`, and
    `examples/oauth/config.yaml.example`.
  - Changed files: `cmd/server/doctor_test.go`, `cmd/server/main.go`,
    `cmd/server/main_test.go`, `internal/appconfig/config.go`,
    `internal/appconfig/oauth.go`, `internal/appconfig/oauth_test.go`,
    `internal/authkit/database_helpers.go`, and
    `internal/authkit/oauth_browser_sessions.go`.
  - Changed files: all files in `internal/oauthserver`,
    `internal/tenants/config.go`, `internal/tenants/oauth.go`,
    `internal/tenants/oauth_test.go`, all files in `pkg/oauthvalidator`,
    `tests/oauth-authorization.browser.test.js`, and
    `tests/repository_neutrality_contract_test.go`.
  - Validation passed with the required baseline, post-implementation,
    standards-audit, and post-review
    `timeout -k 350s -s SIGKILL 350s make ci` runs.
    Focused Go, browser, lint, OpenAPI YAML, and changed-line ASD-STE100 checks
    also passed.
  Resolved 2026-08-09: the implementation passed all development contract and
  acceptance gates. mprlab-gateway F001 and LLM Proxy F021 track the dependent
  feature work.
  Deployment handoff 2026-08-15: the schema-v4 manifest now owns the typed
  `tauth_authorization_server`, production issuer paths, metadata limits, and
  one private-values signing-key reference from the validated gateway F001
  contract.

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

- [x] [I208] (P1) Own the deployment config renderer.
  Goal:
  TAuth converts selected resource contributions into its native config.

  Requirements:
  - Add one versioned render request contract.
  - Read the render request from standard input.
  - Resolve each declared TAuth output inside TAuth.
  - Validate the complete native config before output.
  - Keep private values out of errors and normal logs.

  Deliverables:
  - Add the provider render command.
  - Add public CLI integration coverage.
  - Document the provider-owned deployment boundary.

  Validation:
  - Render one complete browser demo config.
  - Reject an unknown request field.
  - Reject a missing private output.
  - `make ci` passed after the last source change.

- [x] [I207] (P0) Use the permanent versionless selected application manifest.
  Goal:
  Use one selected application manifest contract without a schema number.

  Requirements:
  - Remove `schema_version` from `.mprlab/deploy/resources.yml`.
  - Require only `owner`, `release`, and `resources` at the manifest root.
  - Reject each numbered selected application manifest form.
  - Preserve independent schema contracts.

  Validation:
  - Run `make ci` after the last repository change.
  - Plan release through gateway commit `753c727` without production contact.

  Resolution:
  - The manifest preserves the SemVer release scheme without a schema number.
  - The compiled repository contract rejects a `schema_version` field.
  - `make test-go`, all 44 JavaScript tests, and the final `make ci` passed.

- [x] [I204] Adopt the app-owned resource contract and sibling-gateway lifecycle.
  Goal:
  Make TAuth independently releasable, publishable, and deployable without an
  installed controller, local operator binding, or app-owned production
  lifecycle engine.

  Requirements:
  - Keep `.mprlab/deploy/resources.yml` as the only tracked deployment file.
  - Declare the TAuth image, retained data, gateway-managed tenant config,
    runtime capabilities, public routes, and public health in schema v3.
  - Expose only zero-argument `make release`, `make publish`, and `make deploy`
    wrappers to the exact sibling `../mprlab-gateway`.
  - Keep operator values, Ansible, Compose, Caddy, receipts, publication, and
    convergence in the gateway.

  Validation:
  - The repository lifecycle contract test passes.
  - `make ci` passes.
  - The sibling gateway accepts an exact sealed TAuth release plan without
    release, publication, production contact, or deployment mutation.

  Resolved 2026-07-30 and migrated forward 2026-08-03: replaced the obsolete
  workflow dispatcher with the complete schema-v3 TAuth runtime, removed the local operator binding and
  app-owned production lifecycle implementation, and reduced the public
  lifecycle to the exact sibling-gateway `release`, `publish`, and `deploy`
  wrappers. The repository contract tests and full `make ci` suite passed.
  Gateway commit `76e2e3f` accepted the committed TAuth source as a sealed,
  deterministic release plan without publication, production contact, or
  deployment.

  Post-review correction 2026-07-31: declared the exact bounded retirement of
  the legacy `mprlab-nginx-gateway/tauth-api` Compose service so the first
  schema-v3 convergence removes only the obsolete container while preserving
  the retained `mprlab-nginx-gateway_tauth-data` volume. Extended the
  repository lifecycle contract test to require that exact declaration.
  Validation passed with `make ci`.

  Schema-v3 migration 2026-08-03: moved placement to the `tauth-api` service,
  removed obsolete dependency, profile, and environment-file fields, and kept
  the exact runtime, retirement, retained data, capabilities, routes, and health
  graph. `make ci` passed, and sibling gateway commit `251e3c0` accepted the
  clean committed snapshot as an isolated deploy plan without release,
  publication, production contact, or deployment.

- [x] [I205] (P0) Move the release policy into the resource manifest.
  Goal:
  Use one tracked application file for release and deployment configuration.
  Requirements:
  - Set the manifest schema version to 4.
  - Add `release.scheme: semver` to the manifest.
  - Delete `.mprlab/release.yml`.
  - Keep the resource graph and lifecycle commands unchanged.
  Validation:
  - Pass the repository lifecycle contract test.
  - Pass the sibling gateway manifest plan.
  - Pass `make ci`.
  Resolution 2026-08-12:
  - Moved the SemVer policy into the schema-4 resource manifest.
  - Deleted the obsolete `.mprlab/release.yml` file.
  - Kept the resource graph and lifecycle commands unchanged.
  - The repository contract failed against schema 3 and passed against schema 4.
  - The final `make ci` run passed.
  - The sibling plan remains pending until the gateway checkout is clean.
  - Changed files: `.mprlab/deploy/resources.yml`, `.mprlab/ISSUES.md`,
    `CHANGELOG.md`, and `tests/repository_neutrality_contract_test.go`.

- [x] [I206] (P2) Normalize the managed policy content.
  Goal:
  The repository policy matches the current MPR Lab Governor contract.
  Requirements:
  - Update only the managed content in `.mprlab/POLICY.md`.
  - Preserve repository-owned policy content and all application changes.
  Validation:
  - Run the Governor check.
  - Run `git diff --check`.
  Resolution 2026-08-13:
  - The Governor normalizer updated only `.mprlab/POLICY.md`.
  - The final Governor check and `git diff --check` passed.
  - Changed files: `.mprlab/POLICY.md` and `.mprlab/ISSUES.md`.

- [x] [TA-447] Add the MediaOps static-frontend tenant to the TAuth-owned production registry.
  MediaOps serves its browser UI from `https://mediaops.mprlab.com` and proxies TAuth through `https://mediaops-api.mprlab.com`. Add a dedicated tenant with unique session/refresh cookies, the shared Google web client, `.mprlab.com` cookie scope, and the Pages origin in the production CORS allowlist.
  Resolved 2026-07-15: added the `mediaops` tenant, dedicated `app_session_mediaops`/`app_refresh_mediaops` cookies, Pages origin CORS, and production doctor/preflight coverage. Validation passed with `make ci`.

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
- [x] [TA-446] Make TAuth the canonical owner of shared production configuration and prepare the PoodleScanner tenant for the static frontend/API split.
  Resolved 2026-07-10: TAuth now owns the complete shared tenant registry and environment contract, the `ps` tenant resolves `https://poodlescanner.com` and scopes its cookies to `api.poodlescanner.com`, and the production CORS allowlist includes its declared Google exception. The app-owned deploy manifest moved to the current `.mprlab/deploy/resources.yml` discovery path, and the deploy no-op no longer requires a gateway checkout. Validation passed with the production config black-box test, deployment no-op test, the real TAuth doctor/preflight commands, and `make ci`.


## BugFixes (361–399)

- [x] [B066] (P1) Track each published TAuth page with its production site identity.
  Goal:
  Each published TAuth page sends visits to the current LoopAware site.
  The Pages artifact does not load the LoopAware pixel.
  Requirements:
  - Load the LoopAware pixel one time on each published HTML page.
  - Use the production TAuth site identity.
  Deliverables:
  - Update the landing page and the usage page.
  - Add artifact contract coverage for the current site identity.
  Validation:
  - Run the focused Pages artifact test.
  - Run `make ci`.
  Resolution 2026-08-28:
  - Added the current production site identity to both published pages.
  - Added contract coverage for one exact pixel on each page.
  - The focused test, assembled Pages image check, and `make ci` passed.

- [ ] [B055] (P1) Stop OAuth access for disabled accounts.
  Goal:
  A disabled account cannot get a new OAuth authorization code, access token, or refresh token.
  The OAuth browser session resolver accepts a pre-disable session, and account disablement does not revoke OAuth grants.
  Codex Security assigns medium severity, high confidence, and CWE-862.
  This issue tracks finding `csf_61243b622b8fa29760a82c4a`.
  The source fingerprint is `codex-security/v1:sha256:4a463921a15bc6bab15fd3ed109bc759b84bedd832f83ca93df7d45eb98184d5`.
  The root control is `internal/authkit/oauth_browser_sessions.go:71-82`.
  Requirements:
  - Require active account state before each OAuth authorization, code exchange, and refresh exchange.
  - Revoke all OAuth consent and refresh token families during account disablement.
  - Add one tenant and user revocation operation to each OAuth store.
  - Keep one current revocation contract without a fallback.
  Deliverables:
  - Active-account checks in the OAuth browser session and token paths.
  - User-wide OAuth revocation in the memory store and the database store.
  - Public contract tests for browser sessions and OAuth refresh tokens.
  Validation:
  - Disable an account with two browser sessions.
  - Verify that the second session cannot authorize a client.
  - Verify that an existing OAuth refresh token cannot rotate.
  - Run `make ci`.

- [ ] [B056] (P1) Make application refresh token rotation atomic.
  Goal:
  One application refresh token creates at most one active successor.
  The session and refresh routes issue a new token before they revoke the old token.
  Concurrent requests can create multiple active successors.
  Codex Security assigns medium severity, high confidence, and CWE-367.
  This issue tracks finding `csf_71f227920624a974608811e6`.
  The source fingerprint is `codex-security/v1:sha256:1f311fdff73d248a386a557c0b157c77c3a9641da7fdbbae62c0643c9ac9cbed`.
  The root control is `internal/authkit/routes.go:1314-1411`.
  Requirements:
  - Replace the separate validate, issue, and revoke operations with one atomic rotation operation.
  - Consume the old token and create the new token in one store transaction.
  - Revoke the token family after reuse of an old token.
  - Use the same rotation contract for `GET /auth/session` and `POST /auth/refresh`.
  Deliverables:
  - One narrow rotation operation in the refresh token store interface.
  - Atomic memory and database implementations.
  - Concurrent public route tests for both rotation paths.
  Validation:
  - Race one token through `POST /auth/refresh`.
  - Race one token through `GET /auth/session`.
  - Verify that exactly one request succeeds for each store.
  - Run `make ci`.

- [ ] [B057] (P1) Reject replayed native Google ID tokens.
  Goal:
  One native Google authorization can create one TAuth credential set.
  The native handler compares two client-supplied nonce values and does not consume server nonce state.
  Codex Security assigns medium severity, high confidence, and CWE-294.
  This issue tracks finding `csf_d6e4bf7dad4f4c56abec9f2f`.
  The source fingerprint is `codex-security/v1:sha256:c407b035b40e30b85d52bacd193e45b56717c4fe4887a9a6eadb97d1f3e33b2c`.
  The root control is `internal/authkit/routes.go:1165-1312`.
  Requirements:
  - Issue one tenant nonce before native Google authorization.
  - Require the Google ID token nonce claim to match the issued nonce.
  - Consume the nonce atomically before account or credential changes.
  - Reject unknown, expired, cross-tenant, and used nonces.
  - Remove the client-only nonce contract.
  Deliverables:
  - One server nonce contract for native Google login.
  - Memory and database nonce integration.
  - Public replay tests for the native Google route.
  Validation:
  - Complete one native Google login with an issued nonce.
  - Replay the same token and nonce.
  - Verify that the replay returns `invalid_nonce`.
  - Run `make ci`.

- [ ] [B058] (P1) Bind Apple OAuth state to the first browser.
  Goal:
  Only the browser that starts Apple login can complete that login.
  The signed Apple state has no secret that identifies the first browser.
  Codex Security assigns medium severity, high confidence, and CWE-352.
  This issue tracks finding `csf_50cabd4e6537d3cce9337670`.
  The source fingerprint is `codex-security/v1:sha256:04d87320a65d88f30a09c77353c4a57e656fc922bf9ebd7c76b8b5d08c2640db`.
  The root control is `internal/authkit/apple_oauth.go:110-129`.
  Requirements:
  - Set a short-lived browser correlation cookie at Apple login start.
  - Set `Secure`, `HttpOnly`, and the correct `SameSite` value on the cookie.
  - Bind the correlation value to the signed state.
  - Require and clear the cookie before the callback token exchange.
  - Reject a callback from a different browser.
  Deliverables:
  - One browser-bound Apple state contract.
  - Cookie and callback integration tests.
  Validation:
  - Start Apple login in browser A.
  - Submit its callback in browser B and verify rejection.
  - Submit its callback in browser A and verify success.
  - Verify that TAuth clears the correlation cookie.
  - Run `make ci`.

- [ ] [B059] (P1) Consume persistent one-time tokens atomically.
  Goal:
  One persistent nonce or account challenge can complete one credential operation.
  The database consumers read unused state before a separate mutation that does not verify one changed row.
  Codex Security assigns medium severity, high confidence, and CWE-362.
  This issue tracks finding `csf_ebd0e75221eb3a92fe3bbf67`.
  The source fingerprint is `codex-security/v1:sha256:d4c129002353347b3d2fa6decb780837539be11c170c110250ae53fa8ba990c9`.
  The root controls are `internal/authkit/database_nonce_store.go:92-134` and `internal/authkit/database_user_store.go:1042-1061`.
  Requirements:
  - Use one conditional delete or update for each token consumption.
  - Include tenant, token, token type, unused state, and expiry in the condition.
  - Require exactly one changed row.
  - Keep password changes and token consumption in one database transaction.
  - Reject each concurrent loser before credential issuance.
  Deliverables:
  - Atomic nonce consumption in the database nonce store.
  - Atomic account challenge consumption in the database user store.
  - Concurrent provider, reset, and verification tests.
  Validation:
  - Race one database nonce through provider login.
  - Race one password reset challenge.
  - Race one email verification challenge.
  - Verify that one request succeeds in each test.
  - Run `make ci`.

- [ ] [B060] (P1) Limit password guesses and reject weak passwords.
  Goal:
  Password authentication resists repeated online guesses and trivial user passwords.
  The login path has no attempt limit, and the password policy accepts one-byte passwords.
  Codex Security assigns medium severity, high confidence, CWE-307, and CWE-521.
  This issue tracks finding `csf_04c887ceb1ca32c26b210d36`.
  The source fingerprint is `codex-security/v1:sha256:edb749db4592eb8e71fc6009e8fd0350079544e5394bdb94c2b9d446864b4952`.
  The root control is `internal/authkit/password_credentials.go:223-230`.
  Requirements:
  - Limit attempts by tenant, account, request, and source before bcrypt work.
  - Add a progressive time delay after repeated failures.
  - Keep one uniform invalid credential response.
  - Define one current minimum password length.
  - Enforce the minimum on signup, reset, change, and link operations.
  Deliverables:
  - One shared password attempt limiter.
  - One password strength contract at each password creation boundary.
  - Public route tests for attempt limits and password length.
  Validation:
  - Verify that repeated failures activate the limit before bcrypt work.
  - Verify that each password creation path rejects a one-byte password.
  - Verify that valid passwords continue to work.
  - Run `make ci`.

- [ ] [B061] (P1) Bound public authentication request bodies.
  Goal:
  Each public authentication request has a finite body size and read time.
  The authentication parsers have no body size limit, and the HTTP server has no body read time limit.
  Codex Security assigns medium severity, high confidence, and CWE-400.
  This issue tracks finding `csf_573c8eeaeb08df5704dce67a`.
  The source fingerprint is `codex-security/v1:sha256:7fde80bd99ff48058f93b94711e3cec484bb7b1f5dc5783e07303c55bfe41eb4`.
  The root controls are `internal/authkit/routes.go:1605-1718` and `cmd/server/main.go:318-322`.
  Requirements:
  - Apply a small route-specific body limit before each parser.
  - Return HTTP 413 before the parser accepts an oversized body.
  - Configure finite read, write, and idle time limits on the HTTP server.
  - Keep the existing OAuth form body limit.
  Deliverables:
  - Shared authentication body limit controls.
  - Complete HTTP server time limits.
  - Public route tests for large and slow bodies.
  Validation:
  - Verify that oversized JSON returns HTTP 413.
  - Verify that slow bodies stop at the configured time limit.
  - Verify that normal provider and password bodies succeed.
  - Run `make ci`.

- [ ] [B062] (P1) Bound transient state storage.
  Goal:
  Public authorization and account flows cannot increase transient state without a limit.
  The memory and database stores have no complete capacity or expiry cleanup contract.
  Codex Security assigns medium severity, high confidence, and CWE-400.
  This issue tracks finding `csf_0fa410caf8792c8c0cfebc8f`.
  The source fingerprint is `codex-security/v1:sha256:0004926fcf44f441ed4afede3b70435e83c228e1725883d958b2826d662e8141`.
  The root controls include `internal/oauthserver/memory_store.go:63-99` and `internal/oauthserver/database_store.go:114-140`.
  Requirements:
  - Enforce atomic tenant and global capacity limits before state creation.
  - Limit public authorization, signup, and reset initiation requests.
  - Remove expired records during creation and access.
  - Add scheduled cleanup for persistent records.
  - Remove consumed challenges when replay evidence does not require retention.
  Deliverables:
  - Capacity limits for the memory and database stores.
  - One physical retention and cleanup contract.
  - Sustained request tests for public state creation.
  Validation:
  - Send requests beyond each configured state limit.
  - Verify that memory and database record counts stay bounded.
  - Advance time and verify physical removal of expired records.
  - Run `make ci`.

- [ ] [B063] (P2) Synchronize the in-memory user store.
  Goal:
  Concurrent HTTP requests cannot cause a fatal map access in the in-memory user store.
  The store reads and writes shared nested maps without a lock.
  Codex Security assigns low severity, high confidence, and CWE-362.
  This issue tracks finding `csf_3273d1b7b5bef5965ae694dc`.
  The source fingerprint is `codex-security/v1:sha256:9222bcfa4a1aa6594100016196cb4a8cc68e626962d59dcf88b8a48a3110dc25`.
  The root control is `internal/web/users.go:28-97`.
  Requirements:
  - Protect each map read and write with one `RWMutex`.
  - Copy mutable role slices on input and output.
  - Keep the current in-memory store contract for local and demo use.
  Deliverables:
  - Synchronized in-memory user storage.
  - Concurrent read and write coverage.
  Validation:
  - Run concurrent user updates and profile reads with the race detector.
  - Run parallel login requests with the in-memory store.
  - Run `make ci`.

- [ ] [B064] (P2) Hide account identity in password reset responses.
  Goal:
  Password reset initiation returns the same public response for known and unknown accounts.
  The current response returns a stable account ID only for a known account.
  Codex Security assigns low severity, high confidence, and CWE-203.
  This issue tracks finding `csf_b66d799ea14c915e50b0f677`.
  The source fingerprint is `codex-security/v1:sha256:da724e9d301ce1fe04387f3dac5fac36649844b49edf7b7e30ee8a5cd2853b04`.
  The root control is `internal/authkit/routes.go:1943-1960`.
  Requirements:
  - Return one constant public reset initiation response.
  - Remove account identity fields from this response.
  - Deliver the actual challenge only through the trusted recovery channel.
  - Keep status and timing behavior uniform.
  Deliverables:
  - One identity-neutral password reset response.
  - Public response comparison tests.
  Validation:
  - Compare responses for known and unknown accounts.
  - Verify that all public fields are equal.
  - Verify that the trusted recovery channel still receives the challenge.
  - Run `make ci`.

- [ ] [B065] (P2) Use trusted HTTPS signals for credential routes.
  Goal:
  Only TLS or a trusted proxy can satisfy the HTTPS-only tenant contract.
  The current guard trusts client headers and `Host`, and password reset completion has no guard.
  Codex Security assigns low severity, high confidence, CWE-345, and CWE-319.
  This issue tracks finding `csf_7c671ee325b061a85a04440b`.
  The source fingerprint is `codex-security/v1:sha256:cf5365bb25c8a8c6948052b40370eb8dfdaf60cda7e2309c1ab181cbf8faa6b2`.
  The root control is `internal/authkit/routes.go:2493-2509`.
  Requirements:
  - Define the trusted proxy peers in the server contract.
  - Accept forwarded scheme data only from these peers.
  - Parse each forwarded scheme value strictly.
  - Remove the `Host` localhost exception.
  - Apply one transport guard to every credential route.
  Deliverables:
  - One trusted proxy and transport classification contract.
  - Complete credential route coverage.
  Validation:
  - Send forged forwarding headers from an untrusted peer and verify rejection.
  - Send a forged localhost `Host` value and verify rejection.
  - Verify that password reset completion rejects direct plaintext.
  - Run `make ci`.

- [x] [B054] (P0) Remove ambiguous Docker ignore rules.
  Goal:
  Each Docker context excludes the private deployment input with one clear rule.
  Actual result:
  - The shared Docker ignore file contains two negated documentation rules.
  - Deployment cannot prove that the private input stays excluded.
  - The deployment stops before production convergence.
  Requirements:
  - Keep the documentation source in the shared context without negation.
  - Keep the exact private input exclusion.
  - Reject every Docker ignore negation in the repository contract test.
  Validation:
  - Build the application image and the Pages image.
  - Run `make ci`.
  Resolution 2026-08-15:
  - Removed the documentation exclusion and its two negated rules.
  - The documentation source remains available to the Pages image.
  - The repository contract test now rejects every negated rule.
  - Both image builds, `make test-go`, and `make ci` passed.
  - Changed files: `.dockerignore`, `tests/repository_neutrality_contract_test.go`,
    and `CHANGELOG.md`.

- [x] [B053] (P0) Remove the application-owned Pages marker.
  Goal:
  The gateway owns each GitHub Pages metadata file in the release artifact.
  Actual result:
  - The TAuth Pages image contains `.nojekyll`.
  - The current gateway rejects this reserved path during release assembly.
  - A new TAuth release cannot complete.
  Requirements:
  - Remove `.nojekyll` from the TAuth Pages image source.
  - Remove the obsolete tracked marker file.
  - Keep gateway marker generation as the only active contract.
  Validation:
  - Verify that the repository rejects an application-owned `.nojekyll`.
  - Build the Pages image.
  - Run `make ci`.
  Resolution 2026-08-15:
  - Removed `.nojekyll` from the Pages image and the TAuth repository.
  - The repository contract test now rejects the gateway-owned marker.
  - The Pages target image build passed.
  - `make test-go` and `make ci` passed.
  - Changed files: `docker/pages/Dockerfile`, `web/.nojekyll`,
    `tests/repository_neutrality_contract_test.go`, and `CHANGELOG.md`.

- [x] [B051] (P1) Allow OAuth provider-first deployment.
  Goal:
  TAuth accepts a configured authorization server before an active tenant enables OAuth.
  Actual result:
  - The doctor, preflight, and server reject a configured authorization server without an OAuth tenant.
  - An OAuth tenant deployment also fails until the authorization server is active.
  Requirements:
  - Accept the authorization server when no tenant enables OAuth.
  - Reject an OAuth tenant when the authorization server is absent.
  - Keep one current configuration contract without a fallback or legacy mode.
  Validation:
  - Verify the real doctor command with the authorization server and `tenants: []`.
  - Verify the real server starts and serves OAuth metadata in this state.
  - Verify the preflight report accepts this state.
  - Run `make ci`.
  Resolution 2026-08-15:
  - A configured authorization server now starts before a tenant enables OAuth.
  - An OAuth tenant still requires the configured authorization server.
  - The preflight report accepts the provider-first state.
  - The real doctor, server, health, and OAuth metadata checks passed.
  - `make ci` passed.
  - Changed files: `internal/appconfig/oauth_activation.go`, `internal/doctor/doctor.go`,
    `internal/preflight/report.go`, `internal/preflight/report_test.go`, and `cmd/server/main.go`.
  - Changed files: `tests/oauth-provider-bootstrap-runtime.sh` and `Makefile`.

- [x] [B052] (P1) Preserve Docker build context exclusions.
  Goal:
  Each Docker build context excludes private and unnecessary repository data.
  Actual result:
  - Each Dockerfile-specific ignore file replaces the complete root ignore contract.
  - The root and Pages contexts can include private operator data and unrelated repository files.
  Requirements:
  - Use the complete root ignore contract for both Dockerfiles.
  - Keep private deployment values, Git data, tests, tools, and CI files outside each context.
  Validation:
  - Verify no Dockerfile-specific ignore file replaces the root contract.
  - Verify the root ignore file contains each required exclusion.
  - Run `make ci`.
  Resolution 2026-08-15:
  - Removed both Dockerfile-specific ignore files.
  - The root contract now excludes the private deployment input and `node_modules`.
  - The repository test requires each private and unnecessary data exclusion.
  - The application image and Pages target builds passed with the root contract.
  - `make ci` passed.
  - Changed files: `.dockerignore`, `Dockerfile.dockerignore`,
    `docker/pages/Dockerfile.dockerignore`, and `tests/repository_neutrality_contract_test.go`.

- [x] [B048] (P1) Bound and cancel Apple provider requests.
  Goal:
  A canceled TAuth request cancels its Apple provider request.
  The production Apple HTTP client has a finite request time limit.
  Actual result:
  - The native Apple route passes a Gin context to the JWKS request.
  - The production Apple HTTP client uses `http.DefaultClient` without a request time limit.
  Requirements:
  - Pass the inbound HTTP request context to each Apple provider request.
  - Use one bounded production Apple HTTP client.
  - Keep test HTTP client injection for public contract tests.
  Validation:
  - Cancel a native Apple login request during its JWKS request.
  - Verify that the downstream request receives the cancellation.
  - Run `make ci`.
  Resolution 2026-08-13:
  - The Apple routes now pass the inbound HTTP request context to provider requests.
  - One shared production Apple HTTP client now has a five-second request time limit.
  - The public route test verifies JWKS request cancellation.
  - `make ci` passed.
  - Changed files: `internal/authkit/apple_oauth.go`, `internal/authkit/routes.go`, and `internal/authkit/routes_http_test.go`.

- [x] [B049] (P2) Preserve the first native Apple full name.
  Goal:
  TAuth stores the full name that Apple returns during the first native authorization.
  Actual result:
  - The native exchange body contains only the Apple ID token and nonce.
  - Apple does not put the native credential full name in the ID token.
  Requirements:
  - Add the native Apple full name to the exchange payload.
  - Validate and compose the name at the HTTP boundary.
  - Store the name in the canonical user or account profile.
  - Keep the stored name when a later Apple authorization omits it.
  Validation:
  - Verify the first native login stores and returns the supplied full name.
  - Verify a later login keeps the stored name.
  - Run `make ci`.
  Resolution 2026-08-13:
  - The native exchange now accepts all Apple credential name components in `full_name`.
  - TAuth now stores the composed display name in standard and account profiles.
  - Later native Apple login requests now keep the stored name.
  - Public HTTP tests cover both profile models and Apple tokens without a `name` claim.
  - `make ci` passed.
  - Changed files: `internal/authkit/routes.go`, `internal/authkit/routes_http_test.go`, and `internal/authkit/routes_integration_test.go`.
  - Changed files: `README.md`, `ARCHITECTURE.md`, `docs/usage.md`, and `CHANGELOG.md`.

- [x] [B050] (P2) Prevent caches from storing native Apple config.
  Goal:
  A shared cache cannot return one tenant's native Apple config to another tenant.
  Actual result:
  - The native Apple config response depends on tenant request headers.
  - The response does not define cache behavior or header variance.
  Requirements:
  - Set `Cache-Control: no-store` on each successful native Apple config response.
  Validation:
  - Verify the public config response includes `Cache-Control: no-store`.
  - Run `make ci`.
  Resolution 2026-08-13:
  - The successful native Apple config response now sets `Cache-Control: no-store`.
  - The public HTTP test now verifies the response header.
  - The API usage document now defines the cache behavior.
  - `make ci` passed.
  - Changed files: `internal/authkit/routes.go`, `internal/authkit/routes_http_test.go`, `docs/usage.md`, and `CHANGELOG.md`.

- [x] [B047] (P0) Start the OAuth browser test after the Go build.
  Goal:
  The OAuth browser test must start after the test server is ready.

  Requirements:
  - Build the test server before the 60-second browser test timeout starts.
  - Set up the repository Go version and the Go cache in the frontend workflow.
  - Keep the browser test timeout at 60 seconds.
  - Limit the complete frontend job to 10 minutes.
  - Terminate the test server and the browser after success, failure, or timeout.

  Validation:
  - Run the OAuth browser test with a prebuilt server.
  - Run the complete JavaScript test target.
  - Run `make ci`.

  Resolved 2026-08-12:
  - GitHub Actions now installs the Go version from `go.mod`, uses the Go cache, and builds the test server before `npm test` starts.
  - The frontend job stops after 10 minutes if a tool or child process does not exit.
  - The test uses `TAUTH_BROWSER_TEST_SERVER` for a prebuilt server. A local test build runs before the 60-second browser test starts.
  - The cleanup step starts the server cleanup and the browser cleanup at the same time. The cleanup step first sends `SIGTERM` to the server. It sends `SIGKILL` to a server or Chromium process that does not exit in the time limit.
  - The prebuilt-server test and all 44 JavaScript tests passed. `make ci` passed.

- [x] [B046] (P0) Allow the active TAuth aggregate configuration to start before applications declare tenants.
  After a forward-only production reset, TAuth is deployed before Pinguin and the
  other applications contribute their tenant resources. The canonical aggregate
  configuration therefore contains `tenants: []`. TAuth must accept that active
  zero-tenant state: `tauth doctor` must validate it, the server must expose
  `GET /health`, and all tenant-authenticated routes must remain inactive until
  a subsequent application deployment supplies a tenant. Do not add a legacy
  mode, fallback configuration, or migration path. Cover the contract through
  the real CLI and HTTP server entrypoints.
  Resolved 2026-08-05: removed the obsolete at-least-one-tenant rejection and
  made the validated empty aggregate an initialized registry/resolver state.
  The image-level acceptance run builds the real Docker image, validates
  `tenants: []` through `tauth doctor`, starts the server, observes `GET
  /health` as 200, and observes an auth route reject with 403. `make ci` passed.

- [x] [B045] (P0) Serve tauth.js from one canonical GitHub Pages origin.
  Goal:
  Make `https://tauth.mprlab.com/tauth.js` the only served TAuth browser-helper artifact while keeping `tauth-api.mprlab.com` API-only.

  Requirements:
  - Return 404 from backend `GET /tauth.js`; do not embed or serve a second copy.
  - Expose a dedicated backend health endpoint that does not depend on the browser-helper artifact.
  - Remove the `tauth.mprlab.com` Caddy route and declare its immutable GitHub Pages resource.
  - Keep `tauth-api.mprlab.com` as the only backend Caddy hostname.

  Validation:
  - Prove the 404 and health behavior through the real HTTP router.
  - Prove the schema-v3 manifest contains one Pages resource and no static-host Caddy route.
  - Pass `make ci` and selected-manifest sibling-gateway validation without production mutation.

  Resolved 2026-08-03:
  - The Go backend no longer embeds or registers `tauth.js`; its real router returns 404 for that path and exposes unauthenticated `GET /health` for runtime readiness.
  - The schema-v3 manifest now declares one container-built `github_pages/browser-helper` artifact for `tauth.mprlab.com`. It assembles the complete `docs/` site, the single tracked `web/tauth.js`, and an empty `.nojekyll`, removes the static-host Caddy route, and keeps only `tauth-api.mprlab.com` as a backend route.
  - The exported Pages filesystem contained all seven expected files, preserved the docs and helper byte-for-byte, and included the empty Jekyll-disable marker. Focused Go tests, all 43 JavaScript tests, and complete `make ci` passed. The clean-checkout gateway isolation rerun remains pending because the exact sibling gateway contains unrelated active B398 changes and the verifier accepts committed clean inputs only; production was not contacted.
  - Changed tracked files: `.dockerignore`, `.mprlab/deploy/resources.yml`, `Dockerfile`, `docker/pages/Dockerfile`, `web/.nojekyll`, `cmd/server/main.go`, `cmd/server/main_test.go`, `internal/web/cors.go`, `internal/web/health.go`, `internal/web/web_test.go`, `web/embed.go`, `tests/repository_neutrality_contract_test.go`, public documentation, `.mprlab/ISSUES.md`, and `CHANGELOG.md`.

- [x] [TA-450] Restore the vanilla app deployment discovery manifest.
  The released `make deploy` dispatcher reaches the configured operator target, but the gateway preflight fails on `tutosh` because TAuth no longer exposes the canonical `.mprlab/deploy/resources.yml` manifest for dispatch target `tauth`. Restore only the vendor-neutral repository identity and `make_workflow` lifecycle resource required for discovery. Do not restore any operator image, registry, hostname, route, health URL, credential, tenant, gateway path, or other concrete production binding. Add repository-contract coverage and verify the gateway loader and targeted preflight without contacting production.
  Resolved 2026-07-17: restored the canonical `.mprlab/deploy/resources.yml` discovery manifest with only the TAuth repository identity and generic release/publish/deploy `make_workflow`. Added a strict repository contract that rejects additional deployment resource fields or types and includes the manifest in vendor-neutrality scanning. Validation passed with the initially failing `make test-go`, the repaired `make test-go`, `make deploy-dry-run`, `make ci`, gateway `MPRLAB_APP_DISPATCH_TARGET=tauth make plan-app-resources`, and the targeted gateway `preflight-contract-local` on `tutosh` with `failed=0`. The gateway worktree remained clean and production was not contacted. Changed tracked files: `.mprlab/deploy/resources.yml`, `.mprlab/ISSUES.md`, `CHANGELOG.md`, and `tests/repository_neutrality_contract_test.go`.

- [x] [TA-449] Restore the vanilla repository deployment lifecycle with operator-specific local configuration.
  The TA-448 neutrality change removed `make deploy` together with tracked MPRLab production data, but those are separate ownership boundaries. Restore generic `make deploy` and `make deploy-dry-run` entrypoints backed by one ignored local `.env.deploy` configuration. Tracked deployment files must remain vendor-neutral and contain no operator directory, target, tenant, domain, route, credential, or gateway identity; the local configuration is the sole source of the concrete operator Make directory and target. Add black-box coverage for missing/invalid configuration, non-executing dry-run validation, and local fixture deployment dispatch.
  Resolved 2026-07-17: restored vendor-neutral `make deploy` and `make deploy-dry-run` entrypoints through `scripts/deploy.sh`, added a neutral `.env.deploy.example`, and kept the concrete operator directory and target only in this checkout's ignored `.env.deploy`. The dry run validates the configured Make target with non-executing question mode, while black-box fixture coverage proves missing and invalid configuration fail closed, dry run executes no recipe, and deploy dispatches only the configured target. Validation passed with `make test-go`, `make deploy-dry-run`, and `make ci`; production was not contacted. Changed tracked files: `.env.deploy.example`, `.gitignore`, `.mprlab/ISSUES.md`, `ARCHITECTURE.md`, `CHANGELOG.md`, `Makefile`, `README.md`, `docs/usage.md`, `scripts/deploy.sh`, and `tests/repository_neutrality_contract_test.go`.

- [x] [TA-448] Remove MPRLab deployment knowledge from the generic TAuth product.
  TAuth is a vendor-neutral authentication service and must not own MPRLab tenant identities, domains, credentials, operator environment files, gateway routes, or deployment orchestration. Delete the MPRLab production registry and app deployment entrypoint, retain only generic configuration behavior and neutral examples, and make repository neutrality an executable contract. MPRLab applications will declare their own tenant requirements and `mprlab-gateway` will assemble and deploy the shared runtime configuration.
  Resolved 2026-07-16: removed the operator tenant registry, environment sample, deployment manifest, gateway-coupled deploy entrypoint, MPR UI demo dependency, and operator-specific release metadata. Added a black-box repository-neutrality contract, replaced product surfaces with neutral examples and self-contained demo UI, and kept release/publish as generic product operations. Validation passed with `make ci`.

- [x] [TA-445] (P0) Generate opaque persisted account IDs for account-management sessions.
  Account management currently creates deterministic account subjects from tenant/provider/email identity material even though the public contract is an opaque account user id. Replace deterministic account ID construction with persisted 128-bit base64url values for password signup, seeded password account enablement, and provider-created accounts. Remove the deterministic helpers and reject non-opaque account subjects at runtime; do not keep backward-compatible account-id fallbacks. Account-management session `user_id` must be the persisted bare opaque account ID across login, refresh, `/auth/session`, and `/me`.
  Resolved 2026-06-23: account management now generates persisted bare opaque 128-bit base64url account IDs, reuses stored IDs through password/provider identity records, migrates existing database account references once, revokes refresh tokens tied to old account subjects, and rejects malformed account session subjects at account-route boundaries. Updated README, ARCHITECTURE, docs/usage, and CHANGELOG. Tests: focused `go test ./internal/authkit`; `make ci`.

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

- [x] [B044] Parse the ignored local deployment binding as data.
  Goal:
  Keep TAuth vendor-neutral while preventing its operator-owned `.env.deploy` file from executing shell syntax.

  Requirements:
  - Accept exactly one absolute `DEPLOY_DIRECTORY` and one valid `DEPLOY_MAKE_TARGET` assignment.
  - Reject executable syntax, unknown or duplicate keys, incomplete documents, symlinks, and permissions other than `0600`.
  - Keep all concrete operator values ignored and outside tracked repository files.

  Deliverables:
  - A data-only vendor-neutral deployment dispatcher.
  - Black-box coverage through the real Make lifecycle entrypoints.
  - Operator documentation for installing the ignored file with the required permissions.

  Validation:
  - `make deploy-dry-run` validates the real ignored local binding without executing its target.
  - `make ci` passes without contacting or changing production.

  Resolved 2026-07-18: replaced shell sourcing with an exact data-only parser, enforced a regular non-symlink mode-`0600` binding, rejected unknown, duplicate, incomplete, and executable input, and documented permission-safe installation. Black-box tests cover every rejection boundary and fixture-only dispatch. Validation passed with `make deploy-dry-run`, `make test-go`, and `make ci`; production was not contacted. Changed tracked files: `.env.deploy.example`, `.mprlab/ISSUES.md`, `ARCHITECTURE.md`, `CHANGELOG.md`, `README.md`, `docs/usage.md`, `scripts/deploy.sh`, and `tests/repository_neutrality_contract_test.go`.


## Maintenance

### Recurring

- [ ] [M400R] (P2) Backlog hygiene and archive
  Goal:
  Keep the issue tracker reliable, readable, and focused on active work while preserving resolved history in the appropriate archive.

  Requirements:
  - Cadence: run weekly during active development and before each release cut.
  - Validate section names, identifier prefixes, recurrence suffixes, priority markers, dependencies, and duplicate IDs against the current `issues-md-format.md`.
  - Reconcile stale statuses, duplicate issues, broken references, obsolete instructions, and entries filed under the wrong section.
  - Move completed non-recurring history to the repository issue archive or durable documentation when the active tracker becomes noisy.
  - Keep active, blocked, planning, and recurring entries visible in `ISSUES.md`.

  Deliverables:
  - Normalized `ISSUES.md` structure and statuses.
  - Updated issue archive or docs when completed entries are removed from the active tracker.
  - A short `Last run:` note summarizing the cleanup and any follow-up issues filed.

  Validation:
  - Re-read `ISSUES.md` after edits and confirm every issue is under the right section with a unique section-aware ID.
  - Confirm recurring entries remain open and keep the `R` suffix.
  - Confirm no active, blocked, recurring, or planning work was archived.

- [ ] [M401R] (P2) Polish open issues
  Goal:
  Keep unresolved work executable by making each open issue concrete, ordered, and testable.

  Requirements:
  - Cadence: run weekly during active development and before handing a repo to automated execution.
  - Review every unresolved non-recurring issue for missing context, dependencies, repro steps, acceptance criteria, and validation expectations.
  - Make priorities concrete and ensure each open issue has actionable deliverables.
  - Merge duplicate open issues or add explicit dependency links when separate entries must remain.
  - Do not close or implement issues as part of this polish pass unless that work is separately requested.

  Deliverables:
  - Open issues with enough detail for a person or agent to execute without rediscovery.
  - New or updated dependency markers where ordering matters.
  - A short `Last run:` note listing the number of issues polished and any blockers found.

  Validation:
  - Sample the open entries after the pass and confirm each has clear next actions and validation expectations.
  - Confirm no recurring runbook was marked complete.
  - Confirm duplicates were merged or explicitly cross-referenced.

- [ ] [M402R] (P2) Architecture and policy review
  Goal:
  Catch architecture, policy, and workflow drift before it becomes hidden maintenance debt.

  Requirements:
  - Cadence: run monthly, before large refactors, and after major framework or runtime changes.
  - Review the codebase, docs, and workflow against `AGENTS.md`, `POLICY.md`, stack guides, and the current architecture notes.
  - Look for drift from forward-only contracts, edge-validation boundaries, smart-constructor usage, testing policy, and module ownership.
  - Record findings as new Maintenance issues with concrete scope, priority, and validation.
  - Close the pass with a no-action note only when the review finds no actionable drift.

  Deliverables:
  - New Maintenance issues for each actionable architecture or policy drift finding.
  - Updated notes on areas reviewed and areas intentionally left unchanged.
  - A short `Last run:` note with the review scope and outcome.

  Validation:
  - Confirm every finding is represented as an issue with owner-readable context and validation criteria.
  - Confirm no implementation changes were mixed into the review runbook unless separately requested.
  - Confirm all recurring runbooks remain open.

- [ ] [M403R] (P1) Dependency and security audit
  Goal:
  Keep third-party dependencies, runtime versions, and security-sensitive configuration within the current supported contract.

  Requirements:
  - Cadence: run weekly for active apps and before each release cut.
  - Inspect package managers, lockfiles, language toolchains, container bases, and generated clients for known vulnerabilities or stale direct dependencies.
  - Review auth, secret, CORS, CSP, SQL, network, and permission-sensitive configuration for drift from the current contract.
  - Prefer current supported dependencies; do not add compatibility shims for obsolete dependency behavior.
  - File separate Maintenance or BugFix issues for each actionable vulnerability, unsupported runtime, or security-contract gap.

  Deliverables:
  - Documented audit commands or data sources used for the pass.
  - Updated issues for each actionable dependency or security finding.
  - A short `Last run:` note with clean result or follow-up issue IDs.

  Validation:
  - Rerun the repository-native audit, lint, or dependency checks used for the pass.
  - Confirm every finding is either filed, fixed under a separate issue, or explicitly marked not applicable with evidence.
  - Confirm no secrets or private payloads were written into the tracker.

  Last run 2026-08-21: A Codex Security source scan created issues B055 through B065.

- [ ] [M404R] (P1) CI, release, and artifact health
  Goal:
  Keep the repository's validation, release, publication, and generated artifact surfaces trustworthy.

  Requirements:
  - Cadence: run before every release, publish, or deploy, and weekly for critical services.
  - Verify repository-native CI, lint, format, coverage, release, publish, Docker image, Pages, and artifact workflows still match the documented contract.
  - Check generated artifacts, release tags, published images, and Pages outputs for source-to-public drift.
  - File concrete follow-up issues for failing gates, stale artifacts, missing release prerequisites, or undocumented workflow changes.
  - Do not perform production deployment from this runbook unless the operator explicitly requests that deployment.

  Deliverables:
  - Recorded gate status and artifact surfaces inspected.
  - Follow-up issues for each reproducible CI, release, publish, or artifact drift problem.
  - A short `Last run:` note with commands run and any skipped surfaces.

  Validation:
  - Use repository-native `make` targets or documented release helpers for checks.
  - Confirm release and deployment ownership boundaries remain separate.
  - Confirm public or published artifacts match the intended source revision when that surface is inspected.

- [ ] [M405R] (P1) Code contract and static hygiene
  Goal:
  Keep source contracts explicit, current, and statically guarded against policy drift.

  Requirements:
  - Cadence: run monthly and before large refactors.
  - Scan for dead code, unused exports, duplicated literals, silent fallbacks, legacy aliases, compatibility reads, and zero-but-invalid domain states.
  - Check static analysis, coverage, schema, and contract guards that are supposed to prevent drift.
  - File focused Maintenance issues for each concrete violation instead of broad cleanup placeholders.
  - Keep the current canonical contract only; do not preserve obsolete behavior unless a product requirement explicitly says so.

  Deliverables:
  - Issue entries for each actionable static hygiene or contract violation.
  - Notes on static tools, searches, and contract guards used during the pass.
  - A short `Last run:` note with clean result or follow-up issue IDs.

  Validation:
  - Rerun the relevant static checks, contract tests, or repository searches used to identify drift.
  - Confirm every finding has a narrow follow-up issue and does not duplicate existing backlog work.
  - Confirm no implementation changes were mixed into the audit unless separately requested.

- [ ] [M406R] (P1) Production drift and health
  Goal:
  Detect when production, public, or scheduled runtime state has drifted from the intended repository contract.

  Requirements:
  - Cadence: run weekly for deployed services and after each publish or deploy.
  - Compare current source, runtime configuration, published images, public routes, scheduled jobs, and health checks for drift.
  - Inspect real operator-facing surfaces rather than assuming merged source is deployed.
  - File follow-up issues for stale images, stale Pages output, missing routes, failed monitors, invalid production config, or undocumented runtime differences.
  - Stop before production deploy or destructive operator actions unless the operator explicitly requests them.

  Deliverables:
  - Recorded source revision, public artifact, route, image, or health surfaces inspected.
  - Follow-up issues for each source-to-runtime drift finding.
  - A short `Last run:` note with evidence links or commands used.

  Validation:
  - Verify inspected production or public surfaces directly where access is available.
  - Confirm any deploy-required finding is filed with the exact publish/deploy boundary and owner.
  - Confirm no production state was changed by the audit unless explicitly requested.

- [ ] [M407R] (P2) Documentation and runbook hygiene
  Goal:
  Keep durable documentation and runbooks aligned with the current behavior users and operators actually rely on.

  Requirements:
  - Cadence: run before release cuts and after merge bursts that change user-facing or operator-facing behavior.
  - Review README, ARCHITECTURE, PRD, CHANGELOG, docs, runbooks, setup guides, and local workflow notes for stale behavior or missing new contracts.
  - Update docs when closed issues changed durable behavior, public APIs, operator workflows, release semantics, or deployment expectations.
  - Remove or rewrite stale instructions instead of preserving obsolete alternatives.
  - File separate issues for documentation gaps that require product or implementation decisions.

  Deliverables:
  - Updated documentation or filed follow-up issues for each gap.
  - A short `Last run:` note listing docs inspected and changes made.
  - Cross-references from archived issue history to durable docs when useful.

  Validation:
  - Check links, command names, paths, and public contract descriptions touched by the pass.
  - Confirm docs describe the current canonical path only.
  - Confirm issue archive and active tracker references remain consistent.

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

- [x] [B043] Release lifecycle depended on sibling agentSkills/gitrelease; vendor the canonical container bundle, route release wrappers and Make targets locally, and validate the observable lifecycle contract.
  Resolved: aligned the deployment no-op contract test with the canonical deploy CLI after removal of the obsolete `--skip-ci` option. Validation passed with `timeout -k 350s -s SIGKILL 350s make ci`.

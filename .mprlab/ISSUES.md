# ISSUES

Completed implementation entries are in the [archive](ISSUES-ARCHIVE.md).
Planning and recurring entries stay in this tracker with unresolved work.

## BugFixes

- [x] [B130] (P2) Run the local frontend on the native Docker platform.
  Goal:
  Use the native container architecture for the local ghttp frontend.
  Evidence:
  The local lifecycle started an AMD64 frontend on an ARM64 Docker daemon and showed a platform mismatch warning.
  The published ghttp image includes both architectures, but the local Compose service did not select a platform.
  Requirements:
  - Select the frontend platform from the Docker daemon.
  - Keep the local stack usable on ARM64 and AMD64 hosts.
  Validation:
  - Verify the actual frontend architecture through the local lifecycle command.
  - Run `make test-local-lifecycle` and `make ci`.
  Deliverables:
  The local launcher supplies the Docker daemon platform to the frontend Compose service.
  The lifecycle test compares the selected container manifest with the Docker daemon platform.
  A controlled AMD64 container reproduced the mismatch and verified rejection by the corrected architecture assertion.
  The focused lifecycle test and final CI verified `linux/arm64` without a platform warning.
  Final `make ci` passed all 13 declared targets. Independent review found no further defects.
  Changed files: `local/compose.yml`, `local/stack.sh`, `tests/local-lifecycle.sh`.

- [x] [B129] (P1) Include the application-subject plan in release inputs.
  Goal:
  Supply each necessary migration plan from source control to the release.
  Evidence:
  Deployment of v2.2.13 stopped because its `inputs` directory did not contain `20261006-application-subjects.json`.
  The local plan existed, but the `*.json` ignore rule did not include it in source control.
  Requirements:
  - Include the public application-subject plan in source control.
  - Validate the necessary plans before database changes.
  Validation:
  - Verify the real rollout CLI with repository inputs selected through Git.
  - Verify that the test rejects the release before the ignore exception is added.
  - Run `make test-deployment-migration` and `make ci`.
  Deliverables:
  The exact ignore exception includes the public migration plan in source control.
  The rollout CLI test consumes repository plans selected through a separate Git index.
  The test reproduced the missing plan error before the fix and passed after the fix.
  Final `make ci` passed all 13 declared targets. Independent review found no further defects.
  Release, publication, and production deployment remain operator actions.
  Changed files: `.gitignore`, `deployment/migrations/20261006-application-subjects.json`, `deployment/rollout/main_test.go`.

- [x] [B126] (P2) Keep account IDs when configured password users are added again.
  Goal:
  Keep the public user ID when an operator removes a configured password user and adds that user again.
  Requirements:
  - Use the existing password provider identity before creation of another account.
  - Reject conflicting identity relations and writes to accounts that are not active.
  Validation:
  - Verify removal and addition through password login with database and memory stores.
  - Verify the same public user ID and rejection of accounts that are not active.
  - Run `make ci` after all three review fixes.
  Evidence:
  The next credential write produced `account.exists` after removal and prevented server startup.
  Deliverables:
  The credential writer uses the retained password identity and keeps both account IDs.
  Public HTTP tests verify database and memory stores, removed credentials, and accounts that are not active.
  Final `make ci` passed all 13 declared targets. Independent review found no further defects.
  Changed files: `internal/authkit/database_user_store.go`, `internal/authkit/password_credentials.go`, `internal/authkit/password_seed_http_test.go`, `docs/application-subjects.md`.

- [x] [B127] (P2) Write configured password profile changes to the account.
  Goal:
  Keep the current configured display name and avatar in the account after a password profile change.
  Requirements:
  - Write the configured profile to the canonical account during the password credential write.
  - Keep explicit display overrides, roles, account state, and public user IDs.
  Validation:
  - Verify changed profile fields through password login and session restoration.
  - Verify explicit display overrides with database and memory stores.
  - Run `make ci` after all three review fixes.
  Evidence:
  Password login supplied the previous display name and avatar after a config update.
  Deliverables:
  The credential writer writes configured profile fields to the account and keeps explicit display overrides.
  Public HTTP tests verify login and current session profiles with database and memory stores.
  Final `make ci` passed all 13 declared targets. Independent review found no further defects.
  Changed files: `internal/authkit/database_user_store.go`, `internal/authkit/password_credentials.go`, `internal/authkit/password_seed_http_test.go`, `docs/application-subjects.md`.

- [x] [B128] (P2) Use an explicit account store for provider routes.
  Goal:
  Complete provider login with the same account store and user store.
  Requirements:
  - Require an explicit account store when routes have no password store.
  - Keep database account records and public user IDs after restart.
  Validation:
  - Verify provider login, refresh, and session restoration through database-backed routes.
  - Run `make ci` after all three review fixes.
  Evidence:
  `MountAuthRoutes` created a separate memory account store and database Google login returned HTTP 500.
  Deliverables:
  `MountAuthRoutes` uses an explicit account store. Repository callers use the current signature.
  Account erasure uses the same account store without a password dependency.
  Public HTTP tests verify login, refresh, database restart, and erasure.
  Final `make ci` passed all 13 declared targets. Independent review found no further defects.
  Changed files: `internal/authkit/routes.go`, `internal/authkit/account_erasure.go`, `internal/authkit/mounted_database_http_test.go`, `internal/authkit/routes_http_test.go`, `internal/authkit/routes_integration_test.go`, `internal/authkit/body_security_http_test.go`, `internal/authkit/github_http_test.go`, `ARCHITECTURE.md`, `docs/application-subjects.md`.

- [x] [B125] (P1) Preserve application user IDs across account-management changes.
  Goal:
  Keep each application's user ID unchanged when account management is enabled or disabled.
  Evidence:
  Before B125, provider login returned `provider:<subject>` with account management disabled.
  The same login returned a separate opaque account ID with account management enabled.
  Kamu derives its RevenueCat customer key from this application user ID.
  The initial source inspection found no public transition that preserved these customer keys.
  Requirements:
  - Store one immutable public user ID for each tenant account.
  - Keep the internal account ID opaque and separate from the public user ID.
  - Allocate persistent identity independently of account-management capabilities.
  - Preserve existing public user IDs through an automatic timestamped deployment migration.
  - Resolve each session subject through one exact tenant-scoped stored relation.
  - Reject conflicting identity mappings before migration commits.
  - Keep email addresses separate from identity association.
  - Preserve account disablement, erasure, provider associations, roles, and refresh ownership.
  - Keep account-management operations subject to their configured capability policy.
  Validation:
  - Reproduce the identity change through public HTTP and a persistent database.
  - Verify unchanged public IDs across feature changes, restart, refresh, and provider entry paths.
  - Verify strict internal account IDs, tenant isolation, conflicting mappings, and migration repeat.
  - Verify that disabled or erasing accounts cannot regain access through a feature change.
  - Run focused public tests and final `make ci`.
  - Obtain independent review of the implementation, migration, and remaining limits.
  Deliverables:
  The canonical public subject remains fixed across account-management changes.
  The automatic `20261006-application-subjects` migration preserves existing subjects and rejects conflicting ownership before publication.
  Runtime conversion and obsolete provider-prefix allocation paths are removed.
  Final public authentication, OAuth, and migration regressions pass.
  Final `make ci` passes all 13 targets. The separate deployment migration target also passes.
  Independent final review accepts the source repair and local validation without blocking findings.
  The final command removes its owned temporary caches and disposable Docker builder.
  Evidence is retained in Kamu under `.local/i013-evidence/tauth-continuity-fix/`.
  The source contract and deployment limits are in `docs/application-subjects.md`.
  Scope:
  Preserve the stable application key. Grant no new billing entitlement and introduce no application fallback.
  Production activation remains an operator action.

- [ ] [B118] (P2) Use the request context for account database operations.
  Goal: Account database operations use a context that remains valid after the HTTP handler returns.
  Evidence: The race detector found Gin context reuse while `database/sql.Rows.awaitDone` read that context.
  The password login handler passes its Gin context to `EnsurePasswordAccount` in `internal/authkit/routes.go`.
  Requirements: Pass the HTTP request context to database operations. Keep request cancellation.
  Validation: Run the erasure HTTP tests with the race detector and run `make ci`.

- [ ] [B078] (P1) Preserve the OAuth request when consent completion fails.
  Goal:
  A failed consent operation must not permanently prevent completion of an unexpired login transaction.
  Observed behavior (2026-09-09, UTC):
  - The user started `codex mcp login llm-proxy` in normal Chrome after local MCP logout.
  - Google login completed. `POST /oauth/login` returned 200 at 19:36:32.619.
  - `GET /oauth/consent` returned 200 at 19:36:32.637.
  - The first consent POST returned 500 at 19:36:39.080 after 2.070 seconds.
  - Two further consent POSTs returned 400 at 19:36:39.147 and 19:36:39.160.
  - Chrome displayed `{"error":"invalid_request"}`. Codex received no callback and eventually reported a timeout.
  - The request was less than one minute old. The configured request lifetime was five minutes.
  - A later authorization reused the existing session and consent, and the MCP token exchange succeeded.
  - That later result did not verify a fresh login or selection of another account.
  Cause and evidence limits:
  `handleConsent` removes the request before it saves consent and issues an authorization code.
  These database operations have separate transactions. A later failure cannot restore the request.
  The same ordering affects authorization with existing consent.
  The live access logs contain HTTP status and duration, but no underlying error for the first 500.
  The reason for the repeated submissions is not established.
  Requirements:
  - Complete request removal, new consent storage, and code storage in one atomic operation.
  - If completion fails, preserve the unexpired request and remove partial writes.
  - Validate required provider identities before the storage operation.
  - Preserve request binding, expiry, PKCE, and successful-request replay rejection.
  - Apply the same storage contract to authorization with existing consent.
  Validation:
  - Inject a code storage failure through the real HTTP consent endpoint and SQLite adapter.
  - Verify the initial 500, the unchanged consent page, and successful completion after the failure ends.
  - Verify that the failed attempt leaves no consent or code.
  - Verify that a completed request cannot issue a second code.
  - Run the focused OAuth tests and `make ci`.
  - After deployment, verify fresh login in normal Chrome and receipt of the Codex callback.
  Scope:
  Account selection remains a separate acceptance requirement. Existing-session success does not establish that behavior.
  Implementation (2026-09-09):
  `CompleteAuthorizationRequest` groups request removal, new consent, and code storage in one operation.
  SQLite uses one database transaction. The memory adapter uses one lock.
  The new HTTP tests first reproduced a 400 response after an injected storage failure.
  The corrected implementation passed the focused consent, login, and GitHub OAuth targets.
  Local `make ci` passed formatting, lint, Go tests, JavaScript tests, browser tests, and renderer tests.
  The container check stopped at `test-empty-tenant-bootstrap-runtime` because Docker reported `meta.db: read-only file system`.
  Full CI and deployed browser acceptance remain unverified.

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
  Progress 2026-09-29:
  Memory and database stores enforce shared account, source, and global password request budgets before bcrypt work.
  JSON and OAuth login share the budget. Tests verify HTTP 429 across both interfaces.
  Database migration preserves existing users and adds persistent budgets.
  Remaining: Define the minimum password length and progressive failure delay required by B060.
  The selected audit finding concerns unlimited guesses. Its fixed one-minute request budget is implemented.
  Validation: Focused checks and final `make ci` passed for the completed audit scope.

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
  Progress 2026-09-29:
  Pending OAuth requests now have atomic tenant and global capacity limits in memory and database stores.
  Creation removes expired requests. Tests verify capacity rejection, expiry cleanup, and preservation of requests during migration.
  B109 adds reset cooldowns and bounded reset state.
  Remaining: Complete signup limits, access-time cleanup, and scheduled cleanup for the other transient records required by B062.
  Validation: Focused checks and final `make ci` passed for the completed audit scope.

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
  Progress 2026-09-29:
  Reset initiation now returns exactly `{"status":"accepted"}` for known, unknown, throttled, and failed-delivery requests.
  Public responses contain no account identity, expiry, or recovery secret.
  HTTP tests compare known, unknown, and throttled responses. Email-based recovery still works.
  Remaining: Email delivery is synchronous. The uniform timing requirement remains open.
  Validation: Focused checks and final `make ci` passed for the completed audit scope.

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

## Maintenance

### Recurring

- [ ] [M400R] (P2) Backlog hygiene and archive
  Goal:
  Keep the issue tracker reliable, readable, and focused on active work while preserving resolved history in the appropriate archive.

  Requirements:
  - Cadence: run weekly during active development and before each release cut.
  - Validate section names, identifier prefixes, recurrence suffixes, priority markers, dependencies, and duplicate IDs against the current `issues-md-format.md`.
  - Reconcile stale statuses, duplicate issues, broken references, obsolete instructions, and entries filed under the wrong section.
  - Before archival, update source documents with durable results from each resolved non-recurring issue.
  - Preserve the complete issue entry and its ID in the repository archive.
  - Keep active, blocked, planning, and recurring entries visible in `ISSUES.md`.

  Deliverables:
  - Normalized `ISSUES.md` structure and statuses.
  - Updated archive with complete entries removed from the active tracker.
  - A short `Last run:` note summarizing the cleanup and any follow-up issues filed.

  Validation:
  - Re-read `ISSUES.md` after edits and confirm every issue is under the right section with a unique section-aware ID.
  - Confirm recurring entries remain open and keep the `R` suffix.
  - Confirm no active, blocked, recurring, or planning work was archived.

  Last run 2026-10-05: Archived 196 completed implementation entries with their existing IDs and all evidence.
  Kept 20 entries, including P002 and all eight recurring tasks, in the active tracker.
  Verified entry preservation, unique IDs, and declared dependencies across both files.
  Existing issue IDs stay unchanged, including unresolved TA-434.

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
  - Classify each finding by its requested outcome. Record concrete scope, priority, and validation.
  - Close the pass with a no-action note only when the review finds no actionable drift.

  Deliverables:
  - Correctly classified issues for each actionable architecture or policy drift finding.
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
  - Review auth, secret, CORS, CSP, SQL, network, and service-authorization configuration for drift from the current contract.
  - Prefer current supported dependencies; do not add compatibility shims for obsolete dependency behavior.
  - File each actionable vulnerability, unsupported runtime, or security-contract gap under its outcome-based issue section.

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
  - File each concrete violation under its outcome-based issue section.
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

  Last run 2026-10-05: Reviewed the completed issues against current product, architecture, integration, and deployment documentation.
  Updated `ARCHITECTURE.md` for App ownership, automatic persistence, and account disablement.
  Corrected the issuer instructions in `pkg/sessionvalidator/README.md`.
  Marked `.mprlab/TENANT-CONSOLE.md` as the initial proposal and linked the operations guide.

### Other work

- [ ] [TA-434] (P1) Add `tauth doctor` to proactively diagnose auth misconfiguration.
  Provide a CLI command that reads `config.yaml` and prints a focused, actionable report (and stable error codes) for common “can’t authenticate” issues: origin not configured/unknown, ambiguous origins requiring tenant override, CORS allowlist missing the frontend origin, cookie scope collisions, cookie_domain/localhost pitfalls, missing/incorrect `enable_tenant_header_override` for shared-origin clients, and JWT validation parameters to sync with downstream services (issuer, session cookie name, tenant signing key fingerprints). Include a dedicated check/hint for issuer mismatch with common downstream validators (e.g. expecting `mprlab-auth` vs TAuth issuer `tauth`).

## Planning

- [x] [P002] (P1) Plan a tenant console from the Ledger and LLM Proxy workflows.
  Goal:
  Define a functional UI for owner login, tenant creation, later configuration, and browser and backend integration.
  This issue records the completed analysis. F008 owns implementation of the resulting scope.
  Deliverables:
  - Compare the current Ledger, LLM Proxy, and TAuth source contracts.
  - Define the screens, owner boundary, management API, persistent configuration, and runtime activation.
  - Plan the initial UI integration with `tauth.js` and `sessionvalidator`.
  - Keep OAuth console configuration as optional future scope.
  - Record migration requirements, Gateway dependencies, acceptance criteria, and open product decisions.
  Result:
  The September 26, 2026 source review and proposed delivery sequence are in `.mprlab/TENANT-CONSOLE.md`.
  The proposal uses the Ledger workspace structure and selected LLM Proxy configuration patterns.
  Tenant persistence and runtime activation are required backend work.
  External-domain cookie integration requires a customer-domain auth endpoint.
  Accepted direction:
  Accounts own tenants. Each tenant has one owner, and an account can own multiple tenants.
  Migrate current environment-backed tenant configuration into the database before the tenant management UI.
  Assign all existing application tenants to the account enrolled through verified Google login as `vtyemirov@gmail.com`.
  Bind subsequent ownership checks to the stable account ID and console subject.
  Use the same schema for imported tenants and tenants created later.
  The plan defines the ownership tables, bounded import, database cutover, and migration acceptance criteria.
  Resolution:
  Prepared F008 with six sequential implementation issues: F009, I212, F010, F011, F012, and F013.
  Recorded implementation defaults and acceptance criteria in `.mprlab/TENANT-CONSOLE.md`.
  Google login, customer API proxy routes, and protected session key export define the first delivery.
  P001 remains the separate assessment of shared identity across applications.
  Validation:
  Verified the issue identifiers, dependency sequence, changed prose, and whitespace.
  The Governor check retains six existing managed-file differences. Production implementation and migration remain pending under F008.

- [ ] [P001] Assess customer value and options for a platform account across applications.
  Goal:
  Determine whether shared identity or single sign-on solves a demonstrated customer problem across MPR Lab applications.
  This issue authorizes analysis and a decision only. Implementation requires a separate approved feature issue.
  Current contract:
  TAuth scopes persisted accounts, provider identities, password credentials, and sessions to a tenant.
  Applications can accept the same Google account while retaining separate TAuth accounts and sessions.
  Registration with email and password in one tenant does not create an account in another tenant.
  TAuth has account management and an OAuth authorization server. Their existence does not establish single sign-on across tenants.
  Source references: `ARCHITECTURE.md`, `internal/authkit/database_user_store.go`, and `internal/oauthserver/server.go`.
  Customer hypotheses:
  A platform account could reduce repeated registration, password recovery, and profile entry for users of multiple applications.
  Single sign-on could reduce the time needed to enter another application.
  These hypotheses require customer research. Current cross-application demand and measurable customer value remain unknown.
  Requirements:
  - Identify customers who use, or need to use, at least two applications for a concrete task.
  - Identify where repeated registration, login, identity confusion, or account recovery prevents completion of that task.
  - Compare Google users, email/password users, and users who prefer separate identities across applications.
  - Measure current login completion, time to first useful action, repeat use, and related support requests where data permits.
  - State each measurement period, population, denominator, and data limitation.
  - Keep customer outcomes separate from internal convenience and increased visits to other products.
  - Compare the current system, improvements to individual application login, shared identity, and shared identity with single sign-on.
  - Assess whether customers understand and trust an MPR Lab account across the selected applications.
  - Record customer expectations for profile sharing, separate identities, account recovery, and account deletion.
  - Assess separate application domains, browser restrictions, and native clients for the selected customer tasks.
  - Estimate engineering effort, operating cost, support cost, and dependencies for each option.
  - Assess existing account migration, verified identity linking, application permissions, subscriptions, and product data ownership.
  - Assess central service failure, account compromise, application logout, and platform logout.
  - Require ownership verification when connecting existing accounts. Treat matching email addresses as insufficient proof.
  - Select one canonical account contract if implementation is recommended. Define any required bounded data migration.
  Open Decisions:
  The participating applications, shared profile fields, account membership rules, and logout semantics remain undecided.
  A central login page, protocol choice, and database design remain options for analysis.
  Deliverables:
  - Produce a customer problem statement with research results, source references, and explicit assumptions.
  - Produce an option comparison with expected customer outcomes, costs, risks, and uncertainty.
  - Define a small evaluation with two applications selected from demonstrated customer demand.
  - Set measurable success thresholds and stop conditions before an evaluation starts.
  - Recommend proceed, defer, or decline. Record the decision owner and the reasons for the recommendation.
  - If implementation is recommended, propose the smallest feature scope and its acceptance criteria for user approval.
  Validation:
  - Trace each customer benefit to an observed problem or an explicitly untested hypothesis.
  - Show why the recommended option is sufficient compared with improvements to individual application login.
  - State whether the available research supports a decision or requires further investigation.
  - Close P001 after the user accepts the analysis and decision, including a decision to defer or decline.

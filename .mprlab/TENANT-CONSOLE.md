# TAuth tenant console proposal

Status: P002 planning completed. F008 tracks implementation through six dedicated issues.
Source review date: September 26, 2026.

## Outcome

A person signs in, creates an application tenant, configures authentication, and installs the resulting browser and backend configuration.
The person can return later to manage the same tenants.
Success means a real application login reaches a protected backend endpoint through a published TAuth validator.

The recommendation uses the Ledger workspace structure and selected LLM Proxy configuration patterns.
The main backend requirement is persistent tenant configuration with runtime activation.

## Accepted direction

Accounts own tenants. One account can own multiple tenants, and each tenant has exactly one owner account.
Use a separate deployment migration to assign all current application tenants to the operator's verified owner ID.
Use the same database structure for imported tenants and tenants created through the console.
Complete the migration foundation before the tenant management UI.
The first UI integration uses `tauth.js` and `sessionvalidator`.
OAuth console configuration is optional future scope.

Every verified console user can enroll, regardless of email spelling or login order.
Authorization uses the verified console subject and owner account ID.
Configured administrators can view the account directory. All workspaces remain owner-scoped.
The application has no migration owner or personal account rule.

## Database structure

The current `accounts` table contains application users identified by `(tenant_id, account_id)`.
Keep those users separate from the accounts that own tenants.
Use explicit `owner_accounts` and `owner_login_bindings` tables for the control plane.

```text
Verified console login -> owner_login_bindings -> owner_accounts
                                                    |
                                                    +-- tenants
                                                          |
                                                          +-- tenant_configurations
                                                          +-- tenant_origins
                                                          +-- tenant_providers
                                                          +-- tenant_secrets
                                                          +-- existing application users and sessions
```

| Table | Proposed keys and fields | Invariant |
| --- | --- | --- |
| `owner_accounts` | `id`, display name, contact email, state, timestamps | Stable opaque ID. Email is profile data. |
| `owner_login_bindings` | `owner_account_id`, issuer, console tenant ID, subject | Each verified login tuple binds to one owner account. |
| `tenants` | Existing tenant ID, `owner_account_id`, name, state, active revision, timestamps | Required owner foreign key. Exactly one owner per tenant. |
| `tenant_configurations` | Tenant ID, revision, session policy, account policy, cookie settings | Unique tenant and revision pair. Active revision belongs to that tenant. |
| `tenant_origins` | Tenant ID, revision, exact origin, proof reference | Origin belongs to the addressed configuration revision. |
| `tenant_providers` | Tenant ID, revision, provider type, typed public settings, secret references | One configuration per provider in each revision. |
| `tenant_secrets` | Secret ID, tenant ID, purpose, encrypted value, encryption key ID | Secret references remain within their tenant. |
| `tenant_imports` | Import ID, source digest, owner ID, tenant IDs, completion time | An identical retry has no duplicate effect. A conflicting retry fails. |
| `tenant_audit_events` | Actor account, tenant ID, operation, revision, result, timestamp | Record ownership and configuration changes without secret values. |

Use foreign keys and uniqueness constraints for ownership and revision relationships.
Reject owner deletion while the account owns tenants.
Require an explicit authorized operation for any later ownership transfer.
Authorize every tenant query through its `owner_account_id`.
Store origin proofs and setup checks against their tenant and configuration revision.
Keep existing application-user records and session relations intact.

## Migration sequence

Create the destination schema before the import. The product delivery starts with migration, then exposes the account-owned tenants through the UI.

1. Inventory the active tenant YAML and its referenced environment variables through the canonical configuration loader.
2. Resolve each tenant's complete effective configuration, including literal YAML values and environment substitutions.
3. Produce a redacted inventory with tenant IDs, provider types, counts, and validation errors.
4. Create the ownership schema and the reserved console authentication configuration.
5. Authenticate the destination account through Google in the console tenant.
6. Verify the provider token, nonce, audience, issuer, subject, and verified email before owner enrollment.
7. Create the owner account and persist its stable console login binding.
8. Back up the database and validate the complete import before any tenant write.
9. Run the separate deployment GORM migration to assign every source tenant to that owner in one transaction.
10. Preserve tenant IDs, signing keys, cookie settings, origins, provider configuration, and account policies.
11. Preserve existing users, identities, password hashes, refresh sessions, and OAuth grants.
12. Record an import receipt that identifies the owner and imported tenants without secret values.
13. Verify tenant counts, owner relationships, effective settings, and existing login behavior through the database runtime.
14. Change Gateway provisioning and TAuth runtime reads to the canonical database contract.
15. Remove tenant environment inputs and YAML runtime tenant reads at the verified cutover.
16. Build the tenant console against the same owner and tenant resources.

Keep the temporary importer outside normal service startup.
Remove that importer after verified production migration through the operational cleanup procedure.

Pause configuration changes during the final import and cutover.
Reject missing values, invalid tenants, duplicate identifiers, and conflicting owner assignments before the transaction commits.
Use an import digest that does not disclose secrets.
An identical import retry must return the existing receipt. A changed source requires explicit review.
Keep the database encryption key and database connection settings in service secret configuration.

Existing downstream validators retain their current signing keys and cookie configuration through this migration.
Their backend environment variables remain valid integration inputs.
Only TAuth's tenant configuration authority moves from environment-backed YAML to the database.
Existing encrypted provider credentials remain intact, including any key references required to decrypt them.
Inventory actual tenant counts and verified owner subjects during execution. This plan does not assert access to the production values.

Migration acceptance requires these results:

- Every source tenant occurs once in the database with the explicit destination owner ID.
- A later login through the bound Google identity lists all imported tenants.
- Another owner account cannot read or change those tenants.
- An account created later can own new tenants through the same schema and APIs.
- Service restart restores tenant configuration from the database.
- Existing browser sessions and backend validators retain their documented behavior.
- An import failure preserves the original data and leaves no partial tenant collection.
- Tenant configuration uses the database exclusively after the cutover.

## Confirmed source findings

This review examined local source code and tests. It did not run the deployed applications or their test suites.

| Area | Ledger | LLM Proxy | TAuth consequence |
| --- | --- | --- | --- |
| Owner identity | TAuth session maps to a UserAccount through issuer, tenant, and subject. | TAuth session authenticates a management account. | Use a separate owner account with a stable subject. |
| First visit | Explicit account provision permits an empty tenant collection. | Account provision creates a Default tenant. | Prefer an empty collection and explicit tenant creation. |
| Workspace | Tenant rail and Overview, Credentials, Integration tabs. | Selected tenant controls connections, models, settings, and usage. | Keep tenant selection visible across configuration sections. |
| Provider setup | Not applicable to Ledger credentials. | Named account connections contain masked provider credentials and tenant assignments. | Use provider forms and explicit saved states. Start with tenant-owned provider settings. |
| Secrets | A new client credential appears once. Stored digests permit revocation. | Tenant access keys and encrypted provider credentials have separate roles. | Distinguish public settings, session keys, and provider secrets. |
| Request control | Owner authorization, exact Origin, CSRF header, idempotency keys. | Protected management API, mutation checks, versioned connection updates. | Apply ownership and concurrency checks at every management resource. |
| Browser state | Cancellation and an authentication version reject stale responses. | Account and tenant requests have separate cancellation and version state. | Clear protected state on logout and reject late results after tenant changes. |

TAuth currently loads tenant YAML at startup.
Its origin resolver, CORS list, authentication registry, email delivery, and OAuth registry derive from that configuration.
The reviewed server has no owner account or tenant creation API.
The published website contains documentation and `tauth.js`. It has no tenant console.
Existing account routes manage application users inside a tenant.

The two validator contracts are distinct:

- `pkg/sessionvalidator` validates an HS256 session cookie with a tenant session key.
- `pkg/oauthvalidator` validates an ES256 bearer token with issuer, resource audience, JWKS, and required scopes.

The session validator returns the tenant claim. Consumers must compare that claim with their expected tenant.
Both validators leave application authorization to the resource service.
P001 remains a separate assessment of shared identity and single sign-on across applications.

## Recommended first delivery

Use Google login for console owners and customer applications in the first delivery.
Enable persisted account management for the console tenant.
Let each owner create multiple named application tenants.
Use separate tenants for development and production when their credentials or policies differ.
Keep one owner per tenant for this delivery.

Complete the cookie integration path with `tauth.js` and `pkg/sessionvalidator` first.
Treat OAuth resource configuration and `pkg/oauthvalidator` examples as optional future scope.
Existing Apple, GitHub, password, and OAuth runtime behavior must remain intact through the storage change.
Their new console forms follow the first Google integration.
Shared provider connections, team membership, billing, usage charts, and application-user administration are later scope proposals.

## User flow and screens

```text
Sign in
  -> Your tenants
  -> Create tenant
  -> Configure Google and application addresses
  -> Verify domain and activate configuration
  -> Copy browser settings and install backend secret
  -> Complete a sample login and protected request
  -> Return later, select tenant, and change configuration
```

| Screen | Content and primary action |
| --- | --- |
| Signed out | Brief product description, documentation, and MPR-UI sign-in control. |
| Your tenants | Tenant name, environment label, state, last setup check, and Create tenant. |
| Create tenant | Name and environment label. Save a draft and open its setup form. |
| Overview | Tenant ID, active revision, enabled providers, setup status, and next required step. |
| Domains | Frontend origins, backend address, auth address, origin proof, and local development settings. |
| Sign-in methods | Google client ID and exact provider-console setup values. Later forms add the other providers. |
| Integration | Separate Browser and Backend sections, generated examples, secret export, and setup check result. |
| Settings | Rename, session lifetimes within service limits, and confirmed suspension. |

Use the Ledger tenant rail on desktop and a tenant selector at narrow widths.
Use MPR-UI header, account controls, footer, and theme settings with browser ES modules.
Show loading, empty, saved, invalid, conflict, and unavailable states explicitly.
Preserve form values after request errors.
Keep secrets only in temporary page memory.

Use keyboard-accessible forms, focus return, visible field errors, and status announcements.
Keep the selected tenant in the URL. Authorize that tenant before displaying its details.

Create tenant saves a draft without requiring every integration field.
Activate becomes available when the selected integration contract has all required values and origin proofs.
An active configuration and a successful setup check are separate facts.
Show the setup check time and configuration revision. Invalidate that result when relevant settings change.

## Browser and backend integration

### Cookie integration

An auth response can set cookies only for its own hostname or an allowed parent domain.
A cookie from `tauth-api.mprlab.com` cannot authenticate a request to an unrelated customer domain.
CORS permission does not change this domain boundary.
See the [MDN Set-Cookie domain rules](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#domaindomain-value).

For the first delivery, use the customer's API hostname for both auth routes and protected application routes.
For example, `app.customer.example` calls `api.customer.example/auth/*` and `api.customer.example/private`.
A customer reverse proxy sends the documented auth routes and `/me` to TAuth.
It binds each upstream request to the configured tenant and preserves the browser Origin.

Use a host-only session cookie on the API hostname.
Keep the refresh cookie on `/auth` and preserve the current helper contract.
Generate exact proxy configuration and provider callback values for this topology.
Verify forwarded host handling, tenant selection, callback redirects, HTTPS, CORS, and cookie attributes through a real browser.

The Integration screen supplies these public values:

- The canonical script URL, `https://tauth.mprlab.com/tauth.js`.
- The explicit API `baseUrl` and application `tenantId` for `initAuthClient`.
- The Google client ID and a complete sign-in example with nonce handling.
- The session cookie name, expected tenant ID, and backend environment variable names.

The backend example reads the session key from its secret store.
It configures `sessionvalidator`, checks the expected tenant claim, and applies application authorization.
The browser example contains public configuration only.

A session key has signing authority, unlike a Ledger credential digest.
TAuth must retain the session key in encrypted storage to issue sessions.

Permit secret export only after recent owner authentication. Use a no-store response and record an audit event.
Clear the secret from the page after dismissal, tenant change, or logout.

Define key replacement as an explicit cutover with backend installation and session invalidation.
Replace the key in TAuth and each validator through one documented installation sequence.
Permit one active session key. Reject the old key after the cutover.
Record the access-cookie expiry limit when describing logout or suspension to downstream validator users.

### OAuth integration

Use the existing authorization-code flow with PKCE for resource-bound bearer tokens.
Configure exact resources, scopes, client identifiers, redirect URIs, and consent policy in a later delivery slice.
Generate `oauthvalidator` configuration with the issuer, JWKS URL, exact audience, and required scopes.
Include a real code exchange and protected-resource request in the example.

The existing cookie helper does not implement an OAuth client flow.
Any browser OAuth helper requires an explicit contract and separate acceptance tests.
Keep issuer private keys inside the service. Resource validators need public verification keys only.

## Ownership and runtime design

Use one reserved console tenant to authenticate owners.
Bind each owner account to the verified issuer, console tenant ID, and stable subject.
Keep customer application users inside their application tenants.
Require the console tenant on management requests, independently of customer tenant identifiers.
Use separate console keys and cookie names.
Prevent customer configuration from altering the console tenant.

Use one persistent tenant repository as the canonical runtime source.
Keep server settings and issuer key references in deployment configuration.
Represent owners, tenant settings, encrypted secrets, origin proofs, configuration revisions, and audit events in persistent storage.
Store application tenants with explicit `draft`, `active`, or `suspended` states.

Activation must produce one validated runtime snapshot for the committed revision.
Include origin resolution, CORS, provider settings, account policy, email delivery, cookies, and OAuth policy in that snapshot.
Use one snapshot throughout each request.
Reject invalid revisions before activation.
Keep the previous active revision when an update fails.
Make restart restore the same active revision and secrets.

Define the commit and activation failure behavior before implementation.
The current deployment has one runtime instance. Multiple instances require revision distribution before that topology is supported.

Move existing YAML tenants through one bounded import.
Preserve tenant IDs, account subjects, keys, cookies, provider identities, sessions, and OAuth grants.
Select the operator's verified owner ID as an explicit deployment migration input.
Treat Gateway as an authorized provisioning client, separate from tenant ownership.
After the import, all runtime tenant reads use the persistent repository.

Gateway currently renders tenant contributions into the deployment YAML.
Change that producer to an authenticated provisioning client of the same repository before the storage cutover.
Give each producer authority over its own tenant resources only.
Reject conflicting revisions instead of overwriting console changes.

Use owner-scoped authorization for every provisioning client and console mutation.
This coordinated Gateway change is a delivery dependency, not an existing capability.

Bootstrap the console tenant and its provider settings through an explicit operator command before public registration opens.
Permit console access when the application tenant collection is empty.
Use the existing P001 identity boundary without requiring cross-application account sharing.

## Proposed management API

All routes below are proposals under `/api/management`.
Define their schemas in the canonical OpenAPI document before implementation.

| Resource | Operations | Contract |
| --- | --- | --- |
| `/owner-account` | `PUT`, `GET` | Provision the current owner idempotently, then read its profile. |
| `/tenants` | `POST`, `GET` | Create a draft or list the current owner's tenants with cursor pagination. |
| `/tenants/{id}` | `GET`, `PATCH` | Read metadata or change name and permitted state. |
| `/tenants/{id}/configuration` | `GET`, `PUT` | Read or replace the typed configuration, with secret values omitted. |
| `/tenants/{id}/origin-proofs` | `POST`, `GET` | Create and read bounded hostname proof challenges. |
| `/tenants/{id}/activations` | `POST`, `GET` | Activate an exact configuration revision and read its result. |
| `/tenants/{id}/integration` | `GET` | Read public snippets and backend installation instructions. |
| `/tenants/{id}/secret-exports` | `POST` | Export the session key after recent owner authentication. |
| `/tenants/{id}/setup-checks` | `POST`, `GET` | Record and read bounded integration checks for an exact revision. |

Apply session validation and owner authorization to every resource.
Use exact console Origin checks and a CSRF header for cookie-authenticated mutations.
Use idempotency keys for retry-sensitive creation and ETags for configuration changes.
Return `201` with `Location` for creation and `412` for stale update preconditions.
Use one typed error shape with field details and a request ID.
Send management and secret responses with `Cache-Control: no-store`.

Prove production hostname control before activation, preferably through a bounded DNS TXT challenge.
Reserve platform origins and resource audiences.
Reject claims that conflict with another owner.
Give localhost an explicit development policy with tenant-bound requests and distinct cookies.
Keep provider endpoints, issuer keys, internal addresses, and platform mail credentials under operator control.

Restrict setup checks to verified destinations and fixed protocols to prevent arbitrary server requests.
Bound creation rates, request sizes, and proof lifetimes at API boundaries.

## Delivery sequence and acceptance

F008 is the umbrella feature. P002 records the completed planning work.
Implement the following child issues sequentially. Each issue contains its technical scope and acceptance criteria.

| Issue | Deliverable | Required acceptance |
| --- | --- | --- |
| F009 | Ownership schema, verified login bindings, encrypted secrets, and console bootstrap. | Repeat login retains ownership. Distinct owners remain isolated. |
| I212 | Bounded import and database-only tenant runtime. | Migrated tenants belong to the explicit destination owner and preserve existing authentication behavior. |
| F010 | Owner-authorized tenant API, origin proofs, and runtime activation. | New tenants activate without restart. Failed updates retain the previous active revision. |
| F011 | Owner-scoped Gateway credentials and provisioning client integration. | Repeat provisioning preserves tenant identity and rejects stale or unauthorized writes. |
| F012 | MPR-UI tenant workspace, Google setup, domains, and configuration. | Real browser tests cover imported and newly created tenants. |
| F013 | Proxy instructions, protected secret export, integration examples, and setup checks. | A new tenant reaches a protected backend through `tauth.js` and `sessionvalidator`. |

```text
F009 -> I212 -> F010 -> F011 -> F012 -> F013 -> F008 complete
```

I212 is an Improvement because it changes the existing configuration architecture and persisted contract.
The other child issues add user or operator capabilities.
OAuth console configuration and additional provider forms remain future scope outside F008.

The I212 implementation can pass local acceptance before the production import.
Complete F011's compatible Gateway client before the production configuration cutover.
Record production import, release, publication, deployment, and live-provider qualification separately from child issue closure.

For each behavior change, first run a failing integration test through its public entry point.
Use real HTTP services, persistent test storage, deterministic provider protocols, and automated browsers.
Cover owner isolation, origin substitution, duplicate creation, concurrent edits, failed activation, restart, logout, and late browser responses.
Verify secrets are absent from public payloads, browser storage, URLs, and logs.
Verify suspension blocks new authentication and refresh.
State the expiry limit for tokens already issued to offline validators.

Run the applicable Make target during each slice and `make ci` at the stack completion checkpoint.

## Publication and operations

Publish the console at `https://tauth.mprlab.com/app/` through the existing GitHub Pages artifact.
Keep documentation and the canonical `/tauth.js` URL intact.
Use `https://tauth-api.mprlab.com` for the console API.
Use static routes or query state that survive a GitHub Pages reload.

Record required Google configuration, console bootstrap, database import, Gateway cutover, and secret storage in a runbook.
Verify the deployed website release marker and public API separately from local acceptance.
Qualify actual provider login separately from deterministic browser tests.

## Implementation defaults

These defaults make F008 and its child issues ready for implementation.

| Decision | Contract | Effect |
| --- | --- | --- |
| First provider | Google for the console and first application integration. | Keeps the first complete flow small. |
| External domains | Customer API reverse proxy for cookie integration. | Requires customer route setup. A hosted custom-domain service is additional scope. |
| Session key access | Google reauthentication within five minutes, bound to the owner, tenant, and export operation. | Requires encrypted storage, no-store responses, and a secret-free audit. |
| Gateway provisioning | Revocable opaque credentials with owner, operation, and tenant grants. Store credential digests. | Use F010 resources, stable provisioning receipts, and ETag preconditions. |
| Delivery scope | Migration and database runtime first, then the cookie integration UI. | OAuth and other provider forms remain optional future scope. |

The Accepted direction section records the user's confirmed ownership and migration decisions.
F008 uses these implementation defaults to complete that direction.
P001 remains separate from tenant ownership and console delivery.

## Planning validation

The official STE reference passed its checksum check.
The language review covers this proposal, P002, the F008 child issues, and the added terminology.
The mechanical language check has no findings in that changed scope.
The unchanged tracker has existing language findings.
P002 occurs once in the active tracker and is absent from the archive.
F008 and its child identifiers are unique across the active tracker and archive.
Their dependency graph has no cycles or missing references.

The Governor check reports six existing managed-file differences.
The affected files are `.gitignore`, `.mprlab/AGENTS.DOCKER.md`, `.mprlab/AGENTS.GO.md`, `.mprlab/PLANNING.md`, `.mprlab/POLICY.md`, and `.mprlab/issues-md-format.md`.
Those differences predate this planning change and remain outside its scope.
The repository governance check remains unsuccessful.
Application CI and deployed acceptance were outside this documentation task.

## Source map

- TAuth: `README.md`, `ARCHITECTURE.md`, `docs/openapi.yaml`, and `docs/index.html`.
- TAuth runtime: `cmd/server/main.go`, `internal/tenants/resolver.go`, and `internal/authkit/tenant_registry_builder.go`.
- TAuth policy and validators: `internal/oauthserver/registry.go`, `pkg/sessionvalidator/validator.go`, and both validator READMEs.
- TAuth publication: `docker/pages/Dockerfile` and the `github_pages` resource in `.mprlab/deploy/resources.yml`.
- Ledger: `internal/controlplane/web/index.html`, `internal/controlplane/web/js/app.js`, and `internal/controlplane/server.go`.
- Ledger acceptance: `internal/controlplane/server_test.go`.
- LLM Proxy: `docs/tenant-connections.md`, `internal/proxy/management_api.go`, and `internal/proxy/management_store.go`.
- LLM Proxy session and browser state: `internal/proxy/management_session.go` and `site/assets/llm-proxy/js/ui/managementApplicationState.js`.
- LLM Proxy acceptance: `tests/e2e/management-ui.spec.js` and `tests/blackbox/connection-dashboard.spec.js`.

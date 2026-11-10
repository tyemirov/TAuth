# Tenant console operations

F008 defines the tenant console delivery. F009 adds the owner database and console bootstrap.
The console tenant is `tauth-console`. Application tenants cannot change its configuration.
The console permits Google login, session restore, refresh, logout, and profile reads.
Account linking and password routes are unavailable for this tenant.

## Production command contract

Use the [deployment guide](deployment.md#production-lifecycle) for the current production procedure:

```sh
make release && make publish && make deploy
```

The selected manifest retains the database and existing server encryption key.
The service applies current schema migrations at startup.
The completed tenant, App, and application-subject cutovers require no separate executable or migration command.

## Service inputs

The [configuration reference](service-configuration.md) defines service fields.
The [deployment guide](deployment.md#https-and-proxy-trust) defines proxy trust and database retention.

The service uses AES-256-GCM for stored secret values.
Each application secret binds its ciphertext to the tenant, secret ID, purpose, and encryption key ID.
The console configuration is encrypted in the database.
Owner accounts remain separate from application accounts.
Each owner binding contains the issuer, reserved console tenant ID, and authenticated subject.
The owner account ID remains the same after an email change.

## Bootstrap order

Production performs console bootstrap automatically within `make deploy`.
This section describes the standalone CLI for development and diagnostics.

1. Create a Google Web client for the console.
2. Add the exact console origin to the Google client's authorized JavaScript origins.
3. Add the same origin to `server.cors_allowed_origins`.
4. Create a private console tenant file with the fields below.
5. Supply the persistent database URL and encryption key through the service configuration.
6. Run the bootstrap command.
7. Start TAuth with the same service configuration.
8. Authenticate through Google in the reserved console tenant.
9. Send `PUT /api/management/owner-account` with the console session cookie.
10. Record the returned owner account ID for App administration and provisioning.

```yaml
id: tauth-console
display_name: TAuth console
tenant_origins: [https://tauth.mprlab.com]
google_web_client_id: REPLACE_WITH_GOOGLE_CLIENT_ID
jwt_signing_key: REPLACE_WITH_RANDOM_SESSION_KEY
session_cookie_name: tauth_console_session
refresh_cookie_name: tauth_console_refresh
session_ttl: 15m
refresh_ttl: 720h
account_management:
  enabled: true
  email_delivery:
    server_address: REPLACE_WITH_PINGUIN_ADDRESS
    api_key: REPLACE_WITH_PINGUIN_KEY
    connection_timeout_seconds: 3
    operation_timeout_seconds: 5
    email_verification_url: https://tauth.mprlab.com/app/verify
    password_reset_url: https://tauth.mprlab.com/app/reset
    password_link_url: https://tauth.mprlab.com/app/link
```

The current account configuration requires Pingwin settings. The console does not expose password or linking operations.
The bootstrap command resolves environment inputs before it stores the console configuration.
Do not include the console tenant in the application tenant YAML.
Keep the console cookie domain empty. This value creates host-only cookies on the API hostname.

```sh
tauth --config service.yaml console-bootstrap --tenant-file console.yaml
tauth --config service.yaml
```

An identical bootstrap retry succeeds. A changed configuration fails with `management.bootstrap_conflict`.
A missing bootstrap record or an incorrect encryption key prevents console startup.
The bootstrap command does not replace existing console configuration.
Console administration remains an operator operation.

## Console Google client replacement

Use `console-google-client-replace` to correct the console Google client ID.
The command changes only that field in the console configuration.
It encrypts the updated configuration and updates its digest.
It keeps console keys, owner bindings, application tenants, and sessions.
Existing sessions keep their original expiry. New Google login uses only the replacement client after restart.
The command requires an exact match with the current client ID.
An unchanged replacement or stale expected value fails without a configuration change.

1. Add the console origin to the replacement Google Web client's authorized JavaScript origins.
2. Stop all TAuth service instances that use this database.
3. Back up the database and its encryption-key reference.
4. Run the command with the current and replacement client IDs.
5. Update the private console bootstrap input with the replacement client ID.
6. Restart TAuth with the same database and encryption key.
7. Verify the client ID at `/.well-known/tauth-console`.
8. Complete Google login through the tenant console.

```sh
tauth --config service.yaml console-google-client-replace \
  --expected-client-id "$CURRENT_GOOGLE_CLIENT_ID" \
  --client-id "$NEW_GOOGLE_CLIENT_ID"
```

The command prints the console tenant ID and current Google client ID as JSON.
If the command fails, keep the service stopped and correct the reported input or database error.
If the receipt is lost, inspect `/.well-known/tauth-console` after restart before another replacement.
The original bootstrap input fails after replacement. An identical bootstrap with the new client ID succeeds.

For the local Compose stack, build the current source with `make up` before the procedure.
Stop the API with `docker compose -f local/compose.yml stop tauth`.
Keep the database volume. Run the replacement command through the Compose service:

```sh
docker compose -f local/compose.yml run --rm --no-deps tauth \
  --config /config/service.yaml console-google-client-replace \
  --expected-client-id "$CURRENT_GOOGLE_CLIENT_ID" \
  --client-id "$NEW_GOOGLE_CLIENT_ID"
```

Set `TAUTH_CONSOLE_GOOGLE_CLIENT_ID` in `.cache/tauth-local/runtime.env` to the new client ID.
Keep every other value in that file. Start the local stack with `make up`.
The API bootstrap address is `http://localhost:8082/.well-known/tauth-console`.
The console address is `http://localhost:8081/app/`.

## Owner resources

Send the exact console `Origin` on owner requests.
For `PUT`, also send `X-TAuth-CSRF: 1`.
The endpoint accepts the reserved console session cookie only.
Every verified console identity can create an owner account, regardless of login order or email spelling.
The stable console subject binding controls access. Email matches do not merge accounts.
No owner account has special tenant functionality.

Configure `admin.emails` in service YAML to grant access to `GET /api/management/accounts`.
Use the verified account email. Configuration can list approved email spellings explicitly.
The service does not infer aliases. An empty list grants no administrator access.
The account directory shows registered owners and supports `limit` and `cursor`.
Ordinary users and provisioning credentials cannot read the directory.
Administrators retain the same tenant ownership checks as all other users.

```yaml
admin:
  emails: [administrator@example.com]
```

`PUT /api/management/owner-account` returns `201` for creation and `200` for an identical retry.
`GET /api/management/owner-account` returns the current owner or `404` before provision.
Both resources use `Cache-Control: no-store`.
Owner deletion fails while owned tenants exist.

## Acceptance records

Use `make test-console` for local CLI, HTTP, database, and encryption checks.
The HTTP tests use a TLS listener, SQLite, and an injected Google validator.
These tests do not prove live Google connectivity.
Record live Google qualification separately from software acceptance.

Production deployment uses the current manifest and retained database.
Deployment and live-provider evidence remain separate from release and publication records.

## App hierarchy migration

F017 established account → Apps → tenants as the ownership model.
App membership is required.
Each tenant and its App must have the same owner.
Tenant settings, accounts, and sessions remain isolated within each App.

The completed cutover preserved tenant IDs, states, revisions, keys, and authentication data.
It stored a receipt and rejected changed mappings, duplicates, omissions, and cross-owner assignments.
The cutover removed earlier POST receipts because their responses lacked App membership.
Historical local assignments placed 22 tenants in 19 Apps.
Kamu had two tenants. Prompt Bubbles had three.

B143 removed the completed cutover executable and deployment readers.
The current service requires the canonical persisted ownership contract at startup.

## Deployment data migration

The production tenant, App, and application-subject cutovers are completed.
The current release contains no separate tenant-import executable or migration plan.
The [production lifecycle](deployment.md#production-lifecycle) retains the database and applies current schema migrations at startup.

The tenant cutover preserved IDs, keys, cookies, providers, policies, lifetimes, users, identities, credentials, sessions, and OAuth grants.
Tenant writes and the completion receipt committed together.
An identical retry returned the receipt.
Conflicting inputs failed without partial tenant writes.

The completion receipt stored a keyed source digest without secret values.
Candidate databases protected the original data during failed operations.
The destination owner was verified explicitly, without a first-owner or personal-email rule.
The cutover also removed `console_bootstraps.initial_owner_id` and obsolete `return_challenge_tokens` inputs.

B098 repaired inactive imported definitions through bounded cookie-name and tenant-header corrections.
Those corrections preserved keys, providers, origins, ownership, and unrelated data.
See the [dated local record](local-tenant-migration-2026-09-28.md) for historical evidence.

Runtime reads use encrypted database revisions without tenant environment expansion.
The service rejects the `tenants` YAML field, including an empty array.
New application tenants use the [management API](#tenant-management).
Consumer tests use the [isolated fixture tool](test-fixture.md).
The former import examples document historical data shapes only.

## Tenant management

F010 adds owner resources under `/api/management/tenants`.
The [OpenAPI document](openapi.yaml) defines the request and response fields.
All cookie requests require the exact console Origin. Mutations also require `X-TAuth-CSRF: 1`.
Send JSON with `Content-Type: application/json`.
Responses use `Cache-Control: no-store`. CORS exposes `ETag` and `Location`.

Create an App with `POST /api/management/apps` and its `name`.
Create an active tenant with `app_id`, `name`, `application_origin`, and `google_web_client_id`.
The workspace supplies `app_id` from the selected App. The three tenant fields remain mandatory.
The App must belong to the current owner.
Use `GET /api/management/tenants?app_id=APP_ID` to list its tenants.
App reads return an ETag. App name updates require that ETag with `PATCH /api/management/apps/APP_ID`.
The workspace loads Apps automatically and shows every App with its tenant count.
Select an App to expand its tenant list. Select a tenant to edit its configuration.
The same nested list supports desktop and mobile layouts.
The compact layout uses the Smith MPR styling tokens.
The service generates the tenant ID, keys, cookie names, and session lifetimes.
Creation validates and publishes the complete configuration in one transaction.
A failed creation leaves no tenant record.
The optional customer API origin supports integration instructions and does not control creation.
Use one `Idempotency-Key` for each POST operation. Keep the same body and precondition on a retry.
A changed retry returns `409`. Successful creation returns `201` and a resource Location.
An owner can create up to 100 tenants. The service permits up to 60 recorded mutations per owner per minute.
Request bodies have a 32 KiB limit.

Collections use ascending opaque IDs, `limit` from 1 through 100, and `cursor`.
The default limit is 50. Send the returned `next_cursor` for the next page.
An empty `next_cursor` marks the last page.
Concurrent creation can change later pages. Each page remains owner scoped.

Read the configuration ETag before each configuration PUT or activation POST.
Read the tenant ETag before a metadata PATCH or suspension PATCH.
A missing precondition returns `428`. A stale precondition returns `412`.
Configuration PUT creates an immutable revision and applies it immediately to a tenant that is not suspended.
It preserves imported provider and account fields outside the editable Google, origin, and lifetime settings.
A failed configuration update preserves the previous revision and runtime.
Edits to a suspended tenant do not resume authentication.
Session lifetimes range from one minute through one hour. Refresh lifetimes cannot exceed 90 days.

### Application origins

Production addresses require HTTPS and DNS hostnames.
DNS ownership verification is not a creation or activation prerequisite.
The optional origin-proof API records DNS evidence without controlling activation.
The service rejects reserved console hostnames and hostnames that another active tenant uses.
Local development permits localhost, `127.0.0.1`, and `::1` with HTTP or HTTPS.
Creation detects these local addresses and enables the tenant-header setting.
Each local request must send the exact tenant ID in `X-TAuth-Tenant`.
New tenants have distinct session and refresh cookie names.

### Activation and recovery

Run one TAuth instance with the control database.
The service serializes management mutations and locks the database bootstrap row for each transaction.
Activation validates the complete candidate revision and builds all runtime consumers before commit.
Those consumers include origin resolution, CORS, providers, cookies, account policy, email delivery, and OAuth policy.
The transaction then commits the active revision and activation record.
A successful commit is followed by one runtime pointer replacement before the response.
An existing request retains its original snapshot until completion.
The service closes retired email clients after their last request completes.

An invalid activation returns a typed error with an activation resource in `details.activation`.
Its Location identifies the stored failed activation. The previous active revision remains in use.
A crash before commit leaves the previous revision active.
A crash after commit restores the committed revision on restart.
Multiple service instances require a separate revision-distribution design.

Startup and runtime publication apply the same CORS allowlist validation.
Each explicit service origin must belong to an active tenant or an explicit service exception.
An origin replacement or suspension that breaks this rule returns `422` before publication.
The previous tenant state and active revision remain in use and remain valid after restart.
The runtime adds active tenant origins automatically, so application origins do not need duplicate entries in service configuration.

Before a change that removes an explicitly listed application origin:

1. Remove that application origin from `server.cors_allowed_origins`. Keep the console origin in the list.
2. Restart the service with the corrected service configuration.
3. Read the current resource ETag.
4. For activation, use a new `Idempotency-Key` for the corrected attempt.
5. Retry the tenant change.

Set tenant state to `suspended` with PATCH to stop new authentication and refresh requests.
The service publishes a snapshot without that tenant and waits for requests from retired snapshots.
It then revokes tenant refresh sessions, OAuth refresh grants, consents, and authorization codes.
A successful suspension response means those revocations are completed.
If suspension returns `503` or the request is canceled, read the current tenant ETag and retry the suspension.
Activation returns `409` until pending suspension completes.
Startup completes revocation for every suspended tenant before it accepts requests.
Activation can restore a suspended tenant, but revoked refresh credentials remain invalid.

Offline validators can accept an issued access token until its expiry.
For managed session cookies, that limit is the session lifetime at issuance, at most one hour.
Imported tenants retain their configured lifetime. OAuth access tokens retain the issuer's configured access-token lifetime.
Suspension does not make an offline validator contact TAuth.
Audit records contain resource identifiers, revisions, operations, results, and times. They contain no session keys or provider secrets.


## Gateway provisioning and cutover

Gateway provisions tenants through the authenticated management API.
Use an installed Gateway release that implements the selected manifest and current TAuth contribution contract.
Record that exact release and the TAuth version with the deployment evidence.

Create credentials through `/api/management/provisioning-credentials` with the owner cookie, console Origin, and CSRF header.
Supply `app_id`, a name, permitted operations, explicit tenant IDs, and the `allow_create` grant.
Every granted tenant must belong to that App. Newly provisioned tenants inherit the credential's App.
Operations are `read`, `configure`, `activate`, `suspend`, and `proofs`.
A creation grant adds each created tenant to that credential's tenant grants.
The service stores a digest and shows the generated token once.
A repeated creation request returns metadata without the token. Revoke a lost token and issue another.
DELETE revokes the credential. GET returns metadata only.

The Gateway client sends `Authorization: Bearer <token>` without browser cookies or Origin.
Store the App tokens in the operator's private environment as `MPRLAB_TAUTH_PROVISIONING_CREDENTIALS`.
Use a JSON map from contribution owner to resource ID to token, such as `{"kamu":{"authentication":"tauthp_<token>"}}`.
Assign each contribution the credential for its destination App.
Keep credentials for removed contributions until their tenant suspension succeeds.
Set `MPRLAB_TAUTH_MANAGEMENT_URL` to the TAuth service origin.
Never place the token in a manifest, public output, URL, or browser configuration.

Credential creation and initial convergence share the owner mutation budget.
If the service returns `management.mutation_rate_exceeded`, wait for the one-minute budget to expire.
Then repeat the unchanged operation.

B106 passed the [installed release qualification](production-release-qualification-2026-09-30.md) with Gateway v5.0.0 and sealed TAuth v2.2.6.
That dated record describes the earlier cutover.
Current deployment uses the [production lifecycle](deployment.md#production-lifecycle).
Publication and live Google qualification retain separate evidence records.

Gateway sends an exclusive `provisioning` configuration object with the contribution and application generation.
A machine request with the console shape or a null `provisioning` value returns `422`.
The API validates the contribution through the same TAuth native configuration parser used by the renderer.
In a deployment contribution, `account_management.return_challenge_tokens` can be omitted or set to `false`.
The renderer and API reject `true`, `null`, and other value types.
The field has no native configuration or runtime representation. Challenge tokens remain available only through email delivery.
Activation uses the shared management activation service without a DNS ownership prerequisite.
An identical generation and contribution retain the configuration revision.
A changed contribution at the same generation fails. A console edit causes a revision conflict.
Gateway cannot overwrite that edit or reactivate a suspended tenant.
Existing validator keys and cookie settings must match the active tenant contract.
Gateway configuration writes keep `allow_insecure_http` and `require_tenant_header` from the active tenant configuration.
This rule applies to the first write after import and to later generations.
For a tenant without an active revision, loopback origins set both policies to `true`.
Loopback origins still control origin validation for each configuration write.
Advanced Gateway integrations can retain their existing API topology without the console API-base field.
Public console integration setup requires that field before it can produce complete settings.

Use the [production command contract](#production-command-contract) for deployment.
Deployment retains existing console ownership, application tenants, and credentials.
Record publication, deployment, and live-provider qualification results separately.

The renderer now emits service settings with the database URL and encryption-key input.
`validate-service-config` validates that artifact without database access.
Normal startup requires the bootstrapped database and its encryption key.
A later deployment failure does not reverse a committed tenant revision.
Retry the management request with its persisted contribution binding and activation receipt.


## Browser workspace

The Pages artifact serves the tenant workspace at `/app/`.
It preserves the documentation homepage and `/tauth.js`.
`/app/runtime.json` selects the separate HTTPS API origin.
The browser reads `/.well-known/tauth-console` from that service for the reserved tenant and Google client ID.
The returned console origin must match the page origin exactly.
Change the public runtime file before artifact publication when the API hostname changes.
Never put a session key or provisioning credential in this file.

The workspace uses the pinned MPR-UI account controls, footer, and theme controls.
The destination owner sees imported tenants after Google sign-in.
Another owner starts with an empty collection and can create a tenant from the three required fields.

Tenant navigation shows one label per tenant.
The label is the display name when present, or the tenant ID when the display name is empty.
The mobile selector and detail heading use the same label.
The detail view also shows the tenant ID.

The workspace does not show a notification after tenant data loads.
The workspace shows authentication status as text.
A tenant with no active configuration cannot accept sign-ins, even when all required inputs are present.
A suspended tenant requires Resume tenant before authentication can continue.

Tenant and section selection use the URL fragment, which works on GitHub Pages without a route rewrite.
Anonymous bootstrap preserves bookmarked App, tenant, and section destinations through login.
Sign-out clears the destination from an established session.
The service authorizes each selected tenant before its details appear.

Configuration combines application addresses, Google sign-in, and tenant settings.
Session settings stay collapsed until selected or until a validation error requires attention.
Integration contains code examples, session-key export, and setup checks.
Valid Configuration edits apply automatically unless the tenant is suspended.
App and tenant names persist automatically. The name is the only inline metadata input.
The workspace shows validation errors and request failures. Automatic saves do not produce success announcements.
Transient failures retry without discarding edits.
The workspace updates on a timer, on reconnect, and when the page becomes visible.
It has no manual save, refresh, or reload buttons.

The avatar menu contains Admin for configured administrators.
That menu item opens the separate account-directory modal.
The modal loads its account list automatically. Escape or Close returns focus to the avatar.
Administrator access does not change tenant ownership or grant access to another workspace.

The Google form lists the exact Authorized JavaScript origins.
Other imported provider settings remain in the stored configuration.
Creation requires a name, application origin, and Google OAuth client ID.
The Create button stays disabled until all three fields are valid.
A successful creation makes the tenant active without another action.
The heading shows the App and tenant names. Each pencil icon edits its name inline.
Enter, Escape, or focus departure finishes a valid edit. Failed edits remain available for correction.
The authentication status control pauses or resumes authentication. Pause requires confirmation.
Configuration contains bounded session lifetimes. Integration shows the tenant ID.
The footer contains the Documentation link.

Background updates preserve pending edits.

Only fields that the user changes replace their stored values.
The latest accepted edit wins for each field.
Concurrent changes to untouched fields remain intact.
Validation errors apply only to the input version that produced the request.
Newer input retries automatically after an older request fails.
Temporary request failures, including rate limits, also retry automatically.

Account and tenant changes cancel pending requests and clear protected page state.

`make test-console-browser` drives Chromium against the real TLS service and test database.
Google token validation, DNS, the setup-check network destination, and the expiry clock are injected for routine acceptance.
`make test-console-pages` builds and checks the static artifact.
Live Google qualification and Pages publication remain separate operations.

## Application integration and key export

Integration reads the active revision. Accepted configuration edits update the public snippets automatically.
The generated browser page uses `https://tauth.mprlab.com/tauth.js`, an explicit tenant ID, and the customer API origin.
The [customer application example](../examples/tenant-app/README.md) supplies the complete proxy and validator instructions.
The browser and customer API must share a cookie site and scheme.
Their origins can differ. The TAuth service origin can belong to another site.
The proxy converts upstream cookies to host-only cookies on the customer API.
Google uses the browser frontend origin as its authorized JavaScript origin.
This first integration uses the Google credential callback and nonce exchange. It does not require a Google redirect callback URL.
See the [Google JavaScript reference](https://developers.google.com/identity/gsi/web/reference/js-reference) for the nonce and callback fields.

The Integration tab shows session key export for each active tenant.
A customer API origin and tenant Google client ID are not necessary for key export.
Those settings are necessary for browser examples and setup checks.
Key export uses the active revision, including when a newer configuration is not active.
Draft and suspended tenants cannot export a key.

Public settings contain the Google client ID, tenant ID, API origin, cookie name, session lifetime, and complete browser example.
They contain no session key, provisioning credential, or provider secret.
The backend receives the session key as base64. Decode it before validator construction.
Base64 is transport encoding and does not encrypt the key.
A session key permits token signing. Keep it in the backend secret store.

`POST /tenants/{id}/reauthentications` creates a five-minute transaction for `session-key-export`.
The transaction binds the owner account, tenant, active revision, operation, and Google nonce.
`POST /tenants/{id}/key-exports` verifies a new Google ID token for the console client and that transaction.
The token issue time must be within five minutes and cannot precede the transaction.
The verified Google subject must resolve to the current owner account.
A tenant change, revision change, expired transaction, different owner, or reused transaction prevents export.

Provisioning credentials cannot create or read authentication transactions or key exports.

The first successful export response contains `session_key_base64` and uses `Cache-Control: no-store`.
The resource Location, audit event, and idempotent retry contain metadata only.
If the first response is lost, start a new authentication transaction.
The workspace clears the displayed key on dismissal, expiry, tenant change, page exit, or logout.
It rejects late authentication and export responses after those transitions.
It stores no key in browser storage or URLs.

## Setup checks

`POST /tenants/{id}/setup-checks` accepts the active revision and its ETag.
The request cannot supply a destination URL, path, protocol, header, or credential.
The service uses the verified active API origin and a configured frontend origin.
Local development configurations cannot run server-side checks.

The checker resolves DNS once and rejects private, loopback, link-local, reserved, and mixed public/private answers.
It pins the accepted address for TLS connections and verifies the destination hostname.
It uses HTTPS, a three-second deadline, and a 16 KiB response limit.
It follows no redirects and uses no environment proxy.
It sends no owner cookie, session key, or provisioning credential.

The fixed checks require these results:

| Route | Result |
| --- | --- |
| `POST /auth/nonce` | `200`, exact credentialed CORS, and a nonce issued for this tenant. |
| `GET /me` | `401` with exact credentialed CORS. |
| `GET /private` | `401` with exact credentialed CORS. |

The checker consumes the returned nonce through the tenant nonce store.
It records the tenant, revision, time, state, and bounded evidence codes.
It does not store response bodies, cookies, DNS addresses, or secrets.
A retry returns the same result without another probe.
Integration shows the latest result for the active revision.
A new active revision requires a new check.

A successful setup check does not prove Google sign-in or protected application authorization.
Complete the browser acceptance steps separately.

## Session key replacement

Key replacement is an explicit operator cutover with one current key.
The operator supplies a new key to TAuth and every downstream session validator.
The CLI creates a new draft for a suspended tenant and does not activate that draft.
The owner must activate the new revision after backend installation.
Earlier revisions cannot be selected for activation.
The audit operation records the owner, tenant, and new revision without the key.

1. Stop tenant changes in the console and Gateway.
2. Record the owner ID, tenant ID, latest revision, and affected backend instances.
3. Put protected application routes into maintenance and stop traffic to all old validator instances.
4. Suspend the tenant and wait for a successful response.
5. Stop the TAuth service and back up the database with its encryption-key reference.
6. Generate a new key in the operator secret store. Use at least 32 random bytes encoded as hexadecimal text.
7. Base64-encode that exact text for transport. Keep the encoded value in a private operator input file.
8. Run the command below with the recorded owner, tenant, and latest revision.
9. Install the same base64 value as `TAUTH_SESSION_KEY_BASE64` in every backend instance.
10. Replace all old validator instances before you resume protected traffic.
11. Restart TAuth and sign in to the console.
12. Resume the tenant with the new revision.
13. Confirm that an old session token fails validation and a new Google login reaches the protected API.
14. Run a new setup check and resume application traffic.
15. Keep Gateway convergence paused for this tenant. Its earlier contribution revision must not overwrite the operator change.
16. Remove the temporary key input and record the cutover result without secret values.

```sh
tauth --config service.yaml tenant-key-replace \
  --owner-id "$OWNER_ID" --tenant-id "$TENANT_ID" --revision "$REVISION" \
  < replacement.key.b64
```

The command rejects an active tenant, incomplete suspension, different owner, stale revision, invalid key, or unchanged key.
It reads the key from standard input and prints a secret-free draft receipt.
If any step fails, keep the tenant suspended and the customer routes in maintenance until the installation is completed.
Manual key replacement creates a deliberate Gateway revision conflict for a provisioned tenant.
This delivery does not provide an operation to adopt a conflicting producer revision.
Console management remains available after the cutover.

The new active revision uses only the replacement key.
Every validator must reject the previous key after the cutover.
Suspension revokes refresh credentials before this operation.

Ordinary logout removes the browser cookies and revokes the addressed refresh credential.
A copied access cookie can remain valid at an offline validator until its original expiry.
Managed session lifetimes range from one minute through one hour. Imported tenants retain their configured lifetime until changed.
Suspension alone has the same offline access-cookie limit.
Key replacement ends that acceptance when every validator uses the new key.

## Production delivery record

Local issue acceptance and production operations have separate records.
Do not use deterministic Google fixtures as evidence of live-provider connectivity.
Record these inputs before production work:

| Input | Required record |
| --- | --- |
| TAuth release | Exact released version and source revision with F008. |
| Gateway release | Exact released version and source revision with F017. |
| Website artifact | Image digest, Pages repository, `gh-pages` publication, and selected release marker. |
| Console Google client | Client ID, exact JavaScript origin, and provider project reference. |
| Service | Database URL reference, database backup, encryption-key reference, API origin, and one runtime instance. |
| Destination owner | Verified Google identity, stable console subject, and resulting owner account ID. |
| Retained data | Database backup, existing cutover receipts, tenant inventory, and validator references. |
| Gateway credential | Secret-store reference, owner, operations, and tenant grants. |
| Customer acceptance | Frontend origin, API origin, Google client, tenant ID, and backend release. |

The following list describes acceptance evidence. It is not an additional deployment procedure.
Use the three production commands above to prepare, publish, and deploy the release.

- Release evidence identifies the exact Gateway version, TAuth version, website artifact, and selected release marker.
- Retention evidence identifies the backup, existing receipts, owner identity, tenant inventory, and preserved tenant settings.
- Deployment evidence identifies the database configuration, single runtime instance, health checks, and repeated resource convergence.
- Website evidence identifies the `gh-pages` publication, public `/.mprlab-release.json` marker, API origin, and console bootstrap response.
- Software acceptance covers isolated ownership, immediate tenant authentication, protected access, refresh, logout, cookie attributes, and denied origins.
- Live Google qualification records provider connectivity and the destination owner's public console login separately.

B143 removed the completed data-transfer tools.
Existing completion receipts remain historical evidence.

A failed check leaves the associated production record incomplete.
Keep tenant changes frozen if database retention or Gateway verification fails.
Correct the current contract before retry. Do not restore runtime tenant YAML as a second configuration authority.

## September 27, 2026 local correction record

B093 removes the personal-email and first-owner enrollment rules.
F016 adds the configured administrator account directory and keeps every workspace owner-scoped.
I213 moves migration code outside the application into a separate deployment executable.

The local GORM schema cleanup removed the obsolete first-owner column and foreign key.
A comparison of all 33 database tables found no changes to other stored values.
The local database contains one existing console account and no application tenants at this checkpoint.
The updated local stack is active at `http://localhost:8081/app/`.
Its console uses the operator-selected Google client ID `212947889486-vr99ionvvoie1ke2ee8qelv34oglseoj.apps.googleusercontent.com`.
The administrator email list contains the two spellings approved by the operator.

Focused HTTP, deployment migration, Chromium, and full `make ci` checks passed.
The operator previously confirmed live Google authentication. A new live session after this update is not part of automated acceptance.
The production tenant transfer, production administrator configuration, release, publication, and deployment have not run in this correction.
The current production command contract supersedes this historical manual cutover procedure.

# Tenant console operations

F008 defines the tenant console delivery. F009 adds the owner database and console bootstrap.
The console tenant is `tauth-console`. Application tenants cannot change its configuration.
The console permits Google login, session restore, refresh, logout, and profile reads.
Account linking and password routes are unavailable for this tenant.

## Service inputs

Set `server.database_url` to the persistent database URL.
Set `server.tenant_encryption_key` to a base64 value that contains 32 random bytes.
Keep this key in service secret configuration. Keep a separate protected backup with the database recovery inputs.
The service uses AES-256-GCM for stored secret values.
Each application secret binds its ciphertext to the tenant, secret ID, purpose, and encryption key ID.

The console configuration is encrypted in the database.
The database keeps owner accounts separate from application accounts.
Each owner binding contains the session issuer, reserved console tenant ID, and authenticated subject.
The owner account ID remains the same after an email change.

## Bootstrap order

1. Create a Google Web client for the console.
2. Add the exact console origin to the Google client's authorized JavaScript origins.
3. Add the same origin to `server.cors_allowed_origins`.
4. Create a private console tenant file with the fields below.
5. Supply the persistent database URL and encryption key through the service configuration.
6. Run the bootstrap command.
7. Start TAuth with the same service configuration.
8. Authenticate through Google in the reserved console tenant.
9. Send `PUT /api/management/owner-account` with the console session cookie.
10. Record the returned owner account ID for the later import.

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

The current account configuration requires Pinguin settings. The console does not expose password or linking operations.
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

Production import, Gateway cutover, publication, and deployment remain separate operations under I212 and F011 through F013.

## Deployment data migration

Tenant migration is a one-off deployment routine outside the application.
The service has no import command, migration owner, first-owner rule, or personal account rule.
The separate `deployment/tenantownership` executable uses GORM transactions and its Migrator API.
It is not included in the TAuth service image or invoked at service startup.
GORM `AutoMigrate` creates the receipt schema. The deployment routine explicitly performs the data writes.

The runtime rejects the `tenants` YAML field, including an empty array.
Its database contains every active application tenant and the reserved console configuration.
Tenant environment inputs have no effect after migration.
The database and encryption key remain required service inputs.

1. Inventory every production tenant from the frozen effective configuration.
2. Back up the production database and its encryption-key reference.
3. Initialize the current schema and console configuration against a copy of that database.
4. Enroll the destination owner through verified Google login and record its stable owner ID.
5. Stop all TAuth writers and Gateway provisioning during the migration.
6. Supply the frozen source and its referenced environment inputs to the separate migration executable.
7. Inspect the source and compare all tenant IDs with the production inventory.
8. Run the migration against the deployment database with the recorded owner ID.
9. Save the receipt and compare tenant settings, owners, users, identities, and sessions with the backup.
10. Start the database-only service and verify application login, refresh, logout, and protected requests.
11. Resume Gateway provisioning with the matching F011 client.
12. Remove the deployment migration routine and private source after all target databases complete the migration.

```sh
make deployment-migration MIGRATION_ARGS="--config service.yaml --source tenants.import.yaml --inspect"
make deployment-migration MIGRATION_ARGS="--config service.yaml --source tenants.import.yaml --import-id production-tenants --owner-id $OWNER_ID"
```

Run the migration where the deployment database is accessible, with all writers stopped.
For a remote deployment, run `make build-deployment-migration` with the target `GOOS` and `GOARCH`.
Transfer `.cache/tenant-ownership` as a separate deployment artifact.
The installed Gateway has no application data-migration hook. Run this step in the controlled cutover procedure before service acceptance.
An ordinary `make deploy` does not execute it. Do not declare the cutover complete without its receipt and data comparison.

The destination is an ordinary owner account. The migration does not grant administrator access.
Select the operator's verified owner ID for this production transfer. Do not encode their email in application behavior.
The transaction preserves effective keys, cookies, providers, policies, and lifetimes.
It does not change application accounts, identities, refresh sessions, provider credentials, or OAuth grants.
All tenant writes and the completion receipt commit together.
An identical retry returns the receipt. A changed source, destination, or conflicting tenant ID fails without partial tenant writes.
The receipt stores a keyed source digest and contains no secret values.

The migration also removes the obsolete `console_bootstraps.initial_owner_id` field through GORM.
For an installation with no application tenants to migrate, run only the schema cleanup:

```sh
make deployment-migration MIGRATION_ARGS="--config service.yaml cleanup-schema"
```

Production migration, publication, deployment, and live-provider qualification remain separate acceptance records.

## Tenant management

F010 adds owner resources under `/api/management/tenants`.
The [OpenAPI document](openapi.yaml) defines the request and response fields.
All cookie requests require the exact console Origin. Mutations also require `X-TAuth-CSRF: 1`.
Send JSON with `Content-Type: application/json`.
Responses use `Cache-Control: no-store`. CORS exposes `ETag` and `Location`.

Create a draft with a name and optional environment label.
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
Configuration PUT creates an immutable draft revision.
It preserves imported provider and account fields outside the editable Google, origin, and lifetime settings.
The active revision remains in use until activation succeeds.
Session lifetimes range from one minute through one hour. Refresh lifetimes cannot exceed 90 days.

### Origin verification

Production addresses require HTTPS and DNS hostnames.
Create an origin proof for each frontend and API hostname in the saved revision.
Publish its exact TXT name and value in DNS.
Create a verification under `/origin-proofs/{id}/verifications` after DNS publication.
The service performs a DNS lookup with a five-second deadline.
Each proof expires after 15 minutes and applies to one tenant and revision.
A tenant can have up to 20 unexpired challenges.
Read the proof or verification Location to obtain its current result.

Activation requires verified proofs for new production hostnames.
Imported origins retain their operator-approved provenance.
The service rejects reserved console hostnames and hostnames that another active tenant uses.
Local development permits localhost, `127.0.0.1`, and `::1` without DNS proof.
Enable the explicit local development setting and the service tenant-header setting.
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

F011 requires the Gateway client implemented by F017 in the primary Gateway repository.
No released version is allocated by this source change.
Before production cutover, record the exact released Gateway version that contains F017.
A Gateway release without that client cannot operate the database-only tenant contract.

Create credentials through `/api/management/provisioning-credentials` with the owner cookie, console Origin, and CSRF header.
Supply a name, permitted operations, explicit tenant IDs, and the `allow_create` grant.
Operations are `read`, `configure`, `activate`, `suspend`, and `proofs`.
A creation grant adds each created tenant to that credential's tenant grants.
The service stores a digest and shows the generated token once.
A repeated creation request returns metadata without the token. Revoke a lost token and issue another.
DELETE revokes the credential. GET returns metadata only.

The Gateway client sends `Authorization: Bearer <token>` without browser cookies or Origin.
Store the token in the operator's private environment as `MPRLAB_TAUTH_PROVISIONING_CREDENTIAL`.
Set `MPRLAB_TAUTH_MANAGEMENT_URL` to the TAuth service origin.
Never place the token in a manifest, public output, URL, or browser configuration.

Gateway sends an exclusive `provisioning` configuration object with the contribution and application generation.
A machine request with the console shape or a null `provisioning` value returns `422`.
The API validates the contribution through the same TAuth native configuration parser used by the renderer.
Activation uses the shared management activation service and origin proofs.
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

Use this ordered production cutover:

1. Record the released TAuth and Gateway versions, database backup, service encryption key reference, and initial console inputs.
2. Stop Gateway tenant changes. Preserve each existing validator key, cookie setting, and private output reference.
3. Complete console bootstrap, destination owner enrollment, and the bounded import described above.
4. Verify imported ownership, provider settings, cookies, refresh behavior, and downstream validator values.
5. Issue the scoped Gateway credential and set its private operator inputs.
6. Install the recorded Gateway release. Run one selected tenant convergence and repeat it to verify the stable revision.
7. Verify DNS proofs for new origins. Resolve any concurrent console revision conflict through the owner before another request.
8. Resume tenant changes. Record production import, publication, deployment, and live-provider qualification separately.

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
Another owner starts with an empty collection and can create a named draft.
Tenant and section selection use the URL fragment, which works on GitHub Pages without a route rewrite.
The service authorizes each selected tenant before its details appear.

Save changes in Domains, Sign-in methods, or Settings to create a draft revision.
The Google form lists the exact Authorized JavaScript origins.
Other imported provider settings remain in the stored configuration.
Publish DNS TXT proofs from Domains. Verify each proof before activation.
Activate the saved configuration from Overview.
Settings supports rename, bounded session lifetimes, and confirmed suspension.
A revision conflict preserves the form values and requires an explicit reload.
Account and tenant changes cancel pending requests and clear protected page state.

`make test-console-browser` drives Chromium against the real TLS service and test database.
Google token validation, DNS, the setup-check network destination, and the expiry clock are injected for routine acceptance.
`make test-console-pages` builds and checks the static artifact.
Live Google qualification and Pages publication remain separate operations.

## Application integration and key export

Integration reads the active revision. A newer draft does not change the public snippets.
The generated browser page uses `https://tauth.mprlab.com/tauth.js`, an explicit tenant ID, and the customer API origin.
The [customer application example](../examples/tenant-app/README.md) supplies the complete proxy and validator instructions.
The browser and customer API must share a cookie site and scheme.
Their origins can differ. The TAuth service origin can belong to another site.
The proxy converts upstream cookies to host-only cookies on the customer API.
Google uses the browser frontend origin as its authorized JavaScript origin.
This first integration uses the Google credential callback and nonce exchange. It does not require a Google redirect callback URL.
See the [Google JavaScript reference](https://developers.google.com/identity/gsi/web/reference/js-reference) for the nonce and callback fields.

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
Integration shows the latest result for the active revision and identifies saved changes that still require activation.
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
12. Verify the required DNS proofs for the new revision, then activate it.
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
| Import | Frozen source inventory, import ID, receipt, tenant count, and effective validator references. |
| Gateway credential | Secret-store reference, owner, operations, and tenant grants. |
| Customer acceptance | Frontend origin, API origin, Google client, tenant ID, and backend release. |

Use this delivery order:

1. Record the released Gateway version with F017 and the released TAuth version with F008.
2. Freeze tenant changes and back up the active database and private configuration references.
3. Complete the console bootstrap and verify the destination owner's live Google identity.
4. Inspect and import the complete frozen tenant collection through the separate deployment migration procedure.
5. Compare the import receipt, tenant count, provider configuration, cookies, and effective validator keys with the inventory.
6. Install the database-only service configuration and restart the single TAuth instance.
7. Complete doctor, preflight, existing application login, refresh, and protected-request checks.
8. Configure the scoped Gateway credential and verify a repeated convergence with no revision change.
9. Publish the Pages artifact through the declared `github_pages` resource and `gh-pages` branch.
10. Read the public `/.mprlab-release.json` marker and compare it with the selected website release.
11. Open `/app/` and verify the public API origin and console bootstrap response.
12. Complete live Google login as the destination owner and compare the imported tenant collection with the receipt.
13. Use another owner to create, configure, prove, and activate an isolated acceptance tenant.
14. Install its customer application and complete Google login, protected access, refresh, and logout through the public origins.
15. Confirm the cookie attributes, expected tenant check, denied origin response, and setup-check evidence.
16. Record service deployment, website publication, import, and live Google qualification as separate outcomes.
17. Resume tenant changes after all selected production checks pass.
18. Remove the bounded importer through the separately reviewed cleanup change after verified production migration.

A failed check leaves the associated production record incomplete.
Keep tenant changes frozen if the database cutover or Gateway verification fails.
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
Use the deployment data migration procedure above at production cutover. Record the destination owner ID and all production tenant IDs in its receipt.

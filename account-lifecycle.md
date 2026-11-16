# Account lifecycle

Application accounts belong to one tenant.
Provider bindings and public user IDs follow the [application subject contract](application-subjects.md).
Account management controls signup, verification, recovery, password changes, identity links, profile changes, disablement, and erasure.

The tenant must configure Pingwin for email challenges.
The [usage guide](usage.md#55-emailpassword-accounts) defines signup and credential operations.
These operations do not manage console owner accounts.

## Disablement

TAuth rejects OAuth authorization and token exchanges for accounts in
`disabling` or `disabled` state.
The account disable endpoint revokes consent grants and refresh-token families
and removes outstanding authorization codes for that tenant and account.
Existing access tokens remain valid until their configured expiry.

Account lookup failures do not consume authorization codes or refresh tokens.

If credential revocation fails, the account remains in `disabling` state and
cannot become active. The same authenticated disable request can resume
revocation. Server startup resumes persisted disablements before the server
accepts traffic. This process also revokes application refresh tokens.

## Account display name

`PATCH /auth/account` accepts `{"display_name":"Parent Name"}` with the tenant session cookie.
The tenant must enable `account_management.enabled`.
The server removes outer whitespace. The name must contain 1 to 200 characters and no control characters.

The server rejects email changes and unknown fields with HTTP 400.
Invalid names return HTTP 422. Unsupported media types return HTTP 415.

The HTTP 200 response contains the current account profile with `Cache-Control: no-store`.
The server keeps the explicit name across refresh and future provider login.
The account and its stored user profile update in one database transaction.

`GET /auth/session` reads the current account name.
Previously issued session tokens keep their signed claims until refresh or login issues a new token.
The operation does not change verified email credentials or tenant console owner accounts.

## Account erasure

`DELETE /auth/account` accepts `{"status_key":"CLIENT_GENERATED_KEY"}` as JSON.
Generate the key from 32 random bytes. Encode it as base64url without padding.

Save the key before the first request. Send the tenant session cookie on that request.
The tenant must enable `account_management.enabled`.

Unknown JSON fields return HTTP 400. Invalid keys return HTTP 422.

The HTTP 202 response contains `operation_id`, `state`, `reason`, `created_at`,
`updated_at`, `expires_at`, `account_state`, and `provider_revocations`. Its Location is `/auth/account-erasure`.
Read that resource with `Authorization: Bearer CLIENT_GENERATED_KEY`.

Status reads return HTTP 200 and use `Cache-Control: no-store`.
Keep the key private. Do not put it in a URL or log it.

The server stores its hash. It does not store the key.

A repeated DELETE with the same tenant and key returns the existing operation,
even after session revocation or a lost response. An unknown key requires a valid
session before operation creation. A second key for the same account returns
HTTP 409 with `status_key_conflict`. Status reads cannot create an account.

Unknown keys and expired receipts return HTTP 404.

The operation states are `pending`, `running`, `blocked`, and `completed`.
A blocked operation has one of these reasons: `provider_revocation_unavailable`,
`provider_revocation_failed`, `oauth_purge_failed`, `refresh_purge_failed`, or
`user_purge_failed`, or `apple_revocation_manual_action_required`. Incomplete operations do not expire. A completed receipt
expires after 30 days. Completion removes its account ID and phase details.

The server removes expired receipts during automatic recovery.

Initiation puts the account in `erasing` in the same transaction as operation
creation. Account login, profile changes, identity linking, password changes,
credential seeds, and dependent token writes cannot reactivate that account.
Configured password credentials return HTTP 409 with `configured_credential`
before initiation. That conflict keeps the account active and creates no operation.

Tenant configuration and console owner accounts remain intact.

Each phase records durable progress. Recovery runs at startup and every 30 seconds,
with at most 25 operations per scan and retry delays from 30 seconds to one hour.
A fenced lease prevents an expired worker from completing another worker's job.

Each phase has a 15-second deadline. The supported storage contract requires
canonical database user profiles and database refresh and OAuth stores for the
same selected database URL. Unsupported store combinations return HTTP 503.

Account removal and provider revocation have separate durable results.
`account_state` is `retained` or `removed`.
`provider_revocations` contains one entry for each required provider, in provider name order.

Each entry contains `provider` (`apple` or `github`) and `state` (`pending`, `manual_action_required`, or `revoked`).
Only Apple can require manual action. An empty array means no required provider revocations.

`completed` requires account removal and every required provider revocation.

Initiation copies the encrypted provider grants into the operation before account removal.
Account removal deletes profiles, identities, passwords, challenges, provider credential rows, and application refresh rows.
It also deletes OAuth authorization codes, consents, and refresh grants.

Pending operations keep only the minimum encrypted revocation context and operation fences.
The HTTP routes and background worker use the same Apple revoker.
Apple HTTP 200 confirms token revocation, including an already invalid token.

A failed provider request leaves provider revocation pending after account removal.
The worker repeats the request automatically.
Stored GitHub grants remain pending until a qualified GitHub revoker is available.

Local removal does not count as provider revocation.

Accounts without stored Apple grants still get local account removal.
Their Apple entry becomes `manual_action_required`.
Use [Apple's manual revocation instructions](https://support.apple.com/en-us/102571) to remove the app authorization.

Manual provider revocation can remain pending.
An ordinary Apple login cannot bypass an incomplete operation fence.

These provider rules follow [Apple TN3194](https://developer.apple.com/documentation/technotes/tn3194-handling-account-deletions-and-revoking-tokens-for-sign-in-with-apple).

Completion does not delete RevenueCat records or backups. Previously issued
access tokens can remain valid in an offline verifier until their expiry.
Database schema version 9 adds encrypted grant storage and provider outcomes through automatic startup migration.

The migration preserves existing accounts and marks earlier completed receipts as removed.

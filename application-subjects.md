# Stable Application User IDs

B125 separates the public user ID from the internal account ID.
The public user ID identifies an account to an application and its external records.
The internal account ID identifies TAuth account resources.
Both identifiers remain fixed after allocation.

## Identity Contract

- Store one public user ID for each tenant account.
- Resolve an authenticated public user ID through its exact tenant-scoped stored relation.
- Keep the internal account ID as an opaque 128-bit base64url value.
- Give each new account an opaque public user ID in either account-management state.
- Preserve every existing persisted public user ID through the deployment migration.
- Keep provider subjects separate from public user IDs and internal account IDs.
- Use verified provider bindings for account association. Do not associate accounts by email.
- Keep the public user ID unchanged after an email change, profile correction, feature change, or service restart.
- Use the same public user ID for login responses, session claims, refresh ownership, and OAuth ownership.
- Keep account disablement and erasure effective in either account-management state.

`account_management.enabled` controls account-management capabilities.
It does not select the identity format or allocate a different identity.
Account routes resolve the session subject to the internal opaque account ID before the account operation.
Runtime identity resolution uses one stored relation. It does not parse provider prefixes or try alternative identifiers.

`MountAuthRoutes` requires an explicit account store for provider routes without password credentials.
Use the same database store for account records and user profiles.
If an operator adds a removed password credential again, use its existing provider identity and keep both identifiers.
Write configured profile changes during the credential write. Keep explicit display overrides.

An application can continue to use its existing user ID as an external record key.
For example, Kamu uses `tauth:<user-id>` as its RevenueCat customer key.
The migration preserves that key. It grants no subscription or other application access.

## Existing Database Migration

The timestamped migration identifier is `20261006-application-subjects`.
The normal deployment procedure runs this migration automatically once.
The migration remains separate from normal service startup.

1. Validate the sealed migration inputs and the existing completion receipt.
2. Stop database writers and reject unrelated active writers.
3. Back up the stopped database.
4. Create a private database candidate from that backup.
5. Preserve existing public IDs, internal account IDs, provider bindings, roles, profile overrides, and account states.
6. Create account records and exact identity bindings for existing provider-derived user profiles.
7. Reject duplicate public subjects and conflicting account associations before commit.
8. Commit the canonical data and completion receipt together.
9. Publish the candidate database atomically.
10. Resume the standard deployment procedure.

The migration uses provider-derived identifiers only to convert existing persisted data.
The current runtime does not retain that conversion path.
A completed deployment retry reads the receipt and makes no migration changes.
A failed candidate leaves the original database unchanged.
An unmigrated or inconsistent existing database prevents service startup.
Startup rejects unmapped profiles and credential/account/public-ID mismatches.
It also rejects dangling provider links and pending erasure mismatches.
Password login reads the canonical account. It does not convert an old credential at runtime.

The migration preserves tenant signing keys, server encryption keys, refresh ownership, and existing application records.
It does not recover a historical public ID that an earlier migration already replaced.
The migration requires current opaque internal account IDs. It rejects obsolete internal account IDs.
Ambiguous or already split account records require an explicit data disposition before migration can succeed.

## Validation

- Compare the public user ID before and after account-management changes through public HTTP endpoints.
- Verify the same subject after refresh, session restoration, and service restart.
- Verify account operations through the mapped internal account ID.
- Verify Google, Apple, GitHub, and password entry paths.
- Verify that different provider subjects with the same email remain separate.
- Verify tenant isolation and disabled-account rejection.
- Verify that erasure removes the mapped account and revokes credentials for the preserved public subject.
- Verify deployment migration repeat, conflicts, interrupted candidates, and atomic completion receipts.

Software validation does not establish production activation.
Use the [deployment procedure](tenant-console-operations.md) for the operator handoff.

## October 6 Local Validation

The public HTTP regression first reproduced the account-management user ID change.
The repaired authentication suite passes with persistent SQLite and controlled provider responses.
It covers Google browser and native entry points, Apple, GitHub, password, refresh, restart, account operations, and tenant isolation.
Migration tests verify exact existing subjects, conflict rejection, failed-candidate rollback, and repeat behavior.

Final `make ci` passes all 13 declared targets.
The separate `make test-deployment-migration` target also passes.
Validation uses automated Chromium, SQLite, local Docker, and Ansible.
The command removes its temporary caches and disposable Docker builder after validation.
Independent final review accepts the source repair and local validation without blocking findings.

Production uses the normal release, publish, and operator deployment procedure.
The source validation does not establish actual provider qualification for Kamu account rights.

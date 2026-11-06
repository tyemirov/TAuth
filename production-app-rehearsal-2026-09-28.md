# Production App Migration Rehearsal

I222 tested the current TAuth source against an isolated production database copy.
The data migration passed.
At this rehearsal, B106 blocked production deployment because Gateway v4.7.1 used one credential across Apps.
The rehearsal made no production changes.

## Source And Inputs

| Input | Verified value |
| --- | --- |
| TAuth source | `7adb0c5999f8af04b1426d263a1060df54b21b79` |
| Installed Gateway | `v4.7.1`, source `9e7bb6b79049f260fb8811675df92a38fd9e025f` |
| Production image | `ghcr.io/tyemirov/tauth:2.2.5` |
| Database capture | `2026-09-27T00:42:36.174479+00:00` |
| Database SHA-256 | `e770dc6d5fcef068d2982a1913f09b479cfa8f673dcfa15db92d1593d6a28513` |
| Configuration SHA-256 | `adfa8984280749acd1765a2c92411aba2a48cef8571ef034cf77671f032dd0ee` |
| Production tenants | 20 |
| Existing user profiles | 30 |
| Destination Apps | 20 |

A read-only production check confirmed the same image, container identity, start time, and configuration digest as the original capture.
The database copy retains its original capture time.
A deployment must use a fresh database backup after writers stop.

The [App mapping](../deployment/migrations/production-apps-20260928.json) assigns every captured tenant to one named App.
Each production App has one tenant in this capture.
Local development tenants are absent from the production capture.
The separate local inventory contains 28 tenants under 19 Apps.

## Executed Checks

1. Copied the captured database and configuration into an isolated local directory.
2. Created a separate encryption key and console configuration.
3. Enrolled an ordinary owner through the real HTTP API with an injected Google identity validator.
4. Stopped the service before each deployment import.
5. Imported each App through the separate deployment command with explicit owner, App, and import identifiers.
6. Repeated every import and compared the receipts.
7. Started the service with all imported tenant origins.
8. Checked tenant routing for all 20 tenants.
9. Checked sessions, refresh, logout, and downstream JWT validation for all 30 existing profiles.
10. Created a database backup, restored it, and started the service again.
11. Checked App membership, active tenant state, and isolation from another owner through HTTP.
12. Issued one credential per App and checked access to its tenant.
13. Confirmed that each credential rejected access to another App.
14. Ran the installed Gateway client twice per App with captured contributions and generations.
15. Compared effective tenant settings before import and after Gateway operations.
16. Ran `doctor`, `preflight`, migration tests, and repository CI.

All 20 tenants remained active.
Every repeated import returned the original receipt.
Every second Gateway operation reported no change.
Effective tenant configuration remained equal, including signing keys, providers, origins, cookies, session durations, and tenant-header policy.
The comparison covered every original authentication table immediately before and after import.
All rows in those tables remained equal.
The session checks used fresh test tokens with the captured signing keys and existing profile identities.
They did not use captured browser cookies.

The service started three times, including once from the restored backup.
The migration and HTTP checks completed in approximately five seconds, excluding compilation and repository CI.
This duration does not estimate production downtime.

## Previous Console Schema

A second isolated copy exercised the `app-hierarchy` deployment command.
Its input was the retained local database from before F017, with 22 tenants and no provisioning credentials.
The command created 19 Apps from the explicit local mapping.
A repeated command succeeded without changes.
All original table columns retained their data, except obsolete management idempotency receipts that the migration intentionally removes.
The resulting database passed the foreign-key check.
Migration tests separately covered active and revoked credentials whose owners have no tenants, including invalid owner assignments.

## Deployment Blocker

B106 records a mismatch between App-scoped credentials and the installed Gateway deployment procedure.
Gateway v4.7.1 passes the full tenant contribution set to one client with `MPRLAB_TAUTH_PROVISIONING_CREDENTIAL`.
TAuth binds that credential to one App.
The client can provision the matching App, but it cannot provision another App.

The rehearsal reproduced this failure with the installed client and all 20 captured contributions.
The client returned `management.creation_denied` after the first App.
The credential could not list the next App's tenant, so the client attempted an unauthorized tenant creation.
Direct access to another App also returned HTTP 403.
Separate calls with the correct credential for each App passed for all 20 tenants.

Before production deployment, the Gateway must select the correct credential for each App and its contributions.
It must apply the same scope to removed contributions.
Do not expand TAuth credentials across Apps to bypass this boundary.
The deployment qualification must then repeat the complete contribution operation through the installed Gateway.

## Reproduction And Evidence

Private inputs, databases, test code, and logs remain under `.cache/production-app-rehearsal-i222/`.
That directory is ignored by Git and contains secrets.
The temporary Go overlay uses the current service, migration command, stores, and HTTP handlers.
Only the Google identity validator is injected.
The Gateway client comes from the installed v4.7.1 runtime.

The executed repository targets were:

```sh
TAUTH_REHEARSAL_ROOT="$PWD/.cache/production-app-rehearsal-i222" \
GOFLAGS="-overlay=$PWD/.cache/production-app-rehearsal-i222/overlay.json" \
make test-console
make test-deployment-migration
make ci
```

The private evidence includes `result.json`, `row-comparison.json`, `previous-schema-comparison.json`, import receipts, and per-tenant Gateway results.
`production-identity.log` records the read-only production check.
`test-console.log`, `migrations.log`, and `ci.log` record validation results.

## Production Boundary

This rehearsal qualifies the copied data migration and current application behavior.
It does not qualify the complete installed Gateway deployment, live Google enrollment, or live provider operations.
No release, publication, production import, or deployment ran.

The [installed release qualification](production-release-qualification-2026-09-30.md) subsequently resolved B106.
Use the [deployment data migration procedure](tenant-console-operations.md#deployment-data-migration) for the controlled cutover.
Enroll the real owner through verified console login and pass its stable account ID explicitly.
Prepare the production console configuration and encryption key.
Keep the captured tenant signing keys and provider settings.
Take a fresh database backup after writers stop, then rerun the tested migration with that backup.

## Gateway Source Correction

Gateway B595 extends the retained F017 client under the P005 cutover plan.
The corrected handler selects a private credential for each contribution owner and resource ID.
It includes removed contributions and rejects missing or malformed entries before tenant mutations.
The production descriptor still targets TAuth v2.2.5 until the coordinated release.

A second isolated rehearsal used the corrected Gateway source and all 20 captured production contributions.
The real shared Ansible handler completed the combined operation with 20 App-specific credentials.
A second operation returned the same tenant revisions and reported no changes.
The effective tenant settings remained equal to the captured configuration.
Migration retry, three starts, backup restoration, owner isolation, and sessions for 30 existing profiles passed again.
The private evidence is under `.cache/production-app-rehearsal-b106/`.

TAuth's real-service client acceptance now uses two separate Apps and two credentials.
It verifies tenant membership, stable revisions, and an HTTPS origin without DNS proofs.
Gateway and TAuth final `make ci` passed after the source correction.
The source rehearsal used installed Gateway v4.7.1.
On 2026-09-30, installed Gateway v5.0.0 and sealed TAuth v2.2.6 passed the complete handler rehearsal.
The [qualification record](production-release-qualification-2026-09-30.md) contains the results and the remaining production operations.

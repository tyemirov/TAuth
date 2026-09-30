# Installed Release Qualification

B106 passed on 2026-09-30.
Installed Gateway v5.0.0 managed all 20 imported Apps through the sealed TAuth v2.2.6 container.
The rehearsal used isolated local database copies.
No production data or runtime changed.

## Verified Inputs

| Input | Value |
| --- | --- |
| TAuth release | `v2.2.6` |
| TAuth source | `84458b8a6e5cbafb4433e71c4b928b81aeb2dd08` |
| Gateway release | `v5.0.0` |
| Gateway source | `6d0f3942e2ea1f732e6fbbb57e0b08487064bec3` |
| Gateway platform | `darwin-arm64` |
| TAuth test environment | Docker, `linux/arm64`, with real HTTP requests |
| Container digest | `sha256:779be3d3cf3c6cd584fb0f3aa1fcd2b9f0c964abebeb48b9cc3001a27cd748fc` |
| Release receipt SHA-256 | `ddaf5740ace88caad1de830861f4faef86eabb4de56f28e1b51a0a54b2168e46` |
| Database capture | `2026-09-27T00:42:36.174479+00:00` |
| Database SHA-256 | `e770dc6d5fcef068d2982a1913f09b479cfa8f673dcfa15db92d1593d6a28513` |

The loaded container digest matched the sealed archive.
The current Go source matched the captured release source.
The separate migration executable used that source.

## Input Corrections

The private import source contained 18 obsolete `return_challenge_tokens` fields.
The captured Gateway contributions contained the same 18 fields.
The rehearsal removed these fields from both private copies.
The original capture stayed unchanged.
The current contract delivers account challenges through email.

Credential creation and initial convergence used separate one-minute mutation budgets.
An immediate operation after fixture setup correctly returned `management.mutation_rate_exceeded`.
The final run waited for the setup budget to expire before convergence.

The container used explicit service origins for the console and existing CORS exceptions.
Active tenant origins came from the database.
The copied static application origins initially prevented suspension under B090.
The documented CORS correction permitted suspension without a change to tenant settings.

## Results

- Imported 20 tenants into 20 Apps.
- Repeated each import with an unchanged receipt.
- Preserved every row in all 13 original database tables during import.
- Preserved effective provider settings, session keys, cookies, and tenant policies.
- Started the migrated service three times and restored its backup.
- Verified sessions, refresh, logout, and downstream validation for 30 profiles.
- Verified owner isolation through HTTP.
- Ran the installed shared Gateway handler with 20 separate App credentials.
- Repeated the complete operation with unchanged revisions.
- Rejected cross-App credential access with HTTP 403.
- Rejected a missing credential map before tenant changes.
- Suspended one removed contribution through its App credential.
- Repeated removal with no changes and retained 19 active tenants.
- Verified the sealed container health endpoint with HTTP 200.

`make test-console` passed with the private rehearsal overlay.
Private databases, credentials, test code, and logs remain under `.cache/production-app-rehearsal-b106-installed/`.
The source result is `result.json`. The container result is `artifact-result.json`.
`row-comparison.json` records the original table comparisons.
`final-test-console.log` records the complete successful run.

The private overlay requires the retained rehearsal inputs.
Run its repository target with the recorded package:

```sh
TAUTH_REHEARSAL_ROOT="$PWD/.cache/production-app-rehearsal-b106-installed" \
TAUTH_REHEARSAL_GATEWAY_PACKAGE="$HOME/.local/share/mprlab-gateway/releases/v5.0.0/darwin-arm64" \
GOFLAGS="-overlay=$PWD/.cache/production-app-rehearsal-b106-installed/overlay.json" \
make test-console
```

The source rehearsal injected the Google identity validator.
The container checks used imported accounts and test session tokens.
Neither check proves live Google connectivity.

## Remaining Production Operations

TAuth v2.2.6 is sealed locally. Publication and production deployment have not run.
The canonical deployment file has no `TAUTH_TENANT_ENCRYPTION_KEY` assignment.
The operator file has no `MPRLAB_TAUTH_MANAGEMENT_URL` or `MPRLAB_TAUTH_PROVISIONING_CREDENTIALS` assignment.
Existing local test keys are not production inputs.

Use the [production cutover procedure](tenant-console-operations.md#gateway-provisioning-and-cutover).
Complete verified owner enrollment and prepare the App credentials.
Record the production encryption key and console configuration.
Stop writers before capture of a fresh backup and the bounded import.
Preserve existing tenant keys, providers, cookies, and ownership assignments.
Record import, publication, deployment, and live-provider qualification separately.

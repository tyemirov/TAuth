# Automatic deployment qualification

F018 implements the [production command contract](tenant-console-operations.md#production-command-contract).
The production application procedure is `make release && make publish && make deploy`.
The timestamped migration `20260930-tenant-console` runs automatically within deployment.
Its completion receipt prevents another data transfer during later deployments.

## Implementation

The release packages the migration executable in the service image and seals its public App assignment plan.
The repository deployment command captures the installed Gateway package before its first lifecycle operation.
It prepares the server encryption key and App-scoped operator credentials automatically.
It keeps the key in private local inputs and a remote recovery reference.
Native deployment planning runs before writer shutdown.

The Ansible cutover reads the materialized host configuration at `state/tauth/config.tauth.yml` under the runtime root.
It stops existing TAuth database writers and rejects unrelated active writers.
The first migration requires no previous service container.
The migration preserves every source tenant, including tenants absent from the public App assignment plan.
Each unassigned tenant receives a separate owner App without a Gateway credential.
Absent planned tenants receive no App or credential. Each credential covers only its present assigned tenants.
SQLite creates a fresh backup for each pending attempt.
The migration changes a private database candidate and commits its completion receipt with the data.
Deployment replaces the original database after the candidate succeeds.
Native Gateway convergence then installs the service resources.

The server encryption key protects stored tenant and console secrets.
The tenant console introduced this server input. Clients receive no additional secret.
The migration keeps existing client keys and session settings.

## Software results

| Validation | Result |
| --- | --- |
| `make ci` | Passed, including Go, JavaScript, Chromium, Make, and container checks. |
| `make test-deployment-migration` with the private production-copy inputs | Passed for all 20 production tenants. |
| Original database rows | All original rows remained in 13 tables. The migration added console identity and schema records. |
| Tenant configuration comparison | All current fields matched. The migration removed only the obsolete `account_management.return_challenge_tokens` field. |
| Interrupted CLI migration | The original database remained unchanged. A retry kept later source writes through a fresh backup. |
| Server key preparation | Creation, retention, remote recovery, and conflict rejection passed. Invalid recovery data did not change private inputs. |
| Real Ansible and Docker | Writer shutdown, packaged migration, service health, and the existing client session passed. |
| Generated Gateway credential | The assigned tenant configuration was accessible. The console tenant returned `403`. |
| Gateway suspension request | The generated credential suspended its assigned tenant. The existing client session then returned `404`. |
| Repeated cutover | The old source container was absent. The migration made zero changes and kept the service active. |

The container test used the installed Gateway v5.0.0 Ansible toolchain and the current TAuth image.
Its previous writer was a controlled container dependency.
The migration, database, Docker operations, and new HTTP service were real.
These checks did not execute a production fleet deployment or a live Google login.

Private evidence remains in the ignored `.cache/automatic-cutover-f018` directory.
The CI log is `.cache/f018-ci.log`.
The production-copy log is `.cache/f018-production-cutover.log`.
B112 adds the HTTP suspension regression. Its initial request returned `403 management.operation_denied` before the grant correction.
The regression logs are `.cache/b112-regression-before.log` and `.cache/b112-regression-after.log`.
The correction CI log is `.cache/b112-ci.log`.
No secret value is included in this report.

## B121 and B122 repair results

The CLI regression reproduced `cutover.inventory_incomplete` with one unassigned tenant and two absent planned tenants.
The Docker and Ansible regression reproduced the source-container assertion with a valid durable configuration and no service container.
The repairs preserve all source configuration and limit each Gateway credential to its assigned tenants.
The tests verify existing sessions for an assigned tenant and an unassigned tenant through the new HTTP service.
The unassigned tenant configuration returns `403` to the assigned Gateway credential.
An unrelated active writer causes failure before database changes. A present TAuth writer stops before migration.
A completed retry requires no source file and keeps the current service active.
A private local rehearsal combines the captured 21-tenant configuration with an earlier production database copy.
This rehearsal checks configuration equality and the completion receipt. It does not verify current production account data.

`make ci` and independent review passed after the final correction.
These repairs do not execute a production deployment. The production TAuth container remains stopped at the operator's request.

## Documentation checks

The official ASD-STE100 Issue 9 reference passed its pinned SHA-256 check.
Language review covered the changed prose, not the complete historical documents.
The mechanical checker found no findings in the reviewed changes.
The governance check reported the same six managed-document differences as the initial check.
This change did not normalize those pre-existing differences.

## Production status

Production data and services did not change during this implementation.
The sealed v2.2.6 release predates F018.
A fresh release from the committed implementation is required before publication and deployment.
No separate production migration, bootstrap, credential, or encryption-key command is required.

# Tenant migration rehearsal: September 26, 2026

## Result

The rehearsal used a copy of the production SQLite database and its deployed tenant configuration.
Import, retry, restart, and backup restoration passed.
Gateway changed two settings for `mpr-ui-demo` during its first configuration write.
The second rehearsal completed without errors after the B092 correction.

The production container retained its image, container ID, start time, and configuration digest.
This rehearsal did not deploy a service or publish a website.

## Inputs and isolation

| Input | Selected value |
| --- | --- |
| Production TAuth image | `ghcr.io/tyemirov/tauth:2.2.5` |
| Snapshot capture | `2026-09-27T00:42:36.174479+00:00` |
| Database engine | SQLite |
| TAuth source revision | `506fa902b52cd2428166a3d807a2d1bc6e89fe3d` |
| Gateway client source revision | `752dd924a33dbcae5aa44aa5651be06702b9dee0` |
| Installed Gateway version | `v4.6.6` |
| Tenant inventory | 20 deployed tenants and 20 Gateway contributions |

The capture used the SQLite backup API through a read-only source connection.
The configuration digest stayed the same during capture.
Private inputs, database copies, and diagnostic logs stayed outside the checkout.
The rehearsal used a separate encryption key and a console configuration for local tests.
HTTP servers listened on loopback addresses.

The bootstrap service configuration listed only the console origin in its CORS allowlist.
After import, the service configuration included the captured application origins and the console origin.
Application settings came from the database after import.

The test used the real CLI, HTTP handlers, database stores, and Gateway Python client.
A temporary Go overlay added the rehearsal test to `make test-console` without changes to application source.
The Google identity validator used a test implementation for console enrollment.
This result does not qualify live Google connectivity.

## Completed checks

- Imported all 20 tenants under one enrolled owner.
- Compared every imported tenant field with the resolved source.
- Repeated the import with the same ID and obtained the same receipt.
- Started the service three times, including startup from a restored database backup.
- Ran doctor and preflight against the restored database configuration.
- Verified tenant resolution through HTTP for all 20 tenants.
- Verified sessions, refresh, logout, and downstream JWT validation for all 30 existing user profiles.
- Checked SQLite integrity and foreign keys after restoration and Gateway convergence.
- Ran the Gateway client twice with the captured contribution identities and generations.

The session checks used test tokens created before import for existing user IDs and preserved signing keys.
They did not use captured browser cookies.
Gateway resolved output values came from the captured effective tenant configuration.
The second Gateway run reported no changes and retained all 20 activation revisions.
This check did not run the installed Gateway deployment lifecycle.

The local test completed the import and acceptance sequence in approximately 0.62 seconds.
This duration excludes capture, compilation, operator enrollment, deployment, DNS, and live provider operations.
It is not a production interruption estimate.

## Stored data

| Original data | Original rows | Result after import, restoration, and Gateway convergence |
| --- | ---: | --- |
| User profiles | 30 | Unchanged |
| Password credentials | 1 | Unchanged |
| Accounts | 4 | Unchanged |
| Account identities | 4 | Unchanged |
| Account challenges | 2 | Unchanged |
| Application refresh tokens | 250 | Unchanged |
| OAuth authorization requests | 8 | Unchanged |
| OAuth authorization codes | 17 | Unchanged |
| OAuth consents | 9 | Unchanged |
| OAuth refresh tokens | 770 | Unchanged |

All six existing schema-version records stayed unchanged.
The snapshot used refresh schema version 1, which matches the current service.
The service did not reset refresh-token storage.
Nonce operations removed expired nonce rows.
The row comparison confirmed that every removed original nonce had expired.
The tests added console records and test sessions to the isolated copies.

## B092: Gateway policy change

The import and backup restoration preserved the `mpr-ui-demo` configuration.
The first Gateway configuration write changed these settings:

| Setting | Imported value | Value after Gateway convergence |
| --- | --- | --- |
| `allow_insecure_http` | `false` | `true` |
| `require_tenant_header` | `false` | `true` |

The contribution includes a loopback origin.
The provisioning handler derives both settings from the presence of that origin.
The other 19 tenants retained their effective settings.

Before Gateway convergence, `GET /me` with Origin `http://127.0.0.1:4443` and no tenant header returned `401`.
After convergence, the same unauthenticated request returned `403`.
The final rehearsal assertion failed because Gateway changed the effective tenant settings.
The canonical `make test-console` suite passed without the temporary rehearsal overlay.

The changed prose passed its scoped language review.
The Governor check retained six existing managed-file differences.
The first rehearsal changed only this report and the B092 issue record.

## B092 correction and second rehearsal

The provisioning handler now keeps both policies from the active tenant configuration.
New tenants still use the loopback defaults.
HTTP tests cover all four policy combinations, the first Gateway write, an identical retry, and a later generation.
The tests also use the actual Gateway Python client.

The second rehearsal used a new isolated copy of the original snapshot.
All 20 tenants kept their effective configuration after two Gateway runs.
The second run reported no changes and kept the same activation revisions.
The `mpr-ui-demo` request without a tenant header returned `401` after Gateway configuration.
Both `allow_insecure_http` and `require_tenant_header` stayed `false`.
Import retry, three service starts, backup restoration, session checks, doctor, and preflight completed without errors.
The local test took approximately 0.34 seconds, excluding the operations listed in the original timing note.

This result uses the local TAuth source correction and Gateway source revision `7c3980ccdbc5639cc165e9afcc88220a6758409d`.
It does not select release versions or qualify production deployment and live providers.
The original observations above remain the record of the defect before correction.

## Remaining acceptance

1. Select and record the released TAuth and Gateway versions for cutover.
2. Configure the production console Google client and service encryption key.
3. Verify initial-owner enrollment through live Google authentication.
4. Qualify each enabled provider and customer backend through the selected public origins.
5. Use the [production cutover procedure](tenant-console-operations.md#tenant-import-and-database-cutover).

The captured configuration enables Google for 19 tenants, Apple for two, GitHub for one, and password authentication for two.
This rehearsal preserved their configuration and stored data.
It did not test live provider login or email delivery.

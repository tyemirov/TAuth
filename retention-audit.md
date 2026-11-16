# Retention audit

`tauth-retention-audit` verifies stored authentication data during a bounded ownership handoff.
The tool is a separate executable.
It does not start the service or run migrations.
The production service image remains unchanged.

## Artifact

Build the executable through the repository target:

```sh
make build-retention-audit
```

Use an explicit published artifact for production operations.
The selected manifest declares the host binaries and their GitHub Release assets.
Each archive contains one `tauth-retention-audit` entry.
Gateway captures the qualified artifact as a fixed provider dependency.
The collector verifies its artifact digest before use.
The tool also checks its executable bytes against the request binding.

## Private protocol

The tool accepts one JSON document on standard input.
It accepts no command arguments.
The request limit is 64 MiB.
Unknown fields and additional documents cause an error.
The process returns one private JSON result on standard output.
Errors contain fixed codes on standard error.

Keep requests, results, frames, and service configuration private.
Do not copy these values into public receipts or logs.
The evidence contains keyed opaque record identities and fingerprints.
It contains no plaintext account profiles, session keys, or credentials.

Every request uses `schema: tauth.retention.request.v1`.
Every result uses `schema: tauth.retention.result.v1`.
The operations are `resolve-binding`, `capture`, and `verify`.

### Resolve the native binding

Supply `service_config` as an absolute path.
Supply actual container mounts in `native_mounts`.
Each mount contains an absolute `source` and `target`.
Omit `binding`, `database_path`, and `baseline`.

The tool parses the service configuration through the canonical TAuth parser.
It rejects unresolved environment references.
It selects the longest mount target that contains the configured SQLite path.
An ambiguous or missing mount causes an error.

The `resolved` result contains `resolution` and a private `proof`.
The resolution contains these fields:

```text
database_url
database_path
storage_source
storage_target
config_digest
auditor_artifact_digest
```

The collector independently verifies actual container, image, configuration, and mount identities before and after tool execution.
A caller-supplied binding alone is insufficient evidence.

### Capture a baseline

Supply `operation: capture`, `service_config`, `database_path`, and `binding`.
Omit `native_mounts` and `baseline`.
The binding contains these fields:

```text
handoff_id
candidate_digest
acquisition_id
container_id
image_id
config_digest
database_url
storage_source
storage_target
auditor_artifact_digest
```

The tool verifies the configuration bytes, executable bytes, database path, and mount translation.
It opens SQLite with `mode=ro` and reads one consistent transaction.
It does not initialize or update the database schema.
It classifies every observed service table.
An unknown table causes an error.
It validates encrypted tenant secrets and stored tenant configuration through TAuth-owned interfaces.

The `captured` result contains a sealed private `capture` frame, its `capture_digest`, and a private `proof`.
The frame covers the database schema and every observed row.
It includes retained tenants, owner accounts, application accounts, credentials, keys, and durable sessions.
The server encryption key protects the evidence through a separate HMAC domain.
The result does not export that key.

### Verify retention

Supply `operation: verify` with the same native inputs and the sealed `baseline` frame.
The tool authenticates the baseline before comparison.
A fresh lease acquisition can use the same immutable candidate baseline.
Only `acquisition_id` can differ between the baseline and current bindings.
All other binding values remain equal.

The tool captures the current database through another read-only transaction.
It permits new rows.
It permits missing expired rows only when the baseline expiry precedes the verification time.
It permits session revocation through persisted state and bounded timestamps.
Refresh rotation requires retained ownership and stored session lineage.

Missing active sessions, broken lineage, and unexplained durable data loss cause an error.
Keys, credentials, tenant configuration, and stored account data remain unchanged.
Other concurrent durable updates return `retention.changed_during_window`.

The `retained` result contains the current `capture`, `capture_digest`, `baseline_digest`, and private `proof`.
The original `capture_digest` equals the later `baseline_digest`.
The proof binds both observations and the current acquisition.
Keep the immutable evidence with the handoff journal.
An admitted historical retry uses that journal rather than a new database observation.

## Validation

```sh
make test-retention-audit
make ci
```

The public CLI tests use an encrypted fixture with active and disabled accounts.
They verify retained records, private output, rejected bindings, expiry, rotation, revocation, and reads during concurrent writes.
They verify database contents before and after each audit operation.
Service acceptance separately verifies the same existing signed session before and after the handoff.
These checks do not prove a completed Google login.

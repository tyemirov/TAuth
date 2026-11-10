# Deployment

This guide owns service startup, local orchestration, proxy trust, database retention, and the deployment renderer.
The [configuration reference](service-configuration.md) owns service and tenant fields.
The [console runbook](tenant-console-operations.md) owns bootstrap, enrollment, tenant administration, and key replacement.

## Production lifecycle

The complete MPR Lab application procedure is:

```sh
make release && make publish && make deploy
```

`make release` packages the service and website.
`make publish` publishes those sealed artifacts.
`make deploy` calls the installed Gateway with the selected application root.

The selected `resources.yml` supplies the deployment specification.
The existing retained database volume contains tenant settings, users, keys, and sessions.

Keep the existing server encryption key in the declared private input source.
The completed timestamped cutover tools and their separate plans are removed.
Production deployment does not run a separate tenant-import or App-assignment executable.

The service continues to apply its current database schema migrations at startup.

TAuth reads service settings from YAML and tenant configuration from its persistent owner database.
The operator owns service secrets, routing, and deployment orchestration. This repository ships the generic service, configuration schema,
neutral examples, and validation commands. For the MPR Lab deployment, the
tracked `.mprlab/deploy/resources.yml` declares only desired resources and
secret identities. The installed `mprlab-gateway` runtime owns Ansible orchestration, release receipts, publication, and convergence.

The operator keeps inventory and private config under `MPRLAB_GATEWAY_OPERATOR_ROOT`.
The default operator root is `$HOME/.config/mprlab-gateway`.
The TAuth artifact converts the declared TAuth resources to its native config.



Run one service instance with the control database.
Multiple instances require a separate revision-distribution design.

For a standalone installation, bootstrap the console with the [operator procedure](tenant-console-operations.md#bootstrap-order).
Start the service with its selected YAML and retained database:

```sh
tauth --config service.yaml
```

The production Gateway targets require an installed `mprlab-gateway` on `PATH`.
`MPRLAB_GATEWAY_EXECUTABLE` can select an explicit installed command.
A release, publication, deployment, and live-provider qualification each require their own evidence.

## Deployment renderer contract

The `render-deployment-config` command reads one strict schema-v1 JSON request
from standard input. The request contains complete TAuth resource contributions
and their resolved output envelopes. The command validates contributions and writes service YAML to standard output.

Tenant configuration goes through the authenticated management API. Unknown request fields, unsupported resource
kinds, missing outputs, and invalid native config cause a nonzero exit.

```bash
tauth render-deployment-config < deployment-request.json > service.yaml
tauth validate-service-config service.yaml
```

The render request has this envelope schema:

| Path | Type | Requirement |
| --- | --- | --- |
| `schema_version` | integer | Required. The value is `1`. |
| `contributions` | array | Required. The array contains complete contributions. |
| `contributions[].owner` | string | Required application owner. |
| `contributions[].id` | string | Required resource ID. |
| `contributions[].kind` | string | Required `tauth_authorization_server`, `tauth_tenant`, or `tauth_github_tenant`. |
| `contributions[].desired` | object | Required normalized resource from the gateway schema. |
| `contributions[].outputs` | object | Required map with output names as keys. |
| `contributions[].outputs.*.value` | string | Required resolved output value. |
| `contributions[].outputs.*.digest` | string | Optional output digest. |
| `contributions[].outputs.*.visibility` | string | Optional output visibility. |

The decoder rejects unknown fields in the envelope and nested resource data.
The gateway owns the `resources.yml` resource schema and canonical defaults.
This document does not define a second resource schema. TAuth owns the mapping
from each accepted normalized resource to its native config.

The `tauth_github_tenant` kind requires enabled GitHub login and does not require Google configuration.
Its envelope kind must match the desired resource kind.
It uses the same native tenant validation, private outputs, and OAuth disclosure policy as `tauth_tenant`.

The existing `tauth_tenant` contribution contract remains current.

The gateway treats the request and response as private values. It does not
interpret TAuth fields or write secret values to normal logs.

## HTTPS and proxy trust

Gateway supplies reverse proxy trust automatically through the stable `caddy` Docker DNS name.
The managed service receives `TAUTH_TRUSTED_PROXY_HOSTS=caddy` and `TAUTH_TRUSTED_PROXY_LOOKUP_TIMEOUT=1s` from the manifest.
Private proxy inputs and container IP addresses are not necessary.

TAuth compares the connection peer with the DNS response for each forwarded HTTPS request.
A TAuth restart is not necessary after proxy replacement.
DNS failures reject forwarded HTTPS requests and produce diagnostics.

Gateway and Docker administrators control the proxy alias and DNS configuration.
TAuth does not trust an adjacent container without that alias.

Set `TAUTH_TRUSTED_PROXY_CIDRS` to the actual proxy peer CIDRs, separated by commas, when the proxy terminates TLS.
Use this CIDR configuration for a standalone proxy with fixed addresses.
For a standalone proxy with a stable DNS name, configure `server.trusted_proxy_hosts` and a positive `server.trusted_proxy_lookup_timeout` duration.

The managed Gateway deployment supplies hostname trust automatically and does not use the CIDR input.
An unset or empty value trusts no forwarding peer. Invalid nonempty CIDRs stop configuration loading.

TAuth accepts direct TLS, or one exact `X-Forwarded-Proto: https` value from a configured connection peer.
Duplicate or comma-separated scheme values fail transport classification. `Forwarded` and `Host` supply no transport evidence.

The proxy must overwrite `X-Forwarded-Proto` from its actual client connection scheme.
For Nginx, use its [proxy header directive](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header):

```nginx
proxy_set_header X-Forwarded-Proto $scheme;
```

Credential routes require this transport contract before they read credentials or change state.
The explicit tenant `allow_insecure_http` setting disables the tenant HTTPS requirement. Use this setting for development. OAuth local HTTP requires its loopback issuer and a loopback connection peer.

For a standalone service with fixed proxy addresses, use this configuration fragment:

```yaml
server:
  trusted_proxy_cidrs: ["${TAUTH_TRUSTED_PROXY_CIDRS}"]
```

For a standalone proxy with a stable DNS name, use `trusted_proxy_hosts` and a positive lookup timeout.
The [service example](service-configuration.md#service-settings) shows those fields.

## Database and encryption key

The database URL and base64 encryption key are required. The decoded key must contain 32 bytes.
Writable SQLite stores use write-ahead logging (WAL).

This mode permits authentication writes while other service connections read the same database.
Database diagnostics keep the selected journal mode unchanged.
Conflicting `journal_mode` URL options stop writable store initialization.

SQLite URLs preserve `mode=ro` through the driver URI.
Migration status checks use this read-only connection and permit SQLite sidecar writes on the database volume.
Use a SQLite backup operation that produces a consistent snapshot.

For a file copy, stop writers and successfully checkpoint the database first.
The service rejects missing console bootstrap data and incorrect encryption keys.
The database can contain the console tenant with no application tenants.

Set `database_url` to a persistent SQLite or PostgreSQL DSN.
The database stores tenant configuration, ownership, accounts, provider bindings, nonces, sessions, and OAuth grants.
Structured zap logs report login, refresh, and logout operations.

## Local development

Run `make up` from the repository root. Docker Compose builds the current source and starts the service and browser frontend.
Open `http://localhost:8081/app/` for the tenant console. The API address is `http://localhost:8082`.

Both ports bind to `127.0.0.1`.
Run `make down` to stop the containers. This command keeps the database volume and local keys for the next start.

The first start creates random keys in `.cache/tauth-local/runtime.env` and initializes the reserved console tenant.
Later starts use the same keys and database. Keep the key file with the database.

The local stack uses the same public Google client ID as the Ledger demo.
For another Google client, set `TAUTH_LOCAL_GOOGLE_CLIENT_ID` before the first `make up`.
After the first start, use the [console client replacement procedure](tenant-console-operations.md#console-google-client-replacement).

The database retains the console client ID. A later environment override does not change that ID.
Authorize `http://localhost:8081` in that client's Google configuration before login.

Every verified Google user can enroll, regardless of login order.
The local `admin.emails` configuration controls access to the account directory.
The console uses Google login only. Its required email configuration is inactive.

The local stack does not start Pingwin.

Run `make test-local-lifecycle` to verify startup, browser initialization, restart, data retention, and shutdown.
This test uses a separate Compose project, temporary keys, and ports 18082 and 18083.
It removes its containers and volume after the test.

The browser test injects the Google script. It does not verify live Google login.
The console accepts HTTP API origins only for `localhost`, `127.0.0.1`, and `[::1]`. Other API origins require HTTPS.

For current-source development, use this root stack instead of the historical import-based Compose examples.

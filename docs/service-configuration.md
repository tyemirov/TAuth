# Service and tenant configuration

TAuth reads service settings from YAML and active tenant revisions from its encrypted database.
The service file rejects a `tenants` field.
Owners create Apps and tenants through the [console](tenant-console-operations.md#tenant-management).

Gateway writes complete tenant contributions through the authenticated provisioning API.
The [deployment guide](deployment.md) owns startup, transport, storage, and release procedures.

## Service settings

```yaml
server:
  listen_addr: ":8080"
  database_url: "${TAUTH_DATABASE_URL}"
  tenant_encryption_key: "${TAUTH_TENANT_ENCRYPTION_KEY}"
  trusted_proxy_hosts: ["caddy"]
  trusted_proxy_lookup_timeout: "1s"
  enable_cors: true
  cors_allowed_origins: ["https://console.example.com"]
  enable_tenant_header_override: true
```

The console origin must match the bootstrapped console tenant.
The runtime adds active tenant origins to its CORS policy automatically.
Explicit non-tenant origins require `cors_allowed_origin_exceptions`.

Provider navigation and the Apple form callback do not require a Google origin in the application's CORS list.
The server encryption key must decode from base64 to exactly 32 bytes.

## Service field notes

The service YAML contains the server settings below. It rejects the `tenants` field.

| Key | Purpose | Example |
| --- | --- | --- |
| `listen_addr` | HTTP listen address | `:8080` |
| `database_url` | Persistent service database DSN | `sqlite:///data/tauth.db` |
| `enable_cors` | Enable CORS for cross-origin UIs | `true` / `false` |
| `cors_allowed_origins` | Explicit CORS origins. Active tenant origins are added automatically | `["https://app.example.com","https://accounts.google.com"]` |
| `cors_allowed_origin_exceptions` | Allowed non-tenant origins that may appear in `cors_allowed_origins` | `["https://accounts.google.com"]` |
| `enable_tenant_header_override` | Allow explicit tenant selection for shared origins and non-browser clients | `true` / `false` |
| `tenant_encryption_key` | Base64 encoding of a 32-byte service encryption key | Service secret input |

### Cookie and provider settings

Use HTTPS at the service or its reverse proxy for production credential routes.
Each tenant defines its cookie domain.
A shared domain such as `.example.com` permits cookies across matching subdomains.

An empty domain creates host-only cookies.
For localhost, keep the domain empty because browsers reject `Domain=localhost`.

SQLite URLs require an absolute path such as `sqlite:///data/tauth.db`.
Host-based forms such as `sqlite://file:/data/tauth.db` are rejected.
PostgreSQL accepts a standard DSN such as `postgres://user:pass@host:5432/dbname?sslmode=disable`.

For different browser and API origins, enable CORS and configure the permitted origins.
For the same origin, CORS can remain disabled.
Explicit non-tenant origins also require a matching `cors_allowed_origin_exceptions` entry.

Add each frontend origin to its tenant's `tenant_origins`.
Shared origins and native clients require explicit tenant selection.

Each tenant has a separate `jwt_signing_key` for HS256 session signatures.
Password credentials use normalized emails and bcrypt hashes.
The native parser preserves literal `$2a$`, `$2b$`, and `$2y$` hash prefixes.

Startup reconciles configured password users with the persistent credential store.
A configured user removed from `password_auth.users` cannot authenticate after restart.

Browser Apple login requires `apple_oauth.enabled`, a Services ID, Team ID, Key ID, private key, and callback URI.
The private key uses PKCS8 ECDSA format.
Native Apple clients use `native_client_ids`.

Account management requires the complete `email_delivery` block for email challenges.
Persistent identity is independent of `account_management.enabled`.
See the [application subject contract](application-subjects.md).

### Cookie modes

The tenant's `allow_insecure_http` setting selects local HTTP behavior.
With this setting enabled, cookies use `SameSite=Lax` without `Secure`, including when CORS is enabled.
Otherwise, CORS selects `SameSite=None`.

With insecure HTTP disabled, a service without CORS selects `SameSite=Strict`.
Production cookies use `Secure`.
Browser site rules still control whether requests carry cookies.

For local integration, keep the browser and API on one hostname with different ports.
A change between `localhost` and `127.0.0.1` changes the cookie site.
The [customer API example](../examples/tenant-app/README.md) requires the same cookie site and scheme.

## OAuth issuer and resource configuration

Enable the issuer-level `oauth` block in service YAML and the tenant `oauth` block in its persisted configuration.
The login page uses enabled Google, GitHub, and password providers.
TAuth requires authorization code with PKCE `S256`, one RFC 8707 resource, exact scopes, and an accepted redirect URI.

Registered native clients can declare a bounded loopback-port range.
Public clients can use a validated HTTPS Client ID Metadata Document.
Native metadata callbacks permit ports 1 through 65535 for a declared HTTP loopback IP address.

All other URI text must remain the same.
This rule excludes `localhost`.
Dynamic Client Registration is unavailable.

See the [OAuth usage guide](usage.md#56-oauth-resource-authorization) for request and callback rules.

```yaml
oauth:
  enabled: true
  allow_insecure_http: false
  issuer: "https://auth.example.com"
  authorization_endpoint: "https://auth.example.com/oauth/authorize"
  token_endpoint: "https://auth.example.com/oauth/token"
  revocation_endpoint: "https://auth.example.com/oauth/revoke"
  jwks_uri: "https://auth.example.com/oauth/jwks"
  login_endpoint: "https://auth.example.com/oauth/login"
  consent_endpoint: "https://auth.example.com/oauth/consent"
  authorization_request_ttl: "5m"
  authorization_code_ttl: "1m"
  active_signing_key_id: "oauth-2026-08"
  signing_keys:
    - id: "oauth-2026-08"
      private_key_base64: "${TAUTH_OAUTH_ES256_PRIVATE_KEY_BASE64}"
  client_metadata:
    request_timeout: "3s"
    maximum_bytes: 5120
    minimum_cache_ttl: "1m"
    maximum_cache_ttl: "1h"

```

The next fragment illustrates the native tenant OAuth fields.
It is a field reference, not a service-file input.
Provisioning contributions use the Gateway resource schema and authenticated management API.

```yaml
tenants:
  - id: "product"
    # The normal tenant fields and one issuer-page browser provider are also required.
    oauth:
      enabled: true
      access_token_ttl: "5m"
      refresh_token_ttl: "720h"
      consent_ttl: "720h"
      allow_client_metadata_documents: true
      resources:
        - identifier: "https://api.example.com"
          display_name: "Example API"
          scopes:
            - identifier: "documents:read"
              display_name: "Read documents"
              description: "Read documents from the Example API."
      clients:
        - id: "example-web-client"
          display_name: "Example Web Client"
          application_type: "web"
          redirect_uris:
            - "https://client.example.com/oauth/callback"
          grants:
            - resource: "https://api.example.com"
              scopes: ["documents:read"]
```

The signing keys must be PKCS8 P-256 private keys. TAuth signs new access tokens
with the `active_signing_key_id` and publishes all configured public keys. Add a
new private key, make it active, and replace the old entry with its PKIX P-256
`public_key` or `public_key_base64` value. Retain that verification-only entry
until every access token that uses it has expired. OAuth keys are separate from
tenant HS256 session keys.

The discovery document is at
`/.well-known/oauth-authorization-server`. The complete endpoint and payload
contract is in [docs/openapi.yaml](openapi.yaml). Protected Go services
use [pkg/oauthvalidator](../pkg/oauthvalidator/README.md) to validate issuer,
signature, resource audience, expiry, and scopes.

## Native tenant field reference

The following YAML illustrates native tenant fields and their nesting.
It is not an input to normal service startup or a production import command.
The current configuration authority is the owner database.

Gateway contributions use the resource schema described in the [renderer contract](deployment.md#deployment-renderer-contract).
Consumer tests use the separate [fixture declaration](test-fixture.md#fixture-declaration).
The `tenants.import.yaml` examples record the former bounded migration input.

```yaml
tenants:
  - id: "demo"
    display_name: "Demo tenant"
    tenant_origins:
      - "https://demo.localhost"
      - "https://demo.example.com"
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    google_native_client_id: "demo-native.apps.googleusercontent.com"
    google_native_clients:
      - platform: "ios"
        client_id: "demo-ios.apps.googleusercontent.com"
        redirect_uris: ["com.demo.app://oauth2redirect/google"]
      - platform: "android"
        client_id: "demo-android.apps.googleusercontent.com"
        redirect_uris: ["com.demo.app:/oauth2redirect/google"]
    apple_oauth:
      enabled: true
      client_id: "com.demo.web"
      team_id: "APPLETEAMID"
      key_id: "APPLEKEYID"
      private_key_base64: "${APPLE_PRIVATE_KEY_BASE64}"
      redirect_uri: "https://auth.demo.example.com/auth/apple/callback"
    password_auth:
      enabled: true
      users:
        - email: "user@example.com"
          display_name: "Example User"
          avatar_url: "https://example.com/avatar.png"
          password_hash: "$2a$10$7EqJtq98hPqEX7fNZaFWoOhiG6MQT2Vjex6Dh2M1ngqRh5JalXH1V6"
    account_management:
      enabled: true
      password_signup:
        enabled: true
      email_verification_ttl: "30m"
      email_delivery:
        server_address: "pinguin-grpc:50051"
        api_key: "${PINGUIN_TENANT_API_KEY}"
        email_verification_url: "https://demo.example.com/verify-email"
        password_reset_url: "https://demo.example.com/reset-password"
        password_link_url: "https://demo.example.com/link-password"
        connection_timeout_seconds: 3
        operation_timeout_seconds: 5
      password_reset_ttl: "15m"
    jwt_signing_key: "demo-signing-key"
    cookie_domain: "demo.example.com"
    session_cookie_name: "app_session_demo"
    refresh_cookie_name: "app_refresh_demo"
    session_ttl: "30m"
    refresh_ttl: "720h"
    nonce_ttl: "10m"
    allow_insecure_http: true
```

Rules enforced at the tenant configuration boundary:

- IDs must use lowercase letters, digits, underscores, or hyphens (`demo`, `customer_b`).
- `display_name` is required so operators can distinguish tenants in logs.
- `tenant_origins` entries are validated and normalized as origins (scheme + host + optional port). Add every browser origin for this tenant, such as `https://app.example.com` or `http://localhost:8000`. If multiple tenants share the same origin, enable the header override and send `X-TAuth-Tenant`.
- `allowed_users` is optional. An absent list permits all emails. An empty list denies all logins.
  A populated list permits only the listed emails.
- Unlisted users are rejected during Google, Apple, GitHub, and password login with `403` and `error: "user_not_allowed"` when `allowed_users` is set.
- Each tenant must configure at least one authentication provider. The provider can be browser Google, native Google, Apple, GitHub, or password login.
- `google_native_client_id` and `google_native_clients` enable the native Google endpoints. Each native Google client ID must be unique across tenants.
- `apple_oauth.enabled` gates the browser Apple routes. `apple_oauth.native_client_ids` gates the native Apple routes. Each native Apple client ID must be unique across tenants.
- Enabled Apple providers require a Services ID, Team ID, and Key ID. They also require a PKCS8 ECDSA private key and an HTTPS callback URI.
- Durations use Go's `time.ParseDuration` syntax, for example `15m` or `720h`. Zero or negative values are invalid.
- `cookie_domain` can be blank for host-only cookies. A specified value must be a valid registrable domain, for example `.example.com`.
- `password_auth.enabled` gates `POST /auth/password/login`. Startup seeds configured password users into the active store.
  Persistent deployments keep credentials, refresh tokens, and profiles in the same database. Startup seeding reconciles the credential table, so users removed from `password_auth.users` can no longer authenticate after restart.
  Startup keeps inactive account credentials and profiles unchanged. An inactive configured account does not prevent startup or pending account disablement recovery.
- `account_management.enabled` enables the complete account lifecycle. `password_signup.enabled` requires account management.
- `email_delivery` configures Pingwin for signup verification, password reset, and password linking. The API key selects the Pingwin tenant. TAuth adds the single-use token to the URL fragment of the matching public page.
- Account management requires all Pingwin settings and challenge URLs. Challenge tokens are delivered only by email. Remove the obsolete `return_challenge_tokens` field from configuration.
- `session_cookie_name` / `refresh_cookie_name` must be specified for every tenant. Choose distinct cookie names for tenants that share a cookie domain, such as `app_session_notes` and `app_refresh_notes`.
- `nonce_ttl` defaults to `5m`. The `allow_insecure_http` default is `false`.
  Enable local HTTP only for development. With that flag enabled, cookies downgrade to `SameSite=Lax` and omit the `Secure` bit so browsers accept them over HTTP.
- The former bounded import expanded environment references such as `${TENANT_COOKIE_DOMAIN}` and `$TENANT_COOKIE_DOMAIN`.
  Runtime database reads do not expand tenant environment inputs.
  The native parser preserves bcrypt prefixes `$2a$`, `$2b$`, and `$2y$` as literal hash text.

The `internal/tenants` package validates complete tenant definitions before it returns domain objects.
Routing consumes these validated definitions:

- The resolver matches tenants by the request’s `Origin` header. Requests without an `Origin` header (or with an unknown origin) are rejected unless you enable the header override.
- Enable `enable_tenant_header_override` for non-browser clients or shared origins. TAuth then accepts a tenant ID or a frontend origin. Disable it only when every request uses one unique browser `Origin`.
- `internal/tenants.TenantMiddleware` attaches the resolved tenant to `gin.Context`.
  Handlers call `tenants.TenantFromContext` for the validated tenant configuration.
- Launch the server with `tauth --config=/path/to/service.yaml` after console bootstrap.
- For shared origins, set `data-tenant-id="tenant-a"` on the helper script tag.
  Alternatively, call `setAuthTenantId("tenant-a")` before `initAuthClient(...)`.
  The helper adds `X-TAuth-Tenant` only when a tenant ID is explicit.
  This header applies to `/auth/session`, `/me`, `/auth/*`, and logout calls.
  The helper does not add this header to application API requests.
  Restore hints are scoped by `baseUrl` and tenant ID.
- Refresh tokens, nonce pools, and the demo user store are keyed by tenant ID.
  Session JWTs contain `tenant_id`.
  Middleware rejects session cookies from another tenant.

## Configuration diagnostics

The `tauth doctor` command validates TAuth configurations and reports issues. Use it to verify your configuration before deployment or to audit multiple project configurations:

```bash
# Validate a single configuration
tauth doctor config.yaml

# Validate multiple configurations with cross-config checks
tauth doctor config.yaml other-config.yaml --cross-validate

# Output as JSON for CI/CD pipelines
tauth doctor config.yaml --json

# Check database connectivity
tauth doctor config.yaml --check-database
```

The doctor command performs comprehensive validation including:
- Configuration file syntax and structure
- Active database tenant requirements: lifetimes, signing keys, and origins
- CORS origin alignment with tenant origins
- Cookie scope isolation across tenants
- Cross-config validation (conflicting origins, shared signing keys)

The doctor reads active tenants from the bootstrapped database.
It requires the selected database and server encryption key.
See [preflight reports](usage.md#25-preflight-validation-pre-start) for redacted effective settings.

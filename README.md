# TAuth

*Identity sessions and OAuth 2.1 resource authorization for first-party apps*

TAuth accepts Google, Apple, GitHub, and tenant-managed password authentication. It issues first-party cookies and keeps provider tokens out of browser storage.
The Go service owns `/auth/*` and `/me`. Product applications call these endpoints with the shipped `tauth.js` helper.

TAuth validates provider identities and issues first-party session cookies. Its optional OAuth 2.1 authorization server issues TAuth access tokens for declared first-party resources. It does not keep provider access tokens. GitHub and Apple token exchanges occur only on the server.

---

## Why teams choose TAuth

- **Own the session lifecycle** – verify an identity once, then rely on short-lived access cookies and rotating refresh tokens.
- **Zero tokens in JavaScript** – the client handles hydration, silent refresh, and logout notifications without touching `localStorage`.
- **Minutes to value** – a single binary with predictable defaults, powered by Gin and OpenID Connect provider integrations.
- **Designed for growth** – plug in Postgres or SQLite to persist refresh tokens, and extend the web hook points to fit your product.

## Authorize first-party resource clients

Enable the issuer-level `oauth` block in service YAML and the tenant `oauth` block in its database configuration. The OAuth login page shows controls for enabled Google, GitHub, and password providers. TAuth requires
authorization code plus PKCE `S256`, one
RFC 8707 `resource` value, an exact scope set, and an exact registered redirect
URI. Registered native clients can declare a bounded loopback-port range.
Public clients can also use a validated HTTPS Client ID Metadata Document.
Native metadata clients can select a port from 1 through 65535 for a declared HTTP loopback IP callback.
All other URI text must stay the same. This port rule does not apply to `localhost`.
See [the usage guide](docs/usage.md#56-oauth-resource-authorization) for the callback rules.
TAuth does not provide Dynamic Client Registration.

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

The tenant OAuth block belongs in the bounded migration source.

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
contract is in [docs/openapi.yaml](docs/openapi.yaml). Protected Go services
use [pkg/oauthvalidator](pkg/oauthvalidator/README.md) to validate issuer,
signature, resource audience, expiry, and scopes.

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

---

## GitHub login

GitHub-only tenants need no Google or password provider. See [the GitHub example](examples/github/tenants.import.yaml.example).

1. Register a dedicated GitHub.com OAuth App for identity authentication.
2. Set its callback URL to the configured TAuth URL, for example `https://auth.example.com/auth/github/callback`.
3. Configure the tenant's `github_oauth` block.
4. Add each product origin to `tenant_origins`.
5. Run `tauth doctor --json config.yaml` and `tauth --config config.yaml preflight`.

```yaml
github_oauth:
  enabled: true
  client_id: "${GITHUB_CLIENT_ID}"
  client_secret: "${GITHUB_CLIENT_SECRET}"
  redirect_uri: "https://auth.example.com/auth/github/callback"
  scopes: [read:user, user:email]
```

An absent block disables GitHub login. The required scope set is `read:user user:email`, including when `scopes` is absent.
TAuth rejects other scopes and configurable provider endpoints. GitHub Enterprise is outside this provider contract.
TAuth requires one verified primary email from `/user/emails`. A private email is accepted.
The current `allowed_users` rules apply to this email.

After `initAuthClient`, connect a user control to one of these calls:

```javascript
await startGitHubLogin(); // Full-page login returns to the current page.
await startGitHubLogin({ mode: "popup" });
await startGitHubLogin({ mode: "popup", operation: "link" });
const loginURL = getGitHubLoginUrl();
```

A link requires an active account session and fresh GitHub authentication.
Matching emails never merge accounts. Existing account rules control unlinking and disablement.
The browser helper restores the profile through `/auth/session` after completion.
A popup `returnTo` must use the initiating page origin. The helper rejects another origin before authentication starts.
OAuth login returns a TAuth completion document before navigation to consent. This step keeps Strict session cookies.
Popup messages contain only status and correlation data. The helper checks the message origin and source window.

A resource scope can request the verified GitHub identity:

```yaml
scopes:
  - identifier: resource:use
    display_name: Use the resource
    description: Use this resource with your GitHub identity.
    identity_providers: [github]
```

Consent describes this disclosure. Signed `provider_identities` records contain only `provider` and `provider_id`.
The provider ID is the decimal GitHub user ID. Access without a disclosure scope contains no identity claim.
TAuth checks the current identity at code exchange and refresh. Unlinking a required identity prevents refresh.
Consent also records the disclosure policy. A change to that policy requires new consent.
An issued access token can disclose the previous identity until its configured expiry.
A Go resource reads `claims.ProviderIdentities` after `pkg/oauthvalidator` validates the token.

The consuming application owns GitHub repository authorization and repository credentials.
A TAuth identity claim grants no GitHub repository permission. TAuth keeps no GitHub provider token after identity retrieval.
See [GitHub operations and errors](docs/usage.md#github-login-operations) for transaction and error details.

## Deploy TAuth for a hosted product

TAuth reads service settings from YAML and tenant configuration from its persistent owner database.
The operator owns service secrets, routing, and deployment orchestration. This repository ships the generic service, configuration schema,
neutral examples, and validation commands. For the MPR Lab deployment, the
tracked `.mprlab/deploy/resources.yml` declares only desired resources and
secret identities. The installed `mprlab-gateway` runtime owns Ansible orchestration, release receipts, publication, and convergence.
The operator keeps inventory and private config under `MPRLAB_GATEWAY_OPERATOR_ROOT`.
The default operator root is `$HOME/.config/mprlab-gateway`.
The TAuth artifact converts the declared TAuth resources to its native config.

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

### 1. Initialize persistent ownership

TAuth stores tenant configuration, encrypted secrets, and owner relationships in its database.
The service YAML contains server settings and optional OAuth issuer settings.
It does not accept a `tenants` field.

Use [the console operations runbook](docs/tenant-console-operations.md) to initialize the database and reserved console tenant.
Every verified Google user can enroll and create an owner account.
Authorization uses the stable console subject and owner account ID.
Each account owns Apps. Each App contains its tenants.
Create or select an App before tenant creation. Tenants retain separate origins, providers, keys, and sessions.
Existing databases require the explicit [App hierarchy migration](docs/tenant-console-operations.md#app-hierarchy-migration) before service startup.
Configured administrators can view the account directory. Their tenant workspaces remain owner-scoped.

### 2. Migrate existing application configuration

Run the separate deployment migration for existing effective tenant configuration.
The TAuth service does not expose an import command or select a migration owner.
For local source selection, frozen snapshots, and import repair, follow the [deployment migration procedure](docs/tenant-console-operations.md#deployment-data-migration).
The `tenants.import.yaml` examples describe migration input.
The importer preserves existing tenant IDs, keys, cookies, providers, policies, users, and sessions.

```sh
make deployment-migration MIGRATION_ARGS="--config service.yaml --source tenants.import.yaml --inspect"
make deployment-migration MIGRATION_ARGS="--config service.yaml --source tenants.import.yaml --import-id production-tenants --owner-id $OWNER_ID --app-id $APP_ID --app-name 'Application'"
```

An identical retry returns the same receipt. A changed source fails without partial writes.
Remove tenant environment inputs after the verified import.
The service reads active tenant revisions from the database after restart.

### 3. Start and verify the service

```yaml
server:
  listen_addr: ":8080"
  database_url: "${TAUTH_DATABASE_URL}"
  tenant_encryption_key: "${TAUTH_TENANT_ENCRYPTION_KEY}"
  enable_cors: true
  cors_allowed_origins: ["https://tauth.mprlab.com"]
  enable_tenant_header_override: true
```

```sh
tauth doctor service.yaml --json
tauth --config service.yaml preflight
tauth --config service.yaml
```

The database URL and base64 encryption key are required. The decoded key must contain 32 bytes.
The service rejects missing console bootstrap data and incorrect encryption keys.
The database can contain the console tenant with no application tenants.

### Local orchestration

Run `make up` from the repository root. Docker Compose builds the current source and starts the service and browser frontend.
Open `http://localhost:8081/app/` for the tenant console. The API address is `http://localhost:8082`.
Both ports bind to `127.0.0.1`.
Run `make down` to stop the containers. This command keeps the database volume and local keys for the next start.

The first start creates random keys in `.cache/tauth-local/runtime.env` and initializes the reserved console tenant.
Later starts use the same keys and database. Keep the key file with the database.

The local stack uses the same public Google client ID as the Ledger demo.
For another Google client, set `TAUTH_LOCAL_GOOGLE_CLIENT_ID` before the first `make up`.
After the first start, use the [console client replacement procedure](docs/tenant-console-operations.md#console-google-client-replacement).
The database retains the console client ID. A later environment override does not change that ID.
Authorize `http://localhost:8081` in that client's Google configuration before login.
Every verified Google user can enroll, regardless of login order.
The local `admin.emails` configuration controls access to the account directory.
The console uses Google login only. Its required email configuration is inactive.
The local stack does not start Pinguin.

Run `make test-local-lifecycle` to verify startup, browser initialization, restart, data retention, and shutdown.
This test uses a separate Compose project, temporary keys, and ports 18082 and 18083.
It removes its containers and volume after the test.
The browser test injects the Google script. It does not verify live Google login.
The console accepts HTTP API origins only for `localhost`, `127.0.0.1`, and `[::1]`. Other API origins require HTTPS.

The local Compose examples mount service configuration and a separate tenant import source.
Complete console bootstrap with `docker compose run --rm tauth console-bootstrap --tenant-file /config/console-bootstrap.yaml`.
Enroll the destination owner through the console. Use the separate deployment migration during the database cutover.
Use `docker compose up --build` for tests of current source.

The production cutover requires the matching Gateway provisioning release from F011.
Release, publication, deployment, and live-provider qualification remain separate operations.

The tenant workspace is at `/app/` on the product site.
Integration supplies public settings from the active revision, a complete browser example, protected key export, and persisted setup evidence.
Use the [customer application example](examples/tenant-app/README.md) for the Google cookie integration and explicit backend tenant authorization.
See the [operations guide](docs/tenant-console-operations.md) for key replacement and the ordered production delivery record.

Use Google sign-in to select imported tenants or create an application tenant.
Creation requires a name, application origin, and Google OAuth client ID.
The service creates an active tenant in one transaction.
The Domains, Sign-in methods, and Settings forms save configuration revisions.
Valid configuration edits apply automatically. DNS ownership verification is not required.
See the [console operations guide](docs/tenant-console-operations.md) for bootstrap and publication inputs.

### 4. Integrate the browser helper from the product site

```html
<script src="https://tauth.mprlab.com/tauth.js"></script>
<script>
  initAuthClient({
    baseUrl: "https://tauth-api.mprlab.com",
    tenantId: "demo", // optional override when multiple tenants share an origin
    onAuthenticated(profile) {
      renderDashboard(profile);
    },
    onUnauthenticated() {
      showSignInButtons();
    }
  });
</script>

<div id="googleSignIn"></div>
<button type="button" onclick="startAppleLogin()">Sign in with Apple</button>
```

The GitHub Pages artifact publishes the documentation site and the single helper source `web/tauth.js` at `https://tauth.mprlab.com/tauth.js`. The production backend at `https://tauth-api.mprlab.com` does not serve a helper copy; `GET /tauth.js` returns `404 Not Found`. Keep the helper URL and the required API `baseUrl` separate.

`tauth.js` requires an explicit `baseUrl` in `initAuthClient`; it never infers the API host from the script origin. On first load the helper defaults to `bootstrapMode: "restore-if-hinted"`: anonymous visitors are reported through `onUnauthenticated()` without probing protected endpoints, while browsers that previously authenticated carry a non-secret local restore hint that allows `/auth/session` recovery without browser-visible 401s. Use `bootstrapMode: "eager"` only when you intentionally want a startup session check, or `bootstrapMode: "passive"` when a public surface should never restore on load.

### 5. Prepare and exchange provider credentials across origins

`tauth.js` already fetches nonces, initializes Google Identity Services, and exchanges credentials for you. Render the button, provide `onAuthenticated` / `onUnauthenticated` callbacks, and the helper keeps cookies fresh across your origin. When building a custom UI, follow the handshake described in [ARCHITECTURE.md#google-sign-in-exchange](ARCHITECTURE.md#google-sign-in-exchange): fetch a nonce, pass it to Google when initializing the popup, then POST `{ google_id_token, nonce_token }` to `/auth/google`. The minted `app_session` cookie authenticates `/api/me` and any downstream routes on the configured domain (e.g. `.example.com`).

For tenants with `apple_oauth.enabled: true`, render a Sign in with Apple control. The control calls `startAppleLogin()` or opens the `getAppleLoginUrl()` value. The helper builds `/auth/apple/start` and includes the tenant ID when necessary. It also adds the current page as `return_to`. The callback can then return to the product after TAuth sets cookies. `startAppleLogin()` records the restore hint before it leaves the page. The returned app uses `/auth/session` to restore the session. A native iOS app first reads `/auth/apple/native/config` and obtains a TAuth nonce. It then posts the Apple ID token and nonce to `/auth/apple/native`. TAuth validates the token and nonce. It then sets the same cookies and profile data as the other providers.

For tenants with `password_auth.enabled: true`, call `exchangePasswordCredential({ email, password })` from the same helper or POST directly to `/auth/password/login` with `credentials: "include"`. When `account_management.enabled` is also true, verified provider and password identities resolve to persisted opaque 128-bit base64url subjects. The helper also exposes signup, email verification, reset, password change, identity linking/unlinking, and disable-account methods for the full account lifecycle.

### Configure Google Identity Services (popup flow)

1. **Create or reuse a Google OAuth Web client.** Add every product origin (e.g. `https://app.example.com`) to the *Authorized JavaScript origins* list. Redirect URIs are not required for this popup flow.
2. **Load the GIS SDK before you render a button.**

   ```html
   <script src="https://accounts.google.com/gsi/client" async defer></script>
   <div id="googleSignIn"></div>
   ```

3. **Fetch and attach a nonce before prompting Google.** Use `POST /auth/nonce`, call `google.accounts.id.initialize({ nonce, client_id, ux_mode: "popup" })`, and render the button programmatically (see `prepareGoogleSignIn` above or `examples/tauth-demo/index.html`).
4. **Exchange the credential without redirecting.** When GIS invokes your callback, post `{ google_id_token, nonce_token }` to `https://auth.example.com/auth/google` (or your hosted base URL) with `credentials: "include"` so TAuth can mint cookies.

### Quick verification checklist

- Open the browser console and confirm a nonce request (`POST /auth/nonce`) fires before the GIS popup.
- Click the button; the popup should open and return a credential to `handleCredential`.
- Check the network tab for `POST https://auth.example.com/auth/google` and ensure it succeeds (`200`).
- Inspect cookies; `app_session` and `app_refresh` should now be scoped to the configured domain (e.g. `.example.com`).
- Call `/api/me` and verify it returns the signed-in profile.

> **Tip:** The Docker demo ships with a placeholder Google OAuth Web client inside `examples/tauth-demo/.env.tauth`. Replace it with your own value before sharing the stack beyond local testing.

### Configure Sign in with Apple

1. Create a Sign in with Apple key in Apple Developer and keep the Key ID, Team ID, and downloaded private key PEM.
2. Create or reuse a Services ID for the web client, then add your TAuth callback URL, for example `https://auth.example.com/auth/apple/callback`.
3. Group the Services ID with each native App ID in Apple Developer. This association lets Apple return the same subject for browser and native sign-in.
4. Add the matching `apple_oauth` block to the tenant config. Put native App IDs in `native_client_ids`. Keep `private_key` or `private_key_base64` in an environment variable or secret manager.
5. Point your web UI button at `startAppleLogin()` from `tauth.js` or the URL returned by `getAppleLoginUrl()`.

The Apple callback accepts cross-origin form navigation without CORS response headers. Ordinary API routes retain the tenant CORS allowlist.

Apple redirects back to TAuth with an authorization code. TAuth posts that code to Apple’s token endpoint with an ES256 client secret, validates the returned ID token through Apple JWKS, checks the original nonce, enforces `allowed_users`, issues the standard first-party cookies, and redirects to the signed `return_to` URL when it was provided. Apple access tokens are not returned to the browser or stored.

### Native desktop and mobile login (system browser + PKCE)

TAuth also supports installed apps that cannot use the browser popup flow. Native clients such as PromptDew desktop or PromptDew Mobile should:

1. Fetch tenant-specific metadata from `GET /auth/google/native/config`. Mobile clients should pass `?platform=ios` or `?platform=android`; non-browser requests must include `X-TAuth-Tenant`.
2. Open Google in the system browser with `response_type=code`, `scope=openid email profile`, PKCE `S256`, and the OIDC nonce. Desktop apps can use a loopback redirect like `http://127.0.0.1:<port>/oauth/google/callback`; Expo mobile apps should use one configured custom-scheme or HTTPS app-link redirect URI.
3. Exchange the authorization code directly with Google and extract the returned `id_token`.
4. Send that `id_token` plus the original OIDC nonce to `POST /auth/google/native`. Mobile clients should also send `platform` and the `redirect_uri` they used so TAuth can select the correct accepted audience and reject unconfigured redirects.
5. Reuse the minted `app_session` / `app_refresh` cookies just like a browser client.

This keeps TAuth authentication-only: Google authorization codes and Google refresh tokens never transit through TAuth.
TAuth does not return bearer or refresh tokens in the response body for mobile clients. Expo apps should preserve the `Set-Cookie` headers in the native cookie jar and send cookies on calls to TAuth and downstream API hosts. For cross-host use, configure a shared `cookie_domain` such as `.example.com` and have downstream services validate `app_session` with `pkg/sessionvalidator`.

### Native iOS Sign in with Apple

Native iOS apps use the operating-system Apple sign-in control:

Set `enable_tenant_header_override: true` because native requests do not send a browser `Origin`.

1. Fetch `GET /auth/apple/native/config` with `X-TAuth-Tenant`.
2. Fetch a one-time nonce from `POST /auth/nonce` with the same tenant header.
3. Pass that nonce to the native Apple authorization request.
4. Post the token, nonce, and available `fullName` components to `/auth/apple/native`.
5. Reuse the first-party cookies that TAuth returns.

TAuth accepts only a configured `native_client_ids` audience. It also requires Apple issuer, signature, expiration, verified email, and an exact nonce match. It consumes each nonce once. The mobile app does not receive or store Apple access or refresh tokens.
TAuth stores the native credential name during the first authorization. Later authorizations keep that stored display name when Apple omits it.

### Example `/me` payload

Successful exchanges populate `/me` with a rich profile:

```json
{
  "user_id": "google:12345",
  "user_email": "user@example.com",
  "display": "Example User",
  "avatar_url": "https://lh3.googleusercontent.com/a/AEdFTp7...",
  "roles": ["user"],
  "expires": "2024-05-30T12:34:56.000Z"
}
```

Use the new `avatar_url` field to render signed-in UI chrome in your frontend.

---

## Multi-tenant configuration

The database owns runtime tenant configuration. The following YAML describes the bounded import source.
Use this source with the separate deployment migration. Normal service startup does not read tenant YAML.

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
      return_challenge_tokens: false
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
- `tenant_origins` entries are validated and normalized as origins (scheme + host + optional port). Add every browser origin that should resolve to this tenant (for example `https://app.example.com`, `http://localhost:8000`). If multiple tenants share the same origin, enable the header override and send `X-TAuth-Tenant`.
- `allowed_users` is optional; when provided, only those email addresses can log in for the tenant (an empty list denies all logins).
- Behavior: `allowed_users` absent → allow all; present empty → deny all; present with entries → allow only listed emails.
- Unlisted users are rejected during Google, Apple, GitHub, and password login with `403` and `error: "user_not_allowed"` when `allowed_users` is set.
- Each tenant must configure at least one authentication provider. The provider can be browser Google, native Google, Apple, GitHub, or password login.
- `google_native_client_id` and `google_native_clients` enable the native Google endpoints. Each native Google client ID must be unique across tenants.
- `apple_oauth.enabled` gates the browser Apple routes. `apple_oauth.native_client_ids` gates the native Apple routes. Each native Apple client ID must be unique across tenants.
- Enabled Apple providers require a Services ID, Team ID, and Key ID. They also require a PKCS8 ECDSA private key and an HTTPS callback URI.
- Durations use Go's `time.ParseDuration` syntax, for example `15m` or `720h`. Zero or negative values are invalid.
- `cookie_domain` can be blank for host-only cookies. A specified value must be a valid registrable domain, for example `.example.com`.
- `password_auth.enabled` gates `POST /auth/password/login`. Configured password users are seeded at startup into the active store; persistent deployments keep credentials in the same database as refresh tokens and profiles. Startup seeding reconciles the credential table, so users removed from `password_auth.users` can no longer authenticate after restart.
- `account_management.enabled` enables the complete account lifecycle. `password_signup.enabled` requires account management.
- `email_delivery` configures Pinguin for signup verification, password reset, and password linking. The API key selects the Pinguin tenant. TAuth adds the single-use token to the URL fragment of the matching public page.
- Keep `return_challenge_tokens` false outside tests. TAuth then requires all Pinguin settings and challenge URLs. It does not return challenge tokens in HTTP response bodies.
- `session_cookie_name` / `refresh_cookie_name` must be specified for every tenant. Choose unique values per tenant to avoid overwriting each other’s cookies when they share a cookie domain (for example `app_session_notes`, `app_refresh_notes`).
- `nonce_ttl` defaults to `5m` if omitted; `allow_insecure_http` defaults to `false` and should only be `true` for localhost development. With that flag enabled, cookies downgrade to `SameSite=Lax` and omit the `Secure` bit so browsers accept them over HTTP.
- Values support shell-style environment expansion (`${TENANT_COOKIE_DOMAIN}` or `$TENANT_COOKIE_DOMAIN`) during the bounded import. Normal runtime reads do not expand tenant environment inputs. Literal bcrypt hashes beginning with `$2a$`, `$2b$`, or `$2y$` are preserved so password hashes are not mistaken for env placeholders.

The `internal/tenants` package validates the entire file before returning domain objects, so downstream routing relies on trusted tenant definitions. Request routing works as follows:

- The resolver matches tenants by the request’s `Origin` header. Requests without an `Origin` header (or with an unknown origin) are rejected unless you enable the header override.
- Enable `enable_tenant_header_override` for non-browser clients or shared origins. TAuth then accepts a tenant ID or a frontend origin. Disable it only when every request uses one unique browser `Origin`.
- `internal/tenants.TenantMiddleware` attaches the resolved tenant to `gin.Context`; downstream handlers call `tenants.TenantFromContext` to retrieve the resolved configuration and proceed with tenant-scoped logic.
- Launch the server with `tauth --config=/path/to/service.yaml` after console bootstrap and tenant import.
- Front-ends that share a single origin can opt into an explicit tenant selection by adding `data-tenant-id="tenant-a"` to the `<script src=".../tauth.js">` tag or by calling `setAuthTenantId("tenant-a")` before `initAuthClient(...)` when you need to override the origin mapping (for example, preview builds served from the same origin). `tauth.js` only adds the `X-TAuth-Tenant` header to its own `/auth/session`, `/me`, `/auth/*`, and logout calls when a tenant id is explicitly configured, leaving your product’s API traffic untouched. Restore hints are scoped by `baseUrl` and tenant id so shared-origin tenants do not reuse each other’s bootstrap state.
- Refresh tokens, nonce pools, and the built-in demo user store are keyed by tenant ID. Session JWTs now embed a `tenant_id` claim, and the middleware rejects cookies presented under the wrong tenant so credentials cannot hop between tenants.

---

### Google nonce handling

Custom clients must follow the nonce exchange documented in [ARCHITECTURE.md#google-sign-in-exchange](ARCHITECTURE.md#google-sign-in-exchange). The README’s quick-start sticks to the happy-path view; dive into the architecture doc for the exact sequencing (nonce issuance, GIS initialization, credential exchange, and `/auth/google` expectations). The default helpers already implement the full set of guardrails.

---

## Validate configurations with `tauth doctor`

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
- Tenant configuration requirements (TTLs, signing keys, origins) when active tenants are declared
- CORS origin alignment with tenant origins
- Cookie scope isolation across tenants
- Cross-config validation (conflicting origins, shared signing keys)

---

## Deploy with confidence

- Works out of the box for any single registrable domain—host TAuth once and share cookies across subdomains.
- Toggle CORS (and `SameSite=None` automatically) when your UI is served from a different origin during development.
- Set `database_url` to a Postgres or SQLite DSN to store refresh tokens durably.
- Structured zap logging makes it easy to monitor sign-in, refresh, and logout flows wherever you deploy.

---

## Learn more

- Read the authoritative usage guide in [`docs/usage.md`](docs/usage.md) for end-to-end setup and integration details.
- Dive into [ARCHITECTURE.md](ARCHITECTURE.md) for endpoints, request flows, and deployment guidance.
- Read [POLICY.md](POLICY.md) for the confident-programming rules enforced across the codebase.
- Inspect `web/tauth.js` to extend UI hooks or wire additional analytics.
- Validate sessions from other Go services with [`pkg/sessionvalidator`](pkg/sessionvalidator/README.md).

---

## License

MIT (or your preferred license). Add a `LICENSE` file accordingly.

# TAuth

*Identity sessions and OAuth 2.1 resource authorization for first-party apps*

TAuth lets product teams accept Google Sign-In, Sign in with Apple, or tenant-managed email/password accounts, mint their own cookies, and keep browsers free of token storage. Ship a secure authentication stack by pairing this Go service with the tiny `tauth.js` module.
TAuth servers are the only place `/auth/*` and `/me` endpoints are implemented; consuming apps call those endpoints rather than hosting their own copies.

TAuth validates provider identities and issues first-party session cookies. Its optional OAuth 2.1 authorization server issues TAuth access tokens for declared first-party resources. It does not issue or store Google, Apple, GitHub, or other provider access tokens.

---

## Why teams choose TAuth

- **Own the session lifecycle** – verify an identity once, then rely on short-lived access cookies and rotating refresh tokens.
- **Zero tokens in JavaScript** – the client handles hydration, silent refresh, and logout notifications without touching `localStorage`.
- **Minutes to value** – a single binary with predictable defaults, powered by Gin and OpenID Connect provider integrations.
- **Designed for growth** – plug in Postgres or SQLite to persist refresh tokens, and extend the web hook points to fit your product.

## Authorize first-party resource clients

Enable the issuer-level `oauth` block and at least one tenant `oauth` block in
the same config. OAuth tenants use the existing Google browser provider,
password provider, or both on the TAuth-owned login page. TAuth requires
authorization code plus PKCE `S256`, one
RFC 8707 `resource` value, an exact scope set, and an exact registered redirect
URI. Native clients can declare a bounded loopback-port range. Public clients
can also use a validated HTTPS Client ID Metadata Document. TAuth does not
provide Dynamic Client Registration.

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

---

## Deploy TAuth for a hosted product

TAuth accepts one complete YAML configuration from its operator. The consuming
company owns that file, every tenant value, all secrets, routing, and deployment
orchestration. This repository ships the generic service, configuration schema,
neutral examples, and validation commands. For the MPR Lab deployment, the
tracked `.mprlab/deploy/resources.yml` declares only desired resources and
secret identities. The exact sibling `../mprlab-gateway` owns generic Ansible
orchestration, operator values, release sealing, publication, and convergence.
The TAuth artifact converts the declared TAuth resources to its native config.

The `render-deployment-config` command reads one strict schema-v1 JSON request
from standard input. The request contains complete TAuth resource contributions
and their resolved output envelopes. The command writes one validated native
YAML config to standard output. Unknown request fields, unsupported resource
kinds, missing outputs, and invalid native config cause a nonzero exit.

```bash
tauth render-deployment-config < deployment-request.json > config.yaml
```

The render request has this envelope schema:

| Path | Type | Requirement |
| --- | --- | --- |
| `schema_version` | integer | Required. The value is `1`. |
| `contributions` | array | Required. The array contains complete contributions. |
| `contributions[].owner` | string | Required application owner. |
| `contributions[].id` | string | Required resource ID. |
| `contributions[].kind` | string | Required `tauth_authorization_server` or `tauth_tenant`. |
| `contributions[].desired` | object | Required normalized resource from the gateway schema. |
| `contributions[].outputs` | object | Required map with output names as keys. |
| `contributions[].outputs.*.value` | string | Required resolved output value. |
| `contributions[].outputs.*.digest` | string | Optional output digest. |
| `contributions[].outputs.*.visibility` | string | Optional output visibility. |

The decoder rejects unknown fields in the envelope and nested resource data.
The gateway owns the `resources.yml` resource schema and canonical defaults.
This document does not define a second resource schema. TAuth owns the mapping
from each accepted normalized resource to its native config.

The gateway treats the request and response as private values. It does not
interpret TAuth fields or write secret values to normal logs.

### 1. Describe your tenants

Every active deployment loads one YAML configuration. Define each active tenant
(origins, Google clients, cookie domain, and TTLs) once and pass that file to
every TAuth process:

```bash
cat > tenants.yaml <<'YAML'
tenants:
  - id: "prod"
    display_name: "Production tenant"
    tenant_origins:
      - "https://app.example.com"
      - "https://admin.example.com"
    google_web_client_id: "your_web_client_id.apps.googleusercontent.com"
    google_native_client_id: "your_desktop_native_client_id.apps.googleusercontent.com"
    google_native_clients:
      - platform: "ios"
        client_id: "your_ios_client_id.apps.googleusercontent.com"
        redirect_uris:
          - "com.example.app://oauth2redirect/google"
          - "https://app.example.com/oauth/google/callback"
      - platform: "android"
        client_id: "your_android_client_id.apps.googleusercontent.com"
        redirect_uris:
          - "com.example.app:/oauth2redirect/google"
    apple_oauth:
      enabled: true
      client_id: "com.example.web"
      native_client_ids:
        - "com.example.app"
      team_id: "APPLETEAMID"
      key_id: "APPLEKEYID"
      private_key_base64: "${APPLE_PRIVATE_KEY_BASE64}"
      redirect_uri: "https://auth.example.com/auth/apple/callback"
    password_auth:
      enabled: true
      users:
        - email: "operator@example.com"
          display_name: "Operator"
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
        email_verification_url: "https://app.example.com/verify-email"
        password_reset_url: "https://app.example.com/reset-password"
        password_link_url: "https://app.example.com/link-password"
        connection_timeout_seconds: 3
        operation_timeout_seconds: 5
      password_reset_ttl: "15m"
    jwt_signing_key: "replace-with-your-tenant-signing-key"
    cookie_domain: ".example.com"
    session_cookie_name: "app_session_prod"
    refresh_cookie_name: "app_refresh_prod"
    session_ttl: "15m"
    refresh_ttl: "1440h"
    nonce_ttl: "5m"
    allow_insecure_http: false
YAML
```

Tenant files accept shell-style environment placeholders (`${TENANT_COOKIE_DOMAIN}` or `$TENANT_COOKIE_DOMAIN`) in any string field. TAuth expands those variables before validation so you can keep secrets or per-host values in `.env` files; missing variables collapse to empty strings, so keep sensible defaults in the YAML when a field is required.

Each entry defines:

- `id` – stable identifier used inside JWTs and storage (lowercase letters/numbers/underscores/hyphens).
- `display_name` – friendly label surfaced in logs and the demo UI.
- `tenant_origins` – browser origins that should resolve to this tenant. Entries must be full origins (`https://app.example.com`, `http://localhost:8000`); the resolver uses the request `Origin` header to select a tenant, and can optionally accept an `X-TAuth-Tenant` override when you enable it for shared-origin or non-browser clients.
- `allowed_users` – optional list of email addresses allowed to log in for the tenant; when present, only these users may sign in. An empty list blocks all sign-ins for the tenant.
- `google_web_client_id` – optional OAuth Web client configured in Google Cloud Console for this tenant’s origins. Omit it for Apple-only, password-only, or native-Google-only tenants.
- `google_native_client_id` – optional legacy OAuth Desktop/installed-app client used by native apps that sign in through the system browser and exchange ID tokens with `POST /auth/google/native`.
- `google_native_clients` – optional platform-specific native clients. Use `platform: "ios"` / `"android"` for Expo mobile apps, set the matching Google OAuth client ID, and list every custom-scheme or app-link redirect URI the app may use. Every native client ID must be unique across tenants.
- `apple_oauth` – optional Sign in with Apple provider. Set `enabled: true`. Configure the Services ID, Team ID, and Key ID. Provide a PKCS8 ECDSA private key and an HTTPS callback URI. Add each native iOS App ID under `native_client_ids`. Each native ID must be unique across tenants.
- `password_auth` – optional email/password provider. Set `enabled: true` to allow password login and optionally seed users with normalized emails, display names, optional avatar URLs, and bcrypt `password_hash` values.
- `account_management` – optional first-party account lifecycle. Enable it for persisted account IDs and account routes.
- `email_delivery` – required Pinguin settings and public challenge pages when account management does not return test tokens.
- `oauth` – optional resource-authorization policy. An enabled tenant declares exact resource identifiers, scopes, and consent and token lifetimes. It also declares public clients and whether it accepts valid Client ID Metadata Documents. The issuer-owned login page uses the tenant's configured Google browser provider, password provider, or both.
- `jwt_signing_key` – HS256 secret unique to this tenant. Every tenant must declare its own signing key so sessions remain isolated.
- `cookie_domain` – registrable domain for cookies (e.g. `.example.com` to share cookies across subdomains). Leave it blank to emit host-only cookies when developing on `localhost`.
- `session_ttl` / `refresh_ttl` / `nonce_ttl` – durations using Go’s `time.ParseDuration` syntax.
- `allow_insecure_http` – `true` only for local development; production tenants must stay `false`. When enabled, cookies drop the `Secure` flag and default to `SameSite=Lax` so browsers keep them over HTTP (even if CORS is on). That setup only works when your dev UI also runs on `http://localhost`, so avoid mixing hosts like `127.0.0.1`.

### 2. Launch the service (e.g. on `https://auth.example.com`)

```bash
cat > config.yaml <<'YAML'
server:
  listen_addr: ":8443"
  database_url: "sqlite:///data/tauth.db"
  enable_cors: true
  cors_allowed_origins:
    - "https://app.example.com"
    - "https://accounts.google.com"
  cors_allowed_origin_exceptions:
    - "https://accounts.google.com"
  enable_tenant_header_override: true

tenants:
  - id: "product"
    display_name: "Product"
    tenant_origins: ["https://app.example.com"]
    google_web_client_id: "product-client.apps.googleusercontent.com"
    google_native_client_id: "product-native.apps.googleusercontent.com"
    apple_oauth:
      enabled: true
      client_id: "com.example.product.web"
      native_client_ids:
        - "com.example.product"
      team_id: "APPLETEAMID"
      key_id: "APPLEKEYID"
      private_key_base64: "${APPLE_PRIVATE_KEY_BASE64}"
      redirect_uri: "https://auth.example.com/auth/apple/callback"
    jwt_signing_key: "replace-with-product-signing-key"
    cookie_domain: ".example.com"
    session_cookie_name: "app_session_product"
    refresh_cookie_name: "app_refresh_product"
    session_ttl: "30m"
    refresh_ttl: "720h"
    nonce_ttl: "10m"
    allow_insecure_http: false
YAML

tauth --config=config.yaml
# or set TAUTH_CONFIG_FILE=/etc/tauth/config.yaml and run `tauth`
```

For a forward-only aggregate deployment before any application declares a
tenant, use an explicit empty set instead of inventing a placeholder tenant:

```yaml
tenants: []
```

This bootstrap state is valid for `tauth doctor` and keeps `GET /health`
available. TAuth does not authenticate requests until a subsequent aggregate
configuration supplies a tenant.

Before deploying, run `tauth preflight --config=config.yaml` to validate the config and emit a redacted effective-config report (signing keys and tenant origins are reported as fingerprints only so validators can compare without seeing secrets).

> SQLite DSN tip: use three slashes for absolute paths (e.g. `sqlite:///data/tauth.db`). Host-based forms such as `sqlite://file:/data/tauth.db` are invalid and rejected at startup.

When multiple product origins need access, list them under the `cors_allowed_origins` array inside `config.yaml`. If you include non-tenant origins (for example `https://accounts.google.com`), mirror them in `cors_allowed_origin_exceptions` so config validation permits them.

Host the binary behind TLS (or terminate TLS at your load balancer) so responses set `Secure` cookies. Working from the tenants file above, cookies issued by `https://auth.example.com` will also be sent with requests made by `https://app.example.com` because both live under `.example.com`.

### 3. Use the sibling gateway lifecycle

The three production lifecycle commands are fixed:

```bash
make release
make publish
make deploy
```

Each command passes this exact Git root to `../mprlab-gateway`. TAuth declares
its image, retained data, shared tenant-config mount, runtime capabilities,
backend route, GitHub Pages site, and health check in `.mprlab/deploy/resources.yml`; it contains
no production controller, Ansible, Compose, Caddy, release, publication, or
deployment implementation. Only the operator runs `make deploy`.

### Run the demo with Docker Compose (local quick-start)

We ship a compose example under `examples/tauth-demo` that builds TAuth from the local Dockerfile and pairs it with a simple static web server (`ghcr.io/tyemirov/ghttp:latest`) serving the demo assets on port `8000`. The TAuth service itself serves only API and health endpoints.

1. `cd examples/tauth-demo`
2. Update the environment file with your Google OAuth client ID and signing key:

   ```bash
   $EDITOR .env.tauth
   ```

3. Review `config.yaml` to ensure the tenant origins and ports match your local setup.
4. Build and start the stack: `docker compose up --build`
5. Visit `http://localhost:8000` to load the demo UI (it communicates with TAuth at `http://localhost:8082` via CORS).

The sample config now defines **two tenants** so you can exercise origin-based routing without touching `/etc/hosts`. Thanks to RFC 6761, any `*.localhost` name automatically resolves to `127.0.0.1`, so both tenants work out of the box:

- `notes` – resolve via `http://localhost:8082` or the example UI at `http://localhost:8000`.
- `portal` – a second example frontend runs at `http://localhost:4173`. Its browser origin lives under `tenant_origins`, so TAuth can derive the tenant from the request `Origin` header without extra UI wiring.

This setup lets you verify header overrides, cookie isolation, and resolver behavior locally before promoting changes to production.

When multiple tenants run on the same machine, list each distinct frontend origin (for example `http://localhost:8000` and `http://localhost:4173`) under `tenant_origins`. TAuth resolves tenants by the request `Origin` header, so you only need explicit tenant overrides when two tenants intentionally share the exact same origin.

Stop the stack with `docker compose down`. The compose file persists refresh tokens inside a named `tauth_data` volume mounted at `/data`, so you can inspect or reset the SQLite database between runs. Update `.env.tauth` (or the referenced `config.yaml`) to change ports, database DSNs, origins, cookie domains, or Google credentials before re-running. Re-run `docker compose up --build` whenever you change Go code so the local image picks up your edits.

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

TAuth now reads **all** configuration from a single YAML file (`config.yaml` by default). The snippet above shows the server-level keys; the example below highlights the `tenants` section. A “single-tenant deployment” is simply a file with one entry; adding more entries lets you serve multiple products from the same binary without touching CLI flags.

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

Rules enforced by the loader:

- IDs must use lowercase letters, digits, underscores, or hyphens (`demo`, `customer_b`).
- `display_name` is required so operators can distinguish tenants in logs.
- `tenant_origins` entries are validated and normalized as origins (scheme + host + optional port). Add every browser origin that should resolve to this tenant (for example `https://app.example.com`, `http://localhost:8000`). If multiple tenants share the same origin, enable the header override and send `X-TAuth-Tenant`.
- `allowed_users` is optional; when provided, only those email addresses can log in for the tenant (an empty list denies all logins).
- Behavior: `allowed_users` absent → allow all; present empty → deny all; present with entries → allow only listed emails.
- Unlisted users are rejected during Google, Apple, and password login with `403` and `error: "user_not_allowed"` when `allowed_users` is set.
- Each tenant must configure at least one authentication provider. The provider can be browser Google, native Google, Apple, or password login.
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
- Values support shell-style environment expansion (`${TENANT_COOKIE_DOMAIN}` or `$TENANT_COOKIE_DOMAIN`) before parsing. Missing variables resolve to empty strings, so leave meaningful defaults in the file to avoid loader validation errors. Literal bcrypt hashes beginning with `$2a$`, `$2b$`, or `$2y$` are preserved so password hashes are not mistaken for env placeholders.

The `internal/tenants` package validates the entire file before returning domain objects, so downstream routing relies on trusted tenant definitions. Request routing works as follows:

- The resolver matches tenants by the request’s `Origin` header. Requests without an `Origin` header (or with an unknown origin) are rejected unless you enable the header override.
- Enable `enable_tenant_header_override` for non-browser clients or shared origins. TAuth then accepts a tenant ID or a frontend origin. Disable it only when every request uses one unique browser `Origin`.
- `internal/tenants.TenantMiddleware` attaches the resolved tenant to `gin.Context`; downstream handlers call `tenants.TenantFromContext` to retrieve the resolved configuration and proceed with tenant-scoped logic.
- Launch the server with `tauth --config=/path/to/config.yaml` (or export `TAUTH_CONFIG_FILE`); no other CLI flags or environment variables are required.
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

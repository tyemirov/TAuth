# TAuth

*Google Sign-In, Sign in with Apple, email/password account management, and JWT sessions for single-origin apps*

TAuth lets product teams accept Google Sign-In, Sign in with Apple, or tenant-managed email/password accounts, mint their own cookies, and keep browsers free of token storage. Ship a secure authentication stack by pairing this Go service with the tiny `tauth.js` module.
TAuth servers are the only place `/auth/*` and `/me` endpoints are implemented; consuming apps call those endpoints rather than hosting their own copies.

TAuth is authentication-only: it validates provider identity tokens and issues first-party session cookies/JWTs. It does not implement OAuth2 authorization flows for Google APIs, Apple APIs, or other provider APIs and does not manage provider API access/refresh tokens.

---

## Why teams choose TAuth

- **Own the session lifecycle** – verify an identity once, then rely on short-lived access cookies and rotating refresh tokens.
- **Zero tokens in JavaScript** – the client handles hydration, silent refresh, and logout notifications without touching `localStorage`.
- **Minutes to value** – a single binary with predictable defaults, powered by Gin and OpenID Connect provider integrations.
- **Designed for growth** – plug in Postgres or SQLite to persist refresh tokens, and extend the web hook points to fit your product.

---

## Deploy TAuth for a hosted product

TAuth accepts one complete YAML configuration from its operator. The consuming
company owns that file, every tenant value, all secrets, routing, and deployment
orchestration. This repository ships the generic service, configuration schema,
neutral examples, release artifacts, and validation commands; it does not carry
any company's production registry or deployment implementation.

### 1. Describe your tenants

Every deployment — even “single tenant” ones — loads configuration from a YAML file. Define your tenants (origins, Google clients, cookie domain, and TTLs) once and pass that file to every TAuth process:

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
- `apple_oauth` – optional Sign in with Apple provider. Set `enabled: true`, configure an Apple Services ID as `client_id`, Apple `team_id`, Sign in with Apple `key_id`, either PKCS8 ECDSA `private_key` or one-line `private_key_base64`, and an HTTPS `redirect_uri` that points at `/auth/apple/callback` on your TAuth origin.
- `password_auth` – optional email/password provider. Set `enabled: true` to allow password login and optionally seed users with normalized emails, display names, optional avatar URLs, and bcrypt `password_hash` values.
- `account_management` – optional first-party account lifecycle. Set `enabled: true` to use persisted opaque 128-bit base64url session subjects for password, Google, and Apple identities. `password_signup.enabled` gates public signup, `email_verification_ttl` controls signup/link verification challenges, and `password_reset_ttl` controls reset challenges. Challenge tokens are only included in JSON responses when `return_challenge_tokens: true` for tests or non-email delivery integrations.
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
  enable_tenant_header_override: false

tenants:
  - id: "product"
    display_name: "Product"
    tenant_origins: ["https://app.example.com"]
    google_web_client_id: "product-client.apps.googleusercontent.com"
    google_native_client_id: "product-native.apps.googleusercontent.com"
    apple_oauth:
      enabled: true
      client_id: "com.example.product.web"
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

Before deploying, run `tauth preflight --config=config.yaml` to validate the config and emit a redacted effective-config report (signing keys and tenant origins are reported as fingerprints only so validators can compare without seeing secrets).

> SQLite DSN tip: use three slashes for absolute paths (e.g. `sqlite:///data/tauth.db`). Host-based forms such as `sqlite://file:/data/tauth.db` are invalid and rejected at startup.

When multiple product origins need access, list them under the `cors_allowed_origins` array inside `config.yaml`. If you include non-tenant origins (for example `https://accounts.google.com`), mirror them in `cors_allowed_origin_exceptions` so config validation permits them.

Host the binary behind TLS (or terminate TLS at your load balancer) so responses set `Secure` cookies. Working from the tenants file above, cookies issued by `https://auth.example.com` will also be sent with requests made by `https://app.example.com` because both live under `.example.com`.

### Run the demo with Docker Compose (local quick-start)

We ship a compose example under `examples/tauth-demo` that builds TAuth from the local Dockerfile and pairs it with a simple static web server (`ghcr.io/tyemirov/ghttp:latest`) serving the demo assets on port `8000`. The TAuth service itself serves only API endpoints plus `/tauth.js`.

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

### 3. Integrate the browser helper from the product site

```html
<script src="https://auth.example.com/tauth.js"></script>
<script>
  initAuthClient({
    baseUrl: "https://auth.example.com",
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

The production backend serves the embedded helper at `/tauth.js`; operators expose it through the authentication origin they configure. Documentation under `docs/` is repository source and is not deployed through a separate Pages workflow.

`tauth.js` requires an explicit `baseUrl` in `initAuthClient`; it never infers the API host from the script origin. On first load the helper defaults to `bootstrapMode: "restore-if-hinted"`: anonymous visitors are reported through `onUnauthenticated()` without probing protected endpoints, while browsers that previously authenticated carry a non-secret local restore hint that allows `/auth/session` recovery without browser-visible 401s. Use `bootstrapMode: "eager"` only when you intentionally want a startup session check, or `bootstrapMode: "passive"` when a public surface should never restore on load.

### 4. Prepare and exchange provider credentials across origins

`tauth.js` already fetches nonces, initializes Google Identity Services, and exchanges credentials for you. Render the button, provide `onAuthenticated` / `onUnauthenticated` callbacks, and the helper keeps cookies fresh across your origin. When building a custom UI, follow the handshake described in [ARCHITECTURE.md#google-sign-in-exchange](ARCHITECTURE.md#google-sign-in-exchange): fetch a nonce, pass it to Google when initializing the popup, then POST `{ google_id_token, nonce_token }` to `/auth/google`. The minted `app_session` cookie authenticates `/api/me` and any downstream routes on the configured domain (e.g. `.example.com`).

For tenants with `apple_oauth.enabled: true`, render a Sign in with Apple control that calls `startAppleLogin()` or navigates to `getAppleLoginUrl()`. The helper builds `/auth/apple/start`, includes the configured tenant id when needed, and adds the current page as `return_to` so the callback can return to the product after cookies are minted. `startAppleLogin()` also records the non-secret restore hint before leaving the page, letting the returned app restore through `/auth/session`. TAuth validates Apple’s ID token and nonce, then mints the same cookies and profile payload used by Google and password login.

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
3. Add the matching `apple_oauth` block to the tenant config and keep `private_key` or `private_key_base64` in an environment variable or secret manager.
4. Point your UI button at `startAppleLogin()` from `tauth.js` or the URL returned by `getAppleLoginUrl()`.

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
      email_verification_ttl: "30m"
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
- Unlisted users are rejected during `/auth/google`, `/auth/google/native`, and `/auth/password/login` with `403` and `error: "user_not_allowed"` when `allowed_users` is set.
- Each tenant must configure at least one auth provider: browser Google via `google_web_client_id`, native Google via `google_native_client_id`/`google_native_clients`, Apple via `apple_oauth.enabled`, or password login via `password_auth.enabled`. `google_native_client_id` and `google_native_clients` enable `GET /auth/google/native/config` plus `POST /auth/google/native` for installed apps; every configured native client ID must be unique across tenants. `apple_oauth.enabled` gates `GET /auth/apple/start` plus `GET`/`POST /auth/apple/callback`; enabled Apple providers require a Services ID client, Team ID, Key ID, PKCS8 ECDSA private key supplied as `private_key` or `private_key_base64`, and HTTPS callback URI. Durations use Go’s `time.ParseDuration` syntax (e.g. `15m`, `720h`); zero or negative values are invalid. `cookie_domain` may be blank to issue host-only cookies (recommended locally); when provided it must be a valid registrable domain (e.g. `.example.com`).
- `password_auth.enabled` gates `POST /auth/password/login`. Configured password users are seeded at startup into the active store; persistent deployments keep credentials in the same database as refresh tokens and profiles. Startup seeding reconciles the credential table, so users removed from `password_auth.users` can no longer authenticate after restart.
- `account_management.enabled` enables persisted opaque account IDs, password signup/verification/reset flows, authenticated password changes, provider/password linking, unlinking, and account disablement. Account IDs are generated once as 128-bit base64url values and reused through stored identity links; callers must not derive them from email, provider, subject, tenant values, or `user_id` prefixes. `password_signup.enabled` requires account management to be enabled. Challenge tokens are hashed at rest and single-use; production deployments should keep `return_challenge_tokens` false and deliver tokens through an email adapter or trusted delivery path.
- `session_cookie_name` / `refresh_cookie_name` must be specified for every tenant. Choose unique values per tenant to avoid overwriting each other’s cookies when they share a cookie domain (for example `app_session_notes`, `app_refresh_notes`).
- `nonce_ttl` defaults to `5m` if omitted; `allow_insecure_http` defaults to `false` and should only be `true` for localhost development. With that flag enabled, cookies downgrade to `SameSite=Lax` and omit the `Secure` bit so browsers accept them over HTTP.
- Values support shell-style environment expansion (`${TENANT_COOKIE_DOMAIN}` or `$TENANT_COOKIE_DOMAIN`) before parsing. Missing variables resolve to empty strings, so leave meaningful defaults in the file to avoid loader validation errors. Literal bcrypt hashes beginning with `$2a$`, `$2b$`, or `$2y$` are preserved so password hashes are not mistaken for env placeholders.

The `internal/tenants` package validates the entire file before returning domain objects, so downstream routing relies on trusted tenant definitions. Request routing works as follows:

- The resolver matches tenants by the request’s `Origin` header. Requests without an `Origin` header (or with an unknown origin) are rejected unless you enable the header override.
- For local development, non-browser clients, or shared origins, enable the optional header override (`enable_tenant_header_override: true`). When enabled, TAuth accepts either a tenant ID (`X-TAuth-Tenant: demo`) or a frontend origin (`X-TAuth-Tenant: http://localhost:8000`) as the override hint. Leave it disabled in production when every tenant owns unique origins.
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
- Tenant configuration requirements (TTLs, signing keys, origins)
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

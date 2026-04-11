# TAuth

*Google Sign-In + JWT sessions for single-origin apps*

TAuth lets product teams accept Google Sign-In, mint their own cookies, and keep browsers free of token storage. Ship a secure authentication stack by pairing this Go service with the tiny `tauth.js` module.
TAuth servers are the only place `/auth/*` and `/me` endpoints are implemented; consuming apps call those endpoints rather than hosting their own copies.

TAuth is authentication-only: it validates Google ID tokens and issues first-party session cookies/JWTs. It does not implement OAuth2 authorization flows for Google APIs (YouTube/Drive/etc) and does not manage Google API access/refresh tokens.

---

## Why teams choose TAuth

- **Own the session lifecycle** – verify Google once, then rely on short-lived access cookies and rotating refresh tokens.
- **Zero tokens in JavaScript** – the client handles hydration, silent refresh, and logout notifications without touching `localStorage`.
- **Minutes to value** – a single binary with predictable defaults, powered by Gin and Google’s official identity SDK.
- **Designed for growth** – plug in Postgres or SQLite to persist refresh tokens, and extend the web hook points to fit your product.

---

## Deploy TAuth for a hosted product

### 1. Describe your tenants

Every deployment — even “single tenant” ones — loads configuration from a YAML file. Define your tenants (origins, Google clients, cookie domain, and TTLs) once and pass that file to every TAuth process:

```bash
cat > tenants.yaml <<'YAML'
tenants:
  - id: "prod"
    display_name: "Production tenant"
    tenant_origins:
      - "https://gravity.mprlab.com"
      - "https://pinguin.mprlab.com"
    google_web_client_id: "your_web_client_id.apps.googleusercontent.com"
    google_native_client_id: "your_native_client_id.apps.googleusercontent.com"
    jwt_signing_key: "replace-with-your-tenant-signing-key"
    cookie_domain: ".mprlab.com"
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
- `google_web_client_id` – OAuth Web client configured in Google Cloud Console for this tenant’s origins.
- `google_native_client_id` – optional OAuth Desktop/installed-app client used by native apps that sign in through the system browser and exchange ID tokens with `POST /auth/google/native`. When set, it must be unique per tenant.
- `jwt_signing_key` – HS256 secret unique to this tenant. Every tenant must declare its own signing key so sessions remain isolated.
- `cookie_domain` – registrable domain for cookies (e.g. `.mprlab.com` to share cookies across subdomains). Leave it blank to emit host-only cookies when developing on `localhost`.
- `session_ttl` / `refresh_ttl` / `nonce_ttl` – durations using Go’s `time.ParseDuration` syntax.
- `allow_insecure_http` – `true` only for local development; production tenants must stay `false`. When enabled, cookies drop the `Secure` flag and default to `SameSite=Lax` so browsers keep them over HTTP (even if CORS is on). That setup only works when your dev UI also runs on `http://localhost`, so avoid mixing hosts like `127.0.0.1`.

### 2. Launch the service (e.g. on `https://tauth.mprlab.com`)

```bash
cat > config.yaml <<'YAML'
server:
  listen_addr: ":8443"
  database_url: "sqlite:///data/tauth.db"
  enable_cors: true
  cors_allowed_origins:
    - "https://gravity.mprlab.com"
    - "https://accounts.google.com"
  cors_allowed_origin_exceptions:
    - "https://accounts.google.com"
  enable_tenant_header_override: false

tenants:
  - id: "gravity"
    display_name: "Gravity"
    tenant_origins: ["https://gravity.mprlab.com"]
    google_web_client_id: "gravity-client.apps.googleusercontent.com"
    google_native_client_id: "gravity-native.apps.googleusercontent.com"
    jwt_signing_key: "replace-with-gravity-signing-key"
    cookie_domain: ".mprlab.com"
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

Host the binary behind TLS (or terminate TLS at your load balancer) so responses set `Secure` cookies. Working from the tenants file above, cookies issued by `https://tauth.mprlab.com` will also be sent with requests made by `https://gravity.mprlab.com` because both live under `.mprlab.com`.

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

- `notes` – resolve via `http://localhost:8082` (or the Gravity UI at `http://localhost:8000`). This matches the default Gravity config and is the tenant you’ve already used.
- `mpr-sites` – the `mpr-frontend` container serves `examples/tauth-demo/index.html` on `http://localhost:8001`. Its browser origin (`http://localhost:4173`) lives under `tenant_origins`, so TAuth can derive the tenant from the request `Origin` header without extra UI wiring.

This setup lets you verify header overrides, cookie isolation, and resolver behavior locally before promoting changes to production.

When multiple tenants run on the same machine, list each distinct frontend origin (for example `http://localhost:8000` for Gravity and `http://localhost:4173` for the MPR demo) under `tenant_origins`. TAuth resolves tenants by the request `Origin` header, so you only need explicit tenant overrides when two tenants intentionally share the exact same origin.

Stop the stack with `docker compose down`. The compose file persists refresh tokens inside a named `tauth_data` volume mounted at `/data`, so you can inspect or reset the SQLite database between runs. Update `.env.tauth` (or the referenced `config.yaml`) to change ports, database DSNs, origins, cookie domains, or Google credentials before re-running. Re-run `docker compose up --build` whenever you change Go code so the local image picks up your edits.

### 3. Integrate the browser helper from the product site

```html
<script src="https://tauth.mprlab.com/tauth.js"></script>
<script>
  initAuthClient({
    baseUrl: "https://tauth.mprlab.com",
    tenantId: "demo", // optional override when multiple tenants share an origin
    onAuthenticated(profile) {
      renderDashboard(profile);
    },
    onUnauthenticated() {
      showGoogleButton();
    }
  });
</script>

<div id="googleSignIn"></div>
```

The GitHub Pages workflow in `.github/workflows/frontend-deploy.yml` publishes the `docs/` site and copies `web/tauth.js` into the site root, so the helper is available at `https://<pages-domain>/tauth.js` when Pages is enabled.

`tauth.js` requires an explicit `baseUrl` in `initAuthClient`; it never infers the API host from the script origin.

### 4. Prepare and exchange Google credentials across origins

`tauth.js` already fetches nonces, initializes Google Identity Services, and exchanges credentials for you. Render the button, provide `onAuthenticated` / `onUnauthenticated` callbacks, and the helper keeps cookies fresh across your origin. When building a custom UI, follow the handshake described in [ARCHITECTURE.md#google-sign-in-exchange](ARCHITECTURE.md#google-sign-in-exchange): fetch a nonce, pass it to Google when initializing the popup, then POST `{ google_id_token, nonce_token }` to `/auth/google`. The minted `app_session` cookie authenticates `/api/me` and any downstream routes on the configured domain (e.g. `.mprlab.com`).

### Configure Google Identity Services (popup flow)

1. **Create or reuse a Google OAuth Web client.** Add every product origin (e.g. `https://gravity.mprlab.com`) to the *Authorized JavaScript origins* list. Redirect URIs are not required for this popup flow.
2. **Load the GIS SDK before you render a button.**

   ```html
   <script src="https://accounts.google.com/gsi/client" async defer></script>
   <div id="googleSignIn"></div>
   ```

3. **Fetch and attach a nonce before prompting Google.** Use `POST /auth/nonce`, call `google.accounts.id.initialize({ nonce, client_id, ux_mode: "popup" })`, and render the button programmatically (see `prepareGoogleSignIn` above or `examples/tauth-demo/index.html`).
4. **Exchange the credential without redirecting.** When GIS invokes your callback, post `{ google_id_token, nonce_token }` to `https://tauth.mprlab.com/auth/google` (or your hosted base URL) with `credentials: "include"` so TAuth can mint cookies.

### Quick verification checklist

- Open the browser console and confirm a nonce request (`POST /auth/nonce`) fires before the GIS popup.
- Click the button; the popup should open and return a credential to `handleCredential`.
- Check the network tab for `POST https://tauth.mprlab.com/auth/google` and ensure it succeeds (`200`).
- Inspect cookies; `app_session` and `app_refresh` should now be scoped to the configured domain (e.g. `.mprlab.com`).
- Call `/api/me` and verify it returns the signed-in profile.

> **Tip:** The Docker demo ships with a placeholder Google OAuth Web client inside `examples/tauth-demo/.env.tauth`. Replace it with your own value before sharing the stack beyond local testing.

### Native desktop login (system browser + PKCE)

TAuth also supports installed apps that cannot use the browser popup flow. Native clients such as PromptDew should:

1. Fetch tenant-specific metadata from `GET /auth/google/native/config`.
2. Open Google in the system browser with PKCE and a loopback redirect like `http://127.0.0.1:<port>/oauth/google/callback`.
3. Exchange the authorization code directly with Google and extract the returned `id_token`.
4. Send that `id_token` plus the original OIDC nonce to `POST /auth/google/native`.
5. Reuse the minted `app_session` / `app_refresh` cookies just like a browser client.

This keeps TAuth authentication-only: Google authorization codes and Google refresh tokens never transit through TAuth.

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
    cookie_domain: "demo.example.com"
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
- Unlisted users are rejected during `/auth/google` with `403` and `error: "user_not_allowed"` when `allowed_users` is set.
- `google_web_client_id` and each TTL must be present and non-empty. `google_native_client_id` is optional and enables `GET /auth/google/native/config` plus `POST /auth/google/native` for installed apps; when present it must be unique across tenants. Durations use Go’s `time.ParseDuration` syntax (e.g. `15m`, `720h`); zero or negative values are invalid. `cookie_domain` may be blank to issue host-only cookies (recommended locally); when provided it must be a valid registrable domain (e.g. `.example.com`).
- `session_cookie_name` / `refresh_cookie_name` must be specified for every tenant. Choose unique values per tenant to avoid overwriting each other’s cookies when they share a cookie domain (for example `app_session_notes`, `app_refresh_mpr`). Legacy stacks (such as Gravity) can keep `app_session`/`app_refresh` as long as they understand the collision risk.
- `nonce_ttl` defaults to `5m` if omitted; `allow_insecure_http` defaults to `false` and should only be `true` for localhost development. With that flag enabled, cookies downgrade to `SameSite=Lax` and omit the `Secure` bit so browsers accept them over HTTP.
- Values support shell-style environment expansion (`${TENANT_COOKIE_DOMAIN}` or `$TENANT_COOKIE_DOMAIN`) before parsing. Missing variables resolve to empty strings, so leave meaningful defaults in the file to avoid loader validation errors.

The `internal/tenants` package validates the entire file before returning domain objects, so downstream routing relies on trusted tenant definitions. Request routing works as follows:

- The resolver matches tenants by the request’s `Origin` header. Requests without an `Origin` header (or with an unknown origin) are rejected unless you enable the header override.
- For local development, non-browser clients, or shared origins, enable the optional header override (`enable_tenant_header_override: true`). When enabled, TAuth accepts either a tenant ID (`X-TAuth-Tenant: demo`) or a frontend origin (`X-TAuth-Tenant: http://localhost:8000`) as the override hint. Leave it disabled in production when every tenant owns unique origins.
- `internal/tenants.TenantMiddleware` attaches the resolved tenant to `gin.Context`; downstream handlers call `tenants.TenantFromContext` to retrieve the resolved configuration and proceed with tenant-scoped logic.
- Launch the server with `tauth --config=/path/to/config.yaml` (or export `TAUTH_CONFIG_FILE`); no other CLI flags or environment variables are required.
- Front-ends that share a single origin can opt into an explicit tenant selection by adding `data-tenant-id="tenant-a"` to the `<script src=".../tauth.js">` tag or by calling `setAuthTenantId("tenant-a")` before `initAuthClient(...)` when you need to override the origin mapping (for example, preview builds served from the same origin). `tauth.js` only adds the `X-TAuth-Tenant` header to its own `/me`, `/auth/nonce`, `/auth/google`, `/auth/refresh`, and logout calls when a tenant id is explicitly configured, leaving your product’s API traffic untouched.
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

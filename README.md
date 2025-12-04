# TAuth

*Google Sign-In + JWT sessions for single-origin apps*

TAuth lets product teams accept Google Sign-In, mint their own cookies, and keep browsers free of token storage. Ship a secure authentication stack by pairing this Go service with the tiny `auth-client.js` module.

---

## Why teams choose TAuth

- **Own the session lifecycle** – verify Google once, then rely on short-lived access cookies and rotating refresh tokens.
- **Zero tokens in JavaScript** – the client handles hydration, silent refresh, and logout notifications without touching `localStorage`.
- **Minutes to value** – a single binary with predictable defaults, powered by Gin and Google’s official identity SDK.
- **Designed for growth** – plug in Postgres or SQLite to persist refresh tokens, and extend the web hook points to fit your product.

---

## Deploy TAuth for a hosted product

### 1. Describe your tenants

Every deployment — even “single tenant” ones — loads configuration from a YAML file. Define your tenants (hostnames, Google clients, cookie domain, and TTLs) once and pass that file to every TAuth process:

```bash
cat > tenants.yaml <<'YAML'
tenants:
  - id: "prod"
    display_name: "Production tenant"
    allowed_hosts:
      - "tauth.mprlab.com"
      - "gravity.mprlab.com"
    google_web_client_id: "your_web_client_id.apps.googleusercontent.com"
    jwt_signing_key: "replace-with-your-tenant-signing-key"
    cookie_domain: ".mprlab.com"
    session_ttl: "15m"
    refresh_ttl: "1440h"
    nonce_ttl: "5m"
    allow_insecure_http: false
YAML
```

Each entry defines:

- `id` – stable identifier used inside JWTs and storage (lowercase letters/numbers/underscores/hyphens).
- `display_name` – friendly label surfaced in logs and the demo UI.
- `allowed_hosts` – every hostname that should resolve to this tenant. List the TAuth hostnames (e.g. `tauth.mprlab.com`) and, when multiple front-ends share that host, add their browser origins (`http://localhost:8000`, `https://app.example.com`). Origin entries let the server derive the tenant from the request `Origin` header, so the UI doesn’t need to know whether it’s running in single- or multi-tenant mode.
- `google_web_client_id` – OAuth Web client configured in Google Cloud Console for this tenant’s origins.
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
  enable_tenant_header_override: false

tenants:
  - id: "gravity"
    display_name: "Gravity"
    allowed_hosts: ["gravity.mprlab.com"]
    google_web_client_id: "gravity-client.apps.googleusercontent.com"
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

> SQLite DSN tip: use three slashes for absolute paths (e.g. `sqlite:///data/tauth.db`). Host-based forms such as `sqlite://file:/data/tauth.db` are invalid and rejected at startup.

When multiple product origins need access, list them under the `cors_allowed_origins` array inside `config.yaml`.

Host the binary behind TLS (or terminate TLS at your load balancer) so responses set `Secure` cookies. Working from the tenants file above, cookies issued by `https://tauth.mprlab.com` will also be sent with requests made by `https://gravity.mprlab.com` because both live under `.mprlab.com`.

### Run the demo with Docker Compose (local quick-start)

We ship a compose example under `examples/docker-compose` that builds TAuth from the local Dockerfile and pairs it with a simple static web server (`ghcr.io/tyemirov/ghttp:latest`) serving the repository’s `web/` directory on port `8000`.

1. `cd examples/docker-compose`
2. Copy and edit the environment template:

   ```bash
   cp .env.tauth.example .env.tauth
   # set the per-tenant TAUTH_GOOGLE_WEB_CLIENT_ID*/TAUTH_*_JWT_SIGNING_KEY values
   ```

3. Copy the config template and replace the placeholder Google OAuth Web client ID with one that covers `http://localhost:8000` and `http://localhost:8080` (or keep the environment variable reference if you prefer):

   ```bash
   cp config.yaml.example config.yaml
   $EDITOR config.yaml
   ```

4. Build and start the stack: `docker compose up --build`
5. Visit `http://localhost:8000` to load the demo UI (it communicates with TAuth at `http://localhost:8080` via CORS).

The sample config now defines **two tenants** so you can exercise host-based routing without touching `/etc/hosts`. Thanks to RFC 6761, any `*.localhost` name automatically resolves to `127.0.0.1`, so both tenants work out of the box:

- `notes` – resolve via `http://localhost:8082` (or the Gravity UI at `http://localhost:8000`). This matches the default Gravity config and is the tenant you’ve already used.
- `mpr-sites` – the `mpr-frontend` container serves `examples/tauth-demo/index.html` on `http://localhost:8001`. Its browser origin (`http://localhost:4173`) lives under `allowed_hosts`, so TAuth can derive the tenant from the request `Origin` header without extra UI wiring.

This setup lets you verify header overrides, cookie isolation, and resolver behavior locally before promoting changes to production.

When two tenants share `localhost`, list each frontend origin (for example `http://localhost:8000` for Gravity and `http://localhost:4173` for the MPR demo) under `allowed_hosts`. TAuth inspects the `Origin` header and resolves the tenant automatically, so the UI doesn’t need to set `data-tenant-id` or call `setAuthTenantId` just to distinguish environments.

Stop the stack with `docker compose down`. The compose file persists refresh tokens inside a named `tauth_data` volume mounted at `/data`, so you can inspect or reset the SQLite database between runs. Update `.env.tauth` (or the referenced `config.yaml`) to change ports, database DSNs, hosts, cookie domains, or Google credentials before re-running. Re-run `docker compose up --build` whenever you change Go code so the local image picks up your edits.

### 3. Integrate the browser helper from the product site

```html
<script src="https://tauth.mprlab.com/static/auth-client.js"></script>
<script>
  initAuthClient({
    baseUrl: "https://tauth.mprlab.com",
    tenantId: "demo", // optional override when multiple tenants share a host
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

### 4. Prepare and exchange Google credentials across origins

`auth-client.js` already fetches nonces, initializes Google Identity Services, and exchanges credentials for you. Render the button, provide `onAuthenticated` / `onUnauthenticated` callbacks, and the helper keeps cookies fresh across your origin. When building a custom UI, follow the handshake described in [ARCHITECTURE.md#google-sign-in-exchange](ARCHITECTURE.md#google-sign-in-exchange): fetch a nonce, pass it to Google when initializing the popup, then POST `{ google_id_token, nonce_token }` to `/auth/google`. The minted `app_session` cookie authenticates `/api/me` and any downstream routes on the configured domain (e.g. `.mprlab.com`).

### Configure Google Identity Services (popup flow)

1. **Create or reuse a Google OAuth Web client.** Add every product origin (e.g. `https://gravity.mprlab.com`) and the hosted TAuth origin (e.g. `https://tauth.mprlab.com`) to the *Authorized JavaScript origins* list. Redirect URIs are not required for this popup flow.
2. **Load the GIS SDK before you render a button.**

   ```html
   <script src="https://accounts.google.com/gsi/client" async defer></script>
   <div id="googleSignIn"></div>
   ```

3. **Fetch and attach a nonce before prompting Google.** Use `POST /auth/nonce`, call `google.accounts.id.initialize({ nonce, client_id, ux_mode: "popup" })`, and render the button programmatically (see `prepareGoogleSignIn` above or `web/demo.html`).
4. **Exchange the credential without redirecting.** When GIS invokes your callback, post `{ google_id_token, nonce_token }` to `https://tauth.mprlab.com/auth/google` (or your hosted base URL) with `credentials: "include"` so TAuth can mint cookies.

### Quick verification checklist

- Open the browser console and confirm a nonce request (`POST /auth/nonce`) fires before the GIS popup.
- Click the button; the popup should open and return a credential to `handleCredential`.
- Check the network tab for `POST https://tauth.mprlab.com/auth/google` and ensure it succeeds (`200`).
- Inspect cookies; `app_session` and `app_refresh` should now be scoped to the configured domain (e.g. `.mprlab.com`).
- Call `/api/me` and verify it returns the signed-in profile.

> **Tip:** The Docker demo ships with a placeholder Google OAuth Web client inside `examples/docker-compose/config.yaml.example`. Replace it with your own value before sharing the stack beyond local testing.

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

Use the new `avatar_url` field to render signed-in UI chrome (e.g. the shared mpr-ui header component).

---

## Multi-tenant configuration

TAuth now reads **all** configuration from a single YAML file (`config.yaml` by default). The snippet above shows the server-level keys; the example below highlights the `tenants` section. A “single-tenant deployment” is simply a file with one entry; adding more entries lets you serve multiple products from the same binary without touching CLI flags.

```yaml
tenants:
  - id: "demo"
    display_name: "Demo tenant"
    allowed_hosts:
      - "demo.localhost"
      - "demo.example.com"
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    cookie_domain: "demo.example.com"
    session_ttl: "30m"
    refresh_ttl: "720h"
    nonce_ttl: "10m"
    allow_insecure_http: true
```

Rules enforced by the loader:

- IDs must use lowercase letters, digits, underscores, or hyphens (`demo`, `customer_b`).
- `display_name` is required so operators can distinguish tenants in logs.
- `allowed_hosts` entries are validated and normalized (lowercase, IPv6 brackets handled). If multiple tenants claim the same host, include their front-end origins (`http://localhost:8000`, `https://app.example.com`, …) so TAuth can disambiguate via the `Origin` header. You can still enable the header override to enforce explicit tenant selection. Add every hostname or origin that should resolve to this tenant (API base, UI origin, vanity domain, etc.).
- `google_web_client_id` and each TTL must be present and non-empty. Durations use Go’s `time.ParseDuration` syntax (e.g. `15m`, `720h`); zero or negative values are invalid. `cookie_domain` may be blank to issue host-only cookies (recommended locally); when provided it must be a valid registrable domain (e.g. `.example.com`).
- `session_cookie_name` / `refresh_cookie_name` must be specified for every tenant. Choose unique values per tenant to avoid overwriting each other’s cookies when they share a host (for example `app_session_notes`, `app_refresh_mpr`). Legacy stacks (such as Gravity) can keep `app_session`/`app_refresh` as long as they understand the collision risk.
- `nonce_ttl` defaults to `5m` if omitted; `allow_insecure_http` defaults to `false` and should only be `true` for localhost development. With that flag enabled, cookies downgrade to `SameSite=Lax` and omit the `Secure` bit so browsers accept them over HTTP.
- Values support shell-style environment expansion (`${TENANT_COOKIE_DOMAIN}` or `$TENANT_COOKIE_DOMAIN`) before parsing. Missing variables resolve to empty strings, so leave meaningful defaults in the file to avoid loader validation errors.

The `internal/tenants` package validates the entire file before returning domain objects, so downstream routing relies on trusted tenant definitions. Request routing works as follows:

- The resolver matches tenants by the request’s host header (case-insensitive, port stripped). Hosts not declared in the tenant file are rejected before reaching auth routes.
- For local development or automated tests you can enable the optional header override (`enable_tenant_header_override: true`). When enabled, TAuth accepts either a tenant ID (`X-TAuth-Tenant: demo`) or a frontend origin (`X-TAuth-Tenant: http://localhost:8000`) as the override hint. This keeps shared-host setups working even when certain requests omit `Origin` headers. Leave it disabled in production when every tenant owns unique hosts.
- `internal/tenants.TenantMiddleware` attaches the resolved tenant to `gin.Context`; downstream handlers call `tenants.TenantFromContext` to retrieve the resolved configuration and proceed with tenant-scoped logic.
- Launch the server with `tauth --config=/path/to/config.yaml` (or export `TAUTH_CONFIG_FILE`); no other CLI flags or environment variables are required.
- Front-ends that share a single host can still opt into an explicit tenant selection by adding `data-tenant-id="tenant-a"` to the `<script src=".../auth-client.js">` tag or by calling `setAuthTenantId("tenant-a")` before `initAuthClient(...)` when you need to override the origin mapping (for example, preview builds served from the same origin). `auth-client.js` automatically adds the `X-TAuth-Tenant` header to its own `/me`, `/auth/nonce`, `/auth/google`, `/auth/refresh`, and logout calls (falling back to the current page origin whenever you don’t provide a tenant ID) while leaving your product’s API traffic untouched.
- Refresh tokens, nonce pools, and the built-in demo user store are keyed by tenant ID. Session JWTs now embed a `tenant_id` claim, and the middleware rejects cookies presented under the wrong tenant so credentials cannot hop between hostnames.

---

### Google nonce handling

Custom clients must follow the nonce exchange documented in [ARCHITECTURE.md#google-sign-in-exchange](ARCHITECTURE.md#google-sign-in-exchange). The README’s quick-start sticks to the happy-path view; dive into the architecture doc for the exact sequencing (nonce issuance, GIS initialization, credential exchange, and `/auth/google` expectations). The default helpers already implement the full set of guardrails.

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
- Inspect `web/auth-client.js` to extend UI hooks or wire additional analytics.
- Validate sessions from other Go services with [`pkg/sessionvalidator`](pkg/sessionvalidator/README.md).

---

## License

MIT (or your preferred license). Add a `LICENSE` file accordingly.

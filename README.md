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

### 1. Create a Google OAuth Web client

Register the product origin you want to protect (e.g. `https://gravity.mprlab.com`) inside Google Cloud Console and copy the Web Client ID. Add `https://tauth.mprlab.com` as an authorized JavaScript origin so the nonce exchange can run from the hosted service.

### 2. Launch the service (e.g. on `https://tauth.mprlab.com`)

```bash
export APP_LISTEN_ADDR=":8443"                            # or the port your ingress forwards to
export APP_GOOGLE_WEB_CLIENT_ID="your_web_client_id.apps.googleusercontent.com"
export APP_JWT_SIGNING_KEY="$(openssl rand -base64 48)"
export APP_COOKIE_DOMAIN=".mprlab.com"                    # share cookies across tauth + gravity subdomains
export APP_ENABLE_CORS="true"                            # allow the product origin to call TAuth
export APP_CORS_ALLOWED_ORIGINS="https://gravity.mprlab.com"
# Optional persistence (choose one):
# export APP_DATABASE_URL="postgres://user:pass@db.internal:5432/authdb?sslmode=disable"
# export APP_DATABASE_URL="sqlite:///auth.db"

tauth --listen_addr=":8443" --google_web_client_id="$APP_GOOGLE_WEB_CLIENT_ID" \
  --jwt_signing_key="$APP_JWT_SIGNING_KEY" --cookie_domain="$APP_COOKIE_DOMAIN" \
  --enable_cors --cors_allowed_origins="https://gravity.mprlab.com"
```

> SQLite DSN tip: use three slashes for absolute paths (e.g. `sqlite:///data/tauth.db`). Host-based forms such as `sqlite://file:/data/tauth.db` are invalid and rejected at startup.

When multiple product origins need access, provide a comma-separated list via the environment variable (e.g. `export APP_CORS_ALLOWED_ORIGINS="https://gravity.mprlab.com,https://gravity-admin.mprlab.com"`) or repeat the CLI flag for each origin.

Host the binary behind TLS (or terminate TLS at your load balancer) so responses set `Secure` cookies. With the cookie domain set to `.mprlab.com`, the session cookies issued by `https://tauth.mprlab.com` will also be sent with requests made by `https://gravity.mprlab.com`.

### Run the demo with Docker Compose (local quick-start)

We ship a compose example under `examples/docker-compose` that builds TAuth from the local Dockerfile and pairs it with a simple static web server (`ghcr.io/tyemirov/ghttp:latest`) serving the repository’s `web/` directory on port `8000`.

1. `cd examples/docker-compose`
2. Copy and edit the environment template:

   ```bash
   cp .env.tauth.example .env.tauth
   # edit APP_GOOGLE_WEB_CLIENT_ID + APP_JWT_SIGNING_KEY, keep APP_DATABASE_URL=sqlite:///data/tauth.db
   ```

3. Build and start the stack: `docker compose up --build`
4. Visit `http://localhost:8000` to load the demo UI (it communicates with TAuth at `http://localhost:8080` via CORS).

Stop the stack with `docker compose down`. The compose file persists refresh tokens inside a named `tauth_data` volume mounted at `/data`, so you can inspect or reset the SQLite database between runs. Update `.env.tauth` to change ports, cookie domains, or Google credentials before re-running. Re-run `docker compose up --build` whenever you change Go code so the local image picks up your edits.

### 3. Integrate the browser helper from the product site

```html
<script src="https://tauth.mprlab.com/static/auth-client.js"></script>
<script>
  initAuthClient({
    baseUrl: "https://tauth.mprlab.com",
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

> **Tip:** The demo falls back to a public sample client ID when `APP_GOOGLE_WEB_CLIENT_ID` is not set. Replace it with your own Google OAuth Web client in production.

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

## Multi-tenant configuration (preview)

Upcoming work introduces first-class multi-tenant deployments so a single TAuth instance can front several product surfaces (each with its own Google Web client, cookie domain, and TTL settings). Declare tenants in a JSON file:

```json
{
  "tenants": [
    {
      "id": "demo",
      "display_name": "Demo tenant",
      "hosts": ["demo.localhost", "demo.example.com"],
      "google_web_client_id": "demo-client.apps.googleusercontent.com",
      "cookie_domain": "demo.example.com",
      "session_ttl": "30m",
      "refresh_ttl": "720h",
      "nonce_ttl": "10m",
      "allow_insecure_http": true
    }
  ]
}
```

Rules enforced by the loader:

- IDs must use lowercase letters, digits, underscores, or hyphens (`demo`, `customer_b`).
- Every host can map to only one tenant; duplicates or blank hosts fail validation.
- Durations use Go’s `time.ParseDuration` syntax (e.g. `15m`, `720h`); zero or negative values are invalid.
- `nonce_ttl` defaults to `5m` if omitted; `allow_insecure_http` defaults to `false`.

The new `internal/tenants` package validates the entire file before returning domain objects, enabling the upcoming resolver and routing work to trust tenant data without repeating validation.

---

### Google nonce handling

Custom clients must follow the nonce exchange documented in [ARCHITECTURE.md#google-sign-in-exchange](ARCHITECTURE.md#google-sign-in-exchange). The README’s quick-start sticks to the happy-path view; dive into the architecture doc for the exact sequencing (nonce issuance, GIS initialization, credential exchange, and `/auth/google` expectations). The default helpers already implement the full set of guardrails.

---

## Deploy with confidence

- Works out of the box for any single registrable domain—host TAuth once and share cookies across subdomains.
- Toggle CORS (and `SameSite=None` automatically) when your UI is served from a different origin during development.
- Point `APP_DATABASE_URL` at Postgres or SQLite to store refresh tokens durably.
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

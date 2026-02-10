# TAuth Usage Guide

This document is the authoritative guide for operators and front‑end teams integrating against a TAuth deployment. It explains how to run the service, how sessions work, and how to connect a browser application using either the provided helper script or direct HTTP calls.

For a deep dive into internal architecture and implementation details, see `ARCHITECTURE.md`. For confident‑programming and refactor policies, see `POLICY.md` and `docs/refactor-plan.md`.

---

## 1. What TAuth provides

TAuth sits between Google Identity Services (GIS) and your product UI:

- Verifies Google ID tokens issued by a Google OAuth Web client.
- Mints short‑lived access cookies and long‑lived refresh cookies.
- Rotates refresh tokens on every refresh call and revokes them on logout.
- Exposes a small HTTP API and a browser helper (`/tauth.js`) for zero-token-in-JavaScript sessions.
- Does not implement OAuth2 authorization for Google APIs (YouTube/Drive/etc) and does not issue Google API access tokens.

Once TAuth is running for a given registrable domain, any app on that domain (or its subdomains) can rely on the `HttpOnly` session cookies instead of storing tokens in `localStorage` or JavaScript memory.

---

## 2. Running the service

### 2.1 Binary layout

The `tauth` binary lives under `cmd/server` in this repository. You can:

- Build it directly with Go (e.g. `go build ./cmd/server`), or
 - Use the provided Docker setup in `examples/tauth-demo` for a local stack.

The binary reads configuration exclusively from a YAML file (default `config.yaml`). Use `tauth --config=/path/to/config.yaml` or export `TAUTH_CONFIG_FILE` to point at a different file; no other environment variables or CLI flags are required.

### 2.2 Core configuration

`config.yaml` must include the server-level keys below plus at least one tenant:

| Key | Purpose | Example |
| --- | --- | --- |
| `listen_addr` | HTTP listen address | `:8080` |
| `database_url` | Refresh store DSN | `sqlite:///data/tauth.db` |
| `enable_cors` | Enable CORS for cross-origin UIs | `true` / `false` |
| `cors_allowed_origins` | Allowed origins when CORS is enabled (include your UI origins *and* `https://accounts.google.com`) | `["https://app.example.com","https://accounts.google.com"]` |
| `cors_allowed_origin_exceptions` | Allowed non-tenant origins that may appear in `cors_allowed_origins` | `["https://accounts.google.com"]` |
| `enable_tenant_header_override` | Allow `X-TAuth-Tenant` overrides (dev/local only) | `true` / `false` |
| `tenants` | Array of tenant entries (see README §5.1 for schema) | `[...]` |

Key notes:

- **TLS and cookies**: In production, terminate TLS at the load balancer or the service so cookies can be marked `Secure`. Each tenant defines its own `cookie_domain`; use that field (e.g. `.example.com`) to share cookies across subdomains. Leave the field blank to emit host-only cookies during `localhost` development (browsers reject `Domain=localhost`).
- **Database URL**: For SQLite, use triple‑slash absolute paths (`sqlite:///data/tauth.db`). Host‑based forms such as `sqlite://file:/data/tauth.db` are rejected. For Postgres, use a standard DSN (`postgres://user:pass@host:5432/dbname?sslmode=disable`).
- **CORS**: Leave `enable_cors` set to `false` when UI and API share the same origin. Enable it only when your UI is on a different origin (for example, Vite dev server) and set `cors_allowed_origins` explicitly. If you include non-tenant origins (for example `https://accounts.google.com`), also list them under `cors_allowed_origin_exceptions` so validation permits them.
- **Shared origins**: If multiple tenants run on the same machine, add each distinct frontend origin (`http://localhost:8000`, `http://localhost:4173`, …) to the tenant’s `tenant_origins` so TAuth can resolve the tenant from the request `Origin` header. Only enable `enable_tenant_header_override` (and send `X-TAuth-Tenant`) when tenants intentionally share the exact same origin or when non-browser clients omit `Origin`.
- **Per-tenant signing keys**: Each tenant block must declare a `jwt_signing_key`. TAuth uses that HS256 secret exclusively for the tenant’s cookies, so rotate keys per tenant instead of relying on a global fallback.
- **Local HTTP mode**: Setting `allow_insecure_http: true` on a tenant drops the `Secure` flag and downgrades cookies to `SameSite=Lax` so browsers keep them over HTTP even while CORS is enabled. This only works when your dev UI also runs on `http://localhost` (same host, different port); switching hosts such as `127.0.0.1` will make the browser treat the request as cross-site and block the cookies.

### 2.3 Example: hosted deployment

This example mirrors the README but focuses on the minimum you need to host TAuth at `https://auth.example.com` for a product UI at `https://app.example.com`:

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
  - id: "prod"
    display_name: "Production Tenant"
    tenant_origins:
      - "https://app.example.com"
    allowed_users:
      - "user@example.com"
    google_web_client_id: "your_web_client_id.apps.googleusercontent.com"
    jwt_signing_key: "replace-with-your-tenant-signing-key"
    cookie_domain: ".example.com"
    session_ttl: "15m"
    refresh_ttl: "1440h"
    nonce_ttl: "5m"
    allow_insecure_http: false
YAML

tauth --config=config.yaml
```

Run this behind TLS so the service issues `Secure` cookies and the browser accepts them.
To restrict sign-ins, set `allowed_users` on a tenant; when present, only those email addresses are permitted to log in (an empty list denies all logins).
Behavior: `allowed_users` absent → allow all; present empty → deny all; present with entries → allow only listed emails.

When migrating an existing tenant that expects the legacy cookie names (`app_session`, `app_refresh`), set the `session_cookie_name` / `refresh_cookie_name` fields inside the tenant block. These fields are always required—choose unique names per tenant to avoid collisions when multiple tenants share `localhost`. Legacy stacks (such as Gravity) can keep `app_session` / `app_refresh`, but doing so means any other tenant using the same names will overwrite those cookies.

### 2.4 Example: local quick‑start (Docker Compose)

For a full local stack (TAuth + demo UI) without installing Go:

1. `cd examples/tauth-demo`
2. Edit `.env.tauth` (set `TAUTH_CONFIG_FILE=/config/config.yaml` and the per-tenant `TAUTH_GOOGLE_WEB_CLIENT_ID` / `TAUTH_JWT_SIGNING_KEY` values).
3. Review `config.yaml` and replace the placeholder Google OAuth client with one registered for `http://localhost:8000` and `http://localhost:8082` (or keep the environment variable references from step 2).
4. Start the stack: `docker compose up --build`
5. Visit `http://localhost:8000` for the demo UI. It talks to TAuth at `http://localhost:8082`.

Stop the stack with `docker compose down`. The `tauth_data` volume holds the SQLite database, and `config.yaml` stays next to the compose file for future edits.

### 2.5 Preflight validation (pre-start)

Use the preflight command to validate configuration and emit a redacted effective-config report before you launch the service:

```bash
tauth preflight --config=config.yaml
```

The report includes effective server settings, per-tenant cookie names and TTLs, derived SameSite modes, and JWT signing key fingerprints (never raw keys). Redacted reports still emit `tenant_origin_hashes` and `jwt_signing_key_fingerprint` so external validators can compare secrets without exposing them. To include the raw `tenant_origins` list, pass `--include-origins`.

The JSON payload is versioned and shaped as:
- `schema_version`, `service` metadata
- `effective_config` (server + tenant settings)
- `dependencies` (preflight checks with readiness status)

The preflight builder is generalized under `github.com/tyemirov/utils/preflight` with a Viper-based adapter (`github.com/tyemirov/utils/preflight/viperconfig`) for services that load YAML configs and bind env vars through Viper.

---

## 3. Sessions and cookies

TAuth works with two cookies:

- `app_session` – short‑lived JWT access token.
  - `HttpOnly`, `Secure`, `SameSite` (strict by default).
  - Sent with all requests under the configured cookie domain.
- `app_refresh` – opaque refresh token.
  - `HttpOnly`, `Secure`, `Path=/auth`.
  - Rotated on `/auth/refresh` and revoked on `/auth/logout`.

Your product should:

- Use `app_session` to protect routes (for example via `pkg/sessionvalidator` in other Go services).
- Never store tokens in JavaScript; rely on these cookies.
- Call `/auth/refresh` when API calls return `401` to keep sessions alive.

---

## 4. Recommended integration: `tauth.js`

The simplest way to use TAuth from the browser is through the helper served at `/tauth.js`. It exports eight globals:

- `initAuthClient(options)` – hydrates the current user and sets up refresh behaviour.
- `apiFetch(url, init)` – wrapper around `fetch` that automatically refreshes sessions on `401`.
- `getCurrentUser()` – returns the current profile object or `null`.
- `getAuthEndpoints()` – returns the resolved URL map for `/api/me` and `/auth/*`.
- `requestNonce()` – fetches a one-time nonce for Google Identity Services.
- `exchangeGoogleCredential({ credential, nonceToken })` – exchanges the Google credential for cookies and updates the profile.
- `logout()` – revokes the refresh token and clears client state.
- `setAuthTenantId(tenantId)` – sets the tenant override for subsequent requests.

For backend services written in Go, use the `pkg/sessionvalidator` package described in section 6.8 to validate `app_session` cookies.

### 4.1 Loading the helper

On your product site, include the script from wherever you host the asset:

```html
<script
  src="https://tauth.mprlab.com/tauth.js"
  data-tenant-id="tenant-admin"
></script>
```

### 4.2 Initialising on page load

Call `initAuthClient` once during startup, after the script loads. The `baseUrl` option is required and must point at your TAuth API origin:

```html
<script>
  // Optional: override tenant dynamically when the page knows which tenant to use.
  setAuthTenantId("tenant-admin");
  initAuthClient({
    baseUrl: "https://auth.example.com",
    tenantId: "demo", // optional override for shared-origin dev setups
    onAuthenticated(profile) {
      renderDashboard(profile);
    },
    onUnauthenticated() {
      showSignInButton();
    },
  });
</script>
```

Behaviour:

- TAuth calls `GET /api/me` to check for an existing session.
- If missing or expired, it attempts `POST /auth/refresh`.
- If refresh succeeds, it calls `onAuthenticated(profile)`; otherwise it calls `onUnauthenticated()`.
- The `profile` object matches the `/api/me` response (see section 6.3).

### 4.3 Calling your own APIs with `apiFetch`

Wrap all authenticated HTTP requests through `apiFetch`:

```js
async function loadProtectedData() {
  const response = await apiFetch("/api/data", { method: "GET" });
  if (!response.ok) {
    throw new Error("request_failed");
  }
  return response.json();
}
```

When a call returns `401`, `apiFetch`:

1. Sends `POST /auth/refresh` with `credentials: "include"`.
2. Retries the original request on success.
3. Broadcasts `"refreshed"` events via `BroadcastChannel` (if available), allowing multiple tabs to stay in sync.

If refresh fails, pending requests reject and callers can treat this as “logged out”.

### 4.4 Logging out

Use `logout()` to terminate the session:

```js
async function handleLogoutClick() {
  await logout();
  redirectToLanding();
}
```

The helper:

- Calls `POST /auth/logout` to revoke the refresh token.
- Clears local profile state.
- Broadcasts `"logged_out"` to other tabs.
- Invokes `onUnauthenticated()` if provided.

### 4.5 Selecting a tenant explicitly

Most deployments rely on the request `Origin` header to resolve tenants. When multiple tenants intentionally share the same origin (for example, several apps pointing at `http://localhost:8080`) or when requests omit `Origin` (non-browser clients), enable the TAuth server’s header override (`--enable_tenant_header_override`). Once enabled, the helper tags `/api/me` and `/auth/*` calls only when you explicitly supply a `tenantId`. You can pin a specific tenant explicitly by passing `tenantId` to `initAuthClient`:

```js
initAuthClient({
  baseUrl: "https://auth-dev.example.com",
  tenantId: "team-blue",
  onAuthenticated: hydrateDashboard,
  onUnauthenticated: showGoogleButton,
});
```

The helper automatically attaches `X-TAuth-Tenant: team-blue` to `/api/me`, `/auth/nonce`, `/auth/google`, `/auth/refresh`, and logout requests while leaving your own API traffic alone. Switch tenants by reinitialising with a different `tenantId` (or prefer separate origins when possible). The override still resolves against the configured tenant list, so unknown tenant IDs or origins are rejected.

---

## 5. Google Identity Services flow

TAuth assumes a GIS **Web** client using the popup flow. A nonce protects each sign‑in exchange.

### 5.1 Configure GIS

1. Create (or reuse) a Google OAuth Web client.
2. Add all product origins (for example `https://app.example.com`) to **Authorized JavaScript origins**.
3. Load the GIS script:

   ```html
   <script src="https://accounts.google.com/gsi/client" async defer></script>
   <div id="googleSignIn"></div>
   ```

### 5.2 Nonce and credential exchange

The required sequence for custom clients is:

1. **Nonce** – `POST /auth/nonce`
   - Returns `{ "nonce": "<random>" }`.
2. **Initialize GIS** with the nonce:
   - `google.accounts.id.initialize({ client_id, nonce, ux_mode: "popup", callback })`.
3. **Show the button / popup** via GIS APIs.
4. **Exchange credential** – when GIS invokes your callback with `response.credential`:
   - Call `POST /auth/google` with JSON `{ "google_id_token": "<response.credential>", "nonce_token": "<same nonce>" }` and `credentials: "include"`.
5. TAuth:
   - Validates the ID token against the resolved tenant’s `google_web_client_id`.
   - Verifies the nonce (raw or hashed) and the issuer.
   - Issues `app_session` and `app_refresh` cookies.
   - Returns a profile JSON payload.

> You must fetch a fresh nonce for every sign‑in attempt. TAuth invalidates a nonce as soon as it is used.

When using `tauth.js` or the mpr‑ui header component, this flow is handled internally; you only need to surface the Google button and configure your client ID.

---

## 6. HTTP endpoints

This section documents the public HTTP surface from a client’s perspective. See `ARCHITECTURE.md` for a stable contract summary and versioning notes. These endpoints are served exclusively by the TAuth server; consuming applications should call them, not reimplement them.

### 6.1 `POST /auth/nonce`

Issues a one‑time nonce for the next GIS exchange.

- **Request**: empty JSON body. Include `credentials: "include"` if you want to reuse cookies on same origin.
- **Response**: `200 OK` with JSON:

  ```json
  { "nonce": "..." }
  ```

### 6.2 `POST /auth/google`

Verifies a Google ID token and mints cookies.

- **Request body**:

  ```json
  {
    "google_id_token": "<id_token_from_gis>",
    "nonce_token": "<nonce_from_/auth/nonce>"
  }
  ```

- **Response**: `200 OK` with user profile JSON (see `/api/me` below). Sets `app_session` and `app_refresh` cookies.

Common failure cases:

- Invalid or expired ID token (`401`).
- Mismatched nonce (`401`).
- Audience (`aud`) does not match the resolved tenant’s `google_web_client_id` (`401`).

### 6.3 `GET /api/me`

Returns the profile associated with the current session.

- **Auth**: requires a valid `app_session` cookie.
- **Response**:

  ```json
  {
    "user_id": "google:12345",
    "user_email": "user@example.com",
    "display": "Example User",
    "avatar_url": "https://lh3.googleusercontent.com/a/...",
    "roles": ["user"],
    "expires": "2024-05-30T12:34:56.000Z"
  }
  ```

- **Errors**: `401` when the access cookie is missing, expired, or invalid.

### 6.4 `POST /auth/refresh`

Rotates the refresh token and mints a new access cookie.

- **Auth**: requires a valid `app_refresh` cookie.
- **Request body**: empty.
- **Response**: `204 No Content` on success. Sets new `app_session` and `app_refresh` cookies.

After a successful refresh, call `/api/me` again or rely on `tauth.js` to hydrate the profile.

### 6.5 `POST /auth/logout`

Revokes the refresh token and clears cookies.

- **Auth**: best‑effort; succeeds even if no valid refresh token is present.
- **Request body**: empty.
- **Response**: `204 No Content`. Clears `app_session` and `app_refresh`.

Clients should treat this as “signed out” regardless of prior state.

### 6.6 `GET /tauth.js`

Serves the browser helper described in section 4.

- Include it via `<script src="https://your-tauth-origin/tauth.js"></script>`.
- Exposes `initAuthClient`, `apiFetch`, `getCurrentUser`, `getAuthEndpoints`, `requestNonce`, `exchangeGoogleCredential`, `logout`, and `setAuthTenantId` on `window`.
- The TAuth service serves only API endpoints plus `/tauth.js`; demo pages live in `examples/` and are served separately.

## 6.7 Validating sessions from other Go services

Downstream Go services that share the TAuth cookie domain can validate `app_session` cookies directly using the `pkg/sessionvalidator` package. This is the recommended way to enforce authentication and read identity information without duplicating JWT logic.
If your service can read the same `config.yaml` as TAuth, call `LoadTenantAuthConfig` to derive the tenant’s signing key, issuer, and cookie names before constructing a validator.

### 6.7.1 Basic validator setup

Add the module to your Go service and construct a validator at startup:

```go
import (
    "os"

    "github.com/tyemirov/tauth/pkg/sessionvalidator"
)

func newSessionValidator() (*sessionvalidator.Validator, error) {
    signingKey := []byte(os.Getenv("TAUTH_NOTES_JWT_SIGNING_KEY"))
    return sessionvalidator.New(sessionvalidator.Config{
        SigningKey: signingKey,
        Issuer:     "tauth",
        // CookieName: optional; defaults to "app_session".
    })
}
```

The configuration mirrors your TAuth deployment:

- `SigningKey` must match the `jwt_signing_key` configured for the tenant whose cookies you validate.
- `Issuer` must match the issuer configured by the server (typically `"tauth"`; see `ARCHITECTURE.md`).
- `CookieName` defaults to `app_session` and should only be overridden if you have customised the cookie name on the TAuth side.

The constructor validates configuration up front and returns a typed error if required fields are missing.

### 6.7.2 Gin middleware integration

For Gin-based services, use the built-in middleware to protect routes and attach claims to the context:

```go
import (
    "log"

    "github.com/gin-gonic/gin"
    "github.com/tyemirov/tauth/pkg/sessionvalidator"
)

func main() {
    validator, err := newSessionValidator()
    if err != nil {
        log.Fatalf("invalid validator configuration: %v", err)
    }

    router := gin.Default()
    router.Use(validator.GinMiddleware(sessionvalidator.DefaultContextKey))

    router.GET("/api/me", func(context *gin.Context) {
        claimsValue, exists := context.Get(sessionvalidator.DefaultContextKey)
        if !exists {
            context.AbortWithStatus(http.StatusUnauthorized)
            return
        }
        claims := claimsValue.(*sessionvalidator.Claims)
        context.JSON(http.StatusOK, map[string]interface{}{
            "user_id":    claims.GetUserID(),
            "user_email": claims.GetUserEmail(),
            "display":    claims.GetUserDisplayName(),
            "avatar_url": claims.GetUserAvatarURL(),
            "roles":      claims.GetUserRoles(),
        })
    })

    _ = router.Run()
}
```

Key points:

- The middleware reads the `app_session` cookie from each request, validates it, and aborts with `401` when invalid.
- On success, it stores a `*sessionvalidator.Claims` value in the Gin context under the provided key (default `auth_claims`).
- Handler code can safely cast this value and use the helper methods (`GetUserID`, `GetUserEmail`, `GetUserDisplayName`, `GetUserAvatarURL`, `GetUserRoles`, `GetExpiresAt`) to drive authorization and UI decisions.

### 6.8.3 Manual validation flows

If you are not using Gin, or you need finer-grained control, use the lower-level helpers:

- `ValidateRequest(*http.Request)` – validates the session cookie on an incoming request and returns `*Claims`.
- `ValidateToken(string)` – validates a raw JWT string, for example when the token is forwarded between services.

Example with `net/http`:

```go
func handleProtectedRoute(response http.ResponseWriter, request *http.Request, validator *sessionvalidator.Validator) {
    claims, err := validator.ValidateRequest(request)
    if err != nil {
        http.Error(response, "unauthorized", http.StatusUnauthorized)
        return
    }
    // Use claims.* accessors here.
}
```

Using the shared validator keeps your services aligned with TAuth’s JWT format and validation rules, and avoids duplicating cryptographic or time-based logic across codebases.

---

## 7. Typical flows

### 7.1 First sign‑in

1. User clicks “Sign in with Google”.
2. UI calls `/auth/nonce`, configures GIS with the nonce, and shows the popup.
3. GIS returns a credential; UI posts it to `/auth/google`.
4. TAuth validates the token, issues cookies, returns profile JSON.
5. UI renders signed‑in state and begins using `apiFetch` for protected calls.

### 7.2 Silent refresh

1. An API call via `apiFetch` returns `401`.
2. `apiFetch` sends `POST /auth/refresh` with the refresh cookie.
3. On success, it retries the original request and broadcasts `"refreshed"`.
4. UI continues to operate with renewed session cookies.

### 7.3 Logout

1. User clicks “Sign out”.
2. UI calls `logout()`.
3. TAuth revokes the refresh token and clears cookies.
4. Helper broadcasts `"logged_out"`; all tabs transition to unauthenticated state.

---

## 8. Troubleshooting

Use this checklist when integrating:

- **401 from `/api/me` but refresh works** – Session cookie expired; ensure your client either uses `tauth.js` or calls `/auth/refresh` before retrying.
- **401 from `/auth/refresh`** – Refresh cookie missing or revoked; treat as “signed out” and prompt the user to sign in again.
- **No cookies set** – Verify:
  - The response comes from HTTPS (in production).
  - The tenant’s `cookie_domain` matches the registrable domain you expect.
  - CORS is configured correctly when using a split origin (`enable_cors` and `cors_allowed_origins` in `config.yaml`).
- **Tenant resolution failures** – The JSON response includes `error_code`, `error_message`, and `hint`, plus `origin`/`header_*` fields when applicable. Common codes:
  - `tenantresolver.missing_origin` – browser did not send `Origin`; enable header override for non-browser/same-origin clients.
  - `tenantresolver.unknown_origin` – add the origin to `tenant_origins`.
  - `tenantresolver.ambiguous_origin` – multiple tenants share the origin; provide `X-TAuth-Tenant`.
  - `tenantresolver.override_mismatch` or `tenantresolver.unknown_tenant_id` – header override does not match a configured tenant.
- **403 from `/auth/google` with `user_not_allowed`** – The email is not listed under the tenant’s `allowed_users` allowlist (or the list is empty).
- **Google rejects the client or TAuth rejects the token** – Confirm:
  - The OAuth client type is **Web**.
  - All relevant origins are in the **Authorized JavaScript origins** list.
  - The `aud` claim in the ID token matches the tenant’s `google_web_client_id`.

For more detailed operational guidance, refer to the troubleshooting section in `ARCHITECTURE.md`.
- When multiple tenants share the same origin, list each frontend origin under `tenant_origins` so TAuth can resolve the tenant from the `Origin` header. You can override the mapping by adding `data-tenant-id="tenant-id"` to the script tag (see 4.1) or by calling `setAuthTenantId("tenant-id")` before `initAuthClient(...)`. The helper only sends `X-TAuth-Tenant` when you opt into an explicit override.

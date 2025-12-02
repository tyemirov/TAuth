# TAuth Usage Guide

This document is the authoritative guide for operators and front‑end teams integrating against a TAuth deployment. It explains how to run the service, how sessions work, and how to connect a browser application using either the provided helper script or direct HTTP calls.

For a deep dive into internal architecture and implementation details, see `ARCHITECTURE.md`. For confident‑programming and refactor policies, see `POLICY.md` and `docs/refactor-plan.md`.

---

## 1. What TAuth provides

TAuth sits between Google Identity Services (GIS) and your product UI:

- Verifies Google ID tokens issued by a Google OAuth Web client.
- Mints short‑lived access cookies and long‑lived refresh cookies.
- Rotates refresh tokens on every refresh call and revokes them on logout.
- Exposes a small HTTP API and a browser helper (`/static/auth-client.js`) for zero-token-in-JavaScript sessions.

Once TAuth is running for a given registrable domain, any app on that domain (or its subdomains) can rely on the `HttpOnly` session cookies instead of storing tokens in `localStorage` or JavaScript memory.

---

## 2. Running the service

### 2.1 Binary layout

The `tauth` binary lives under `cmd/server` in this repository. You can:

- Build it directly with Go (e.g. `go build ./cmd/server`), or
- Use the provided Docker setup in `examples/docker-compose` for a local stack.

The binary exposes configuration via environment variables (preferred) and CLI flags (for overrides). Viper merges both sources.

### 2.2 Core configuration

At minimum you must set:

- `APP_TENANTS_FILE` – Path to the tenants YAML file (see section 5.1 in the README for the schema).
- `APP_JWT_SIGNING_KEY` – HS256 signing key for access JWTs (use a high‑entropy secret shared across all tenants).

Common environment variables:

| Variable                     | Purpose                                                          | Example                                 |
|------------------------------|------------------------------------------------------------------|-----------------------------------------|
| Variable                    | Purpose                                                          | Example                                 |
|-----------------------------|------------------------------------------------------------------|-----------------------------------------|
| `APP_LISTEN_ADDR`           | HTTP listen address                                              | `:8080`                                 |
| `APP_TENANTS_FILE`          | Path to tenants YAML file                                        | `/etc/tauth/tenants.yaml`               |
| `APP_JWT_SIGNING_KEY`       | HS256 signing secret                                             | `openssl rand -base64 48`               |
| `APP_DATABASE_URL`          | Refresh store DSN                                                | `sqlite:///data/tauth.db`               |
| `APP_ENABLE_CORS`           | Enable CORS for cross-origin UIs                                 | `true`                                  |
| `APP_CORS_ALLOWED_ORIGINS`  | Comma-separated allowed origins when CORS is enabled (include your UI origins *and* `https://accounts.google.com`) | `https://app.example.com,https://accounts.google.com` |

Key notes:

- **TLS and cookies**: In production, terminate TLS at the load balancer or the service so cookies can be marked `Secure`. Each tenant in `APP_TENANTS_FILE` defines its own `cookie_domain`; use that field (e.g. `.example.com`) to share cookies across subdomains.
- **Database URL**: For SQLite, use triple‑slash absolute paths (`sqlite:///data/tauth.db`). Host‑based forms such as `sqlite://file:/data/tauth.db` are rejected. For Postgres, use a standard DSN (`postgres://user:pass@host:5432/dbname?sslmode=disable`).
- **CORS**: Leave `APP_ENABLE_CORS` unset when UI and API share the same origin. Enable it only when your UI is on a different origin (for example, Vite dev server) and set `APP_CORS_ALLOWED_ORIGINS` explicitly. Google Identity Services performs its nonce/login exchange from the `https://accounts.google.com` origin, so *always* include that origin alongside your UI hosts.

### 2.3 Example: hosted deployment

This example mirrors the README but focuses on the minimum you need to host TAuth at `https://auth.example.com` for a product UI at `https://app.example.com`:

```bash
cat > tenants.yaml <<'YAML'
tenants:
  - id: "prod"
    display_name: "Production Tenant"
    hosts:
      - "auth.example.com"
      - "app.example.com"
    google_web_client_id: "your_web_client_id.apps.googleusercontent.com"
    cookie_domain: ".example.com"
    session_ttl: "15m"
    refresh_ttl: "1440h"
    nonce_ttl: "5m"
    allow_insecure_http: false
YAML

export APP_LISTEN_ADDR=":8443"
export APP_JWT_SIGNING_KEY="$(openssl rand -base64 48)"
export APP_TENANTS_FILE="$(pwd)/tenants.yaml"
export APP_ENABLE_CORS="true"
export APP_CORS_ALLOWED_ORIGINS="https://app.example.com,https://accounts.google.com"
export APP_DATABASE_URL="sqlite:///data/tauth.db"

tauth \
  --listen_addr=":8443" \
  --jwt_signing_key="$APP_JWT_SIGNING_KEY" \
  --tenants_file="$APP_TENANTS_FILE" \
  --enable_cors \
  --cors_allowed_origins="https://app.example.com" \
  --cors_allowed_origins="https://accounts.google.com"
```

Run this behind TLS so the service issues `Secure` cookies and the browser accepts them.

### 2.4 Example: local quick‑start (Docker Compose)

For a full local stack (TAuth + demo UI) without installing Go:

1. `cd examples/docker-compose`
2. Copy the environment template: `cp .env.tauth.example .env.tauth`
3. Copy the tenant template: `cp tenants.yaml.example tenants.yaml`
4. Edit `.env.tauth` (set `APP_JWT_SIGNING_KEY`, keep `APP_TENANTS_FILE=/config/tenants.yaml`, adjust DB/CORS settings as needed).
5. Edit `tenants.yaml` and replace the placeholder Google OAuth client with one registered for `http://localhost:8000` and `http://localhost:8080`.
6. Start the stack: `docker compose up --build`
7. Visit `http://localhost:8000` for the demo UI. It talks to TAuth at `http://localhost:8080`.

Stop the stack with `docker compose down`. The `tauth_data` volume holds the SQLite database, and `tenants.yaml` stays next to the compose file for future edits.

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

## 4. Recommended integration: `auth-client.js`

The simplest way to use TAuth from the browser is through the helper served at `/static/auth-client.js`. It exports four globals:

- `initAuthClient(options)` – hydrates the current user and sets up refresh behaviour.
- `apiFetch(url, init)` – wrapper around `fetch` that automatically refreshes sessions on `401`.
- `getCurrentUser()` – returns the current profile object or `null`.
- `logout()` – revokes the refresh token and clears client state.

For backend services written in Go, use the `pkg/sessionvalidator` package described in section 6.8 to validate `app_session` cookies.

### 4.1 Loading the helper

On your product site, include the script from your TAuth origin:

```html
<script src="https://auth.example.com/static/auth-client.js"></script>
```

If your UI and TAuth share a host (for example both under `https://app.example.com`), you can serve it directly from that origin instead.

### 4.2 Initialising on page load

Call `initAuthClient` once during startup, after the script loads:

```html
<script>
  initAuthClient({
    baseUrl: "https://auth.example.com",
    tenantId: "demo", // optional override for shared-host dev setups
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

- TAuth calls `GET /me` to check for an existing session.
- If missing or expired, it attempts `POST /auth/refresh`.
- If refresh succeeds, it calls `onAuthenticated(profile)`; otherwise it calls `onUnauthenticated()`.
- The `profile` object matches the `/me` response (see section 6.3).

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

Most deployments rely on hostnames to resolve tenants. When multiple tenants intentionally share the same host (for example, several apps pointing at `localhost:8080`), enable the TAuth server’s header override (`--enable_tenant_header_override`) and pass `tenantId` to `initAuthClient`:

```js
initAuthClient({
  baseUrl: "https://auth-dev.example.com",
  tenantId: "team-blue",
  onAuthenticated: hydrateDashboard,
  onUnauthenticated: showGoogleButton,
});
```

The helper automatically attaches `X-TAuth-Tenant: team-blue` to `/me`, `/auth/nonce`, `/auth/google`, `/auth/refresh`, and logout requests while leaving your own API traffic alone. Switch tenants by reinitialising with a different `tenantId` (or prefer separate hosts when possible).

---

## 5. Google Identity Services flow

TAuth assumes a GIS **Web** client using the popup flow. A nonce protects each sign‑in exchange.

### 5.1 Configure GIS

1. Create (or reuse) a Google OAuth Web client.
2. Add all product origins (for example `https://app.example.com`) and the TAuth origin (for example `https://auth.example.com`) to **Authorized JavaScript origins**.
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

When using `auth-client.js` or the mpr‑ui header component, this flow is handled internally; you only need to surface the Google button and configure your client ID.

---

## 6. HTTP endpoints

This section documents the public HTTP surface from a client’s perspective. See `ARCHITECTURE.md` for a stable contract summary and versioning notes.

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

- **Response**: `200 OK` with user profile JSON (see `/me` below). Sets `app_session` and `app_refresh` cookies.

Common failure cases:

- Invalid or expired ID token (`401`).
- Mismatched nonce (`401`).
- Audience (`aud`) does not match the resolved tenant’s `google_web_client_id` (`401`).

### 6.3 `GET /me`

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

After a successful refresh, call `/me` again or rely on `auth-client.js` to hydrate the profile.

### 6.5 `POST /auth/logout`

Revokes the refresh token and clears cookies.

- **Auth**: best‑effort; succeeds even if no valid refresh token is present.
- **Request body**: empty.
- **Response**: `204 No Content`. Clears `app_session` and `app_refresh`.

Clients should treat this as “signed out” regardless of prior state.

### 6.6 `GET /static/auth-client.js`

Serves the browser helper described in section 4.

- Include it via `<script src="https://your-tauth-origin/static/auth-client.js"></script>`.
- Exposes `initAuthClient`, `apiFetch`, `getCurrentUser`, `logout` on `window`.

### 6.7 `GET /demo`

Optional demo page shipped with the repository. Intended for local development only.

---

## 6.8 Validating sessions from other Go services

Downstream Go services that share the TAuth cookie domain can validate `app_session` cookies directly using the `pkg/sessionvalidator` package. This is the recommended way to enforce authentication and read identity information without duplicating JWT logic.

### 6.8.1 Basic validator setup

Add the module to your Go service and construct a validator at startup:

```go
import (
    "os"

    "github.com/tyemirov/tauth/pkg/sessionvalidator"
)

func newSessionValidator() (*sessionvalidator.Validator, error) {
    signingKey := []byte(os.Getenv("APP_JWT_SIGNING_KEY"))
    return sessionvalidator.New(sessionvalidator.Config{
        SigningKey: signingKey,
        Issuer:     "tauth",
        // CookieName: optional; defaults to "app_session".
    })
}
```

The configuration mirrors your TAuth deployment:

- `SigningKey` must match `APP_JWT_SIGNING_KEY` used by TAuth.
- `Issuer` must match the issuer configured by the server (typically `"tauth"`; see `ARCHITECTURE.md`).
- `CookieName` defaults to `app_session` and should only be overridden if you have customised the cookie name on the TAuth side.

The constructor validates configuration up front and returns a typed error if required fields are missing.

### 6.8.2 Gin middleware integration

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

    router.GET("/me", func(context *gin.Context) {
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

- **401 from `/me` but refresh works** – Session cookie expired; ensure your client either uses `auth-client.js` or calls `/auth/refresh` before retrying.
- **401 from `/auth/refresh`** – Refresh cookie missing or revoked; treat as “signed out” and prompt the user to sign in again.
- **No cookies set** – Verify:
  - The response comes from HTTPS (in production).
  - The tenant’s `cookie_domain` matches the registrable domain you expect.
  - CORS is configured correctly when using a split origin (`APP_ENABLE_CORS` and `APP_CORS_ALLOWED_ORIGINS`).
- **Google rejects the client or TAuth rejects the token** – Confirm:
  - The OAuth client type is **Web**.
  - All relevant origins are in the **Authorized JavaScript origins** list.
  - The `aud` claim in the ID token matches the tenant’s `google_web_client_id`.

For more detailed operational guidance, refer to the troubleshooting section in `ARCHITECTURE.md`.

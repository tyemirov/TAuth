# TAuth

*Google Sign-In + JWT Sessions (Go + Gin)*

Production-grade, single-origin authentication service that:

* Verifies **Google ID tokens** (Google Identity Services).
* Issues **short-lived access JWTs** in `HttpOnly` cookies.
* Rotates **long-lived refresh tokens** (PostgreSQL store or in-memory).
* Serves a **reusable frontend module** (`auth-client.js`) to hydrate login state and auto-refresh sessions.
* Exposes a tiny, stable **wire-protocol** shared between frontend and backend.

---

## Contents

* [Why this exists](#why-this-exists)
* [Quick start](#quick-start)
* [Directory layout](#directory-layout)
* [Wire protocol](#wire-protocol)
* [Frontend module](#frontend-module)
* [Backend details](#backend-details)
* [Configuration](#configuration)
* [Local development](#local-development)
* [Database schema](#database-schema)
* [Security hardening](#security-hardening)
* [API examples](#api-examples)
* [Troubleshooting](#troubleshooting)
* [Versioning](#versioning)
* [License](#license)

---

## Why this exists

Most apps need to trust Google Sign-In **server-side**—not just in the browser. This project gives you a clean, reusable pattern:

* **Frontend**: zero token storage in JS; sessions are cookies; silent refresh on 401.
* **Backend**: verify Google ID token once → upsert user → mint your **own** access JWT and refresh token.

---

## Quick start

1. **Google OAuth Client**

* Create a **Web** client in Google Cloud Console.
* Add your origins (e.g. `https://app.example.com`).
* Note the **Client ID**.

2. **Run the server**

```bash
export APP_LISTEN_ADDR=":8080"
export APP_GOOGLE_WEB_CLIENT_ID="your_web_client_id.apps.googleusercontent.com"
export APP_JWT_SIGNING_KEY="$(openssl rand -base64 48)"
export APP_COOKIE_DOMAIN="localhost"
# Optional: Persistent refresh tokens (Postgres or SQLite):
# export APP_DATABASE_URL="postgres://user:pass@localhost:5432/authdb?sslmode=disable"
# export APP_DATABASE_URL="sqlite://file:./auth.db"
# Optional cross-origin UI local dev (not recommended for prod):
# export APP_ENABLE_CORS="true"
# export APP_DEV_INSECURE_HTTP="true"

go mod tidy
go run ./cmd/server
```

3. **Serve the client script in your page**

```html
<script src="/static/auth-client.js"></script>
<script>
  // On page load, hydrate session state.
  initAuthClient({
    onAuthenticated: function(profile) { /* render signed-in UI */ },
    onUnauthenticated: function() { /* show Google Sign-In button */ }
  });
</script>
```

4. **On Google Sign-In success**

* Send the returned **ID token** to your backend once:

```js
await fetch("/auth/google", {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ google_id_token: idTokenFromGoogle })
});
```

After that, `auth-client.js` keeps the user logged in silently.

---

## Directory layout

```
.
├─ cmd/server/                # main service (Gin, graceful shutdown, logging)
├─ internal/
│  ├─ authkit/                # core auth (JWT, routes, refresh token stores)
│  └─ web/                    # static serving, demo user store, CORS helper
└─ web/
   └─ auth-client.js          # reusable frontend module (hydration + refresh)
```

---

## Wire protocol

Endpoints (same origin):

| Method | Path            | Purpose                              | Response                                  |
| -----: | --------------- | ------------------------------------ | ----------------------------------------- |
|   POST | `/auth/google`  | Verify Google ID token, set cookies  | `200` JSON `{ user_id, user_email, ... }` |
|   POST | `/auth/refresh` | Rotate refresh → new access cookie   | `204 No Content`                          |
|   POST | `/auth/logout`  | Revoke refresh, clear cookies        | `204 No Content`                          |
|    GET | `/me`           | Read current user from access cookie | `200` JSON or `401`                       |

**Cookies (server-set only):**

* `app_session` — **access JWT**, short TTL (e.g., 15–30 min), `HttpOnly`, `Secure`, `SameSite` (Strict by default).
* `app_refresh` — **refresh token**, long TTL (e.g., 30–90 days), `HttpOnly`, `Secure`, `SameSite`, `Path=/auth`.

---

## Frontend module

`/static/auth-client.js` exposes:

```js
initAuthClient({
  baseUrl: "/",                 // default
  meEndpoint: "/me",            // default
  refreshEndpoint: "/auth/refresh",
  logoutEndpoint: "/auth/logout",
  onAuthenticated: (profile) => {},
  onUnauthenticated: () => {}
});

const user = getCurrentUser();  // { user_id, user_email, display, roles, expires } | null

const response = await apiFetch("/api/your-endpoint", { method: "GET" });
// apiFetch auto-attempts a single silent refresh on 401 and retries once

await logout(); // clears server cookies and transitions UI to signed-out
```

**Behavior**

* On load: `GET /me` → if 401 → `POST /auth/refresh` → retry `GET /me`.
* For any API call via `apiFetch`: if 401 → single refresh → retry.
* Uses `BroadcastChannel("auth")` for tab sync: `"refreshed"`, `"logged_out"`.

---

## Backend details

* **Verify Google ID token** using `google.golang.org/api/idtoken`.
* **Mint access JWT** with `github.com/golang-jwt/jwt/v5` (HS256).
* **Rotate refresh tokens** on every refresh:

  * **In-memory** store for dev (`internal/authkit`).
  * **GORM-backed** store for prod (`internal/authkit`), supports Postgres (`postgres://`) or SQLite (`sqlite://`).

Protected routes use:

```go
protected := router.Group("/api")
protected.Use(authkit.RequireSession(cfg))
```

---

## Configuration

Environment (via Viper):

| Variable                   | Description                                      | Example                                             |
| -------------------------- | ------------------------------------------------ | --------------------------------------------------- |
| `APP_LISTEN_ADDR`          | HTTP listen address                              | `:8080`                                             |
| `APP_GOOGLE_WEB_CLIENT_ID` | Google Web OAuth Client ID                       | `<client_id>.apps.googleusercontent.com`            |
| `APP_JWT_SIGNING_KEY`      | **Strong** HS256 secret                          | `openssl rand -base64 48`                           |
| `APP_COOKIE_DOMAIN`        | Cookie domain (empty = host-only)                | `app.example.com`                                   |
| `APP_SESSION_TTL`          | Access token TTL                                 | `15m`                                               |
| `APP_REFRESH_TTL`          | Refresh token TTL                                | `1440h` (60 days)                                   |
| `APP_DATABASE_URL`         | Database URL for refresh tokens (postgres/sqlite) | `postgres://user:pass@host:5432/db?sslmode=disable` |
| `APP_ENABLE_CORS`          | `true` to enable permissive CORS (split origins) | `false`                                             |
| `APP_DEV_INSECURE_HTTP`    | Allow non-HTTPS (local only)                     | `false`                                             |

**SameSite policy**

* Same origin (recommended): `SameSite=Strict`.
* Cross-origin UI/API: set `APP_ENABLE_CORS=true` → `SameSite=None` (+ `Secure` required).

---

## Local development

**Single origin (recommended)**

* Run server on `https://localhost:8080` (behind a local TLS proxy if possible).
* Keep `APP_ENABLE_CORS` **unset**. Cookies = `SameSite=Strict`.

**Cross origin (only if you must)**

* UI at `http://localhost:5173`, API at `http://localhost:8080`:

  * `APP_ENABLE_CORS=true`
  * `APP_DEV_INSECURE_HTTP=true` (local only)
  * Browser will require `SameSite=None; Secure` in production.

---

## Database schema

Created automatically by `EnsureSchema()`; for reference:

```sql
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_unix BIGINT NOT NULL,
    revoked_at_unix BIGINT NOT NULL DEFAULT 0,
    previous_token_id TEXT NOT NULL DEFAULT '',
    issued_at_unix BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens (token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens (user_id);
```

**Notes**

* Store **hashes** of opaque tokens (SHA-256 + base64url); never store the raw token.
* Rotate on every refresh: insert new, revoke previous.

---

## Security hardening

* **HTTPS everywhere**. In prod, terminate TLS before Gin or run Gin with TLS.
* Cookies: `HttpOnly`, `Secure`, `SameSite` (Strict for same-origin).
* **No tokens in localStorage/sessionStorage**.
* Access TTL **short** (15–30 min). Refresh TTL **longer** (30–90 days).
* Rate-limit `/auth/google` and `/auth/refresh`; log failures.
* Validate Google token strictly: `aud` (your Client ID), `iss` ∈ `accounts.google.com` / `https://accounts.google.com`, `exp`, `iat`.
* Use Google `sub` as stable primary key; email can change.
* Consider nonce binding on initial Google sign-in (optional param supported).
* Consider IP+UA heuristics on refresh if you want tighter security.
* Backup & rotate `APP_JWT_SIGNING_KEY` via standard secrets management.

---

## API examples

**1) Exchange Google ID token**

```bash
curl -i -X POST https://app.example.com/auth/google \
  -H "Content-Type: application/json" \
  -d '{ "google_id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." }'
```

**2) Hydration**

```bash
curl -i -X GET https://app.example.com/me \
  --cookie "app_session=..."  # set automatically by browser
```

**3) Silent refresh**

```bash
curl -i -X POST https://app.example.com/auth/refresh \
  --cookie "app_refresh=..."
```

**4) Logout**

```bash
curl -i -X POST https://app.example.com/auth/logout
```

---

## Troubleshooting

* **401 on `/me` but refresh succeeds**: Access cookie expired; expected. The client will refresh on next call.
* **401 on `/auth/refresh`**: Refresh cookie missing/expired/revoked. User must re-authenticate with Google.
* **Cookies not set**:

  * Check domain mismatch (`APP_COOKIE_DOMAIN`) and `Secure` on HTTP.
  * For split origins, ensure `APP_ENABLE_CORS=true` (sets `SameSite=None`) and use HTTPS in browsers (required for `SameSite=None; Secure`).
* **Google token fails**:

  * Confirm you used a **Web** client; verify `aud` matches `APP_GOOGLE_WEB_CLIENT_ID`.
  * Ensure your OAuth consent screen and allowed origins are configured.

---

## Versioning

This project treats the wire protocol as the contract:

* Endpoints: `/auth/google`, `/auth/refresh`, `/auth/logout`, `/me`.
* Cookie names: `app_session`, `app_refresh`.
* JSON profile fields: `{ user_id, user_email, display, roles, expires }`.

When you change any of the above, bump the service version and the embedded `auth-client.js` together.

---

## License

MIT (or your preferred license). Add a `LICENSE` file accordingly.

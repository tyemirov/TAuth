# ARCHITECTURE

## 1. System Overview

TAuth is a single-origin authentication service that sits between Google Identity Services and your product UI. It verifies Google ID tokens, issues first-party JWT access cookies, and rotates long-lived refresh tokens. The service is written in Go (Gin router) and ships the companion browser helper `web/auth-client.js`.

```
Browser ──(Google ID token)──> TAuth ──(verify)──> Google Identity Services
Browser <─(HttpOnly cookies)── TAuth ──(refresh token persistence)──> Database
```

## 2. Top-Level Layout

```
. 
├─ cmd/server/                 # Cobra + Viper CLI entrypoint (Gin server bootstrap)
├─ internal/
│  ├─ authkit/                 # Domain logic: routes, JWT helpers, refresh stores
│  └─ web/                     # Demo user store, CORS middleware, static file serving
└─ web/                        # Embeddable auth-client.js + demo HTML
```

All Go packages under `internal/` are private; only the CLI is exported.

## 3. Request and Session Flow

### 3.1 Endpoints

| Method | Path            | Responsibility                                          | Response                                    |
| ------ | --------------- | ------------------------------------------------------- | ------------------------------------------- |
| POST   | `/auth/nonce`   | Issue short-lived single-use nonce for Google exchange | `200` JSON `{ nonce }`                       |
| POST   | `/auth/google`  | Verify Google ID token, issue access + refresh cookies | `200` JSON `{ user_id, user_email, ... }`   |
| POST   | `/auth/refresh` | Rotate refresh token, mint new access cookie           | `204 No Content`                            |
| POST   | `/auth/logout`  | Revoke refresh token, clear cookies                    | `204 No Content`                            |
| GET    | `/me`           | Return profile associated with current access cookie   | `200` JSON or `401` when unauthenticated    |
| GET    | `/static/auth-client.js` | Serve the client helper                        | `200` JavaScript                            |
| GET    | `/demo`         | Static demo page (local development)                   | `200` HTML                                  |

### 3.2 Cookies

- `app_session`: short-lived JWT access token (`HttpOnly`, `Secure`, `SameSite` strict by default).
- `app_refresh`: long-lived opaque refresh token (`HttpOnly`, `Secure`, `Path=/auth`).

The access cookie authenticates `/me` and any downstream protected routes. The refresh cookie is rotated on each `/auth/refresh` and revoked on `/auth/logout`.

### 3.3 Google Sign-In exchange

1. Browser obtains a Google ID token from Google Identity Services.
2. Browser requests a nonce from `/auth/nonce`, passes it to Google Identity Services via `google.accounts.id.initialize({ nonce })`, and includes the same value as `nonce_token` when posting `{ "google_id_token": "...", "nonce_token": "..." }` to `/auth/google`.
3. `MountAuthRoutes` enforces HTTPS unless `AllowInsecureHTTP` is explicitly enabled for local development.
4. `idtoken.NewValidator` validates issuer and audience against `ServerConfig.GoogleWebClientID`.
5. `UserStore.UpsertGoogleUser` persists or updates email, display name, and avatar URL, then returns the application user ID plus roles.
6. `MintAppJWT` signs a short-lived access JWT (`HS256`, issuer `ServerConfig.AppJWTIssuer`) embedding `tenant_id`, `user_avatar_url`, and the other profile claims so downstream services can verify both the user and the tenant context.
7. `RefreshTokenStore.Issue` creates a new opaque refresh token (hashed before storage) with `RefreshTTL`.
8. Helper functions set `app_session` (path `/`) and `app_refresh` (path `/auth`) cookies with `HttpOnly`, `Secure`, and configured SameSite attributes.
9. The JSON response mirrors key profile fields (including `avatar_url`) so the browser helper can hydrate UI state.

### 3.4 Browser helper handshake

`web/auth-client.js` abstracts the nonce and credential exchange, but custom front-ends can implement the same flow with a small wrapper around Google Identity Services:

```js
let pendingNonce = "";

async function prepareGoogleSignIn(baseUrl, clientId) {
  const response = await fetch(`${baseUrl}/auth/nonce`, {
    method: "POST",
    credentials: "include",
    headers: { "X-Requested-With": "XMLHttpRequest" },
  });
  if (!response.ok) {
    throw new Error("nonce request failed");
  }
  pendingNonce = (await response.json()).nonce;
  google.accounts.id.initialize({
    client_id: clientId,
    callback: handleCredential,
    nonce: pendingNonce,
    ux_mode: "popup",
  });
  google.accounts.id.renderButton(document.getElementById("googleSignIn"), {
    theme: "outline",
    size: "large",
    text: "signin_with",
  });
  google.accounts.id.prompt();
}

async function exchangeGoogleCredential(baseUrl, googleIdToken) {
  await fetch(`${baseUrl}/auth/google`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      google_id_token: googleIdToken,
      nonce_token: pendingNonce,
    }),
  });
}
```

Nonce handling rules:

- TAuth issues one-time nonces via `POST /auth/nonce`; Google never provides one for you.
- Always supply the nonce to Google Identity Services when calling `google.accounts.id.initialize` (or via `data-nonce` on `g_id_onload`) before prompting the user.
- Echo the same nonce back to `/auth/google` as `nonce_token`. Requests without a matching nonce fail with `auth.login.nonce_mismatch`.
- Google Identity Services may hash the nonce inside the ID token (`base64url(sha256(nonce_token))`). TAuth accepts hashed or raw forms.
- Fetch a fresh nonce for every sign-in attempt. Nonces are invalidated once consumed and cannot be reused.
- The default helpers (`auth-client.js`, the `mpr-ui` header) already implement these invariants and emit events when authentication state changes.

## 4. Components

### 4.1 `cmd/server`

- Cobra CLI with Viper-backed configuration.
- Wires logging (zap), Gin middleware, CORS, routes, and graceful shutdown.
- Selects refresh token store:
  - In-memory (`authkit.NewMemoryRefreshTokenStore`) when `APP_DATABASE_URL` unset.
  - Persistent (`authkit.NewDatabaseRefreshTokenStore`) when pointing at Postgres (`postgres://`) or SQLite (`sqlite://`), using GORM.
- Attaches `authkit.RequireSession` to protected route groups (see `/api` group in `cmd/server/main.go`).

### 4.2 `internal/authkit`

- `ServerConfig`: cookie + session settings.
- `MountAuthRoutes`: installs `/auth/*` handlers and binds stores.
- JWT helpers: signing, validation, claims modeling.
- Refresh token stores:
  - Memory implementation for tests/dev.
  - GORM-backed implementation (`DatabaseRefreshTokenStore`) that performs migrations and issues hashed refresh tokens.
- `RequireSession`: Gin middleware backed by the shared session validator; confirms issuer and injects `JwtCustomClaims` into the request context (`auth_claims`).
- Shared helpers (`refresh_token_helpers.go`) generate token IDs and opaque values consistently across store implementations.

### 4.3 `internal/web`

- `NewInMemoryUsers`: placeholder application user store (maps Google `sub` to a profile).
- `PermissiveCORS`: development-only CORS middleware.
- `ServeEmbeddedStaticJS`: serves `auth-client.js` from the embedded FS.
- `HandleWhoAmI`: returns profile data for `/api/me`.

### 4.4 `web/auth-client.js`

- Initializes session state via `/me`.
- Dispatches events on authentication changes.
- Attempts silent refresh on 401 using `/auth/refresh`.
- Provides hooks for UI callbacks (`onAuthenticated`, `onUnauthenticated`).
- Emits DOM events (`auth:authenticated`, `auth:unauthenticated`) to coordinate UI without global state.

### 4.5 Interfaces and extension points

```go
type UserStore interface {
    UpsertGoogleUser(ctx context.Context, tenantID string, googleSub string, userEmail string, userDisplayName string, userAvatarURL string) (applicationUserID string, userRoles []string, err error)
    GetUserProfile(ctx context.Context, tenantID string, applicationUserID string) (userEmail string, userDisplayName string, userAvatarURL string, userRoles []string, err error)
}

type RefreshTokenStore interface {
    Issue(ctx context.Context, tenantID string, applicationUserID string, expiresUnix int64, previousTokenID string) (tokenID string, tokenOpaque string, err error)
    Validate(ctx context.Context, tenantID string, tokenOpaque string) (applicationUserID string, tokenID string, expiresUnix int64, err error)
    Revoke(ctx context.Context, tenantID string, tokenID string) error
}
```

- Swap `UserStore` for a production datastore (e.g., Postgres) while keeping the auth kit isolated from application models.
- Implement a custom `RefreshTokenStore` (e.g., Redis, DynamoDB) by reusing the hashing helpers to maintain compatibility.
- Downstream services can read `auth_claims` and rely on `JwtCustomClaims` to authorize domain-specific operations.

### 4.6 `pkg/sessionvalidator`

- Reusable library for downstream Go services to validate the `app_session` cookie.
- Smart constructor enforces signing key and issuer configuration, with optional cookie name overrides.
- Provides `ValidateToken`, `ValidateRequest`, and a Gin middleware adapter to populate typed `Claims`.
- Shares the same claim shape (`user_id`, `user_email`, `display`, `avatar_url`, `roles`, `expires`) used by the server.

## 5. Configuration Surface

| Variable / Flag            | Purpose                                             | Example                                             |
| -------------------------- | --------------------------------------------------- | --------------------------------------------------- |
| `APP_LISTEN_ADDR`          | HTTP listen address                                 | `:8080`                                             |
| `APP_COOKIE_DOMAIN`        | Domain for cookies (empty = host only)              | `app.example.com`                                   |
| `APP_GOOGLE_WEB_CLIENT_ID` | Google OAuth Client ID                              | `<client-id>.apps.googleusercontent.com`            |
| `APP_JWT_SIGNING_KEY`      | HS256 signing secret                                | `openssl rand -base64 48`                           |
| `APP_SESSION_TTL`          | Access token lifetime                               | `15m`                                               |
| `APP_REFRESH_TTL`          | Refresh token lifetime                              | `1440h` (60 days)                                   |
| `APP_DATABASE_URL`         | Refresh store DSN (`postgres://` or `sqlite://`)    | `sqlite:///auth.db`                                 |
| `APP_ENABLE_CORS`          | Enable permissive CORS (cross-origin dev only)      | `true`                                              |
| `APP_DEV_INSECURE_HTTP`    | Allow non-HTTPS (local development)                 | `true`                                              |
| `APP_TENANTS_FILE`         | Path to tenants JSON for multi-tenant deployments   | `/etc/tauth/tenants.json`                           |
| `APP_ENABLE_TENANT_HEADER_OVERRIDE` | Allow `X-TAuth-Tenant` overrides (dev/testing) | `true`                                     |

Viper reads environment variables (prefixed `APP_`) and command-line flags.

### 5.1 Multi-tenant configuration file

Multi-tenant deployments rely on the declarative config file parsed by `internal/tenants`. The JSON document describes each tenant’s identity, hostnames, Google Web client, and cookie/scheduling knobs:

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

Validation rules baked into the loader:

- IDs use lowercase letters/digits/underscores/hyphens; duplicates are rejected.
- Each host maps to only one tenant; hosts are normalized to lowercase and deduplicated.
- `google_web_client_id`, `cookie_domain`, and each TTL must be present and non-empty; durations follow Go’s `time.ParseDuration` syntax.
- `nonce_ttl` defaults to `5m` when omitted; `allow_insecure_http` defaults to `false`.

Tenant resolution & runtime:

- `internal/tenants.NewResolver` consumes the validated config and maps HTTP requests to tenants. Hostnames are matched case-insensitively, and unknown hosts are rejected with a 404 response before hitting auth routes.
- Local and development tooling can opt into the `X-TAuth-Tenant` override header (configurable via `WithHeaderOverride`/`--enable_tenant_header_override`) when multiple tenants share a single host. The override is disabled by default for production safety.
- `internal/tenants.TenantMiddleware` injects the resolved tenant into `gin.Context` so auth routes and stores can look up per-tenant keys (`tenants.TenantFromContext`) without touching global state.
- Multi-tenant mode is enabled via `--tenants_file=/path/to/tenants.json` (or `APP_TENANTS_FILE`). Single-tenant deployments continue to rely on the existing CLI/env flags. Use `--enable_tenant_header_override` in local/testing environments when you need to override tenants via headers instead of hostnames.
- Front-ends pass `tenantId` to `initAuthClient` when they need to pin a tenant explicitly; the helper automatically sets the `X-TAuth-Tenant` header on every request to line up with the override flow above.
- All per-tenant server configs live inside `authkit.TenantRegistry`, which backs `MountAuthRoutes` and `RequireSession` so cookies, TTLs, and SameSite/AllowInsecure decisions reflect the resolved tenant.
- refresh token stores, nonce pools, and in-memory user stores are now keyed by tenant ID, and JWT sessions embed a `tenant_id` claim that `RequireSession` verifies against the resolved tenant to prevent cross-tenant cookie replay.

## 6. Persistence Model

The persistent refresh token store manages the `refresh_tokens` table (automigrated via GORM):

```sql
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
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

Opaque refresh tokens are hashed (`SHA-256`, Base64 URL) before storage. Each refresh rotation inserts the new token, links it to the previous ID, and marks older tokens revoked.

`DatabaseRefreshTokenStore` parses the database URL to select a GORM dialector (`postgres` or the CGO-free `github.com/glebarez/sqlite`), silences default logging, auto-migrates the schema, and tags errors with context (`refresh_store.*`) for observability. For SQLite, only triple-slash absolute paths (`sqlite:///data/tauth.db`) or opaque memory URLs (`sqlite://file::memory:?cache=shared`) are accepted; host-prefixed forms such as `sqlite://file:/data/tauth.db` are rejected. Shared helpers ensure memory and persistent stores derive token IDs and hashes identically.

## 7. Security Considerations

- Always run behind HTTPS in production; `APP_DEV_INSECURE_HTTP` is for local use only.
- Access cookies are short-lived; refresh cookies survive longer but are `HttpOnly` and scoped to `/auth`.
- Validate Google tokens strictly: issuer, audience, expiry, issued-at.
- Rate limit `/auth/google` and `/auth/refresh` and monitor failures via zap logs.
- Require nonce tokens from `/auth/nonce` for every Google Sign-In exchange and treat missing or mismatched nonces as unauthorized.
- Rotate `APP_JWT_SIGNING_KEY` using standard secrets management practices.
- Only hashed refresh tokens are stored—never persist the raw opaque value.
- Serve browser code through `/static/auth-client.js` and avoid inline scripts to keep CSP-friendly deployments.

## 8. Local Development Modes

### 8.1 Same Origin (recommended)

- Serve UI and API from the same host; keep `APP_ENABLE_CORS` unset.
- Cookies remain `SameSite=Strict`.

### 8.2 Split Origin (local labs)

- UI: `http://localhost:5173`, API: `http://localhost:8080`.
- Set `APP_ENABLE_CORS=true` and `APP_DEV_INSECURE_HTTP=true`.
- Browser will require HTTPS + `SameSite=None` in production for cross-origin cookies.

## 9. CLI and Server Lifecycle

- Cobra command `tauth` exposes configuration as flags.
- Graceful shutdown listens for `SIGINT`/`SIGTERM`, allowing 10s for in-flight requests.
- zap middleware logs method, path, status, IP, and latency for each request.
- Integration tests use the exported CLI wiring to spin up in-memory servers (`go test ./...`).

## 10. Dependency Highlights

- **Web framework**: `github.com/gin-gonic/gin` for routing/middleware.
- **Configuration**: `spf13/viper` + `spf13/cobra` for flags and environment merging.
- **Google verification**: `google.golang.org/api/idtoken`.
- **JWT**: `github.com/golang-jwt/jwt/v5` with HS256 signatures.
- **Persistence**: `gorm.io/gorm` with `gorm.io/driver/postgres` and the CGO-free `github.com/glebarez/sqlite`.
- **Logging**: `go.uber.org/zap` (production configuration).
- **Testing**: standard library `httptest` plus the memory refresh store for fast integration coverage.

## 11. Troubleshooting Playbook

- **401 on `/me` but refresh succeeds** – Access cookie expired; the client will refresh on next call.
- **401 on `/auth/refresh`** – Refresh cookie missing/expired/revoked; prompt user to sign in again.
- **Cookies missing** – Verify `APP_COOKIE_DOMAIN`, HTTPS usage, and CORS settings.
- **Google token rejection** – Confirm OAuth client type (Web) and that `aud` matches configured client ID.

## 12. Versioning Contract

The following surface area is considered stable across releases:

- Endpoints: `/auth/nonce`, `/auth/google`, `/auth/refresh`, `/auth/logout`, `/me`.
- Cookie names: `app_session`, `app_refresh`.
- JSON payload fields returned to the client (`user_id`, `user_email`, `display`, `roles`, `expires`).

Update the embedded client and bump the service version together when changing these contracts.

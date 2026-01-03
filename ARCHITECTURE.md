# ARCHITECTURE

## 1. System Overview

TAuth is a single-origin authentication service that sits between Google Identity Services and your product UI. It verifies Google ID tokens, issues first-party JWT access cookies, and rotates long-lived refresh tokens. The service is written in Go (Gin router) and ships the companion browser helper `web/tauth.js`.

```
Browser ──(Google ID token)──> TAuth ──(verify)──> Google Identity Services
Browser <─(HttpOnly cookies)── TAuth ──(refresh token persistence)──> Database
```

## 2. Top-Level Layout

```
. 
├─ cmd/server/                 # Cobra CLI entrypoint (reads config.yaml, boots Gin server)
├─ internal/
│  ├─ authkit/                 # Domain logic: routes, JWT helpers, refresh stores
│  └─ web/                     # Demo user store, CORS middleware, static file serving
└─ web/                        # Embeddable tauth.js helper
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
| GET    | `/tauth.js` | Serve the client helper                        | `200` JavaScript                            |

These endpoints are implemented only by the TAuth server. Consuming applications should call them, not host copies.
TAuth serves no other static assets; demo pages live in the repository under `examples/` and are hosted separately for local development.

### 3.2 Cookies

- `app_session`: short-lived JWT access token (`HttpOnly`, `Secure`, `SameSite` strict by default).
- `app_refresh`: long-lived opaque refresh token (`HttpOnly`, `Secure`, `Path=/auth`).

The access cookie authenticates `/me` and any downstream protected routes. The refresh cookie is rotated on each `/auth/refresh` and revoked on `/auth/logout`.

### 3.3 Google Sign-In exchange

1. Browser obtains a Google ID token from Google Identity Services.
2. Browser requests a nonce from `/auth/nonce`, passes it to Google Identity Services via `google.accounts.id.initialize({ nonce })`, and includes the same value as `nonce_token` when posting `{ "google_id_token": "...", "nonce_token": "..." }` to `/auth/google`.
3. `MountAuthRoutes` enforces HTTPS unless `AllowInsecureHTTP` is explicitly enabled for local development.
4. `idtoken.NewValidator` validates issuer and audience against `ServerConfig.GoogleWebClientID`.
5. If the tenant config includes `allowed_users`, `/auth/google` rejects any email not on the list with `403` and `error: "user_not_allowed"`.
6. `UserStore.UpsertGoogleUser` persists or updates email, display name, and avatar URL, then returns the application user ID plus roles.
7. `MintAppJWT` signs a short-lived access JWT (`HS256`, issuer `ServerConfig.AppJWTIssuer`) embedding `tenant_id`, `user_avatar_url`, and the other profile claims so downstream services can verify both the user and the tenant context.
8. `RefreshTokenStore.Issue` creates a new opaque refresh token (hashed before storage) with `RefreshTTL`.
9. Helper functions set `app_session` (path `/`) and `app_refresh` (path `/auth`) cookies with `HttpOnly`, `Secure`, and configured SameSite attributes.
10. The JSON response mirrors key profile fields (including `avatar_url`) so the browser helper can hydrate UI state.

### 3.4 Browser helper handshake

`web/tauth.js` abstracts the nonce and credential exchange, but custom front-ends can implement the same flow with a small wrapper around Google Identity Services:

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
- The default helper (`tauth.js`) already implements these invariants; custom UIs should mirror the same flow when wiring auth state.

## 4. Components

### 4.1 `cmd/server`

- Cobra CLI with a YAML-backed configuration loader.
- Wires logging (zap), Gin middleware, CORS, routes, and graceful shutdown.
- Selects refresh token store:
  - In-memory (`authkit.NewMemoryRefreshTokenStore`) when `database_url` is empty.
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
- `ServeEmbeddedStaticJS`: serves `tauth.js` from the embedded FS.
- `HandleWhoAmI`: returns profile data for `/api/me`.

### 4.4 `web/tauth.js`

- Initializes session state via `/me`.
- Dispatches events on authentication changes.
- Attempts silent refresh on 401 using `/auth/refresh`.
- Provides hooks for UI callbacks (`onAuthenticated`, `onUnauthenticated`).
- Accepts an optional `tenantId` when calling `initAuthClient`; when present the helper attaches `X-TAuth-Tenant` to `/me`, `/auth/*`, and logout requests so multiple tenants can share an origin in development. When you omit `tenantId`, the helper now falls back to the current page origin so header overrides remain accurate even when browsers omit `Origin` on certain requests.
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
- Includes `LoadTenantAuthConfig` to derive tenant signing keys, issuer, and cookie names from the same `config.yaml` used by TAuth.

## 5. Configuration Surface

| Variable / Flag            | Purpose                                             | Example                                             |
| -------------------------- | --------------------------------------------------- | --------------------------------------------------- |
| `listen_addr`          | HTTP listen address                                 | `:8080`                                             |
| `database_url`         | Refresh store DSN (`postgres://` or `sqlite://`)    | `sqlite:///auth.db`                                 |
| `enable_cors`          | Enable permissive CORS (cross-origin dev only)      | `true` / `false`                                    |
| `cors_allowed_origins` | List of allowed origins when CORS is enabled (include GIS) | `["https://app.example.com","https://accounts.google.com"]` |
| `cors_allowed_origin_exceptions` | Non-tenant origins that may appear in `cors_allowed_origins` | `["https://accounts.google.com"]` |
| `enable_tenant_header_override` | Allow `X-TAuth-Tenant` overrides (dev/testing) | `true`                                     |
| `tenants`              | Array of tenant entries (id, tenant_origins, client IDs, TTLs) | See README §5 |

Configuration is loaded from a single YAML file (`config.yaml` by default, override via `tauth --config=/path/to/file` or `TAUTH_CONFIG_FILE`).

### 5.1 Multi-tenant configuration file

Every deployment relies on the declarative config file parsed by `internal/tenants`. The YAML document describes each tenant’s identity, origins, Google Web client, and cookie/scheduling knobs:

```yaml
tenants:
  - id: "demo"
    display_name: "Demo tenant"
    tenant_origins:
      - "https://demo.localhost"
      - "https://app.example.com"
    allowed_users:
      - "user@example.com"
    google_web_client_id: "demo-client.apps.googleusercontent.com"
    jwt_signing_key: "demo-signing-key"
    cookie_domain: "demo.example.com"
    session_ttl: "30m"
    refresh_ttl: "720h"
    nonce_ttl: "10m"
    allow_insecure_http: true
```

Validation rules baked into the loader:

- IDs use lowercase letters/digits/underscores/hyphens; duplicates are rejected.
- `display_name` is required so operators can identify tenants in logs.
- Origins are normalized to lowercase and deduplicated within each tenant definition. Entries must be full origins (scheme + host + optional port). When multiple tenants share the same origin, the runtime requires `X-TAuth-Tenant` to be enabled so requests can declare their tenant explicitly.
- `allowed_users` is optional; when provided, only the listed email addresses may authenticate for the tenant.
- `google_web_client_id` must be present for every tenant. Each tenant also requires its own `jwt_signing_key`; the server rejects definitions that omit it. TTLs follow Go’s `time.ParseDuration` syntax. `cookie_domain` may be blank to emit host-only cookies (required for `localhost`); otherwise provide a registrable domain (e.g. `.example.com`). `session_cookie_name` / `refresh_cookie_name` are mandatory; set them explicitly per tenant (for example `app_session_notes`, `app_refresh_notes`). Reuse the legacy `app_session`/`app_refresh` names only when you intentionally want multiple tenants to share the same cookies.
- `nonce_ttl` defaults to `5m` when omitted; `allow_insecure_http` defaults to `false`.
- Before decoding, the loader expands environment variables (`$VAR` / `${VAR}`) inside the YAML so operator templates can stay DRY. Unset variables resolve to empty strings, triggering the same validation rules as blank values.

Tenant resolution & runtime:

- `internal/tenants.NewResolver` consumes the validated config and maps HTTP requests to tenants. Origins are matched case-insensitively, and unknown origins are rejected with a 404 response before hitting auth routes. When multiple tenants intentionally share the same origin, enable the header override and send `X-TAuth-Tenant` to disambiguate.
- Local and development tooling can opt into the `X-TAuth-Tenant` override header (configurable via `WithHeaderOverride`/`--enable_tenant_header_override`) when requests lack `Origin` headers or when multiple tenants share a single origin. The override accepts either tenant IDs or frontend origins. Leave it disabled in production where origins stay unique.
- `internal/tenants.TenantMiddleware` injects the resolved tenant into `gin.Context` so auth routes and stores can look up per-tenant keys (`tenants.TenantFromContext`) without touching global state.
- Multi-tenant mode is always enabled via the `tenants` array inside `config.yaml`. Launch TAuth with `tauth --config=/path/to/config.yaml` (or set `TAUTH_CONFIG_FILE`). Use `enable_tenant_header_override: true` in local/testing environments when you need to override tenants via headers instead of origins.
- Front-ends pass `tenantId` to `initAuthClient` when they need to pin a tenant explicitly; the helper automatically sets the `X-TAuth-Tenant` header on its own `/me`, `/auth/*`, and logout requests to line up with the override flow above while leaving product APIs untouched. When no tenant ID is supplied, the helper falls back to the page origin so shared-origin setups work without extra wiring.
- All per-tenant server configs live inside `authkit.TenantRegistry`, which backs `MountAuthRoutes` and `RequireSession` so cookies, TTLs, and SameSite/AllowInsecure decisions reflect the resolved tenant.
- Refresh token stores, nonce pools, and in-memory user stores are keyed by tenant ID, and JWT sessions embed a `tenant_id` claim that `RequireSession` verifies against the resolved tenant to prevent cross-tenant cookie replay. Front-end clients normally rely on origins, but when multiple tenants share the same origin (local dev boxes, automation rigs) you can enable the header override and pass `tenantId` to `initAuthClient`. The helper adds `X-TAuth-Tenant` to `/me`, `/auth/*`, and logout requests without touching product APIs so you can switch tenants without DNS changes.

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

- Always run behind HTTPS in production; set a tenant’s `allow_insecure_http` to `true` only for local development.
- Access cookies are short-lived; refresh cookies survive longer but are `HttpOnly` and scoped to `/auth`.
- Validate Google tokens strictly: issuer, audience, expiry, issued-at.
- Rate limit `/auth/google` and `/auth/refresh` and monitor failures via zap logs.
- Require nonce tokens from `/auth/nonce` for every Google Sign-In exchange and treat missing or mismatched nonces as unauthorized.
- Rotate each tenant's `jwt_signing_key` using standard secrets management practices.
- Only hashed refresh tokens are stored—never persist the raw opaque value.
- Serve browser code through `/tauth.js` and avoid inline scripts to keep CSP-friendly deployments.

## 8. Local Development Modes

### 8.1 Same Origin (recommended)

- Serve UI and API from the same host; keep `enable_cors` set to `false`.
- Cookies remain `SameSite=Strict`.

### 8.2 Split Origin (local labs)

- UI: `http://localhost:5173`, API: `http://localhost:8080`.
- Set `enable_cors: true` and mark the tenant’s `allow_insecure_http` as `true`.
- Browser will require HTTPS + `SameSite=None` in production for cross-origin cookies.

## 9. CLI and Server Lifecycle

- Cobra command `tauth` reads configuration from a single YAML file (`--config=/path/to/config.yaml` or `TAUTH_CONFIG_FILE`).
- `tauth preflight --config=...` validates configuration and emits a versioned, redacted effective-config report (with dependency readiness) for external validators before launch, built on the shared `github.com/tyemirov/utils/preflight` builder.
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
- **Cookies missing** – Verify the tenant’s `cookie_domain`, HTTPS usage, and CORS settings.
- **Google token rejection** – Confirm OAuth client type (Web) and that `aud` matches configured client ID.

## 12. Versioning Contract

The following surface area is considered stable across releases:

- Endpoints: `/auth/nonce`, `/auth/google`, `/auth/refresh`, `/auth/logout`, `/me`.
- Cookie names: `app_session`, `app_refresh`.
- JSON payload fields returned to the client (`user_id`, `user_email`, `display`, `roles`, `expires`).

Update the embedded client and bump the service version together when changing these contracts.

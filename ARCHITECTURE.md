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
6. `MintAppJWT` signs a short-lived access JWT (`HS256`, issuer `ServerConfig.AppJWTIssuer`) embedding `user_avatar_url` alongside the existing claims.
7. `RefreshTokenStore.Issue` creates a new opaque refresh token (hashed before storage) with `RefreshTTL`.
8. Helper functions set `app_session` (path `/`) and `app_refresh` (path `/auth`) cookies with `HttpOnly`, `Secure`, and configured SameSite attributes.
9. The JSON response mirrors key profile fields (including `avatar_url`) so the browser helper can hydrate UI state.

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
    UpsertGoogleUser(ctx context.Context, googleSub string, userEmail string, userDisplayName string, userAvatarURL string) (applicationUserID string, userRoles []string, err error)
    GetUserProfile(ctx context.Context, applicationUserID string) (userEmail string, userDisplayName string, userAvatarURL string, userRoles []string, err error)
}

type RefreshTokenStore interface {
    Issue(ctx context.Context, applicationUserID string, expiresUnix int64, previousTokenID string) (tokenID string, tokenOpaque string, err error)
    Validate(ctx context.Context, tokenOpaque string) (applicationUserID string, tokenID string, expiresUnix int64, err error)
    Revoke(ctx context.Context, tokenID string) error
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
| `APP_DATABASE_URL`         | Refresh store DSN (`postgres://` or `sqlite://`)    | `sqlite://file:./auth.db`                           |
| `APP_ENABLE_CORS`          | Enable permissive CORS (cross-origin dev only)      | `true`                                              |
| `APP_DEV_INSECURE_HTTP`    | Allow non-HTTPS (local development)                 | `true`                                              |

Viper reads environment variables (prefixed `APP_`) and command-line flags.

## 6. Persistence Model

The persistent refresh token store manages the `refresh_tokens` table (automigrated via GORM):

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

Opaque refresh tokens are hashed (`SHA-256`, Base64 URL) before storage. Each refresh rotation inserts the new token, links it to the previous ID, and marks older tokens revoked.

`DatabaseRefreshTokenStore` parses the database URL to select a GORM dialector (`postgres` or `sqlite`), silences default logging, auto-migrates the schema, and tags errors with context (`refresh_store.*`) for observability. Shared helpers ensure memory and persistent stores derive token IDs and hashes identically.

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
- **Persistence**: `gorm.io/gorm` with `gorm.io/driver/postgres` and `gorm.io/driver/sqlite`.
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

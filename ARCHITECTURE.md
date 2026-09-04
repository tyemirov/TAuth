# ARCHITECTURE

## 1. System Overview

TAuth is an authentication service that sits between identity providers and your product UI. It verifies Google ID tokens, completes Sign in with Apple redirects, or checks tenant-managed email/password credentials, issues first-party JWT access cookies, and rotates long-lived refresh tokens. The backend is written in Go with Gin. GitHub Pages publishes the companion `web/tauth.js` only at `https://tauth.mprlab.com/tauth.js`.

```
Browser ──(Google ID token)──────────────> TAuth ──(verify)──> Google Identity Services
Browser ──(Apple auth code)──────────────> TAuth ──(exchange/verify)──> Apple ID
Native iOS ──(Apple ID token)────────────> TAuth ──(verify)──> Apple ID
Browser ──(email/password credential)────> TAuth ──(bcrypt)──> PasswordCredentialStore
Browser <─(HttpOnly cookies)───────────── TAuth ──(refresh token persistence)──> Database
```

## 2. Top-Level Layout

```
. 
├─ cmd/server/                 # Cobra CLI entrypoint (reads config.yaml, boots Gin server)
├─ internal/
│  ├─ authkit/                 # Domain logic: routes, JWT helpers, refresh stores
│  ├─ oauthserver/             # OAuth issuer routes, signing, policy, and stores
│  └─ web/                     # Health/profile handlers, demo user store, CORS middleware
├─ pkg/                        # Public session and OAuth token validators
└─ web/                        # GitHub Pages source for the canonical tauth.js helper
```

Go packages under `internal/` are private. The CLI and packages under `pkg/`
are public integration surfaces.

## 3. Request and Session Flow

### 3.1 Endpoints

| Method | Path            | Responsibility                                          | Response                                    |
| ------ | --------------- | ------------------------------------------------------- | ------------------------------------------- |
| POST   | `/auth/nonce`   | Issue short-lived single-use nonce for Google exchange | `200` JSON `{ nonce }`                       |
| GET    | `/auth/google/native/config` | Return native Google OAuth metadata for the resolved tenant and optional `platform` | `200` JSON `{ client_id, client_ids, redirect_uris, pkce_required, ... }` |
| POST   | `/auth/google`  | Verify Google ID token from the web GIS popup flow, issue access + refresh cookies | `200` JSON `{ user_id, user_email, ... }`   |
| POST   | `/auth/google/native` | Verify Google ID token from a native system-browser flow, issue access + refresh cookies | `200` JSON `{ user_id, user_email, ... }`   |
| GET    | `/auth/apple/native/config` | Return native Apple client metadata for the resolved tenant | `200` JSON `{ client_id, client_ids, nonce_required, ... }` |
| POST   | `/auth/apple/native` | Verify a native Apple ID token and issue access + refresh cookies | `200` JSON `{ user_id, user_email, ... }` |
| GET    | `/auth/apple/start` | Start a Sign in with Apple redirect for the resolved tenant | `302` to Apple authorization endpoint |
| GET/POST | `/auth/apple/callback` | Complete Apple code exchange, validate Apple ID token, issue access + refresh cookies | `200` JSON `{ user_id, user_email, ... }` |
| POST   | `/auth/password/login` | Verify a tenant-managed email/password credential, issue access + refresh cookies | `200` JSON `{ user_id, user_email, ... }`   |
| POST   | `/auth/password/signup` | Start a first-party password signup when account management and signup are enabled | `202` JSON challenge metadata |
| POST   | `/auth/password/verify-email` | Verify a signup challenge, activate the account, issue access + refresh cookies | `200` JSON `{ user_id, user_email, ... }` |
| POST   | `/auth/password/reset/start` | Start a password reset with a timing-masked accepted response | `202` JSON challenge metadata |
| POST   | `/auth/password/reset/complete` | Complete reset, rotate password, revoke account refresh sessions, issue cookies | `200` JSON `{ user_id, user_email, ... }` |
| POST   | `/auth/account/password/change` | Authenticated password rotation for opaque account sessions | `200` JSON `{ user_id, user_email, ... }` |
| POST   | `/auth/account/password/link/start` | Start linking a password identity to the current account | `202` JSON challenge metadata |
| POST   | `/auth/account/password/link/verify` | Complete password identity linking | `200` JSON `{ user_id, user_email, ... }` |
| POST   | `/auth/account/google/link` | Link a verified Google identity to the current account | `200` JSON `{ user_id, user_email, ... }` |
| POST   | `/auth/account/unlink` | Remove a linked identity unless it is the last login method | `200` JSON `{ user_id, user_email, ... }` |
| POST   | `/auth/account/disable` | Disable the current account, revoke refresh sessions, clear cookies | `204 No Content` |
| GET    | `/auth/session` | Return current/restored session profile for browser bootstrap | `200` JSON or `204 No Content` when anonymous |
| POST   | `/auth/refresh` | Rotate refresh token, mint new access cookie           | `204 No Content`                            |
| POST   | `/auth/logout`  | Revoke refresh token, clear cookies                    | `204 No Content`                            |
| GET    | `/.well-known/oauth-authorization-server` | Publish issuer metadata | `200` RFC 8414 JSON |
| GET    | Configured OAuth JWKS path | Publish retained ES256 public keys | `200` JWKS JSON |
| GET    | Configured OAuth authorization path | Validate a public client request and start login or consent | `303` issuer page or exact client callback |
| POST   | Configured OAuth token path | Redeem a one-time code or rotate a refresh token | `200` OAuth token JSON |
| POST   | Configured OAuth revocation path | Revoke a refresh-token family and consent grant | `200` for known or unknown tokens |
| GET/POST | Configured OAuth login and consent paths | Authenticate the tenant user and record an explicit decision | no-store HTML or `303` |
| GET    | `/me`           | Return profile associated with current access cookie   | `200` JSON or `401` when unauthenticated    |
| GET    | `/health`       | Report backend process readiness                       | `200 OK` with an empty body                 |

These endpoints are implemented only by the TAuth backend at `tauth-api.mprlab.com`. The backend registers no static asset routes, so `GET /tauth.js` returns `404 Not Found`.
Consuming applications load the sole public helper from `https://tauth.mprlab.com/tauth.js`; demo pages live under `examples/` and are hosted separately for local development.

### 3.2 Cookies

- `app_session`: short-lived JWT access token (`HttpOnly`, `Secure`, `SameSite` strict by default).
- `app_refresh`: long-lived opaque refresh token (`HttpOnly`, `Secure`, `Path=/auth`).

The access cookie authenticates `/me` and any downstream protected routes. The refresh cookie is rotated on each `/auth/refresh` and revoked on `/auth/logout`.

### 3.3 Google Sign-In exchange (web popup)

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

### 3.4 Native provider exchange

Installed apps such as PromptDew use the same session issuance path without embedding Google sign-in in a `WKWebView`:

1. The native client resolves tenant metadata from `GET /auth/google/native/config`. Expo iOS/Android clients request `?platform=ios` or `?platform=android`.
2. The client opens Google in the system browser with `response_type=code`, PKCE `S256`, `scope=openid email profile`, one configured redirect URI, and an OIDC nonce.
3. Google redirects back to a loopback URI for desktop, or to a custom-scheme/app-link URI for mobile.
4. The native client exchanges the authorization code directly with Google and extracts the returned `id_token`.
5. The client posts `{ "google_id_token": "...", "nonce_token": "...", "platform": "ios", "redirect_uri": "..." }` to `/auth/google/native`.
6. `MountAuthRoutes` validates that ID token against the selected platform’s accepted Google native audience, checks any supplied redirect URI against config, requires the nonce claim to match the posted `nonce_token`, then mints the same access and refresh cookies used by the browser flow.

TAuth still does not receive Google authorization codes or store Google refresh tokens.
TAuth also does not return mobile bearer tokens in the response body. Mobile apps persist the issued `HttpOnly` cookies in the platform cookie jar; downstream API hosts under the same configured `cookie_domain` validate `app_session` with `pkg/sessionvalidator`.

Native iOS apps use the system Sign in with Apple sheet:

1. The client reads `GET /auth/apple/native/config` with `X-TAuth-Tenant` and confirms its App ID is the selected client.
2. The client obtains a one-time nonce from `POST /auth/nonce` with the same tenant header.
3. The client passes the nonce to Apple and obtains an Apple ID token.
4. The client posts the token, nonce, and available `fullName` components to `/auth/apple/native`.
5. TAuth stores the first credential name and keeps it when a later authorization omits the name.
6. TAuth validates the Apple signature, issuer, expiration, configured native audience, verified email, and exact nonce. It then consumes the nonce and issues the standard cookies.

Apple Developer groups the native App ID with the browser Services ID. This provider association keeps the Apple subject stable across the two Apple sign-in modes. TAuth then resolves both modes to the same provider identity and account.

### 3.5 Sign in with Apple exchange

Apple login is tenant-enabled with `apple_oauth.enabled: true`. It uses a provider redirect because Apple returns authorization codes to the service, not browser-visible ID tokens to the product UI.

1. The browser navigates to `GET /auth/apple/start`. TAuth resolves the tenant from `Origin`, a permitted tenant override, or the optional `tenant_id` query parameter used by `tauth.js` for shared-origin setups.
2. TAuth issues a one-time nonce, signs a short-lived state JWT with the tenant signing key, and redirects to Apple’s authorization endpoint with `response_type=code`, `response_mode=form_post`, `scope=openid email name`, `state`, and `nonce`.
3. Apple posts or redirects back to `/auth/apple/callback` with `code` and `state`. The server-level origin and tenant middlewares bypass this exact provider callback path; the route validates signed state before doing any tenant-scoped work.
4. TAuth signs an ES256 Apple client-secret JWT using the configured Team ID, Key ID, Services ID, and PKCS8 ECDSA private key, then exchanges the authorization code at Apple’s token endpoint.
5. The returned Apple ID token is validated against Apple JWKS, issuer `https://appleid.apple.com`, tenant `client_id` audience, expiration, verified email, and the nonce stored at `/auth/apple/start`.
6. `allowed_users` applies to the Apple email the same way it applies to Google and password login.
7. Without account management, the session subject is `apple:<sub>` and the application user profile is upserted through `UserStore.UpsertProviderUser`. With account management, `apple:<sub>` resolves through the generic provider-identity store and first login creates an active account.
8. Session JWT and refresh cookie issuance then uses the same finalizer as other login methods.

TAuth does not expose Apple access tokens to JavaScript and does not store Apple API refresh tokens.

### 3.6 Email/password accounts

Password authentication is tenant-enabled with `password_auth.enabled: true`. Account management is separately gated by `account_management.enabled`; when enabled, TAuth uses a persisted tenant-scoped opaque 128-bit base64url value as the session subject and stores provider identities separately.

1. Seeded password users continue to authenticate through `POST /auth/password/login`. Without account management, the session subject remains `email:<normalized-email>`. With account management, verified credentials return their linked bare opaque account ID.
2. Public signup is gated by `account_management.password_signup.enabled`. `POST /auth/password/signup` creates a pending account, stores only the bcrypt password hash, and creates a single-use email verification challenge whose raw token is never stored.
3. `POST /auth/password/verify-email` consumes the challenge, activates the account, links the password identity, and mints the standard access and refresh cookies.
4. `POST /auth/password/reset/start` always returns an accepted response shape for valid-looking input. Known verified password accounts receive a reset challenge; unknown accounts receive a synthetic accepted response.
5. `POST /auth/password/reset/complete` consumes the reset challenge, rotates the bcrypt hash, revokes all account refresh sessions, and issues fresh cookies.
6. Authenticated `/auth/account/*` endpoints require a bare opaque account-ID session. They support password change, password link verification, Google identity linking, provider unlinking with last-identity rejection, and account disablement.
7. Google and Apple login also participate in account management when enabled: linked `google:<sub>` and `apple:<sub>` identities resolve to the account, and a first provider login creates an active account with that provider identity.

### 3.7 Browser helper handshake

The canonical `https://tauth.mprlab.com/tauth.js` asset is built from `web/tauth.js` and abstracts the nonce and credential exchange, but custom front-ends can implement the same flow with a small wrapper around Google Identity Services:

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

For Apple, custom UIs do not fetch or manage a nonce themselves. Use `getAppleLoginUrl()` to render a tenant-aware link or call `startAppleLogin()` from a click handler. TAuth creates and validates the nonce/state pair around the Apple redirect.

### 3.8 OAuth resource authorization

1. The client reads issuer metadata and creates a PKCE `S256` challenge.
2. The authorization route requires one exact resource indicator and resolves it to one tenant policy.
3. The registry resolves an explicit client or retrieves one strict HTTPS Client ID Metadata Document. It then validates the exact redirect URI and requested scopes.
4. TAuth stores a short-lived pending request under an opaque handle. The browser uses only issuer-owned login and consent routes.
5. The normal tenant session supplies the stable user subject. A new exact client, resource, and scope set requires approval. An active exact consent grant skips repeat consent.
6. TAuth stores only an authorization-code digest. Code redemption atomically verifies the client, redirect URI, resource, expiry, and PKCE verifier before consumption.
7. The token route returns an ES256 resource-bound access token and an opaque rotating refresh token. The access-token audience is the exact requested resource.
8. Refresh reuse revokes every member of the refresh-token family and the consent grant. Explicit revocation has the same family and consent result. Issued access tokens expire after the configured short lifetime.

OAuth access and refresh tokens do not enter the TAuth session cookies, browser
storage, page content, or issuer redirects. The required authorization code is
returned only to the exact validated client callback. Provider tokens remain
outside this authorization-server contract.

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
- `MountAuthRoutesWithPassword`: installs `/auth/*` handlers and binds user, refresh, nonce, and optional password credential stores. `MountAuthRoutes` remains the compatibility wrapper for tests and embedding code that do not configure password auth.
- JWT helpers: signing, validation, claims modeling.
- Refresh token stores:
  - Memory implementation for tests/dev.
  - GORM-backed implementation (`DatabaseRefreshTokenStore`) that performs migrations and issues hashed refresh tokens.
- `RequireSession`: Gin middleware backed by the shared session validator; confirms issuer and injects `JwtCustomClaims` into the request context (`auth_claims`).
- Shared helpers (`refresh_token_helpers.go`) generate token IDs and opaque values consistently across store implementations.

### 4.3 `internal/web`

- `NewInMemoryUsers`: placeholder application user store (maps provider subjects or password emails to profiles).
- `PermissiveCORS`: development-only CORS middleware.
- `HandleHealth`: returns backend readiness at `/health` without tenant resolution.
- `HandleWhoAmI`: returns profile data for `/api/me`.

### 4.4 `web/tauth.js`

- Is published by the gateway-managed GitHub Pages resource only at `https://tauth.mprlab.com/tauth.js`; the API binary neither embeds nor serves it.
- Tracks client auth state as `unknown`, `anonymous`, `restoring`, `authenticated`, or `error`.
- Defaults `initAuthClient` to `bootstrapMode: "restore-if-hinted"` so a fresh anonymous page load reports `onUnauthenticated()` without calling protected endpoints. Successful login, profile restore, and refresh set a non-secret local restore hint keyed by `baseUrl` and tenant id.
- Restores hinted sessions by calling `/auth/session`, which returns profile JSON for valid or refresh-restored cookies and `204 No Content` for anonymous or expired browsers without emitting expected 401s.
- Preserves `bootstrapMode: "eager"` for legacy probe-first integrations and `bootstrapMode: "passive"` for public surfaces that should never restore on load.
- Keeps `apiFetch` refresh-on-401 behavior for protected application requests, then retries the original request once on refresh success.
- Exposes `getAppleLoginUrl()` and `startAppleLogin()` for tenants that enable Sign in with Apple. These helpers navigate to `/auth/apple/start` and append the configured tenant id when shared-origin setups need explicit tenant selection.
- Exposes `exchangePasswordCredential({ email, password })` for tenants that enable the password provider; the helper posts to `/auth/password/login`, applies the authenticated profile, and leaves the raw password out of client state.
- Exposes account-management helpers for `signupPasswordCredential`, `verifyPasswordEmail`, `startPasswordReset`, `completePasswordReset`, `changePassword`, `startPasswordLink`, `verifyPasswordLink`, `linkGoogleCredential`, `unlinkAccountIdentity`, and `disableAccount`. These helpers use cookie credentials, tenant override headers, and local variables only; they do not persist raw passwords or challenge tokens in client state.
- Provides hooks for UI callbacks (`onAuthenticated`, `onUnauthenticated`, `onAuthError`) plus `getCurrentUser()` and `getAuthState()`.
- Accepts an optional `tenantId` when calling `initAuthClient`; when present the helper attaches `X-TAuth-Tenant` to `/auth/session`, `/me`, `/auth/*`, and logout requests so multiple tenants can share an origin in development. When you omit `tenantId`, the helper relies on the browser `Origin` header for tenant resolution and does not send overrides.

### 4.5 Interfaces and extension points

```go
type UserStore interface {
    UpsertGoogleUser(ctx context.Context, tenantID string, googleSub string, userEmail string, userDisplayName string, userAvatarURL string) (applicationUserID string, userRoles []string, err error)
    UpsertProviderUser(ctx context.Context, tenantID string, provider string, providerID string, userEmail string, userDisplayName string, userAvatarURL string) (applicationUserID string, userRoles []string, err error)
    UpsertPasswordUser(ctx context.Context, tenantID string, userEmail string, userDisplayName string, userAvatarURL string) (applicationUserID string, userRoles []string, err error)
    UpsertAccountUser(ctx context.Context, tenantID string, accountID string, userEmail string, userDisplayName string, userAvatarURL string) (applicationUserID string, userRoles []string, err error)
    GetUserProfile(ctx context.Context, tenantID string, applicationUserID string) (userEmail string, userDisplayName string, userAvatarURL string, userRoles []string, err error)
}

type RefreshTokenStore interface {
    Issue(ctx context.Context, tenantID string, applicationUserID string, expiresUnix int64, previousTokenID string) (tokenID string, tokenOpaque string, err error)
    Validate(ctx context.Context, tenantID string, tokenOpaque string) (applicationUserID string, tokenID string, expiresUnix int64, err error)
    Revoke(ctx context.Context, tenantID string, tokenID string) error
    RevokeUser(ctx context.Context, tenantID string, applicationUserID string) error
}

type PasswordCredentialStore interface {
    UpsertPasswordCredential(ctx context.Context, tenantID string, credential PasswordCredentialSeed) error
    ReconcilePasswordCredentials(ctx context.Context, tenantID string, configuredEmails []string) error
    AuthenticatePassword(ctx context.Context, tenantID string, userEmail string, password string) (PasswordCredentialProfile, error)
}

type AccountManagementStore interface {
    CreatePasswordSignup(ctx context.Context, tenantID string, request AccountPasswordRequest, expiresUnix int64) (AccountChallenge, error)
    VerifyEmailChallenge(ctx context.Context, tenantID string, token string) (AccountProfile, error)
    StartPasswordReset(ctx context.Context, tenantID string, userEmail string, expiresUnix int64) (AccountChallenge, error)
    CompletePasswordReset(ctx context.Context, tenantID string, token string, password string) (AccountProfile, error)
    ChangePassword(ctx context.Context, tenantID string, accountID string, currentPassword string, newPassword string) (AccountProfile, error)
    EnsurePasswordAccount(ctx context.Context, tenantID string, userEmail string) (AccountProfile, error)
    CreatePasswordLink(ctx context.Context, tenantID string, accountID string, request AccountPasswordRequest, expiresUnix int64) (AccountChallenge, error)
    VerifyPasswordLink(ctx context.Context, tenantID string, accountID string, token string) (AccountProfile, error)
    AuthenticateProviderAccount(ctx context.Context, tenantID string, identity AccountProviderIdentity) (AccountProfile, bool, error)
    UpsertProviderAccount(ctx context.Context, tenantID string, identity AccountProviderIdentity) (AccountProfile, error)
    LinkProviderIdentity(ctx context.Context, tenantID string, accountID string, identity AccountProviderIdentity) (AccountProfile, error)
    UnlinkIdentity(ctx context.Context, tenantID string, accountID string, provider string, providerID string) (AccountProfile, error)
    DisableAccount(ctx context.Context, tenantID string, accountID string) (AccountProfile, error)
    ReactivateAccount(ctx context.Context, tenantID string, accountID string) (AccountProfile, error)
    ResolveAccountProfile(ctx context.Context, tenantID string, accountID string) (AccountProfile, error)
}
```

- Swap `UserStore` for a production datastore (e.g., Postgres) while keeping the auth kit isolated from application models.
- `PasswordCredentialStore` stores bcrypt hashes separately from refresh tokens while returning profiles that flow into the same session finalizer.
- `AccountManagementStore` owns persisted opaque account IDs, linked identities, single-use challenges, account state, and account-level operations while preserving the existing cookie/JWT session model. Provider identities use explicit `provider` plus `provider_id` pairs such as `google:<sub>` and `apple:<sub>`.
- Implement a custom `RefreshTokenStore` (e.g., Redis, DynamoDB) by reusing the hashing helpers to maintain compatibility.
- Downstream services can read `auth_claims` and rely on `JwtCustomClaims` to authorize domain-specific operations.

### 4.6 `pkg/sessionvalidator`

- Reusable library for downstream Go services to validate the `app_session` cookie.
- Smart constructor enforces signing key and issuer configuration, with optional cookie name overrides.
- Provides `ValidateToken`, `ValidateRequest`, and a Gin middleware adapter to populate typed `Claims`.
- Shares the same claim shape (`user_id`, `user_email`, `display`, `avatar_url`, `roles`, `expires`) used by the server.
- Includes `LoadTenantAuthConfig` to derive tenant signing keys, issuer, and cookie names from the same `config.yaml` used by TAuth.

### 4.7 OAuth authorization components

- `internal/oauthserver` owns issuer discovery, JWKS, client and resource resolution, browser transactions, PKCE, signing, consent, authorization-code, and refresh-token behavior.
- `MemoryStore` and `DatabaseStore` implement one store contract. The database implementation uses atomic code consumption and refresh rotation for SQLite and Postgres.
- `ClientMetadataResolver` permits only HTTPS client IDs with a non-root path. It resolves public DNS addresses and dials a validated address. It disables proxy and redirect use and limits response time and size. It validates public-client metadata and bounds valid-document caching.
- `authkit.OAuthBrowserSessions` resolves and creates the same tenant session used by the existing TAuth routes. The issuer-owned login page accepts the tenant's configured Google browser provider, password provider, or both.
- `pkg/oauthvalidator` is the public protected-resource library. It accepts only ES256 access tokens with `typ=at+jwt` and a known key ID. It also requires the configured issuer, audience, expiry, and scopes.

## 5. Configuration Surface

| Variable / Flag            | Purpose                                             | Example                                             |
| -------------------------- | --------------------------------------------------- | --------------------------------------------------- |
| `listen_addr`          | HTTP listen address                                 | `:8080`                                             |
| `database_url`         | Refresh store DSN (`postgres://` or `sqlite://`)    | `sqlite:///auth.db`                                 |
| `enable_cors`          | Enable permissive CORS (cross-origin dev only)      | `true` / `false`                                    |
| `cors_allowed_origins` | List of allowed origins when CORS is enabled (include GIS) | `["https://app.example.com","https://accounts.google.com"]` |
| `cors_allowed_origin_exceptions` | Non-tenant origins that may appear in `cors_allowed_origins` | `["https://accounts.google.com"]` |
| `enable_tenant_header_override` | Allow explicit tenant selection for shared origins and non-browser clients | `true` |
| `tenants`              | Array of tenant entries (id, tenant_origins, web/native/Apple clients, TTLs) | See README §5 |

Configuration is loaded from a single YAML file (`config.yaml` by default, override via `tauth --config=/path/to/file` or `TAUTH_CONFIG_FILE`).

Each operator supplies one complete runtime configuration to the generic TAuth
service. Tenant identities, origins, provider clients, cookie policy, secrets,
routing, and secret values remain operator-owned. The MPR Lab deployment shape
is declarative: `.mprlab/deploy/resources.yml` names the TAuth image, retained
data, gateway-managed tenant configuration, exported capabilities, public
routes, and health contract without containing secret bytes or host paths.

The root `make release`, `make publish`, and `make deploy` entrypoints delegate
the exact selected Git root to the required sibling `../mprlab-gateway`.
Gateway-owned Ansible validates the `resources.yml` schema, resolves declared
outputs, manages immutable lifecycle receipts, and performs convergence. The
gateway sends complete TAuth contributions and output envelopes to
`tauth render-deployment-config` through standard input. TAuth owns the strict
render request, TAuth defaults, output-name resolution, native config assembly,
and native validation. The command returns the complete native YAML through
standard output. TAuth carries no production lifecycle script or alternative
controller. The README defines the render request envelope. It does not define
a second `resources.yml` schema.

### 5.1 Multi-tenant configuration file

Every deployment relies on the declarative config file parsed by `internal/tenants`. The YAML document describes each tenant’s identity, origins, identity-provider clients, and cookie/scheduling knobs:

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
    google_native_client_id: "demo-native.apps.googleusercontent.com"
    google_native_clients:
      - platform: "ios"
        client_id: "demo-ios.apps.googleusercontent.com"
        redirect_uris:
          - "com.demo.app://oauth2redirect/google"
          - "https://demo.example.com/oauth/google/callback"
      - platform: "android"
        client_id: "demo-android.apps.googleusercontent.com"
        redirect_uris:
          - "com.demo.app:/oauth2redirect/google"
    apple_oauth:
      enabled: true
      client_id: "com.demo.web"
      team_id: "APPLETEAMID"
      key_id: "APPLEKEYID"
      private_key: "${APPLE_PRIVATE_KEY_PEM}"
      redirect_uri: "https://auth.demo.example.com/auth/apple/callback"
    password_auth:
      enabled: true
      users:
        - email: "operator@example.com"
          display_name: "Operator"
          avatar_url: "https://demo.example.com/operator.png"
          password_hash: "$2a$10$..."
    account_management:
      enabled: true
      password_signup:
        enabled: true
      return_challenge_tokens: false
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

Validation rules baked into the loader:

- IDs use lowercase letters/digits/underscores/hyphens; duplicates are rejected.
- `display_name` is required so operators can identify tenants in logs.
- Origins are normalized to lowercase and deduplicated within each tenant definition. Entries must be full origins (scheme + host + optional port). When multiple tenants share the same origin, the runtime requires `X-TAuth-Tenant` to be enabled so requests can declare their tenant explicitly.
- `allowed_users` is optional; when provided, only the listed email addresses may authenticate for the tenant (an empty list denies all logins).
- Behavior: `allowed_users` absent → allow all; present empty → deny all; present with entries → allow only listed emails.
- `google_web_client_id` must be present for every tenant. `google_native_client_id` remains the legacy single installed-app audience; `google_native_clients` adds platform-specific audiences and redirect URIs for mobile clients. These fields enable native installed-app login via `GET /auth/google/native/config` and `POST /auth/google/native`; every configured native client ID must be unique across tenants.
- `apple_oauth.enabled` gates the browser Apple endpoints. Optional `native_client_ids` gate the native Apple endpoints.
- Native Apple IDs must be nonempty and unique. A native Apple ID must also be unique across tenants.
- Enabled Apple providers require a Services ID, Team ID, Key ID, PKCS8 ECDSA private key, and HTTPS callback URI.
- Optional endpoint overrides support local provider tests. These overrides must be absolute HTTP(S) URLs. Production overrides must use HTTPS.
- `password_auth.enabled` gates `/auth/password/login`; configured users require unique normalized emails and valid bcrypt hashes. `account_management.enabled` gates persisted opaque account IDs and account lifecycle endpoints. `account_management.password_signup.enabled` cannot be true unless account management is enabled. `return_challenge_tokens` is intended for tests or trusted non-email delivery integrations. Each tenant also requires its own `jwt_signing_key`; the server rejects definitions that omit it. TTLs follow Go’s `time.ParseDuration` syntax. `cookie_domain` may be blank to emit host-only cookies (required for `localhost`); otherwise provide a registrable domain (e.g. `.example.com`). `session_cookie_name` / `refresh_cookie_name` are mandatory; set them explicitly per tenant (for example `app_session_notes`, `app_refresh_notes`). Reuse the legacy `app_session`/`app_refresh` names only when you intentionally want multiple tenants to share the same cookies.
- `nonce_ttl` defaults to `5m` when omitted; `allow_insecure_http` defaults to `false`.
- String fields expand environment variables (`$VAR` / `${VAR}`) during typed config loading so operator templates can stay DRY. Unset variables resolve to empty strings, triggering the same validation rules as blank values. Literal bcrypt hashes beginning with `$2a$`, `$2b$`, or `$2y$` are preserved rather than treated as shell variables.

Tenant resolution & runtime:

- The explicit `tenants: []` aggregate is the valid bootstrap state before an application contributes a tenant. The server exposes `GET /health`; tenant-authenticated routes remain inactive because no origin or override can resolve to a tenant.
- `internal/tenants.NewResolver` consumes the validated config and maps HTTP requests to tenants. Origins are matched case-insensitively, and unknown origins are rejected with a 404 response before hitting auth routes. When multiple tenants intentionally share the same origin, enable the header override and send `X-TAuth-Tenant` to disambiguate.
- Non-browser clients and shared-origin callers use the `X-TAuth-Tenant` override. The override accepts tenant IDs or frontend origins. Disable it only when every request uses one unique browser `Origin`.
- `internal/tenants.TenantMiddleware` injects the resolved tenant into `gin.Context` so auth routes and stores can look up per-tenant keys (`tenants.TenantFromContext`) without touching global state.
- Multi-tenant mode uses the `tenants` array in `config.yaml`. Start TAuth with `tauth --config=/path/to/config.yaml` or `TAUTH_CONFIG_FILE`. Use `enable_tenant_header_override: true` when requests require explicit tenant selection.
- Native clients without a browser `Origin` header must send `X-TAuth-Tenant`. Google mobile clients use `platform` to select iOS or Android audiences. Without `platform`, `/auth/google/native` accepts any configured native Google audience for the tenant. Native Apple login accepts only the resolved tenant's `native_client_ids` audiences.
- Apple start requests can include `tenant_id` when the initiating page configured a tenant explicitly. Apple callbacks do not rely on `Origin`; the signed state token identifies the tenant after the provider redirect.
- Front-ends pass `tenantId` to `initAuthClient` when they need to pin a tenant explicitly; the helper automatically sets the `X-TAuth-Tenant` header on its own `/auth/session`, `/me`, `/auth/*`, and logout requests to line up with the override flow above while leaving product APIs untouched. When no tenant ID is supplied, the helper relies on the request `Origin` header instead of sending overrides.
- All per-tenant server configs live inside `authkit.TenantRegistry`, which backs `MountAuthRoutes` and `RequireSession` so cookies, TTLs, and SameSite/AllowInsecure decisions reflect the resolved tenant.
- Refresh token stores, nonce pools, and in-memory user stores are keyed by tenant ID, and JWT sessions embed a `tenant_id` claim that `RequireSession` verifies against the resolved tenant to prevent cross-tenant cookie replay. Front-end clients normally rely on origins, but when multiple tenants share the same origin (local dev boxes, automation rigs) you can enable the header override and pass `tenantId` to `initAuthClient`. The helper adds `X-TAuth-Tenant` to `/auth/session`, `/me`, `/auth/*`, and logout requests without touching product APIs so you can switch tenants without DNS changes.

## 6. Persistence Model

The persistent store manages refresh tokens, user profiles, optional password credentials, account records, identity links, and account challenges (automigrated via GORM). Refresh tokens live in the `refresh_tokens` table:

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

Email/password credentials live in `password_credentials`, keyed by tenant and normalized email, with only bcrypt hashes stored:

```sql
CREATE TABLE IF NOT EXISTS password_credentials (
    tenant_id TEXT NOT NULL,
    user_email TEXT NOT NULL,
    user_id TEXT NOT NULL,
    account_id TEXT,
    user_display_name TEXT NOT NULL,
    user_avatar_url TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT TRUE,
    created_at_unix BIGINT NOT NULL,
    last_updated_unix BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, user_email)
);
```

When account management is enabled, account state and identity links live in separate tables. `accounts.account_id` is generated once as a 128-bit base64url value and is never derived from tenant, email, provider, provider subject material, or a `user_id` prefix.

```sql
CREATE TABLE IF NOT EXISTS accounts (
    tenant_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    user_email TEXT NOT NULL,
    user_display_name TEXT NOT NULL,
    user_avatar_url TEXT NOT NULL,
    account_state TEXT NOT NULL,
    user_roles TEXT NOT NULL,
    created_at_unix BIGINT NOT NULL,
    last_updated_unix BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, account_id)
);

CREATE TABLE IF NOT EXISTS account_identities (
    tenant_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    created_at_unix BIGINT NOT NULL,
    last_updated_unix BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, provider, provider_id)
);

CREATE TABLE IF NOT EXISTS account_challenges (
    tenant_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    account_id TEXT NOT NULL,
    challenge_kind TEXT NOT NULL,
    user_email TEXT NOT NULL,
    user_display_name TEXT NOT NULL,
    user_avatar_url TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    expires_unix BIGINT NOT NULL,
    consumed_at_unix BIGINT NOT NULL DEFAULT 0,
    created_at_unix BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, token_hash)
);
```

Challenge rows store only `hashOpaque(token)`, are scoped by tenant and kind, expire by `expires_unix`, and are consumed once by setting `consumed_at_unix`.

OAuth persistence uses four additional tables:

- `oauth_authorization_requests` stores the short-lived validated browser transaction under a request digest.
- `oauth_authorization_codes` stores a code digest and its immutable client, user, redirect, resource, scope, consent, PKCE, and expiry bindings.
- `oauth_consents` stores one time-bounded exact user approval and its revocation time.
- `oauth_refresh_tokens` stores only a token digest, family ID, minimum grant metadata, absolute expiry, and active, rotated, or revoked state.

`DatabaseRefreshTokenStore` and `DatabaseUserStore` parse the database URL to select a GORM dialector (`postgres` or the CGO-free `github.com/glebarez/sqlite`), silence default logging, auto-migrate their schemas, and tag errors with context (`refresh_store.*` / `user_store.*`) for observability. For SQLite, only triple-slash absolute paths (`sqlite:///data/tauth.db`) or opaque memory URLs (`sqlite://file::memory:?cache=shared`) are accepted; host-prefixed forms such as `sqlite://file:/data/tauth.db` are rejected. Shared helpers ensure memory and persistent stores derive token IDs and hashes identically.

## 7. Security Considerations

- Always run behind HTTPS in production; set a tenant’s `allow_insecure_http` to `true` only for local development.
- Access cookies are short-lived; refresh cookies survive longer but are `HttpOnly` and scoped to `/auth`.
- Validate provider tokens strictly: issuer, audience, expiry, signature, and nonce where applicable.
- Rate limit all login, signup, password reset, refresh, and Apple callback endpoints. Monitor failures through zap logs.
- Require nonce tokens from `/auth/nonce` for every Google Sign-In exchange and signed state-backed nonces for every Apple redirect exchange; treat missing or mismatched nonces as unauthorized.
- Store only bcrypt password hashes and hashed one-time challenge tokens. Raw passwords and raw challenge tokens should exist only at HTTP/delivery edges.
- Rotate each tenant's `jwt_signing_key` using standard secrets management practices.
- Only hashed refresh tokens are stored—never persist the raw opaque value.
- Load browser code only from `https://tauth.mprlab.com/tauth.js` and avoid inline scripts to keep CSP-friendly deployments.
- Keep OAuth P-256 signing keys separate from tenant session keys. Publish only public coordinates in JWKS. Add the new key before activation and retain the prior key until its access tokens expire.
- Require PKCE `S256`, one resource indicator, one exact redirect URI, and configured scopes for every authorization-code flow.
- Require the exact issuer `Origin` header for login and consent POST requests. Do not emit CORS headers at the authorization endpoint.
- Keep access-token lifetimes short. Protected resources validate issuer, ES256 signature, audience, expiry, client, tenant, and required scopes with `pkg/oauthvalidator`.
- Treat Client ID Metadata retrieval as untrusted network input. Keep its HTTPS, public-address, no-redirect, response-size, timeout, media-type, document, and cache limits enabled.

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
- `tauth doctor <config-paths...>` validates one or more TAuth configurations and reports issues:
  - `--cross-validate`: Check for conflicts across multiple configs (shared origins, signing keys, cookie names).
  - `--check-database`: Verify database connectivity for configured database URLs.
  - `--json`: Output results as JSON for CI/CD pipelines.
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

- **204 on `/auth/session`** – No current or refresh-restorable browser session; prompt the user to sign in.
- **401 on `/me` but refresh succeeds** – Access cookie expired on a protected profile route; the client will refresh on the next protected API retry.
- **401 on `/auth/refresh`** – Refresh cookie missing/expired/revoked; prompt user to sign in again.
- **Cookies missing** – Verify the tenant’s `cookie_domain`, HTTPS usage, and CORS settings.
- **Google token rejection** – Confirm OAuth client type (Web) and that `aud` matches configured client ID.
- **Password login returns `password_auth_not_configured`** – Enable `password_auth.enabled` for the resolved tenant.
- **Password login returns `invalid_credentials`** – The email/password pair did not match a seeded bcrypt credential; the same response is used for unknown users and wrong passwords.
- **Signup returns `password_signup_not_configured`** – Enable both `account_management.enabled` and `account_management.password_signup.enabled`.
- **Password login returns `account_not_active`** – Complete email verification before password login on a newly created account.
- **Unlink returns `last_identity`** – Link another login method before removing the current account's only identity.

## 12. Versioning Contract

The following surface area is considered stable across releases:

- Native identity endpoints: `/auth/google/native/config`, `/auth/google/native`, `/auth/apple/native/config`, and `/auth/apple/native`.
- Other identity endpoints: `/auth/nonce`, `/auth/google`, and the password login, signup, verification, and reset endpoints.
- Account and session endpoints: `/auth/account/password/change`, `/auth/account/password/link/start`, `/auth/account/password/link/verify`, `/auth/account/google/link`, `/auth/account/unlink`, `/auth/account/disable`, `/auth/session`, `/auth/refresh`, `/auth/logout`, and `/me`.
- OAuth endpoints: `/.well-known/oauth-authorization-server` and every exact configured OAuth endpoint.
- Cookie names: `app_session`, `app_refresh`.
- JSON payload fields returned to the client (`user_id`, `user_email`, `display`, `avatar_url`, `roles`, `expires`, and `state` for account-management profile responses).

Update the embedded client and bump the service version together when changing these contracts.

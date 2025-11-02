# Refactor Plan (TA-402)

This document records the gaps between the current codebase and the confident-programming rules in `POLICY.md`, and it outlines the refactor roadmap to resolve them. The plan is split into thematic areas with concrete follow-up tasks and proposed sequencing.

## 1. Policy Alignment Snapshot

- **Edge-only validation & smart constructors** – Inputs must be validated exactly once and wrapped in smart constructors (POLICY §A.1–2).
- **Context-rich errors** – All exported paths should wrap errors with op + subject + stable code (POLICY §A.5).
- **Injected effects** – External dependencies (network, storage, time) must be injected (POLICY §A.6).
- **Typed domain invariants** – No loose primitives when a domain type exists (POLICY §A.4).
- **Comprehensive tests** – Black-box tests covering public APIs and DOM (POLICY §7 / Backend Testing).

## 2. Findings & Recommendations

### 2.1 Configuration lifecycle

- `cmd/server/main.go:64` reads configuration directly from Viper without validation beyond two required fields. There is no smart constructor for `authkit.ServerConfig` (`internal/authkit/config.go:6`), and invalid TTLs or cookie names can slip through.
- Recommendation:
  - Introduce a `LoadServerConfig` function returning `(ServerConfig, error)` that enforces non-empty IDs, positive TTLs, and consistent cookie names.
  - Move validation into `Cobra.PreRunE` so configuration failures surface before starting the HTTP server.
  - Emit structured zap errors with stable codes (e.g., `config.missing_jwt_key`).

### 2.2 Google token verification flow

- `MountAuthRoutes` creates a new `idtoken.Validator` per request (`internal/authkit/routes.go:25`), violating the “inject external effects” rule and hindering testability.
- `MintAppJWT` returns the raw signing error without wrapping (`internal/authkit/jwthelper.go:28`), losing operator context.
- Recommendation:
  - Define a `GoogleTokenValidator` interface and inject a singleton validator from `cmd/server`.
  - Wrap JWT signing errors (`jwt.mint.failure`) and add defensive checks for empty subject before signing.
  - Replace repeated `time.Now()` calls with an injected clock to simplify deterministic testing.

### 2.3 Refresh token stores

- The memory store returns ad-hoc string errors (`internal/authkit/memory_refresh_store.go:71`), while the database store returns wrapped sentinels. Consumers handle both, leading to inconsistency.
- Recommendation:
  - Extract typed sentinel errors in `authkit` (e.g., `ErrRefreshTokenNotFound`) and reuse across store implementations.
  - Add context to memory-store errors to meet POLICY §A.5.
  - Expose a revocation helper returning idempotent results instead of returning `nil` silently on already-revoked tokens, enabling precise logging.

### 2.4 Session middleware and profile surfaces

- `authkit.RequireSession` sets `auth_claims` but downstream code (`internal/web/users.go:48`) ignores it. `/api/me` currently returns `{"message":"ok"}` instead of the authenticated profile, which diverges from the documented behaviour.
- `InMemoryUsers.GetUserProfile` returns `http.ErrNoCookie` on missing users (`internal/web/users.go:43`), which is semantically incorrect and complicates error handling.
- Recommendation:
  - Update `HandleWhoAmI` to read `auth_claims` and return the resolved profile, matching the `/auth/me` contract.
  - Replace `http.ErrNoCookie` with a typed error (e.g., `ErrUserNotFound`) aligned with the confident-programming policy.
  - Add logging (via `zap`) when claims are missing or invalid.

### 2.5 CORS and security safeguards

- `PermissiveCORS` allows `*` origins while `AllowCredentials` is `true` (`internal/web/static.go:25`), which browsers reject and violates “principle of least privilege”.
- Recommendation:
  - Parameterise allowed origins via configuration and disallow wildcard credentials.
  - Surface a warning when `APP_ENABLE_CORS` is used with insecure origins.

### 2.6 Logging & observability

- Handler failures currently return HTTP codes without logging, making production troubleshooting difficult.
- Recommendation:
  - Plumb a lightweight logger interface into `MountAuthRoutes` so unexpected errors (e.g., store failures) are logged with stable codes.
  - Capture metrics hooks (success/failure counters) for `/auth/*` endpoints to support future dashboards.

## 3. Testing & Coverage Gaps

- No integration tests cover the `/auth/google → /auth/refresh → /auth/logout` cycle.
- No coverage exists for `authkit.RequireSession` with tampered tokens.
- Recommendation:
  - Build an HTTP-level suite using `httptest.Server` that exercises public endpoints with a fake Google validator and in-memory stores (black-box, satisfying POLICY §7).
  - Add browser-level tests (Puppeteer) verifying `auth-client.js` emits the expected DOM events on auth transitions.
  - Capture coverage via `go test ./... -coverprofile` and target ≥95% by expanding integration cases (will dovetail with TA-403).

## 4. Sequencing Roadmap

1. **Config & dependency injection** – implement smart constructors, PreRun validation, and validator injection (enables test harness improvements).
2. **Store harmonisation** – unify refresh-store error semantics and logging.
3. **Session surface cleanup** – fix `/api/me`, adjust user store errors, and wire logging.
4. **Security hardening** – tighten CORS configuration and add warnings.
5. **Test suite expansion** – deliver end-to-end Go tests followed by browser automation for the client.

Each step delivers value independently and keeps the codebase aligned with AGENTS + POLICY while paving the way for future features.

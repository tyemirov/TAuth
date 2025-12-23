# GAuss to TAuth Migration

## Audience and goal
This document is written from the perspective of an engineer migrating an established GAuss integration to the TAuth service in a running application. The goal is to move authentication and session management to TAuth while keeping product behavior stable and minimizing user disruption.

## Current GAuss footprint to inventory
I will start by mapping where GAuss is embedded in the running app so the migration is scoped correctly.

- Authentication flow uses GAuss routes: /login, /auth/google, /auth/google/callback, /logout, and the post-login redirect.
- Session state lives in the gauss_session cookie and is enforced through gauss.AuthMiddleware.
- User identity is stored in session keys for email, name, and picture, plus the OAuth token for downstream Google API usage.
- OAuth scopes may be broader than profile and email; any non-profile scope implies the app depends on Google API access tokens.
- Logout behavior is driven by GAuss redirect configuration.

## Target TAuth model
TAuth is a standalone service that verifies Google Identity Services ID tokens and mints first-party cookies.

- Session cookies are app_session (JWT access token) and app_refresh (opaque refresh token).
- Core endpoints are /auth/nonce, /auth/google, /auth/refresh, /auth/logout, and /me.
- These endpoints are provided by the TAuth server only; consuming apps should call them rather than implement them.
- Tenant configuration is YAML-driven and includes host routing, cookie domain, Google web client ID, signing keys, and TTLs.
- Session validation is performed by verifying the JWT signature, issuer, and time-based claims in app_session.

## Migration path
### 1. Pre-migration assessment
I will confirm the GAuss responsibilities that must move to TAuth and identify any blockers.

- List every route guarded by gauss.AuthMiddleware and any code that reads GAuss session keys.
- Identify where the stored GAuss OAuth token is used to call Google APIs; TAuth only validates Google ID tokens and does not mint OAuth access tokens for Google APIs.
- Define the application user identity and roles used today so TAuth can embed equivalent claims in its JWTs.

### 2. Build the TAuth deployment
I will deploy TAuth as a separate service with production-grade settings.

- Choose the TAuth host and cookie domain so cookies cover the product origin without leaking beyond the intended registrable domain.
- Configure the tenant entry with allowed hosts, Google web client ID, JWT signing key, and TTLs that match existing session expectations.
- Use a persistent refresh token store and set database_url to avoid losing refresh tokens between restarts.
- Enable CORS only when the UI and TAuth are on different origins and include accounts.google.com and the product origin in cors_allowed_origins.
- Keep allow_insecure_http disabled in production and terminate TLS in front of TAuth so Secure cookies are issued.
- Use environment variable expansion for secrets in the YAML to keep signing keys and client IDs out of the file.

### 3. Update Google Identity configuration
I will update Google Cloud OAuth settings to support TAuth.

- Add the TAuth host and the product origin to Authorized JavaScript origins for the Google web client.
- Keep the existing GAuss OAuth client and redirect URIs until cutover so legacy logins remain functional.

### 4. Integrate user store and roles
I will ensure the TAuth user store maps Google identities to the existing application user model.

- Implement a UserStore in the TAuth service that maps Google subject values to existing user IDs and roles.
- Ensure /me returns the fields required by the product UI and that JWT claims align with the current authorization model.

### 5. Frontend integration
I will replace the GAuss redirect login flow with the TAuth browser flow.

- Load /static/auth-client.js from the TAuth host and initialize it on app startup.
- Use the authenticated and unauthenticated callbacks to drive the UI state, replacing the GAuss login page and redirect flow.
- Use `getAuthEndpoints()` to derive `/auth/nonce` and `/auth/google` URLs from the helper (the base URL defaults to the script origin unless overridden).
- Route all authenticated API calls through a fetch wrapper that can call /auth/refresh when a 401 response is returned.
- Replace GAuss logout with /auth/logout so refresh tokens are revoked and cookies are cleared.

### 6. Backend integration
I will update backend services to validate TAuth sessions instead of GAuss cookies.

- Replace gauss.AuthMiddleware with JWT validation for app_session and return 401 rather than redirecting to /login.
- Use the TAuth sessionvalidator package in Go services, and use equivalent JWT validation in other services with the tenant signing key and issuer.
- Update authorization logic to read roles and tenant_id from the JWT claims.

### 7. Parallel run and cutover
I will switch traffic without downtime and accept that reauthentication is required.

- Run GAuss and TAuth in parallel during rollout; cookies do not collide because their names differ.
- Ship the TAuth UI integration behind a feature flag, then ramp gradually.
- Expect users to reauthenticate to obtain TAuth cookies because GAuss sessions cannot be migrated.
- After adoption is stable, remove GAuss handlers, session storage, and configuration from the application.

### 8. Validation and monitoring
I will validate the flow end to end and monitor for regressions.

- Confirm nonce issuance, Google credential exchange, and session cookie issuance work consistently.
- Confirm /me returns expected user data and that refresh rotation works across browser tabs.
- Monitor logs for nonce mismatches, token validation failures, tenant resolution errors, and CORS rejections.

### 9. Cleanup
I will remove remaining GAuss dependencies once TAuth is the sole authentication path.

- Remove GAuss environment variables, routes, and templates from the codebase.
- Update operational runbooks to document TAuth configuration, signing key rotation, and troubleshooting.

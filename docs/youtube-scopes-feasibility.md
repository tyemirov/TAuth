# YouTube Scopes Feasibility Report (TAuth)

## Summary

TAuth cannot currently request Google OAuth scopes beyond Google Identity Services (GIS) sign-in because it only verifies **Google ID tokens** (authentication) and never obtains/stores **OAuth access or refresh tokens** (authorization). Retrieving a user’s YouTube channel data (for example `channels.list(...).mine=true`) requires a Google OAuth access token with YouTube scopes such as `https://www.googleapis.com/auth/youtube.readonly`.

Re-implementing the GAuss/Sheet2Tube YouTube-scope flow inside TAuth is feasible, but it is a meaningful scope expansion: TAuth would need to add a Google OAuth2 Authorization Code flow (offline access) plus server-side token storage and YouTube API calls (or proxy endpoints) while preserving TAuth’s “no Google tokens in browser storage” design.

Decision (2026-02-10): Declined for TAuth. TAuth remains authentication-only and will not implement third-party authorization/token custody (YouTube/Drive/etc).

## Current State

### GAuss (reference implementation)

GAuss implements a classic Google OAuth2 web flow:

- Redirect-based OAuth2 Authorization Code flow via `/auth/google` and `/auth/google/callback`.
- Scopes are configurable and include YouTube scopes.
- Requests offline access and forces consent so a refresh token is issued:
  - `oauth2.AccessTypeOffline`
  - `prompt=consent`
- Stores the resulting `oauth2.Token` (access + refresh token) inside a Gorilla cookie session (`gauss.SessionKeyOAuthToken`).
- Consumers build an authenticated HTTP client from the token and use Google API client libraries (`youtube/v3`) to call endpoints such as:
  - `youtubeService.Channels.List(...).Mine(true).Do()`

Code pointers:

- GAuss OAuth start + offline consent: `tools/GAuss/pkg/gauss/handlers.go`
- GAuss scope constants: `tools/GAuss/pkg/gauss/scopes.go`
- GAuss YouTube demo using `channels.list(mine=true)`: `tools/GAuss/examples/youtube_listing/main.go`

### Sheet2Tube (consumer usage)

Sheet2Tube relies on GAuss for OAuth and requests YouTube scopes (read + manage + upload). It then:

- Reads the OAuth token from the GAuss session.
- Builds a `youtube.Service` with an authenticated HTTP client.
- Fetches channel information (`Channels.List(...).Mine(true)`) and uses it for UI (avatar) and API operations.

Code pointers:

- Requested YouTube scopes: `tools/Sheet2Tube/cmd/web.go`
- YouTube API client creation + channel avatar lookup: `tools/Sheet2Tube/cmd/middleware.go`

### TAuth (current implementation)

TAuth is intentionally different from GAuss:

- Auth flow is GIS “Sign in with Google” (popup) returning a **Google ID token** to the browser.
- Browser posts `{ google_id_token, nonce_token }` to `POST /auth/google`.
- TAuth validates the ID token audience/issuer and mints first-party cookies:
  - `app_session` (JWT access cookie)
  - `app_refresh` (opaque refresh cookie for TAuth’s own session rotation)
- TAuth does not obtain OAuth access tokens and has no concept of OAuth scopes.
- Tenant configuration includes `google_web_client_id` but does not include a Google OAuth client secret or Google API scopes.

Code pointers:

- ID token validation + session/refresh cookie minting: `internal/authkit/routes.go`
- Tenant schema (`google_web_client_id` only): `internal/tenants/config.go`
- Client helper used by frontends to call `/auth/*` + `/me`: `web/tauth.js`

## Why YouTube Channel APIs Need “Wider Scopes”

YouTube Data API calls that act on the authenticated user (for example `mine=true`) require a Google OAuth **access token** with an appropriate YouTube scope, typically:

- `https://www.googleapis.com/auth/youtube.readonly` for read-only channel/video metadata.

An ID token cannot be used to call the YouTube Data API. Therefore, “requesting wider scopes” in practice means adding a Google OAuth2 authorization flow to obtain and refresh an access token.

## Feasibility Assessment (Re-implementing in TAuth)

### Feasible, with these core additions

1. **Google OAuth2 Authorization Code flow (offline)**
   - TAuth needs a flow that results in an access token and refresh token for the user.
   - Must request offline access so channel access works long-term without re-consent.

2. **Server-side storage for Google OAuth tokens**
   - Unlike GAuss (cookie sessions), TAuth’s design goal is “no tokens in JS storage”.
   - Tokens must be persisted server-side, keyed by:
     - `tenant_id`
     - `application_user_id` (TAuth user id)
     - a stable “scope-set” identifier (for example `youtube_readonly`), or a normalized scope list hash.

3. **A YouTube channel information endpoint (TAuth as proxy)**
   - Stand-alone front-ends should call TAuth, not Google APIs directly, to keep OAuth tokens off the browser.
   - Example capability: “return my YouTube channel id/title/thumbnails/uploads playlist id”.

4. **Tenant-safe OAuth callback routing**
   - OAuth callbacks may not include `Origin`, so tenant resolution cannot rely on the current origin-only resolver.
   - The tenant (and return origin) must be encoded in a signed `state` payload and validated on callback, similar to the tenant guidance already captured for future OAuth providers (see TA-433).

### Expected configuration changes

At minimum, a tenant that enables YouTube scopes will need additional secrets and knobs:

- `google_oauth_client_secret` (or a reference to a secret source) for server-side code exchange.
- A per-tenant declared set of supported scope bundles (at least YouTube read-only).
- Optional: a per-tenant “enable_google_oauth” gate to avoid changing behavior for existing tenants.

Without adding a client secret to tenant config, TAuth cannot reliably do a standard server-side code exchange comparable to GAuss.

### Required product behavior changes

TAuth’s current sign-in is authentication-only. To support YouTube data, clients will need an additional user action/flow:

- A “Connect YouTube” step that triggers the OAuth consent screen for the YouTube scope bundle.
- On completion, the frontend can call a TAuth endpoint to retrieve channel info (fetched server-side).

This is additive and can coexist with the existing `/auth/google` ID-token exchange.

## Recommended Re-implementation Shape in TAuth

This is the smallest design that mirrors GAuss capabilities while staying aligned with TAuth’s model.

### New endpoints (high level)

- `GET /auth/google/authorize/youtube`
  - Requires a valid TAuth session (`app_session`).
  - Mints a signed state payload containing: tenant id, application user id, initiating origin, and a short TTL.
  - Redirects to Google OAuth consent screen with:
    - requested scopes (YouTube read-only + identity scopes needed for binding)
    - offline access + consent prompt (refresh token)

- `GET /auth/google/callback`
  - Validates state signature/TTL and tenant binding.
  - Exchanges code for tokens (server-side).
  - Validates the token belongs to the same user as the current TAuth session (binding check).
  - Stores refresh token and token metadata server-side.
  - Redirects to a small “success” page that notifies the opener and closes (popup-friendly).

- `GET /api/google/youtube/channel`
  - Requires TAuth session.
  - Loads stored token, refreshes if needed, calls YouTube Data API, returns a minimal JSON payload.

### Binding check (avoid cross-account confusion)

The OAuth consent can be completed with a different Google account than the one used for GIS sign-in. TAuth should validate the OAuth result matches the signed-in user before storing it, for example by requesting identity scopes and comparing:

- Google subject (`sub`) or verified email from a userinfo lookup, against the user identity already stored for the TAuth session.

### Storage model (minimum viable)

- A new `GoogleOAuthTokenStore` interface with database + in-memory implementations (matching how refresh token storage is abstracted today).
- A GORM-backed table storing:
  - tenant id
  - application user id
  - scope bundle id (or normalized scope hash)
  - encrypted refresh token (must be retrievable, so hashing is insufficient)
  - access token expiry metadata (optional; can always refresh on demand)
  - created/updated timestamps

## Risks and Constraints

- **Google Cloud project setup**
  - The Google Cloud project behind the OAuth client must have **YouTube Data API v3 enabled**, and the OAuth consent screen must list the requested YouTube scopes for the environment (internal/external).

- **OAuth consent verification requirements**
  - YouTube scopes are considered sensitive; depending on distribution, Google may require app verification. This is operational work outside TAuth code but directly impacts feasibility for public deployments.

- **Token lifecycle edge cases**
  - Google refresh tokens may not be re-issued on every consent; implementations must handle “missing refresh token” scenarios and force re-consent only when necessary (GAuss explicitly handles this).

- **Security posture change**
  - TAuth will become a Google API token custodian (refresh tokens). This increases the blast radius and introduces new requirements for secret handling and storage encryption.

- **Tenant resolution on callback**
  - Callback requests cannot depend on `Origin`; state must carry tenant identity and be cryptographically verified.

## Conclusion

Implementing “wider scopes” in TAuth to retrieve YouTube channel information is feasible and aligns with the direction already implied by planned OAuth provider work (TA-433). It requires adding a Google OAuth2 code flow (offline), per-tenant secrets/scopes configuration, server-side token storage, and a small set of proxy endpoints for YouTube data retrieval. Without these additions, TAuth will remain authentication-only and cannot replace GAuss in YouTube-enabled tools such as Sheet2Tube.

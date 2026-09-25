# GitHub Credentials For Resource Services

A resource service can use the GitHub credential from the user's TAuth login.
The service must verify the user's current GitHub permissions for each repository operation.
TAuth does not grant repository permissions.

## Configuration

Set the tenant's `github_oauth.scopes` to `[read:user, repo, user:email]`.
Set `github_oauth.credential_key` to a private value of exactly 32 bytes.
TAuth uses this key to encrypt provider credentials with AES-256-GCM.
The encrypted record belongs to one tenant and user.
Keep this key across service restarts.

Set `oauth.resources[].github_credentials_key` for each resource that needs provider credentials.
Use a private service key of at least 32 characters with no whitespace.
Give the same key to that resource service. Do not give it to an MCP client.
Each resource has its own key.

An identity-only GitHub tenant uses `[read:user, user:email]` and has no credential key.
A resource credential key requires repository scopes and the encryption key.
An existing user without a stored repository credential must complete GitHub login again.
The OAuth flow redirects that user to GitHub before it issues the resource authorization code.

## Service Request

Send `POST /oauth/github-credentials` with `Content-Type: application/json`.
Use `Authorization: Bearer <resource-service-key>` and this body:

```json
{"subject_token":"<user-resource-access-token>"}
```

TAuth checks the token signature, expiry, audience, tenant, client, scopes, current consent, and active account.
The GitHub identity must match the current credential owner.
A successful response contains `github_id`, `access_token`, `token_type`, and `scope`.
The response prohibits caching. Do not log or return the provider token to the MCP client.

Invalid tokens return `401 invalid_token`. An invalid service key returns `401 invalid_client`.
Revoked consent or account authority returns `403 invalid_grant`.
A missing provider credential returns `403 github_authorization_required`.
Storage failures return `500 server_error`.

## Gateway Configuration

The selected application manifest uses private output references for both keys.
Gateway sends `github-credential-key` and `oauth-resource-<index>-github-credentials-key` as private provider outputs.
The resource index starts at zero. The TAuth renderer resolves these outputs into native configuration values.
Deploy Gateway support, TAuth support, and the resource service configuration together.

The public OAuth client needs no service key or separate repository approval.
GitHub organization restrictions and the user's repository permissions still apply.

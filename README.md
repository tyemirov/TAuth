# TAuth

**Authentication, tenant-isolated accounts, and OAuth authorization for first-party applications.**

TAuth is a self-hosted Go service for web applications, native clients, and protected APIs.
It verifies Google, Apple, GitHub, and password credentials and issues first-party session cookies.
An optional OAuth authorization server issues scoped access tokens for declared resources.

TAuth gives application teams one service for login, session renewal, account recovery, and account removal.
The included browser helper and Go validators provide application integration.
Owners manage Apps and tenants through a web console.

## Capabilities

| Capability | Current contract |
| --- | --- |
| Browser login | Google Identity Services popup, Apple redirect, GitHub redirect or popup, and tenant-managed passwords. |
| Native login | Google system-browser flow with PKCE. Native Apple sign-in on iOS. These paths return TAuth cookies. |
| Application sessions | Short-lived HttpOnly session cookies, rotating refresh cookies, session restoration, and logout. |
| Account lifecycle | Password signup, email verification, recovery, password changes, identity links, display-name changes, disablement, and erasure. |
| Tenant isolation | Separate accounts, provider bindings, origins, keys, cookie names, sessions, and account policies. |
| Owner console | Account → Apps → tenants, automatic configuration updates, integration examples, protected key export, and setup checks. |
| Resource authorization | Authorization code with PKCE `S256`, resource-bound grants, consent, ES256 access tokens, and rotating refresh tokens. |
| Backend integration | Go packages for [session cookies](pkg/sessionvalidator/README.md) and [OAuth access tokens](pkg/oauthvalidator/README.md). |

The console authenticates owners through Google.
Console tenant creation requires a Google Web client ID.
The service also accepts Apple, GitHub-only, and password configurations through its provisioning contract.
Console edits preserve provider settings outside its editable fields.

## How it fits

```text
Browser or native client ── provider identity ──> TAuth ──> tenant database
        │                                         │
        └──────── HttpOnly session cookies <───────┘
        │
        └── authenticated request ──> application API + session validator

OAuth client ── TAuth login + consent + PKCE ──> resource access token
        └── Bearer token ──> resource API + OAuth validator
```

Cookie sessions authenticate users to an application.
OAuth grants authorize a client to request specified permissions on a declared resource.
Applications retain responsibility for their own data, subscriptions, and resource permissions.
Cookie validators must verify the expected tenant as well as the token signature and expiry.

Each account has a fixed, tenant-scoped public user ID.
New accounts receive opaque IDs. Existing persisted IDs remain preserved.
Provider subjects remain separate from application user IDs.
Matching email addresses do not merge accounts.

Accounts and sessions remain tenant-scoped across applications.
Cross-tenant shared identity and single sign-on remain under investigation in P001.

## Try it locally

The local stack requires Docker Engine, Docker Compose, OpenSSL, and curl.
Docker builds the service from this checkout.
The stack includes a persistent SQLite database and a separate static frontend.

1. Clone this repository and open its root directory.
2. For your own Google client, set `TAUTH_LOCAL_GOOGLE_CLIENT_ID` before the first start.
3. Authorize `http://localhost:8081` in that Google client's JavaScript origins.
4. Start the stack:

   ```sh
   make up
   ```

5. Open the console at <http://localhost:8081/app/>.
6. Sign in with Google and create an App.
7. Create a tenant with its name, application origin, and Google Web client ID.
8. Set the customer API origin in Configuration, on the same cookie site as the application frontend.
9. Wait for the valid edit to apply automatically.
10. Open Integration for the browser example and backend settings.

The API is at `http://localhost:8082`.
Both published ports bind to `127.0.0.1`.
The default console client is the public Google client used by the Ledger demo.
Each verified Google user can enroll as an owner.
Valid configuration edits apply automatically to an active tenant.
DNS ownership verification is optional evidence.

The first start creates keys in `.cache/tauth-local/runtime.env` and bootstraps the reserved console tenant.
Later starts retain those keys, the console client ID, and the database.
The [local deployment guide](docs/deployment.md#local-development) explains client replacement and startup checks.

Stop the stack with:

```sh
make down
```

This command retains the database volume and local keys.
The local stack does not start Pingwin for account email flows.

## Integrate an application

- **Browser and Go API:** Follow the [customer application example](examples/tenant-app/README.md).
  It includes Google login, a customer API proxy, cookie validation, refresh, logout, and tenant checks.
  Its frontend and API share a cookie site. The TAuth service can use another site.
- **Custom browser client:** Use the [browser helper guide](docs/usage.md#4-recommended-integration-tauthjs) and [provider procedures](docs/usage.md#5-google-identity-services-flow).
  Configure the helper's explicit API `baseUrl` and the tenant's exact frontend origins.
- **Native client:** Follow the [Google system-browser procedure](docs/usage.md#53-native-installed-app-flow-system-browser--pkce) or [native Apple procedure](docs/usage.md#54-sign-in-with-apple).
  Native login retains cookies in the native cookie jar.
- **OAuth resource client:** Follow [resource authorization](docs/usage.md#56-oauth-resource-authorization) and the [issuer configuration](docs/service-configuration.md#oauth-issuer-and-resource-configuration).
  Protected Go resources use `pkg/oauthvalidator`.

The published browser helper is at `https://tauth.mprlab.com/tauth.js`.
The MPR Lab API is at `https://tauth-api.mprlab.com` and does not serve `/tauth.js`.
Self-hosted integrations must select their own API origin explicitly.

## Operating requirements and limits

- **Runtime:** Use one TAuth service instance with its persistent SQLite or PostgreSQL database.
  Multiple instances require a separate revision-distribution design.
- **Secrets:** Retain the server encryption key with the database across restarts and upgrades.
  Keep tenant session keys in backend secret stores.
  OAuth ES256 keys and tenant HS256 session keys have separate purposes.
- **Transport:** Production credential routes require HTTPS or verified HTTPS forwarding from a configured reverse proxy.
  Local HTTP mode changes cookie attributes.
  Browser cookie rules still apply across origins and sites.
- **Browser:** The helper requires Web Locks in a secure context.
  TAuth session credentials use HttpOnly cookies.
  Google ID tokens pass through the login callback. Non-secret restore hints use `localStorage`.
- **Providers and email:** Configure your own provider clients and permitted origins or callbacks.
  Account management requires Pingwin settings for email challenges.
- **Revocation:** Logout, disablement, and erasure revoke the applicable refresh credentials.
  Offline validators can accept previously issued access tokens until expiry.
  Account removal and provider revocation have separate results. Some Apple cases require manual action.
  Account erasure leaves application data, RevenueCat records, and backups under their respective owners.

The [deployment guide](docs/deployment.md) defines the current production lifecycle:

```sh
make release && make publish && make deploy
```

These repository targets require the installed MPR Lab Gateway and the selected `.mprlab/deploy/resources.yml` manifest.
The guide also covers standalone startup, proxy trust, and database retention.

## Documentation

| Task | Guide |
| --- | --- |
| Configure service, tenants, OAuth keys, or diagnostics | [Service configuration](docs/service-configuration.md) |
| Run locally or deploy | [Deployment](docs/deployment.md) |
| Integrate browser, native, or OAuth clients | [Usage and HTTP endpoints](docs/usage.md) |
| Manage owners, Apps, tenants, provisioning, or session keys | [Console operations](docs/tenant-console-operations.md) |
| Implement display-name changes or account erasure | [Account lifecycle](docs/account-lifecycle.md) |
| Understand password policy, request limits, or refresh coordination | [Authentication limits](docs/authentication-limits.md) |
| Understand stable application IDs | [Application subjects](docs/application-subjects.md) |
| Inspect exact HTTP schemas | [OpenAPI](docs/openapi.yaml) |
| Understand internals | [Architecture](ARCHITECTURE.md) |
| Prepare isolated consumer tests | [Isolated fixtures](docs/test-fixture.md) |

Repository checks use `make ci`.
Routine provider tests use controlled local responses.
Live-provider qualification and deployment require separate evidence.
The [repository policy](.mprlab/POLICY.md) defines contribution and validation requirements.

## License

TAuth is distributed under the [PolyForm Noncommercial License 1.0.0](LICENSE).
The [commercial licensing notice](COMMERCIAL_LICENSE.md) describes separate commercial agreements through <legal@mprlab.com>.
Third-party materials retain their own license terms.

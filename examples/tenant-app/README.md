# Customer application example

This example uses the public `pkg/sessionvalidator` interface and the canonical `tauth.js` helper.
The browser, customer API, and TAuth service have separate origins.
The browser and customer API use HTTPS subdomains of the same cookie site.
For local development, use one localhost hostname with different ports.
The example rejects cross-site frontend and API pairs because its cookies use `SameSite=Lax`.

## Prepare the tenant

1. Open the TAuth workspace at `https://tauth.mprlab.com/app/`.
2. Create a tenant or select an imported tenant.
3. Set the Google Web client ID and exact frontend and API origins.
4. Publish the DNS records shown in Domains.
5. Verify both hostnames and activate the saved revision.
6. Open Integration and save the complete Browser example as `index.html`.
7. Publish that page through GitHub Pages at the configured frontend origin.
8. Complete fresh Google authentication through Export session key.
9. Install the displayed base64 key in the customer backend secret store.
10. Close the export dialog.

The generated page requests a nonce, initializes Google with that nonce, and exchanges the Google credential through the customer API.
Its protected request uses `apiFetch` with the complete API URL.
That helper retries a protected request after session refresh when the first response is `401`.
The generated page contains no session key.

## Start the customer API

Use the released TAuth source version selected for this application.
Set these backend inputs from Integration and the operator's service configuration:

| Input | Value |
| --- | --- |
| `TAUTH_UPSTREAM_ORIGIN` | The TAuth HTTPS service origin, such as `https://tauth-api.mprlab.com`. |
| `TAUTH_API_ORIGIN` | The exact customer API origin from Integration. |
| `TAUTH_FRONTEND_ORIGIN` | One configured frontend origin from Integration. |
| `TAUTH_TENANT_ID` | The explicit tenant ID from Integration. |
| `TAUTH_SESSION_COOKIE` | The session cookie name from Integration. |
| `TAUTH_SESSION_KEY_BASE64` | The exported base64 key, supplied by the backend secret store. |
| `CUSTOMER_API_LISTEN_ADDR` | The internal listener address, such as `127.0.0.1:9090`. |

```sh
make run-tenant-app
```

Terminate HTTPS at the customer API hostname and forward requests to this listener.
Keep that listener private to the HTTPS terminator.
Preserve the browser Origin header.
Enable TAuth CORS and explicit tenant-header selection in service configuration.
The example accepts these proxy routes only:

```text
POST /auth/nonce
POST /auth/google
GET  /auth/session
POST /auth/refresh
POST /auth/logout
GET  /me
```

The proxy sets the configured tenant header and forwarded API host.
It removes upstream cookie domains and sets host-only, HttpOnly cookies.
HTTPS cookies are Secure. The refresh cookie keeps its `/auth` path.
The customer API supplies one exact CORS origin and rejects other origins.
It rejects an incoming tenant header that differs from its configured tenant.

`GET /private` validates the session cookie and compares `claims.TenantID` with `TAUTH_TENANT_ID`.
An application must also apply its own user and resource authorization rules after this check.
For an existing Go backend, install the selected release with this command:

```sh
go get github.com/tyemirov/tauth/pkg/sessionvalidator@"$TAUTH_VERSION"
```

Decode `TAUTH_SESSION_KEY_BASE64` with `base64.StdEncoding.DecodeString` before you call `sessionvalidator.New`.
Use the decoded bytes as `Config.SigningKey` and the generated cookie name as `Config.CookieName`.
Use `ValidateRequest` at the protected route and compare the returned tenant claim.
See [server.go](../../internal/customerapp/server.go) for the complete implementation.

## Verify the application

1. Open the generated page at the configured frontend origin.
2. Complete Google sign-in and select Call protected API.
3. Confirm the protected success message.
4. Select Sign out and confirm that the protected route requires sign-in.
5. Run the setup check in Integration and inspect its revision, time, and evidence.

`make test-console-browser` executes this application flow with real browser cookies and the real Go validator.
The test injects Google, DNS, the setup-check network destination, and the expiry clock.
It also covers refresh, restart, owner isolation, wrong-tenant tokens, denied origins, and cleared exports.
The [operations guide](../../docs/tenant-console-operations.md) defines key replacement, token expiry, and live-provider qualification.

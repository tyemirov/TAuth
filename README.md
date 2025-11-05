# TAuth

*Google Sign-In + JWT sessions for single-origin apps*

TAuth lets product teams accept Google Sign-In, mint their own cookies, and keep browsers free of token storage. Ship a secure authentication stack by pairing this Go service with the tiny `auth-client.js` module.

---

## Why teams choose TAuth

- **Own the session lifecycle** – verify Google once, then rely on short-lived access cookies and rotating refresh tokens.
- **Zero tokens in JavaScript** – the client handles hydration, silent refresh, and logout notifications without touching `localStorage`.
- **Minutes to value** – a single binary with predictable defaults, powered by Gin and Google’s official identity SDK.
- **Designed for growth** – plug in Postgres or SQLite to persist refresh tokens, and extend the web hook points to fit your product.

---

## Deploy TAuth for a hosted product

### 1. Create a Google OAuth Web client

Register the product origin you want to protect (e.g. `https://gravity.mprlab.com`) inside Google Cloud Console and copy the Web Client ID. Add `https://tauth.mprlab.com` as an authorized JavaScript origin so the nonce exchange can run from the hosted service.

### 2. Launch the service (e.g. on `https://tauth.mprlab.com`)

```bash
export APP_LISTEN_ADDR=":8443"                            # or the port your ingress forwards to
export APP_GOOGLE_WEB_CLIENT_ID="your_web_client_id.apps.googleusercontent.com"
export APP_JWT_SIGNING_KEY="$(openssl rand -base64 48)"
export APP_COOKIE_DOMAIN=".mprlab.com"                    # share cookies across tauth + gravity subdomains
export APP_ENABLE_CORS="true"                            # allow the product origin to call TAuth
export APP_CORS_ALLOWED_ORIGINS='["https://gravity.mprlab.com"]'
# Optional persistence (choose one):
# export APP_DATABASE_URL="postgres://user:pass@db.internal:5432/authdb?sslmode=disable"
# export APP_DATABASE_URL="sqlite://file:./auth.db"

tauth --listen_addr=":8443" --google_web_client_id="$APP_GOOGLE_WEB_CLIENT_ID" \
  --jwt_signing_key="$APP_JWT_SIGNING_KEY" --cookie_domain="$APP_COOKIE_DOMAIN" \
  --enable_cors --cors_allowed_origins="https://gravity.mprlab.com"
```

Host the binary behind TLS (or terminate TLS at your load balancer) so responses set `Secure` cookies. With the cookie domain set to `.mprlab.com`, the session cookies issued by `https://tauth.mprlab.com` will also be sent with requests made by `https://gravity.mprlab.com`.

### 3. Integrate the browser helper from the product site

```html
<script src="https://tauth.mprlab.com/static/auth-client.js"></script>
<script>
  initAuthClient({
    baseUrl: "https://tauth.mprlab.com",
    onAuthenticated(profile) {
      renderDashboard(profile);
    },
    onUnauthenticated() {
      showGoogleButton();
    }
  });
</script>

<div id="googleSignIn"></div>
```

### 4. Prepare and exchange Google credentials across origins

```js
let pendingNonce = "";

async function prepareGoogleSignIn() {
  const response = await fetch("https://tauth.mprlab.com/auth/nonce", {
    method: "POST",
    credentials: "include",
    headers: { "X-Requested-With": "XMLHttpRequest" },
  });
  if (!response.ok) {
    throw new Error("nonce request failed");
  }
  const payload = await response.json();
  pendingNonce = payload.nonce;
  google.accounts.id.initialize({
    client_id: "your_web_client_id.apps.googleusercontent.com",
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

async function exchangeGoogleCredential(idTokenFromGoogle) {
  await fetch("https://tauth.mprlab.com/auth/google", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      google_id_token: idTokenFromGoogle,
      nonce_token: pendingNonce,
    }),
  });
}
```

The login flow is identical to a local setup—the only difference is that every call points at the hosted TAuth origin. Because cookies are scoped to `.mprlab.com`, the `app_session` cookie is now available to product routes on `https://gravity.mprlab.com` while remaining `HttpOnly`.

### How to configure Google Identity Services for the popup flow

1. **Load the GIS SDK** on any page that renders a sign-in button:

   ```html
   <script src="https://accounts.google.com/gsi/client" async defer></script>
   ```

2. **Authorise JavaScript origins** (not redirect URIs) in Google Cloud Console. Add both your product origin (e.g. `https://gravity.mprlab.com`) and the TAuth origin (e.g. `https://tauth.mprlab.com`). The popup flow never navigates the browser away from your page, so `/auth/google/callback` does not need to be registered.

3. **Initialize GIS only after you have a nonce** (see `prepareGoogleSignIn` above). The nonce is echoed in the ID credential and TAuth rejects mismatches.

4. **Post the credential to TAuth** while sending cookies: `fetch("https://tauth.mprlab.com/auth/google", { method: "POST", credentials: "include", … })`. The frontend keeps control of the UX; you should never redirect the browser to the TAuth domain.

The example above renders the Google button into `#googleSignIn`; the demo app mirrors the same approach (`web/demo.html`).

That’s it. The client keeps sessions fresh, dispatches events on auth changes, and protects tokens behind `HttpOnly` cookies.

Successful exchanges populate `/me` with a rich profile:

```json
{
  "user_id": "google:12345",
  "user_email": "user@example.com",
  "display": "Example User",
  "avatar_url": "https://lh3.googleusercontent.com/a/AEdFTp7...",
  "roles": ["user"],
  "expires": "2024-05-30T12:34:56.000Z"
}
```

Use the new `avatar_url` field to render signed-in UI chrome (e.g. the shared mpr-ui header component).

---

### Google nonce handling

- TAuth issues one-time nonces via `POST /auth/nonce`. Google does **not** provide a nonce for you.
- Supply the nonce to Google Identity Services via `google.accounts.id.initialize({ nonce })` or the `data-nonce` attribute on the `g_id_onload` element before prompting the user.
- Echo the same nonce back to TAuth as `nonce_token` when exchanging the ID token. Tokens without a matching nonce are rejected (`auth.login.nonce_mismatch`).
- Google Identity Services may hash the nonce inside the ID token (`base64url(sha256(nonce_token))`); TAuth accepts that form automatically, so clients should continue sending the raw nonce they received.
- Fetch a fresh nonce for every sign-in attempt (including retries). TAuth invalidates a nonce as soon as it is consumed.
- The default `auth-client.js` and `mpr-ui` helpers take care of this flow automatically; custom clients must follow the same sequence.

---

## Deploy with confidence

- Works out of the box for any single registrable domain—host TAuth once and share cookies across subdomains.
- Toggle CORS (and `SameSite=None` automatically) when your UI is served from a different origin during development.
- Point `APP_DATABASE_URL` at Postgres or SQLite to store refresh tokens durably.
- Structured zap logging makes it easy to monitor sign-in, refresh, and logout flows wherever you deploy.

---

## Learn more

- Dive into [ARCHITECTURE.md](ARCHITECTURE.md) for endpoints, request flows, and deployment guidance.
- Read [POLICY.md](POLICY.md) for the confident-programming rules enforced across the codebase.
- Inspect `web/auth-client.js` to extend UI hooks or wire additional analytics.
- Validate sessions from other Go services with [`pkg/sessionvalidator`](pkg/sessionvalidator/README.md).

---

## License

MIT (or your preferred license). Add a `LICENSE` file accordingly.

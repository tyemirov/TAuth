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

## Get started

1. **Create a Google OAuth Web client**  
   Add your origin (e.g. `https://app.example.com`) and copy the Client ID.
2. **Launch the server**

```bash
export APP_LISTEN_ADDR=":8080"
export APP_GOOGLE_WEB_CLIENT_ID="your_web_client_id.apps.googleusercontent.com"
export APP_JWT_SIGNING_KEY="$(openssl rand -base64 48)"
export APP_COOKIE_DOMAIN="localhost"
# Optional persistence:
# export APP_DATABASE_URL="postgres://user:pass@localhost:5432/authdb?sslmode=disable"
# export APP_DATABASE_URL="sqlite://file:./auth.db"

go run ./cmd/server
```

3. **Mount the browser helper**

```html
<script src="/static/auth-client.js"></script>
<script>
  initAuthClient({
    onAuthenticated(profile) {
      renderDashboard(profile);
    },
    onUnauthenticated() {
      showGoogleButton();
    }
  });
</script>
```

4. **Request a nonce before prompting Google Identity Services**

```js
let pendingNonce = "";

async function prepareGoogleSignIn() {
  const response = await fetch("/auth/nonce", {
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
  });
  google.accounts.id.prompt();
}
```

Call `prepareGoogleSignIn()` before every login attempt. The nonce is single-use and must be supplied to Google so the ID token echoes it back.

5. **Exchange the Google ID token using the issued nonce**

```js
await fetch("/auth/google", {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    google_id_token: idTokenFromGoogle,
    nonce_token: pendingNonce,
  }),
});
```

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
- Fetch a fresh nonce for every sign-in attempt (including retries). TAuth invalidates a nonce as soon as it is consumed.
- The default `auth-client.js` and `mpr-ui` helpers take care of this flow automatically; custom clients must follow the same sequence.

---

## Deploy with confidence

- Works out of the box for single-origin deployments.
- Toggle CORS and insecure HTTP flags to iterate locally across ports.
- Point `APP_DATABASE_URL` at Postgres or SQLite to store refresh tokens durably.
- Structured zap logging makes it easy to monitor sign-in, refresh, and logout flows.

---

## Learn more

- Dive into [ARCHITECTURE.md](ARCHITECTURE.md) for endpoints, request flows, and deployment guidance.
- Read [POLICY.md](POLICY.md) for the confident-programming rules enforced across the codebase.
- Inspect `web/auth-client.js` to extend UI hooks or wire additional analytics.
- Validate sessions from other Go services with [`pkg/sessionvalidator`](pkg/sessionvalidator/README.md).

---

## License

MIT (or your preferred license). Add a `LICENSE` file accordingly.

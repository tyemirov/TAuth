# Advanced Apple Server Events

Apple server events are optional. Normal Apple login and explicit account deletion do not need this feature.

The single advanced setting is `apple_oauth.notification_audience`.
An absent or empty value disables event processing for that tenant.
A nonempty value must be the exact primary App ID registered for Apple server events.
Use a lowercase dotted application identifier, as the Gateway contract specifies.
TAuth does not infer the value from browser or native client IDs.
Apple group membership and provider registration require separate verification.

Register `/auth/apple/notifications` with Apple only when this feature is necessary.
The endpoint accepts JSON `{"payload":"SIGNED_APPLE_NOTIFICATION"}` without a session cookie.
The route stays registered when the feature is disabled.
If no tenant enables the feature, the endpoint returns `404` before payload processing, provider requests, or database access.
With mixed tenant configurations, an event must select exactly one explicitly enabled audience.
Unmatched or ambiguous audiences return `401` before provider requests or database access.
An enabled event requires the encrypted account store. If this store is unavailable, the endpoint returns `503`.

TAuth verifies the RS256 signature, key ID, Apple issuer, single audience, subject, and event time.
Only `consent-revoked` and `account-deleted` can confirm provider revocation.
Email events cannot complete erasure.
Each event must occur after the operation and each applicable grant generation, measured in whole seconds.
Same-second events keep the operation pending because their order is ambiguous.
Durable receipts prevent repeated events from completing another operation.

Explicit account deletion and outbound Apple token revocation operate independently of this feature.
Local protocol tests do not prove Apple registration or actual provider delivery.

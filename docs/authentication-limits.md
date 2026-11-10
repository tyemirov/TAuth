# Authentication limits

This reference defines HTTP limits, password policy, recovery queues, and refresh coordination.
See the [usage guide](usage.md) for request bodies and client procedures.

Authentication bodies have a 32 KiB limit. OAuth forms retain their 16 KiB limit.
The HTTP server uses a 15-second read limit, a 30-second write limit, and a
60-second idle limit.

Password login permits five attempts per tenant and email address per minute.
It also permits 30 attempts per connection source and 1,000 attempts across the
service per minute. JSON login and OAuth login share these limits. A rejected
login returns HTTP 429. Request budget rejection uses `Retry-After: 60`. Budgets include successful attempts.

New passwords must contain at least 15 Unicode code points in valid UTF-8 and at most 72 bytes.
Signup, reset, change, link, and `HashPassword` use this policy. Authentication verifies current stored bcrypt hashes.

Each failed login delays the next attempt for 1, 2, 4, 8, 16, 32, then 60 seconds.
The delay remains at 60 seconds for later failures and expires after 15 minutes without an admitted attempt.
Parallel valid login requests can receive HTTP 429 while one password verification remains pending.

A successful active-account login clears its own delay reservation. Concurrent requests cannot remove a newer reservation.
JSON and OAuth share this state by tenant and normalized email. `Retry-After` reports the remaining delay, rounded up.

Each store permits at most 10,000 delay records. Request budgets apply before delay admission and bcrypt work.
The minimum follows the [NIST single-factor password length guidance](https://pages.nist.gov/800-63-4/sp800-63b.html#passwordver).

Source identity comes from the connection peer. Deployments behind a proxy share
the proxy source budget. PostgreSQL and SQLite deployments share budgets through
the database. Memory deployments share them within one process.

Password reset permits one request per tenant and email address per minute,
10 per connection source, and 1,000 across the service per minute. Each admitted
recovery job replaces the previous reset challenge for that account. Reset initiation
always returns `202` with `{"status":"accepted"}` after valid input, including
unknown accounts, throttled requests, full queues, storage failures, and delivery errors.

Account lookup, challenge creation, and email delivery run independently of the public response.
Each runtime snapshot permits 256 outstanding recovery jobs, with limits of 8 per source and 64 per tenant.
Repeated pending requests for the same tenant and email share one job. Full or closed queues retain the same public response.

Jobs have a 30-second execution limit. Failed delivery cancels its challenge through a separate cleanup context with a five-second limit.
Retirement and shutdown cancel and join recovery work before the notification client closes.

Rate-limit records expire after one minute and are removed at the next admission.
Their global capacity is 10,000 records. Reset challenges have a global capacity
of 10,000 records. Expired reset challenges are removed during creation.

Pending OAuth authorization requests have a capacity of 1,000 per tenant and
10,000 globally. Creation removes expired requests and returns HTTP 429 when
capacity is full.

Owner credential creation and revocation share the console limit of 60 mutations
per owner per minute. Idempotent replays do not use that budget. Each owner can
retain 1,000 credentials, including revoked credentials, with at most 20 active.

Creation removes credentials revoked more than 30 days ago and their receipts.

Refresh-token rotation consumes a parent and inserts its successor atomically.
Reuse revokes the refresh-token family. Clients must serialize refresh requests, including
session refresh requests.

The bundled client uses Web Locks to coordinate tabs
from the same origin. It requires a secure browser context with Web Locks.

Apple browser login uses a separate host-only, secure
cookie for each transaction. The callback requires this cookie with the signed
state and clears it after validation.

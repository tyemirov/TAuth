# Resolved issues

## Features

- [x] [F004] (P0) Deliver each password challenge email through Pinguin.
  Goal:
  TAuth delivers password reset and password link challenges without returning their tokens to the browser.
  Requirements:
  - Use the injected Pinguin adapter for each password challenge email.
  - Configure one public URL for each challenge type.
  - Deliver a reset link after TAuth creates a password reset challenge.
  - Deliver a link verification URL after TAuth creates a password link challenge.
  - Cancel each challenge when Pinguin rejects its email.
  - Keep challenge tokens out of production HTTP responses.
  Deliverables:
  - Extend the notification adapter, config, server wiring, documentation, and black-box tests.
  Validation:
  - Verify each password challenge sends one email with the correct URL.
  - Verify each HTTP response does not contain a challenge token.
  - Verify signup and password-link delivery errors return an error response.
  - Verify a password-reset delivery error cancels the real challenge and preserves the enumeration-safe accepted response.
  - Run `make ci`.
  Resolution 2026-09-03:
  TAuth now sends verification, reset, and password-link challenges through one Pinguin adapter. Each configured public URL carries its token in a fragment. Production responses contain no challenge tokens. A failed delivery cancels the real challenge. Reset failures keep the enumeration-safe accepted response. Black-box tests cover delivery, token secrecy, and cancellation. `make ci` passed.

  Stack validation 2026-09-04:
  - Merged updated F003 into F004 with a forward-only merge.
  - Preserved password reset and password link config with the I208 renderer fixes.
  - The renderer target and `make ci` passed on the combined source.

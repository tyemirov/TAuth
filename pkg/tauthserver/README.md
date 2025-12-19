# TAuth Server Embed

This package mounts the TAuth auth endpoints (`/auth/*` and `/me`) into an existing Gin router.
It loads the tenant YAML configuration, builds the tenant registry, and registers the same routes
as the standalone TAuth server so applications can embed the auth flow without reimplementing it.

## Usage

1. Load the tenant YAML file used by TAuth.
2. Provide a `UserStore` and `RefreshTokenStore`.
3. Call `Mount` on your router.

For same-origin deployments use the default same-site resolver. For cross-origin use
`CrossOriginSameSiteResolver()` or pass a custom resolver via `WithSameSiteResolver`.

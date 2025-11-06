package webassets

import "embed"

// FS contains embedded web assets from this directory.

//go:embed auth-client.js mpr-sites.js
var FS embed.FS

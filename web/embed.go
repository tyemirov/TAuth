package webassets

import "embed"

// FS contains embedded web assets from this directory.

//go:embed auth-client.js
var FS embed.FS

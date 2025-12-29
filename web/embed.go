package webassets

import "embed"

// FS contains embedded web assets from this directory.

//go:embed tauth.js
var FS embed.FS

package webassets

import "embed"

// FS contains embedded web assets from this directory.

//go:embed auth-client.js
var FS embed.FS

//go:embed mpr-ui.js
var MPRUIFooterJS []byte

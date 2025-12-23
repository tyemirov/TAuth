// Package buildinfo provides build-time metadata.
package buildinfo

// ServiceName identifies the TAuth service.
const ServiceName = "tauth"

// Version is the semantic version injected at build time.
var Version = "dev"

// Commit is the git commit injected at build time.
var Commit = "unknown"

// BuildTime is the build timestamp injected at build time.
var BuildTime = "unknown"

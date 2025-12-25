package authkit

import (
	"path/filepath"
	"testing"
)

func sqliteDatabaseURL(testContext *testing.T) string {
	testContext.Helper()
	databasePath := filepath.Join(testContext.TempDir(), "tauth.db")
	return "sqlite://" + databasePath
}

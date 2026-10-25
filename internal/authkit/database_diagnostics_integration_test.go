package authkit

import (
	"context"
	"database/sql"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func TestDatabaseDiagnosticsPreserveSQLiteJournalMode(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "diagnostics.db")
	databaseURL := "sqlite://" + databasePath
	diagnostic, err := OpenControlDatabase(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := diagnostic.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	mode := func() string {
		t.Helper()
		// Inspect persisted mode through a fresh driver connection. An already
		// open SQLite connection can cache its previous journal-mode value.
		fresh, err := sql.Open("sqlite", databasePath)
		if err != nil {
			t.Fatal(err)
		}
		defer fresh.Close()
		var value string
		if err := fresh.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	if got := mode(); got != "delete" {
		t.Fatalf("diagnostic open changed journal mode: %s", got)
	}
	if _, err := CheckDatabaseConnectivity(ctx, databaseURL); err != nil {
		t.Fatal(err)
	}
	if got := mode(); got != "delete" {
		t.Fatalf("connectivity check changed journal mode: %s", got)
	}
	users, err := NewDatabaseUserStore(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	userPool, err := users.db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { userPool.Close() })
	if got := mode(); got != "wal" {
		t.Fatalf("writable store did not initialize WAL: %s", got)
	}
}

func TestDatabaseWritableSQLiteRejectsConflictingJournalPragmas(t *testing.T) {
	for _, pragma := range []string{"journal_mode(DELETE)", "journal_mode = MEMORY", "main.journal_mode(TRUNCATE)", `"journal_mode"(DELETE)`} {
		t.Run(pragma, func(t *testing.T) {
			databaseURL := "sqlite://" + filepath.Join(t.TempDir(), "journal.db") + "?_pragma=" + url.QueryEscape(pragma)
			if _, err := NewDatabaseUserStore(context.Background(), databaseURL); err == nil || !strings.Contains(err.Error(), "conflicting SQLite journal pragma") {
				t.Fatalf("conflicting journal mode accepted: %v", err)
			}
		})
	}
}

func TestDatabaseReadOnlySQLiteRejectsWritesDuringWALActivity(t *testing.T) {
	ctx := context.Background()
	databaseURL := (&url.URL{Scheme: "sqlite", Path: filepath.Join(t.TempDir(), "read only #fixture.db")}).String()
	users, err := NewDatabaseUserStore(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	writer := users.db.Begin()
	if writer.Error != nil {
		t.Fatal(writer.Error)
	}
	t.Cleanup(func() { writer.Rollback() })
	if err := writer.Exec("CREATE TABLE uncommitted_fixture (id INTEGER)").Error; err != nil {
		t.Fatal(err)
	}
	readOnly, err := OpenControlDatabase(ctx, databaseURL+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := readOnly.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	var count int64
	if err := readOnly.Raw("SELECT count(*) FROM accounts").Scan(&count).Error; err != nil {
		t.Fatal(err)
	}
	if err := writer.Rollback().Error; err != nil {
		t.Fatal(err)
	}
	if err := readOnly.Exec("CREATE TABLE forbidden_write (id INTEGER)").Error; err == nil || !strings.Contains(err.Error(), "readonly") {
		t.Fatalf("read-only database permitted a write: %v", err)
	}
}

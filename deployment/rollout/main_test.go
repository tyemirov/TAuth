package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPersistentServerKeyPreparation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.env")
	if err := writeFile(path, []byte("EXISTING='preserved'\n")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TAUTH_TENANT_ENCRYPTION_KEY", "")
	key, err := prepareKey(path, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatal("wrong key length")
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	again, err := prepareKey(path, encoded, encoded)
	if err != nil || !bytes.Equal(again, key) {
		t.Fatal("key changed", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(content), "TAUTH_TENANT_ENCRYPTION_KEY=") != 1 || !strings.Contains(string(content), "EXISTING='preserved'") {
		t.Fatal("private input overwritten")
	}
	recoveredPath := filepath.Join(t.TempDir(), "private.env")
	if err = writeFile(recoveredPath, nil); err != nil {
		t.Fatal(err)
	}
	recovered, err := prepareKey(recoveredPath, "", encoded)
	if err != nil || !bytes.Equal(recovered, key) {
		t.Fatal("remote key not recovered", err)
	}
	if _, err = prepareKey(path, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), encoded); err == nil {
		t.Fatal("key conflict accepted")
	}
	if _, err = prepareKey(recoveredPath, "", "malformed"); err == nil {
		t.Fatal("invalid recovery key accepted")
	}
	content, err = os.ReadFile(recoveredPath)
	if err != nil || strings.Contains(string(content), "malformed") {
		t.Fatal("invalid recovery key persisted", err)
	}
}

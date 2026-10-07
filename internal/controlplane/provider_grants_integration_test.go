package controlplane_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"path/filepath"
	"testing"

	"github.com/tyemirov/tauth/internal/controlplane"
)

func TestCanonicalProviderGrantCipherBoundary(t *testing.T) {
	databaseURL := "sqlite://" + filepath.Join(t.TempDir(), "provider-grants.db")
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	store, err := controlplane.Open(context.Background(), databaseURL, key)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	binding := `["account_erasure","tenant-a","operation-a","apple"]`
	grant := []byte(`{"subject":"private-parent","audience":"com.example.ios","refresh_token":"private-refresh"}`)
	ciphertext, err := store.SealProviderGrant(binding, grant)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("private-parent")) || bytes.Contains(ciphertext, []byte("private-refresh")) {
		t.Fatal("provider grant was not encrypted")
	}
	recovered, err := store.OpenProviderGrant(binding, ciphertext)
	if err != nil || !bytes.Equal(recovered, grant) {
		t.Fatalf("exact provider binding: %s %v", recovered, err)
	}
	for _, other := range []string{`["account_erasure","tenant-b","operation-a","apple"]`, `["account_erasure","tenant-a","operation-b","apple"]`, `["account_erasure","tenant-a","operation-a","github"]`} {
		if _, err := store.OpenProviderGrant(other, ciphertext); err == nil {
			t.Fatalf("provider ciphertext accepted foreign binding %s", other)
		}
	}
	other, err := controlplane.OpenExisting(context.Background(), databaseURL, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.OpenProviderGrant(binding, ciphertext); err == nil {
		t.Fatal("provider ciphertext accepted another canonical key")
	}
}

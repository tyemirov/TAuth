package oauthserver

import (
	"context"
	"github.com/tyemirov/tauth/internal/authkit"
	"testing"
)

func newTestPasswordResetDispatcher(t *testing.T) *authkit.PasswordResetDispatcher {
	t.Helper()
	dispatcher, err := authkit.NewPasswordResetDispatcher(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dispatcher.Close)
	return dispatcher
}

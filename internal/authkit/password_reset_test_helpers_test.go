package authkit

import (
	"context"
	"testing"
	"time"
)

func newTestPasswordResetDispatcher(t *testing.T) *PasswordResetDispatcher {
	t.Helper()
	dispatcher, err := NewPasswordResetDispatcher(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dispatcher.Close)
	return dispatcher
}

func waitTestPasswordResetIdle(t *testing.T, dispatcher *PasswordResetDispatcher) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		dispatcher.mu.Lock()
		idle := dispatcher.outstanding == 0
		dispatcher.mu.Unlock()
		if idle {
			return
		}
		select {
		case <-deadline:
			t.Fatal("reset worker did not become idle")
		case <-ticker.C:
		}
	}
}

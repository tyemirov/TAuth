package authkit

import (
	"testing"
	"time"
)

type fixedClock struct {
	timestamp time.Time
}

func (clock fixedClock) Now() time.Time {
	return clock.timestamp
}

func TestMintAppJWTRejectsEmptySubject(t *testing.T) {
	t.Parallel()

	_, _, err := MintAppJWT(fixedClock{timestamp: time.Unix(1700000000, 0)}, "", "user@example.com", "User", []string{"user"}, "issuer", []byte("signing-key"), time.Minute)
	if err == nil {
		t.Fatalf("expected error when user ID is empty")
	}

	expected := "jwt.mint.failure: subject must be non-empty"
	if err.Error() != expected {
		t.Fatalf("expected error %q, got %q", expected, err.Error())
	}
}

func TestMintAppJWTCarriesClockTimestamps(t *testing.T) {
	t.Parallel()

	reference := time.Unix(1700000000, 0).UTC()
	token, expiresAt, err := MintAppJWT(fixedClock{timestamp: reference}, "user-123", "user@example.com", "User", []string{"user"}, "issuer", []byte("signing-key"), 2*time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token == "" {
		t.Fatalf("expected signed token")
	}
	expectedExpiry := reference.Add(2 * time.Minute)
	if !expiresAt.Equal(expectedExpiry) {
		t.Fatalf("expected expiry %v, got %v", expectedExpiry, expiresAt)
	}
}

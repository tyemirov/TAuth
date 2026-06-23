package authkit

import (
	"errors"
	"strings"
	"testing"
)

type failingAccountIDRandomSource struct{}

func (source failingAccountIDRandomSource) Read(buffer []byte) (int, error) {
	return 0, errors.New("account_id.random_failed")
}

func TestNewOpaqueAccountIDUsesBase64URL128BitEntropy(testingHandle *testing.T) {
	accountID, accountIDErr := newOpaqueAccountID()
	if accountIDErr != nil {
		testingHandle.Fatalf("failed to generate account id: %v", accountIDErr)
	}
	assertOpaqueAccountID(testingHandle, accountID)
}

func TestNewOpaqueAccountIDReturnsRandomSourceErrors(testingHandle *testing.T) {
	previousRandomSource := accountIDRandomSource
	accountIDRandomSource = failingAccountIDRandomSource{}
	defer func() {
		accountIDRandomSource = previousRandomSource
	}()

	_, accountIDErr := newOpaqueAccountID()
	if accountIDErr == nil || !strings.Contains(accountIDErr.Error(), "account.id.random") {
		testingHandle.Fatalf("expected contextual account id random error, got %v", accountIDErr)
	}
}

func TestValidateOpaqueAccountIDRejectsMalformedValues(testingHandle *testing.T) {
	malformedAccountIDs := []string{
		"",
		" U6fYpCTyBv0qcDKw9d0o2g",
		"U6fYpCTyBv0qcDKw9d0o2g ",
		"email:user@example.com",
		"account:U6fYpCTyBv0qcDKw9d0o2g",
		"short",
		"U6fYpCTyBv0qcDKw9d0o2!",
		"AAAAAAAAAAAAAAAAAAAAAAA",
	}
	for _, accountID := range malformedAccountIDs {
		if validateErr := validateOpaqueAccountID(accountID); !errors.Is(validateErr, ErrAccountInvalidID) {
			testingHandle.Fatalf("expected invalid account id error for %q, got %v", accountID, validateErr)
		}
	}
}

func assertOpaqueAccountID(testingHandle *testing.T, accountID string) string {
	testingHandle.Helper()
	if validateErr := validateOpaqueAccountID(accountID); validateErr != nil {
		testingHandle.Fatalf("expected opaque account id, got %q: %v", accountID, validateErr)
	}
	return accountID
}

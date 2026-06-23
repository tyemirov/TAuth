package authkit

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const (
	accountIDOpaqueByteLength    = 16
	accountIDOpaqueStringLength  = 22
	accountIDGenerationAttempts  = 8
	accountIDMigrationRecordName = "user_store.opaque_account_ids"
	accountIDMigrationVersion    = 2
)

var (
	ErrAccountInvalidID             = errors.New("account.invalid_id")
	accountIDRandomSource io.Reader = rand.Reader
)

func newOpaqueAccountID() (string, error) {
	opaqueValue, _, randomErr := generateOpaqueToken(accountIDRandomSource, accountIDOpaqueByteLength, "account.id")
	if randomErr != nil {
		return "", randomErr
	}
	return opaqueValue, nil
}

func validateOpaqueAccountID(rawAccountID string) error {
	if len(rawAccountID) != accountIDOpaqueStringLength {
		return fmt.Errorf("%w: length", ErrAccountInvalidID)
	}
	decodedValue, decodeErr := base64.RawURLEncoding.DecodeString(rawAccountID)
	if decodeErr != nil {
		return fmt.Errorf("%w: base64url", ErrAccountInvalidID)
	}
	if len(decodedValue) != accountIDOpaqueByteLength {
		return fmt.Errorf("%w: entropy", ErrAccountInvalidID)
	}
	if base64.RawURLEncoding.EncodeToString(decodedValue) != rawAccountID {
		return fmt.Errorf("%w: canonical", ErrAccountInvalidID)
	}
	return nil
}

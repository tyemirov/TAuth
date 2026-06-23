package authkit

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	accountIDPrefix              = "account:"
	accountIDOpaqueByteLength    = 16
	accountIDOpaqueStringLength  = 22
	accountIDGenerationAttempts  = 8
	accountIDMigrationRecordName = "user_store.opaque_account_ids"
	accountIDMigrationVersion    = 1
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
	return accountIDPrefix + opaqueValue, nil
}

func validateOpaqueAccountID(rawAccountID string) error {
	if rawAccountID != strings.TrimSpace(rawAccountID) {
		return fmt.Errorf("%w: whitespace", ErrAccountInvalidID)
	}
	if !strings.HasPrefix(rawAccountID, accountIDPrefix) {
		return fmt.Errorf("%w: missing_prefix", ErrAccountInvalidID)
	}
	encodedValue := strings.TrimPrefix(rawAccountID, accountIDPrefix)
	if len(encodedValue) != accountIDOpaqueStringLength {
		return fmt.Errorf("%w: length", ErrAccountInvalidID)
	}
	decodedValue, decodeErr := base64.RawURLEncoding.DecodeString(encodedValue)
	if decodeErr != nil {
		return fmt.Errorf("%w: base64url", ErrAccountInvalidID)
	}
	if len(decodedValue) != accountIDOpaqueByteLength {
		return fmt.Errorf("%w: entropy", ErrAccountInvalidID)
	}
	if base64.RawURLEncoding.EncodeToString(decodedValue) != encodedValue {
		return fmt.Errorf("%w: canonical", ErrAccountInvalidID)
	}
	return nil
}

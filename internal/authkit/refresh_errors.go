package authkit

import "errors"

var (
	// ErrRefreshTokenNotFound indicates no refresh token matched the provided identifier.
	ErrRefreshTokenNotFound = errors.New("refresh_store.not_found")
	// ErrRefreshTokenRevoked indicates the refresh token has been revoked.
	ErrRefreshTokenRevoked = errors.New("refresh_store.revoked")
	// ErrRefreshTokenExpired indicates the refresh token has exceeded its expiry.
	ErrRefreshTokenExpired = errors.New("refresh_store.expired")
	// ErrRefreshTokenAlreadyRevoked signals an idempotent revoke call on an already-revoked token.
	ErrRefreshTokenAlreadyRevoked = errors.New("refresh_store.already_revoked")
	// ErrRefreshTokenEmptyOpaque indicates that the provided opaque token text is empty.
	ErrRefreshTokenEmptyOpaque = errors.New("refresh_store.empty_token")
)

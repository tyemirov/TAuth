package authkitpg

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresRefreshTokenStore persists rotating refresh tokens in PostgreSQL.
type PostgresRefreshTokenStore struct {
	pool *pgxpool.Pool
}

// NewPostgresRefreshTokenStore constructs a Postgres store.
func NewPostgresRefreshTokenStore(pool *pgxpool.Pool) *PostgresRefreshTokenStore {
	return &PostgresRefreshTokenStore{pool: pool}
}

// Issue inserts a new token row and returns token id and opaque token.
func (store *PostgresRefreshTokenStore) Issue(ctx context.Context, applicationUserID string, expiresUnix int64, previousTokenID string) (string, string, error) {
	tokenID := store.newTokenID()
	opaque, hashValue, err := store.randomOpaque()
	if err != nil {
		return "", "", err
	}
	_, execErr := store.pool.Exec(ctx, `
INSERT INTO refresh_tokens (token_id, user_id, token_hash, expires_unix, revoked_at_unix, previous_token_id, issued_at_unix)
VALUES ($1, $2, $3, $4, 0, $5, $6)
`, tokenID, applicationUserID, hashValue, expiresUnix, previousTokenID, time.Now().UTC().Unix())
	if execErr != nil {
		return "", "", execErr
	}
	return tokenID, opaque, nil
}

// Validate checks the opaque token and returns user, token id, and expiry.
func (store *PostgresRefreshTokenStore) Validate(ctx context.Context, tokenOpaque string) (string, string, int64, error) {
	if tokenOpaque == "" {
		return "", "", 0, errors.New("empty")
	}
	hashValue := store.hash(tokenOpaque)
	var applicationUserID string
	var tokenID string
	var expiresUnix int64
	var revokedAt int64
	row := store.pool.QueryRow(ctx, `
SELECT user_id, token_id, expires_unix, revoked_at_unix
FROM refresh_tokens
WHERE token_hash = $1
`, hashValue)
	if scanErr := row.Scan(&applicationUserID, &tokenID, &expiresUnix, &revokedAt); scanErr != nil {
		return "", "", 0, scanErr
	}
	if revokedAt != 0 {
		return "", "", 0, errors.New("revoked")
	}
	if time.Unix(expiresUnix, 0).Before(time.Now().UTC()) {
		return "", "", 0, errors.New("expired")
	}
	return applicationUserID, tokenID, expiresUnix, nil
}

// Revoke marks a token as revoked.
func (store *PostgresRefreshTokenStore) Revoke(ctx context.Context, tokenID string) error {
	_, err := store.pool.Exec(ctx, `
UPDATE refresh_tokens
SET revoked_at_unix = $1
WHERE token_id = $2 AND revoked_at_unix = 0
`, time.Now().UTC().Unix(), tokenID)
	return err
}

func (store *PostgresRefreshTokenStore) newTokenID() string {
	nowString := time.Now().UTC().Format(time.RFC3339Nano)
	return base64.RawURLEncoding.EncodeToString([]byte(nowString))
}

func (store *PostgresRefreshTokenStore) randomOpaque() (string, string, error) {
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", err
	}
	opaque := base64.RawURLEncoding.EncodeToString(randomBytes)
	return opaque, store.hash(opaque), nil
}

func (store *PostgresRefreshTokenStore) hash(opaque string) string {
	sum := sha256.Sum256([]byte(opaque))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

package authkitpg

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureSchema creates tables if they do not exist.
func EnsureSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_unix BIGINT NOT NULL,
    revoked_at_unix BIGINT NOT NULL DEFAULT 0,
    previous_token_id TEXT NOT NULL DEFAULT '',
    issued_at_unix BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens (token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens (user_id);
`)
	return err
}

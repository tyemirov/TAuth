package authkitpg

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// BuildPool creates a pgx pool with sane defaults.
func BuildPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	config.MinConns = 1
	config.MaxConns = 8
	config.MaxConnLifetime = 30 * time.Minute
	config.HealthCheckPeriod = 30 * time.Second
	return pgxpool.NewWithConfig(ctx, config)
}

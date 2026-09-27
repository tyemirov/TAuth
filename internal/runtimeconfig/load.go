package runtimeconfig

import (
	"context"
	"fmt"

	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/controlplane"
	"github.com/tyemirov/tauth/internal/tenants"
)

// Load reads active tenant revisions without database or schema changes.
func Load(ctx context.Context, config *appconfig.ApplicationConfig) (tenants.Config, error) {
	store, err := controlplane.OpenExisting(ctx, config.Server.DatabaseURL, config.Server.TenantEncryptionKey)
	if err != nil {
		return tenants.Config{}, err
	}
	document, err := store.RuntimeTenants(ctx)
	closeErr := store.Close()
	if err != nil {
		return tenants.Config{}, err
	}
	if closeErr != nil {
		return tenants.Config{}, fmt.Errorf("runtime_config.close: %w", closeErr)
	}
	return document, nil
}

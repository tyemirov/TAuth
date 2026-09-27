package controlplane

import (
	"context"
	"fmt"
	"strings"

	"gorm.io/gorm"
)

// These tables use composite references so revisions and secrets cannot cross tenants.
var tenantSchema = []string{
	`CREATE TABLE IF NOT EXISTS provisioning_credentials (
 id TEXT PRIMARY KEY, owner_account_id TEXT NOT NULL REFERENCES owner_accounts(id), name TEXT NOT NULL,
 operations TEXT NOT NULL, tenant_ids TEXT NOT NULL, allow_create BOOLEAN NOT NULL,
 digest TEXT NOT NULL UNIQUE, created_at TIMESTAMP NOT NULL, revoked_at TIMESTAMP)`,

	`CREATE TABLE IF NOT EXISTS management_receipts (
 owner_account_id TEXT NOT NULL REFERENCES owner_accounts(id), path TEXT NOT NULL, key TEXT NOT NULL,
 digest TEXT NOT NULL, response TEXT NOT NULL, status BIGINT NOT NULL, location TEXT NOT NULL,
 PRIMARY KEY(owner_account_id,path,key))`,
	`CREATE TABLE IF NOT EXISTS tenants (
		id TEXT PRIMARY KEY, owner_account_id TEXT NOT NULL REFERENCES owner_accounts(id) ON DELETE RESTRICT,
		name TEXT NOT NULL, environment TEXT NOT NULL DEFAULT '', version BIGINT NOT NULL DEFAULT 1, state TEXT NOT NULL CHECK(state IN ('draft','active','suspended')),
		active_revision BIGINT, suspension_pending BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		CHECK(state != 'active' OR active_revision IS NOT NULL),
		FOREIGN KEY(id,active_revision) REFERENCES tenant_configurations(tenant_id,revision) DEFERRABLE INITIALLY DEFERRED
	)`,
	`CREATE TABLE IF NOT EXISTS tenant_configurations (
		tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
		revision BIGINT NOT NULL CHECK(revision > 0), configuration TEXT NOT NULL,
		api_base_url TEXT NOT NULL DEFAULT '', local_development BOOLEAN NOT NULL DEFAULT FALSE, operator_integration BOOLEAN NOT NULL DEFAULT FALSE,
		PRIMARY KEY(tenant_id,revision)
	)`,
	`CREATE TABLE IF NOT EXISTS tenant_secrets (
		id TEXT NOT NULL, tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
		purpose TEXT NOT NULL, encrypted_value BYTEA NOT NULL, encryption_key_id TEXT NOT NULL,
		PRIMARY KEY(tenant_id,id)
	)`,
	`CREATE TABLE IF NOT EXISTS tenant_origins (
		tenant_id TEXT NOT NULL, revision BIGINT NOT NULL, origin TEXT NOT NULL, provenance TEXT NOT NULL,
		PRIMARY KEY(tenant_id,revision,origin),
		FOREIGN KEY(tenant_id,revision) REFERENCES tenant_configurations(tenant_id,revision) ON DELETE RESTRICT
	)`,
	`CREATE TABLE IF NOT EXISTS tenant_providers (
		tenant_id TEXT NOT NULL, revision BIGINT NOT NULL, provider_type TEXT NOT NULL,
		public_settings TEXT NOT NULL, secret_id TEXT,
		PRIMARY KEY(tenant_id,revision,provider_type),
		FOREIGN KEY(tenant_id,revision) REFERENCES tenant_configurations(tenant_id,revision) ON DELETE RESTRICT,
		FOREIGN KEY(tenant_id,secret_id) REFERENCES tenant_secrets(tenant_id,id) ON DELETE RESTRICT
	)`,
	`CREATE TABLE IF NOT EXISTS tenant_imports (
		id TEXT PRIMARY KEY, source_digest TEXT NOT NULL UNIQUE,
		owner_account_id TEXT NOT NULL REFERENCES owner_accounts(id) ON DELETE RESTRICT,
		tenant_ids TEXT NOT NULL, completed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS tenant_audit_events (
		id TEXT PRIMARY KEY, actor_account_id TEXT NOT NULL REFERENCES owner_accounts(id) ON DELETE RESTRICT,
		tenant_id TEXT REFERENCES tenants(id) ON DELETE RESTRICT, operation TEXT NOT NULL,
		revision BIGINT, result TEXT NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS tenant_origin_proofs (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, revision BIGINT NOT NULL, hostname TEXT NOT NULL,
 name TEXT NOT NULL, value TEXT NOT NULL, state TEXT NOT NULL, expires_at TIMESTAMP NOT NULL,
 verified_at TIMESTAMP, FOREIGN KEY(tenant_id,revision) REFERENCES tenant_configurations(tenant_id,revision))`,
	`CREATE TABLE IF NOT EXISTS tenant_origin_verifications (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), proof_id TEXT NOT NULL REFERENCES tenant_origin_proofs(id),
 state TEXT NOT NULL, created_at TIMESTAMP NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS tenant_activations (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, revision BIGINT NOT NULL,
 state TEXT NOT NULL, error_code TEXT NOT NULL, created_at TIMESTAMP NOT NULL,
 FOREIGN KEY(tenant_id,revision) REFERENCES tenant_configurations(tenant_id,revision))`,
	`CREATE TABLE IF NOT EXISTS provisioning_bindings (
 tenant_id TEXT PRIMARY KEY REFERENCES tenants(id), contribution_owner TEXT NOT NULL, contribution_id TEXT NOT NULL,
 generation BIGINT NOT NULL, revision BIGINT NOT NULL, digest TEXT NOT NULL,
 UNIQUE(contribution_owner,contribution_id))`,
	`CREATE TABLE IF NOT EXISTS tenant_reauthentications (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, owner_account_id TEXT NOT NULL REFERENCES owner_accounts(id),
 revision BIGINT NOT NULL, operation TEXT NOT NULL CHECK(operation = 'session-key-export'), nonce TEXT NOT NULL UNIQUE,
 created_at TIMESTAMP NOT NULL, expires_at TIMESTAMP NOT NULL, consumed_at TIMESTAMP,
 FOREIGN KEY(tenant_id,revision) REFERENCES tenant_configurations(tenant_id,revision))`,
	`CREATE TABLE IF NOT EXISTS tenant_key_exports (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, owner_account_id TEXT NOT NULL REFERENCES owner_accounts(id),
 reauthentication_id TEXT NOT NULL UNIQUE REFERENCES tenant_reauthentications(id), revision BIGINT NOT NULL, created_at TIMESTAMP NOT NULL,
 FOREIGN KEY(tenant_id,revision) REFERENCES tenant_configurations(tenant_id,revision))`,
	`CREATE TABLE IF NOT EXISTS tenant_setup_checks (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, revision BIGINT NOT NULL, state TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL, evidence TEXT NOT NULL,
 FOREIGN KEY(tenant_id,revision) REFERENCES tenant_configurations(tenant_id,revision))`,
}

func initializeTenantSchema(ctx context.Context, db *gorm.DB) error {
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, statement := range tenantSchema {
			if tx.Dialector.Name() == "postgres" {
				statement = strings.Replace(statement, ",\n\t\tFOREIGN KEY(id,active_revision) REFERENCES tenant_configurations(tenant_id,revision) DEFERRABLE INITIALLY DEFERRED", "", 1)
			}
			if err := tx.Exec(statement).Error; err != nil {
				return fmt.Errorf("management.initialize_tenant_schema: %w", err)
			}
		}
		if tx.Dialector.Name() == "postgres" {
			if err := tx.Exec(`DO $$ BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'tenants'::regclass AND conname = 'tenant_active_revision') THEN
			ALTER TABLE tenants ADD CONSTRAINT tenant_active_revision FOREIGN KEY(id,active_revision)
			REFERENCES tenant_configurations(tenant_id,revision) DEFERRABLE INITIALLY DEFERRED;
			END IF; END $$`).Error; err != nil {
				return fmt.Errorf("management.active_revision_constraint: %w", err)
			}
		}
		return nil
	})
}

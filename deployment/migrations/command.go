package migrations

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/tenants"
)

// NewCommand constructs the separate deployment migration entry point.
func NewCommand() *cobra.Command {
	var sourcePath, snapshotPath, importID, ownerID, configPath string
	var inspect bool
	command := &cobra.Command{Use: "tenant-ownership", Short: "Import effective tenant configuration under an explicitly selected owner", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		config, err := appconfig.LoadConfig(configPath)
		if err != nil {
			return err
		}
		var document tenants.FileDocument
		if snapshotPath != "" {
			file, err := os.Open(snapshotPath)
			if err != nil {
				return err
			}
			defer file.Close()
			decoder := json.NewDecoder(file)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&document); err != nil {
				return fmt.Errorf("migration.read_snapshot: %w", err)
			}
		} else {
			source, err := appconfig.LoadImportSource(sourcePath)
			if err != nil {
				return err
			}
			document, err = tenants.ResolveDocument(source.TenantDocument())
			if err != nil {
				return err
			}
		}
		tenantConfig, err := tenants.LoadResolvedConfig(document)
		if err != nil {
			return err
		}
		if err := appconfig.ValidateOAuthActivation(config.OAuthServer(), tenantConfig); err != nil {
			return err
		}
		if inspect {
			type tenantSummary struct {
				ID          string   `json:"id"`
				Providers   []string `json:"providers"`
				OriginCount int      `json:"origin_count"`
			}
			inventory := make([]tenantSummary, 0, len(document.Tenants))
			for _, tenant := range document.Tenants {
				providers := []string{}
				if tenant.GoogleWebClientID != "" || tenant.GoogleNativeClientID != "" || len(tenant.GoogleNativeClients) > 0 {
					providers = append(providers, "google")
				}
				if tenant.AppleOAuth.Enabled {
					providers = append(providers, "apple")
				}
				if tenant.GitHubOAuth.Enabled {
					providers = append(providers, "github")
				}
				if tenant.PasswordAuth.Enabled {
					providers = append(providers, "password")
				}
				inventory = append(inventory, tenantSummary{ID: tenant.ID, Providers: providers, OriginCount: len(tenant.TenantOrigins)})
			}
			if err := json.NewEncoder(command.OutOrStdout()).Encode(inventory); err != nil {
				return fmt.Errorf("tenant_import.write_inventory: %w", err)
			}
			return nil
		}
		receipt, err := Apply(command.Context(), config.Server.DatabaseURL, config.Server.TenantEncryptionKey, importID, ownerID, document)
		if err != nil {
			return err
		}
		if err := json.NewEncoder(command.OutOrStdout()).Encode(receipt); err != nil {
			return fmt.Errorf("tenant_import.write_receipt: %w", err)
		}
		return nil
	}}
	command.PersistentFlags().StringVar(&configPath, "config", "", "Service configuration for the deployment database")
	command.Flags().StringVar(&sourcePath, "source", "", "Effective tenant YAML source")
	command.Flags().StringVar(&snapshotPath, "snapshot", "", "Frozen effective JSON source without environment substitution")
	command.MarkFlagsMutuallyExclusive("source", "snapshot")
	command.Flags().StringVar(&ownerID, "owner-id", "", "Destination owner account ID")
	command.Flags().StringVar(&importID, "import-id", "", "Stable import identifier")
	command.Flags().BoolVar(&inspect, "inspect", false, "Validate source and print a secret-free inventory")
	var repairSnapshot, repairImportID, repairID, repairOwnerID string
	repair := &cobra.Command{Use: "repair-import", Short: "Apply corrected isolation settings to an inactive deployment import", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		config, err := appconfig.LoadConfig(configPath)
		if err != nil {
			return err
		}
		file, err := os.Open(repairSnapshot)
		if err != nil {
			return err
		}
		defer file.Close()
		var document tenants.FileDocument
		decoder := json.NewDecoder(file)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&document); err != nil {
			return err
		}
		tenantConfig, err := tenants.LoadResolvedConfig(document)
		if err != nil {
			return err
		}
		if err := appconfig.ValidateOAuthActivation(config.OAuthServer(), tenantConfig); err != nil {
			return err
		}
		receipt, err := RepairImport(command.Context(), config.Server.DatabaseURL, config.Server.TenantEncryptionKey, repairImportID, repairID, repairOwnerID, document)
		if err != nil {
			return err
		}
		return json.NewEncoder(command.OutOrStdout()).Encode(receipt)
	}}
	repair.Flags().StringVar(&repairSnapshot, "snapshot", "", "Corrected effective JSON configuration")
	repair.Flags().StringVar(&repairImportID, "import-id", "", "Original inactive import identifier")
	repair.Flags().StringVar(&repairID, "repair-id", "", "Stable repair identifier")
	repair.Flags().StringVar(&repairOwnerID, "owner-id", "", "Existing destination owner account ID")
	command.AddCommand(repair)
	command.AddCommand(&cobra.Command{Use: "cleanup-schema", Short: "Remove the obsolete first-owner schema during deployment", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		config, err := appconfig.LoadConfig(configPath)
		if err != nil {
			return err
		}
		return RemoveInitialOwner(command.Context(), config.Server.DatabaseURL)
	}})
	var freezePath string
	freeze := &cobra.Command{Use: "freeze-source", Short: "Write effective tenant JSON to a private migration snapshot", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		source, err := appconfig.LoadImportSource(freezePath)
		if err != nil {
			return err
		}
		document, err := tenants.ResolveDocument(source.TenantDocument())
		if err != nil {
			return err
		}
		if err := json.NewEncoder(command.OutOrStdout()).Encode(document); err != nil {
			return fmt.Errorf("migration.write_snapshot: %w", err)
		}
		return nil
	}}
	freeze.Flags().StringVar(&freezePath, "source", "", "Tenant YAML source with environment inputs")
	command.AddCommand(freeze)
	return command
}

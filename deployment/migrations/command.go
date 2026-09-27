package migrations

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/tenants"
)

// NewCommand constructs the separate deployment migration entry point.
func NewCommand() *cobra.Command {
	var sourcePath, importID, ownerID, configPath string
	var inspect bool
	command := &cobra.Command{Use: "tenant-ownership", Short: "Import effective tenant configuration under an explicitly selected owner", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		config, err := appconfig.LoadConfig(configPath)
		if err != nil {
			return err
		}
		source, err := appconfig.LoadImportSource(sourcePath)
		if err != nil {
			return err
		}
		document, err := tenants.ResolveDocument(source.TenantDocument())
		if err != nil {
			return err
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
	command.Flags().StringVar(&ownerID, "owner-id", "", "Destination owner account ID")
	command.Flags().StringVar(&importID, "import-id", "", "Stable import identifier")
	command.Flags().BoolVar(&inspect, "inspect", false, "Validate source and print a secret-free inventory")
	command.AddCommand(&cobra.Command{Use: "cleanup-schema", Short: "Remove the obsolete first-owner schema during deployment", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		config, err := appconfig.LoadConfig(configPath)
		if err != nil {
			return err
		}
		return RemoveInitialOwner(command.Context(), config.Server.DatabaseURL)
	}})
	return command
}

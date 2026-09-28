package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/controlplane"
)

func newConsoleGoogleClientReplaceCommand() *cobra.Command {
	var expected, replacement string
	command := &cobra.Command{
		Use:   "console-google-client-replace",
		Short: "Replace the console Google client while the service is stopped",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			path, err := resolveConfigPath(command)
			if err != nil {
				return err
			}
			config, err := appconfig.LoadConfig(path)
			if err != nil {
				return err
			}
			store, err := controlplane.OpenExisting(command.Context(), config.Server.DatabaseURL, config.Server.TenantEncryptionKey)
			if err != nil {
				return err
			}
			defer store.Close()
			if err := store.ReplaceConsoleGoogleClient(command.Context(), expected, replacement); err != nil {
				return err
			}
			receipt := struct {
				TenantID string `json:"console_tenant_id"`
				ClientID string `json:"google_web_client_id"`
			}{controlplane.ConsoleTenantID, replacement}
			if err := json.NewEncoder(command.OutOrStdout()).Encode(receipt); err != nil {
				return fmt.Errorf("console_client.write_receipt: %w", err)
			}
			return nil
		},
	}
	command.Flags().StringVar(&expected, "expected-client-id", "", "Current persisted Google client ID")
	command.Flags().StringVar(&replacement, "client-id", "", "Replacement Google Web client ID")
	return command
}

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/controlplane"
	"github.com/tyemirov/tauth/internal/tenants"
	"gopkg.in/yaml.v3"
)

func newConsoleBootstrapCommand() *cobra.Command {
	var tenantFile string
	command := &cobra.Command{Use: "console-bootstrap", Short: "Create the reserved console tenant", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		configPath, err := resolveConfigPath(command)
		if err != nil {
			return err
		}
		config, err := appconfig.LoadConfig(configPath)
		if err != nil {
			return err
		}
		file, err := os.Open(tenantFile)
		if err != nil {
			return fmt.Errorf("console.bootstrap.read: %w", err)
		}
		defer file.Close()
		var tenant tenants.FileTenant
		decoder := yaml.NewDecoder(file)
		decoder.KnownFields(true)
		if err := decoder.Decode(&tenant); err != nil {
			return fmt.Errorf("console.bootstrap.decode: %w", err)
		}
		store, err := controlplane.Open(command.Context(), config.Server.DatabaseURL, config.Server.TenantEncryptionKey)
		if err != nil {
			return err
		}
		defer store.Close()
		if err := store.Bootstrap(command.Context(), tenant); err != nil {
			return err
		}
		_, err = fmt.Fprintln(command.OutOrStdout(), `{"console_tenant_id":"tauth-console","state":"ready"}`)
		return err
	}}
	command.Flags().StringVar(&tenantFile, "tenant-file", "", "Console tenant configuration file")
	return command
}

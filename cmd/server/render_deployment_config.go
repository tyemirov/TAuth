package main

import (
	"fmt"
	"github.com/tyemirov/tauth/internal/appconfig"

	"github.com/spf13/cobra"
	"github.com/tyemirov/tauth/internal/deploymentconfig"
)

func newRenderDeploymentConfigCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "render-deployment-config",
		Short: "Render validated native config from deployment contributions",
		Args:  cobra.NoArgs,
		RunE:  runRenderDeploymentConfig,
	}
}

func runRenderDeploymentConfig(command *cobra.Command, arguments []string) error {
	payload, renderErr := deploymentconfig.Render(command.InOrStdin())
	if renderErr != nil {
		return renderErr
	}
	if _, writeErr := command.OutOrStdout().Write(payload); writeErr != nil {
		return fmt.Errorf("deployment_config.write_output: %w", writeErr)
	}
	return nil
}

func newValidateServiceConfigCommand() *cobra.Command {
	return &cobra.Command{Use: "validate-service-config FILE", Short: "Validate service settings without opening the control database", Args: cobra.ExactArgs(1), RunE: func(command *cobra.Command, arguments []string) error {
		if _, err := appconfig.LoadConfig(arguments[0]); err != nil {
			return err
		}
		_, err := fmt.Fprintln(command.OutOrStdout(), `{"valid":true,"contract":"service-configuration"}`)
		return err
	}}
}

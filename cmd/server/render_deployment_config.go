package main

import (
	"fmt"

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

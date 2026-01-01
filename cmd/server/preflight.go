package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/tyemirov/tauth/internal/preflight"
)

const preflightOutputIncludeOriginsFlag = "include-origins"

func newPreflightCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "preflight",
		Short: "Validate configuration and emit a redacted effective-config report",
		RunE:  runPreflight,
	}
	command.Flags().Bool(preflightOutputIncludeOriginsFlag, false, "Include tenant_origins in output (default redacts origins)")
	return command
}

func runPreflight(command *cobra.Command, arguments []string) error {
	configPath, pathErr := resolveConfigPath(command)
	if pathErr != nil {
		return pathErr
	}
	includeOrigins, includeErr := command.Flags().GetBool(preflightOutputIncludeOriginsFlag)
	if includeErr != nil {
		return includeErr
	}
	var reportBytes []byte
	var reportErr error
	if includeOrigins {
		reportBytes, reportErr = preflight.BuildFullReport(configPath)
	} else {
		reportBytes, reportErr = preflight.BuildRedactedReport(configPath)
	}
	if reportErr != nil {
		return reportErr
	}
	if _, writeErr := command.OutOrStdout().Write(reportBytes); writeErr != nil {
		return fmt.Errorf("preflight.write_output: %w", writeErr)
	}
	return nil
}

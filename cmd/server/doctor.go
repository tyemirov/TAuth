package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/tyemirov/tauth/internal/doctor"
)

const (
	doctorFlagCrossValidate = "cross-validate"
	doctorFlagCheckDatabase = "check-database"
	doctorFlagOutputJSON    = "json"
)

func newDoctorCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "doctor [config-paths...]",
		Short: "Validate TAuth configurations and report issues",
		Long: `Validate one or more TAuth configuration files and report any issues.

The doctor command performs comprehensive validation including:
- Configuration file syntax and structure
- Tenant configuration requirements (TTLs, signing keys, origins)
- CORS origin alignment with tenant origins
- Cookie scope isolation across tenants
- Optional database connectivity check
- Cross-config validation (when multiple configs are provided)

Examples:
  tauth doctor config.yaml
  tauth doctor config.yaml other-config.yaml --cross-validate
  tauth doctor ./configs/*.yaml --json`,
		Args: cobra.MinimumNArgs(1),
		RunE: runDoctor,
	}

	command.Flags().Bool(doctorFlagCrossValidate, false, "Validate cross-config consistency (signing keys, origins, cookie names)")
	command.Flags().Bool(doctorFlagCheckDatabase, false, "Verify database connectivity for configured database URLs")
	command.Flags().Bool(doctorFlagOutputJSON, false, "Output results as JSON instead of human-readable summary")

	return command
}

func runDoctor(command *cobra.Command, arguments []string) error {
	crossValidate, crossErr := command.Flags().GetBool(doctorFlagCrossValidate)
	if crossErr != nil {
		return crossErr
	}
	checkDatabase, dbErr := command.Flags().GetBool(doctorFlagCheckDatabase)
	if dbErr != nil {
		return dbErr
	}
	outputJSON, jsonErr := command.Flags().GetBool(doctorFlagOutputJSON)
	if jsonErr != nil {
		return jsonErr
	}

	options := doctor.Options{
		ConfigPaths:          arguments,
		ValidateCrossConfigs: crossValidate,
		CheckDatabaseStore:   checkDatabase,
	}

	report, runErr := doctor.Run(context.Background(), options)
	if runErr != nil {
		return runErr
	}

	var output []byte
	if outputJSON {
		formatted, formatErr := doctor.FormatReport(report)
		if formatErr != nil {
			return fmt.Errorf("doctor.format_json: %w", formatErr)
		}
		output = formatted
	} else {
		output = []byte(doctor.FormatSummary(report))
	}

	if _, writeErr := command.OutOrStdout().Write(output); writeErr != nil {
		return fmt.Errorf("doctor.write_output: %w", writeErr)
	}

	if report.Summary.InvalidConfigs > 0 || len(report.CrossValidation.Errors) > 0 {
		return fmt.Errorf("doctor: validation failed (%d invalid configs, %d cross-config errors)",
			report.Summary.InvalidConfigs, len(report.CrossValidation.Errors))
	}

	return nil
}

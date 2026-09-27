package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/controlplane"
)

func newTenantKeyReplaceCommand() *cobra.Command {
	var owner, id string
	var revision int64
	command := &cobra.Command{Use: "tenant-key-replace", Short: "Create a session-key draft for a suspended tenant; read base64 key from stdin", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		path, err := resolveConfigPath(command)
		if err != nil {
			return err
		}
		config, err := appconfig.LoadConfig(path)
		if err != nil {
			return err
		}
		input, err := io.ReadAll(io.LimitReader(command.InOrStdin(), 2049))
		if err != nil {
			return fmt.Errorf("key_replace.read: %w", err)
		}
		if len(input) > 2048 {
			return errors.New("key_replace.input_too_large")
		}
		store, err := controlplane.OpenExisting(command.Context(), config.Server.DatabaseURL, config.Server.TenantEncryptionKey)
		if err != nil {
			return err
		}
		defer store.Close()
		receipt, err := store.ReplaceSessionKey(command.Context(), owner, id, revision, strings.TrimSpace(string(input)))
		if err != nil {
			return err
		}
		if err := json.NewEncoder(command.OutOrStdout()).Encode(receipt); err != nil {
			return fmt.Errorf("key_replace.write_receipt: %w", err)
		}
		return nil
	}}
	command.Flags().StringVar(&owner, "owner-id", "", "Expected owner account ID")
	command.Flags().StringVar(&id, "tenant-id", "", "Suspended application tenant ID")
	command.Flags().Int64Var(&revision, "revision", 0, "Expected latest configuration revision")
	return command
}

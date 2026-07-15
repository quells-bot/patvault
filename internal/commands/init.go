package commands

import (
	"fmt"

	"github.com/quells-bot/patvault/internal/encrypt"
	"github.com/spf13/cobra"
)

// NewInitCmd builds the `patvault init` command. With --keychainless the master
// key is stored in a file (keyPath) instead of the OS keychain.
func NewInitCmd(keyPath string) *cobra.Command {
	var keychainless bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize patvault by creating the master key",
		RunE: func(cmd *cobra.Command, args []string) error {
			var kr encrypt.Keyring
			if keychainless {
				kr = encrypt.FileKeyring{Path: keyPath}
				fmt.Fprintln(cmd.ErrOrStderr(), "warning: keychainless mode stores the master key in a plaintext file (0600); this is less secure than the OS keychain")
			} else {
				kr = encrypt.OSKeyring{}
			}
			if _, err := encrypt.GetOrCreateMasterKey(kr); err != nil {
				return fmt.Errorf("init: %w", err)
			}
			fmt.Println("patvault initialized")
			return nil
		},
	}
	cmd.Flags().BoolVar(&keychainless, "keychainless", false, "store master key in a file instead of the OS keychain (less secure)")
	return cmd
}

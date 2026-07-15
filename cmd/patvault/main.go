package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/quells-bot/patvault/internal/commands"
	"github.com/quells-bot/patvault/internal/db"
	"github.com/quells-bot/patvault/internal/encrypt"
	"github.com/quells-bot/patvault/internal/gitconfig"
	"github.com/quells-bot/patvault/internal/github"
)

func main() {
	root := &cobra.Command{
		Use:   "patvault",
		Short: "GitHub PAT credential helper with encrypted storage",
	}

	root.AddCommand(commands.NewInitCmd(defaultKeyPathMust()))
	root.AddCommand(buildAddCmd())
	root.AddCommand(buildListCmd())
	root.AddCommand(buildRemoveCmd())
	root.AddCommand(buildCredentialCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func defaultDBPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "patvault", "credentials.db"), nil
}

func defaultKeyPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "patvault", encrypt.MasterKeyFileName), nil
}

func defaultKeyPathMust() string {
	p, err := defaultKeyPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "patvault:", err)
		os.Exit(1)
	}
	return p
}

// selectKeyring returns the FileKeyring if the keychainless master-key file
// exists, otherwise the OS keychain keyring.
func selectKeyring() encrypt.Keyring {
	p, err := defaultKeyPath()
	if err != nil {
		return encrypt.OSKeyring{}
	}
	if _, err := os.Stat(p); err == nil {
		return encrypt.FileKeyring{Path: p}
	}
	return encrypt.OSKeyring{}
}

func openDB() (*db.DB, error) {
	path, err := defaultDBPath()
	if err != nil {
		return nil, err
	}
	return db.Open(path)
}

func buildAddCmd() *cobra.Command {
	return commands.NewAddCmd(openDB, selectKeyring(), github.HTTPVerifier{}, gitconfig.GitRunner{})
}

func buildListCmd() *cobra.Command {
	return commands.NewListCmd(openDB, selectKeyring())
}

func buildRemoveCmd() *cobra.Command {
	return commands.NewRemoveCmd(openDB)
}

func buildCredentialCmd() *cobra.Command {
	kr := selectKeyring()
	cred := &cobra.Command{
		Use:   "credential",
		Short: "git credential helper protocol (invoked by git)",
	}
	cred.AddCommand(&cobra.Command{
		Use: "get",
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := openDB()
			if err != nil {
				return err
			}
			return exitCode(commands.RunGet(os.Stdin, os.Stdout, os.Stderr, d, kr))
		},
	})
	cred.AddCommand(&cobra.Command{
		Use: "store",
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := openDB()
			if err != nil {
				return err
			}
			return exitCode(commands.RunStore(os.Stdin, os.Stderr, d, kr))
		},
	})
	cred.AddCommand(&cobra.Command{
		Use: "erase",
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := openDB()
			if err != nil {
				return err
			}
			return exitCode(commands.RunErase(os.Stdin, os.Stderr, d, kr))
		},
	})
	return cred
}

// exitCode maps a credential handler's numeric exit code onto cobra's RunE
// contract: 0 → nil (success). Non-zero calls os.Exit directly so the process
// exits with the exact code git expects, bypassing cobra's error printing.
func exitCode(code int) error {
	if code == 0 {
		return nil
	}
	os.Exit(code)
	return nil
}

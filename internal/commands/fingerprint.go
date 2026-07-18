package commands

import (
	"fmt"
	"io"
	"os"

	"github.com/quells-bot/patvault/internal/encrypt"
	"github.com/spf13/cobra"
)

// NewFingerprintCmd builds `patvault fingerprint`: read a token on stdin, print
// its fingerprint under the current master key. Reveals nothing about the token.
func NewFingerprintCmd(kr encrypt.Keyring) *cobra.Command {
	return &cobra.Command{
		Use:   "fingerprint",
		Short: "Print the fingerprint of a token read from stdin",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFingerprint(kr, os.Stdin, cmd.OutOrStdout())
		},
	}
}

func runFingerprint(kr encrypt.Keyring, stdin io.Reader, out io.Writer) error {
	tok, err := readPassword(stdin)
	if err != nil {
		return fmt.Errorf("read token: %w", err)
	}
	mk, err := encrypt.GetOrCreateMasterKey(kr)
	if err != nil {
		return fmt.Errorf("master key: %w", err)
	}
	fmt.Fprintln(out, encrypt.Fingerprint(mk, tok))
	return nil
}

package commands

import (
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/quells-bot/patvault/internal/db"
	"github.com/quells-bot/patvault/internal/encrypt"
	"github.com/spf13/cobra"
)

// NewListCmd builds the `patvault list` cobra command. krFn is invoked only for
// --refresh-fingerprints; the default listing never constructs a keyring.
func NewListCmd(open func() (*db.DB, error), krFn func() encrypt.Keyring) *cobra.Command {
	var prune, refresh bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List stored credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := open()
			if err != nil {
				return err
			}
			if refresh {
				return runRefreshFingerprints(d, krFn(), cmd.OutOrStdout())
			}
			return runList(d, cmd.OutOrStdout(), prune)
		},
	}
	cmd.Flags().BoolVar(&prune, "prune", false, "delete expired credentials")
	cmd.Flags().BoolVar(&refresh, "refresh-fingerprints", false,
		"decrypt all rows once to backfill missing fingerprints (migration aid)")
	return cmd
}

// runList renders credential metadata. It never fetches the master key or
// decrypts a token — fingerprint and type are read from stored columns.
func runList(d *db.DB, out io.Writer, prune bool) error {
	if prune {
		n, err := d.DeleteExpired()
		if err != nil {
			return fmt.Errorf("prune: %w", err)
		}
		if n > 0 {
			fmt.Fprintf(out, "Pruned %d expired credential(s)\n", n)
		}
	}

	rows, err := d.List()
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}

	tw := tabwriter.NewWriter(out, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "Host\tPath\tUsername\tType\tFingerprint\tExpires")
	for _, c := range rows {
		fp, typ := c.Fingerprint, c.TokenType
		if fp == "" {
			// Un-backfilled legacy row: never decrypt to compute one.
			fp, typ = "(legacy)", "(legacy)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			c.Host, c.Path, c.Username, typ, fp, formatExpires(c.Expires))
	}
	return tw.Flush()
}

// runRefreshFingerprints is the ONE list path that decrypts. It backfills the
// fingerprint + token_type for every row, for one-time migration of pre-existing
// entries. It prints a warning because it reintroduces decryption to `list`.
func runRefreshFingerprints(d *db.DB, kr encrypt.Keyring, out io.Writer) error {
	fmt.Fprintln(out, "warning: --refresh-fingerprints decrypts every stored token to backfill fingerprints")
	mk, err := encrypt.GetOrCreateMasterKey(kr)
	if err != nil {
		return fmt.Errorf("master key: %w", err)
	}
	rows, err := d.List()
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}
	var n int
	for _, c := range rows {
		if c.Fingerprint != "" {
			continue
		}
		key, err := encrypt.DeriveKey(mk, c.Host, c.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "patvault: warning: skipping %s/%s: %v\n", c.Host, c.Path, err)
			continue
		}
		pat, err := encrypt.Decrypt(key, c.PAT)
		if err != nil {
			fmt.Fprintf(os.Stderr, "patvault: warning: skipping %s/%s: %v\n", c.Host, c.Path, err)
			continue
		}
		if err := d.UpdateFingerprint(c.Host, c.Path,
			encrypt.Fingerprint(mk, string(pat)), tokenType(string(pat))); err != nil {
			return fmt.Errorf("update %s/%s: %w", c.Host, c.Path, err)
		}
		n++
	}
	fmt.Fprintf(out, "Backfilled %d fingerprint(s)\n", n)
	return nil
}

// formatExpires renders relative expiry: (unknown), (expired), ⚠ N days, or N days.
func formatExpires(expires *int64) string {
	if expires == nil {
		return "(unknown)"
	}
	now := time.Now().Unix()
	if *expires <= now {
		return "(expired)"
	}
	days := (*expires - now) / 86400
	if days <= 7 {
		return fmt.Sprintf("⚠ %d days", days)
	}
	return fmt.Sprintf("%d days", days)
}

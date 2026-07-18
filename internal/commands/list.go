package commands

import (
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/quells-bot/patvault/internal/db"
	"github.com/quells-bot/patvault/internal/encrypt"
	"github.com/spf13/cobra"
)

// NewListCmd builds the `patvault list` cobra command. krFn is invoked only for
// --refresh-fingerprints; the default listing never constructs a keyring.
func NewListCmd(open func() (*db.DB, error), krFn func() encrypt.Keyring) *cobra.Command {
	var prune bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List stored credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := open()
			if err != nil {
				return err
			}
			return runList(d, cmd.OutOrStdout(), prune)
		},
	}
	cmd.Flags().BoolVar(&prune, "prune", false, "delete expired credentials")
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

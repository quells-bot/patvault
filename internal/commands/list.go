package commands

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/quells-bot/patvault/internal/db"
	"github.com/quells-bot/patvault/internal/encrypt"
	"github.com/spf13/cobra"
)

// NewListCmd builds the `patvault list` cobra command.
func NewListCmd(open func() (*db.DB, error), kr encrypt.Keyring) *cobra.Command {
	var show, prune bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List stored credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := open()
			if err != nil {
				return err
			}
			return runList(d, kr, cmd.OutOrStdout(), show, prune)
		},
	}
	cmd.Flags().BoolVar(&show, "show", false, "reveal full PATs (masked by default)")
	cmd.Flags().BoolVar(&prune, "prune", false, "delete expired credentials")
	return cmd
}

func runList(d *db.DB, kr encrypt.Keyring, out io.Writer, show, prune bool) error {
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

	mk, err := encrypt.GetOrCreateMasterKey(kr)
	if err != nil {
		return fmt.Errorf("master key: %w", err)
	}

	tw := tabwriter.NewWriter(out, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "Host\tPath\tUsername\tExpires\tPAT")
	for _, c := range rows {
		key, err := encrypt.DeriveKey(mk, c.Host, c.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "patvault: warning: skipping %s/%s: %v\n", c.Host, c.Path, err)
			continue
		}
		pat, err := encrypt.Decrypt(key, c.PAT)
		patStr := "????"
		if err == nil {
			patStr = string(pat)
		}
		twline := maskPAT(patStr)
		if show {
			twline = patStr
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			c.Host, c.Path, c.Username, formatExpires(c.Expires), twline)
	}
	return tw.Flush()
}

// patPrefixes are GitHub's token-type prefixes, longest first so github_pat_
// matches before any shorter prefix. Fine-grained tokens (github_pat_) are the
// first-class case, so we must not stop at the first underscore.
var patPrefixes = []string{"github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_"}

// maskPAT shows the token-type prefix plus ****, e.g. github_pat_****.
func maskPAT(pat string) string {
	for _, p := range patPrefixes {
		if strings.HasPrefix(pat, p) {
			return p + "****"
		}
	}
	return "****"
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

package commands

import (
	"fmt"
	"io"

	"github.com/quells-bot/patvault/internal/db"
	"github.com/quells-bot/patvault/internal/urlparse"
	"github.com/spf13/cobra"
)

// NewRemoveCmd builds the `patvault remove` cobra command.
func NewRemoveCmd(open func() (*db.DB, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove <repo-url>",
		Short: "Delete a stored credential",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := open()
			if err != nil {
				return err
			}
			return runRemove(d, cmd.OutOrStdout(), args[0])
		},
	}
	return cmd
}

func runRemove(d *db.DB, out io.Writer, rawURL string) error {
	host, path, err := urlparse.ParseRepoURL(rawURL)
	if err != nil {
		return err
	}
	if err := d.Delete(host, path); err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	fmt.Fprintf(out, "Removed credential for %s/%s\n", host, path)
	return nil
}

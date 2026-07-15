package commands

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/quells-bot/patvault/internal/db"
	"github.com/quells-bot/patvault/internal/encrypt"
	"github.com/quells-bot/patvault/internal/gitconfig"
	"github.com/quells-bot/patvault/internal/github"
	"github.com/quells-bot/patvault/internal/urlparse"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// NewAddCmd builds the `patvault add` cobra command.
func NewAddCmd(open func() (*db.DB, error), kr encrypt.Keyring, v github.Verifier, r gitconfig.Runner) *cobra.Command {
	var (
		username string
		ttlDays  int
		noVerify bool
	)
	cmd := &cobra.Command{
		Use:   "add <repo-url>",
		Short: "Store (and verify) a GitHub PAT for a repository",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := open()
			if err != nil {
				return err
			}
			return runAdd(d, kr, v, r, os.Stdin, args[0], username, ttlDays, noVerify)
		},
	}
	cmd.Flags().StringVar(&username, "username", "", "display login (defaults to repo owner)")
	cmd.Flags().IntVar(&ttlDays, "ttl-days", 0, "fallback expiry in days when online verification is unavailable")
	cmd.Flags().BoolVar(&noVerify, "no-verify", false, "skip online token verification")
	return cmd
}

func runAdd(d *db.DB, kr encrypt.Keyring, v github.Verifier, r gitconfig.Runner,
	stdin io.Reader, rawURL, username string, ttlDays int, noVerify bool) error {

	host, path, err := urlparse.ParseRepoURL(rawURL)
	if err != nil {
		return err
	}
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("invalid repository path %q (expected owner/repo)", path)
	}
	owner, repo := parts[0], parts[1]

	if username == "" {
		username = owner
	}

	pat, err := readPassword(stdin)
	if err != nil {
		return fmt.Errorf("read PAT: %w", err)
	}

	var expires *int64
	if !noVerify {
		exp, err := v.Verify(owner, repo, pat)
		if err != nil {
			if errors.Is(err, github.ErrAuthFailed) {
				return fmt.Errorf("token verification failed: %w", err)
			}
			// network failure: warn and fall back
			fmt.Fprintf(os.Stderr, "patvault: warning: verification unavailable: %v\n", err)
		} else if exp != nil {
			e := exp.Unix()
			expires = &e
		}
	}
	if expires == nil && ttlDays > 0 {
		e := time.Now().Add(time.Duration(ttlDays) * 24 * time.Hour).Unix()
		expires = &e
	}

	if err := gitconfig.EnsureUseHTTPPath(host, r); err != nil {
		return fmt.Errorf("configure git: %w", err)
	}

	mk, err := encrypt.GetOrCreateMasterKey(kr)
	if err != nil {
		return fmt.Errorf("master key: %w", err)
	}
	key, err := encrypt.DeriveKey(mk, host, path)
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}
	blob, err := encrypt.Encrypt(key, []byte(pat))
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	label := host + "/" + path
	if err := d.Upsert(db.Credential{
		Host: host, Path: path, Username: username, PAT: blob,
		Label: label, Created: time.Now().Unix(), Expires: expires,
	}); err != nil {
		return fmt.Errorf("store: %w", err)
	}

	fmt.Printf("Stored credential for %s\n", label)
	return nil
}

// readPassword reads a hidden line from stdin; falls back to plain read if not a TTY.
func readPassword(stdin io.Reader) (string, error) {
	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		b, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(os.Stderr) // newline after hidden prompt
		return string(b), err
	}
	var line string
	_, err := fmt.Fscanln(stdin, &line)
	return line, err
}

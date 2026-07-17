package commands

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/quells-bot/patvault/internal/db"
	"github.com/quells-bot/patvault/internal/encrypt"
	"github.com/quells-bot/patvault/internal/relay"
)

// NewRelayCmd builds 'patvault relay', the credential-injecting transport relay.
func NewRelayCmd(openDB func() (*db.DB, error), kr encrypt.Keyring, defaultHostKey, defaultAuthKeys string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "relay",
		Short: "credential-injecting git transport relay",
		Long: "Serve the agent's git over SSH and bridge it to GitHub over HTTPS,\n" +
			"injecting a stored PAT upstream. The agent never holds the token.",
	}
	cmd.AddCommand(newRelayServeCmd(openDB, kr, defaultHostKey, defaultAuthKeys))
	cmd.AddCommand(newRelayAddKeyCmd(defaultAuthKeys))
	return cmd
}

func newRelayServeCmd(openDB func() (*db.DB, error), kr encrypt.Keyring, defaultHostKey, defaultAuthKeys string) *cobra.Command {
	var listen, hostKey, authKeys string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "run the relay in the foreground until SIGINT/SIGTERM",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateListen(listen); err != nil {
				return err
			}
			ln, err := net.Listen("tcp", listen)
			if err != nil {
				return fmt.Errorf("listen on %s: %w", listen, err)
			}
			defer ln.Close()

			srv := &relay.Server{
				HostKeyPath:  hostKey,
				AuthKeysPath: authKeys,
				OpenDB:       openDB,
				Keyring:      kr,
				Logger:       slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), nil)),
				// Bridge is nil until slice 3. Every request that passes the
				// front door's checks is refused as an internal fault until then.
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			fmt.Fprintf(cmd.ErrOrStderr(), "patvault relay listening on %s\n", ln.Addr())
			return srv.Serve(ctx, ln)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "", "address to bind, as <ip:port> (required)")
	cmd.Flags().StringVar(&hostKey, "host-key", defaultHostKey, "path to the relay's SSH host key")
	cmd.Flags().StringVar(&authKeys, "authorized-keys", defaultAuthKeys, "path to the agent-key allowlist")
	return cmd
}

func newRelayAddKeyCmd(defaultAuthKeys string) *cobra.Command {
	var authKeys string

	cmd := &cobra.Command{
		Use:   "add-key <path-to-pubkey>",
		Short: "append an agent's public key to the allowlist",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			added, err := relay.AddKey(authKeys, args[0])
			if err != nil {
				return err
			}
			if added {
				fmt.Fprintf(cmd.OutOrStdout(), "patvault: key added to %s\n", authKeys)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "patvault: key already authorized in %s\n", authKeys)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&authKeys, "authorized-keys", defaultAuthKeys, "path to the agent-key allowlist")
	return cmd
}

// validateListen requires an explicit IP and port.
//
// The base spec forbids auto-detecting the host-only interface and forbids
// binding a wildcard: this is a security boundary, and guessing it wider than
// intended is the one configuration mistake here with a real consequence. A
// hostname is refused too — it can resolve to more than the operator meant.
func validateListen(addr string) error {
	if addr == "" {
		return errors.New("--listen <ip:port> is required (e.g. --listen 192.168.64.1:2222)")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid --listen %q: %w", addr, err)
	}
	if port == "" {
		return fmt.Errorf("--listen %q: missing port", addr)
	}
	if host == "" {
		return fmt.Errorf("--listen %q binds every interface; give the host-only interface IP explicitly", addr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("--listen %q: host must be an IP address, not a name", addr)
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("--listen %q binds every interface; give the host-only interface IP explicitly", addr)
	}
	return nil
}

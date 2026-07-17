package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/quells-bot/patvault/internal/db"
	"github.com/quells-bot/patvault/internal/encrypt"
)

// loadOrCreateHostKey returns the relay's persistent ed25519 host key,
// generating it on first run. created reports whether this call generated it, so
// the caller can print the fingerprint for the operator to pin.
//
// The key is reused across restarts on purpose: the guest pins it in
// known_hosts, so a key that changed would be indistinguishable from an
// impersonation attempt. A corrupt file is therefore an error rather than a
// reason to regenerate.
func loadOrCreateHostKey(path string) (signer ssh.Signer, created bool, err error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, false, fmt.Errorf("parse host key %s: %w", path, err)
		}
		return signer, false, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, false, fmt.Errorf("read host key: %w", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, fmt.Errorf("generate host key: %w", err)
	}
	blk, err := ssh.MarshalPrivateKey(priv, "patvault relay host key")
	if err != nil {
		return nil, false, fmt.Errorf("marshal host key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, fmt.Errorf("create config dir: %w", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(blk), 0o600); err != nil {
		return nil, false, fmt.Errorf("write host key: %w", err)
	}
	signer, err = ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, false, fmt.Errorf("host key signer: %w", err)
	}
	return signer, true, nil
}

// Request carries everything the bridge needs. By the time one is built, every
// fallible check — auth, exec parse, v2 gate, repo resolution, expiry, decrypt —
// has already passed.
type Request struct {
	Repo string // normalized "owner/repo", already shape-checked
	PAT  string // decrypted, already expiry-checked
}

// bridge is the seam to slice 3, named here so this slice cannot grow a shape
// slice 3 cannot use. Slice 3's exported Bridge struct satisfies it.
//
// It takes io.Reader/io.Writer rather than an ssh.Channel so the bridge never
// sees SSH and its tests need none. Neither method may write a byte to out until
// the upstream advertisement has returned 2xx — the fail-before-first-byte
// invariant, which is the bridge's to keep.
type bridge interface {
	Fetch(ctx context.Context, req Request, in io.Reader, out io.Writer) error
	Push(ctx context.Context, req Request, in io.Reader, out io.Writer) error
}

// Server is the relay's SSH front door. Dependencies are injected in the
// repo's existing style: the DB open func and the Keyring, per the base spec's
// module layout.
type Server struct {
	// HostKeyPath is the persistent ed25519 host key the guest pins.
	HostKeyPath string
	// AuthKeysPath is the OpenSSH-format allowlist.
	AuthKeysPath string
	// OpenDB opens the credential store. One call per resolution.
	OpenDB func() (*db.DB, error)
	// Keyring holds the master key.
	Keyring encrypt.Keyring
	// Bridge relays to the upstream. Nil until slice 3 implements one, in which
	// case every otherwise-valid request is refused as an internal fault.
	Bridge bridge
	// Logger receives the operational log. Nil discards it.
	Logger *slog.Logger
}

// logger returns the operational logger, or one that discards.
func (s *Server) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.New(slog.DiscardHandler)
}

// resolve looks up the stored PAT for repo and decrypts it, reusing the same
// keyring → derive → decrypt chain as the credential helper.
//
// The expiry check runs before the decrypt and before any upstream contact: a
// lapsed token is refused without a network round trip, which is what makes
// "expiry as a feature" cheap.
func (s *Server) resolve(repo string) (Request, error) {
	d, err := s.OpenDB()
	if err != nil {
		return Request{}, fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	cred, err := d.Get(upstreamHost, repo)
	if err != nil {
		return Request{}, fmt.Errorf("db get: %w", err)
	}
	if cred == nil {
		return Request{}, errNoPAT(repo)
	}
	if cred.Expires != nil && *cred.Expires <= time.Now().Unix() {
		return Request{}, errExpiredPAT(repo, time.Unix(*cred.Expires, 0))
	}

	mk, err := encrypt.GetOrCreateMasterKey(s.Keyring)
	if err != nil {
		return Request{}, fmt.Errorf("keyring: %w", err)
	}
	key, err := encrypt.DeriveKey(mk, upstreamHost, repo)
	if err != nil {
		return Request{}, fmt.Errorf("derive key: %w", err)
	}
	pat, err := encrypt.Decrypt(key, cred.PAT)
	if err != nil {
		return Request{}, fmt.Errorf("decrypt: %w", err)
	}
	return Request{Repo: repo, PAT: string(pat)}, nil
}

// SSH channel-request payloads. These mirror RFC 4254 and are the shape
// spike/relay-ssh/sshreq.go pinned against a real client.
type (
	envRequest  struct{ Name, Value string }
	execRequest struct{ Command string }
	exitStatus  struct{ Status uint32 }
)

// Serve accepts connections on ln until ctx is cancelled, then stops accepting
// and waits for in-flight sessions to drain. It returns nil after a graceful
// shutdown.
//
// It takes a listener rather than an address so the caller owns the bind — which
// is what lets commands/relay.go refuse a wildcard address and tests bind
// 127.0.0.1:0.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	hostKey, created, err := loadOrCreateHostKey(s.HostKeyPath)
	if err != nil {
		return err
	}
	if created {
		s.logger().Info("generated relay host key",
			"path", s.HostKeyPath,
			"fingerprint", ssh.FingerprintSHA256(hostKey.PublicKey()))
	}
	keys, err := loadAuthorizedKeys(s.AuthKeysPath)
	if err != nil {
		return err
	}

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			fp := ssh.FingerprintSHA256(key)
			if !keys.has(key) {
				s.logger().Info("refused unlisted key", "fingerprint", fp)
				return nil, fmt.Errorf("key %s is not authorized", fp)
			}
			// The fingerprint rides along so the session can log which agent it
			// served without re-deriving it.
			return &ssh.Permissions{Extensions: map[string]string{"fingerprint": fp}}, nil
		},
	}
	cfg.AddHostKey(hostKey)

	// Cancellation unblocks Accept by closing the listener.
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handleConn(ctx, conn, cfg)
		}()
	}
}

// handleConn runs one SSH connection: handshake, then its session channels.
func (s *Server) handleConn(ctx context.Context, conn net.Conn, cfg *ssh.ServerConfig) {
	defer conn.Close()

	sConn, chans, globalReqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		// An unlisted key lands here; PublicKeyCallback already logged it.
		s.logger().Debug("handshake failed", "remote", conn.RemoteAddr().String(), "err", err)
		return
	}
	defer sConn.Close()
	go ssh.DiscardRequests(globalReqs)

	fp := sConn.Permissions.Extensions["fingerprint"]
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		s.handleSession(ctx, newCh, fp)
	}
}

// handleSession runs one session channel's request loop: env requests are
// captured, the exec is dispatched, and everything else is refused.
//
// The shape is spike/relay-ssh's serveOnce, which the findings note names as the
// reference for exactly this loop.
func (s *Server) handleSession(ctx context.Context, newCh ssh.NewChannel, fp string) {
	ch, reqs, err := newCh.Accept()
	if err != nil {
		return
	}
	defer ch.Close()

	// GIT_PROTOCOL arrives as an env request before the exec (relay-ssh spike),
	// so the version is known by the time the exec is handled. Never count env
	// requests: the caller's locale is forwarded through them too, so the count
	// varies with the invoking shell.
	var gitProtocol string

	for req := range reqs {
		switch req.Type {
		case "env":
			var e envRequest
			if err := ssh.Unmarshal(req.Payload, &e); err != nil {
				if req.WantReply {
					req.Reply(false, nil)
				}
				s.refuse(ch, fp, "", "", errDisallowedExec(), fmt.Errorf("env payload: %w", err))
				return
			}
			if e.Name == "GIT_PROTOCOL" {
				gitProtocol = e.Value
			}
			if req.WantReply {
				req.Reply(true, nil)
			}

		case "exec":
			var x execRequest
			if err := ssh.Unmarshal(req.Payload, &x); err != nil {
				if req.WantReply {
					req.Reply(false, nil)
				}
				s.refuse(ch, fp, "", "", errDisallowedExec(), fmt.Errorf("exec payload: %w", err))
				return
			}
			if req.WantReply {
				req.Reply(true, nil)
			}
			s.dispatch(ctx, ch, fp, x.Command, gitProtocol)
			return

		default:
			// shell, pty-req, subsystem, ... — a relay serves git and nothing
			// else, so these are the disallowed-exec row rather than a
			// negotiation.
			if req.WantReply {
				req.Reply(false, nil)
			}
			s.refuse(ch, fp, "", "", errDisallowedExec(), fmt.Errorf("channel request %q", req.Type))
			return
		}
	}
}

// gitProtocolV2 is the exact GIT_PROTOCOL value that admits a fetch.
//
// The comparison is against the value, never the presence of the env request: a
// real git sends GIT_PROTOCOL=version=1 under protocol.version=1, so a presence
// check admits a v1 client into the v2 stateless pump. The relay-ssh findings
// note records this being got wrong once already.
const gitProtocolV2 = "version=2"

// dispatch turns one exec into an outcome: parse it, gate it on v2, resolve the
// repo to a decrypted PAT, and only then hand the bridge a Request.
//
// Every refusal here happens before the bridge is reached, and therefore before
// any upstream contact — the no-network half of the fail-before-first-byte
// invariant. The other half (the advertisement must return 2xx before a byte
// reaches out) is the bridge's, in slice 3.
func (s *Server) dispatch(ctx context.Context, ch ssh.Channel, fp, cmd, gitProtocol string) {
	op, repo, err := parseExec(cmd)
	if err != nil {
		s.refuse(ch, fp, "", "", errDisallowedExec(), err)
		return
	}

	// Push has no v2 and bridges cleanly regardless, so the gate is fetch-only.
	if op == opFetch && gitProtocol != gitProtocolV2 {
		s.refuse(ch, fp, op, repo, errNotV2(),
			fmt.Errorf("GIT_PROTOCOL = %q, want %q", gitProtocol, gitProtocolV2))
		return
	}

	req, err := s.resolve(repo)
	if err != nil {
		s.refuse(ch, fp, op, repo, clientError(err), err)
		return
	}
	if s.Bridge == nil {
		s.refuse(ch, fp, op, repo, errInternal(), errors.New("no bridge configured"))
		return
	}

	switch op {
	case opFetch:
		err = s.Bridge.Fetch(ctx, req, ch, ch)
	case opPush:
		err = s.Bridge.Push(ctx, req, ch, ch)
	}
	if err != nil {
		// Streaming may already have started, in which case this cannot be
		// clean: the client gets the message and a non-zero status, and the host
		// log gets the detail.
		s.refuse(ch, fp, op, repo, clientError(err), err)
		return
	}

	ch.SendRequest("exit-status", false, ssh.Marshal(exitStatus{Status: 0}))
	s.logger().Info("served", "fingerprint", fp, "op", op, "repo", repo)
}

// clientError maps an internal failure to what the client is told. A relayError
// is already a row of the spec's table and passes through; anything else is a
// host-side fault the client can do nothing about, so it becomes the internal
// row and the real cause goes to the log.
func clientError(err error) *relayError {
	var re *relayError
	if errors.As(err, &re) {
		return re
	}
	return errInternal()
}

// refuse writes err's message to the channel's stderr and closes with its exit
// status, then records the outcome host-side.
//
// Errors never touch stdout: git parses stdout as pkt-lines, so text injected
// there corrupts the parse. Over SSH git passes remote stderr straight to the
// user's terminal, which is why a patvault:-prefixed line is readable there.
func (s *Server) refuse(ch ssh.Channel, fp, op, repo string, clientErr *relayError, cause error) {
	fmt.Fprintln(ch.Stderr(), clientErr.Error())
	ch.SendRequest("exit-status", false, ssh.Marshal(exitStatus{Status: clientErr.Exit()}))

	// The operational log records the agent, the operation, and why — never the
	// PAT.
	s.logger().Info("refused",
		"fingerprint", fp,
		"op", op,
		"repo", repo,
		"exit", clientErr.Exit(),
		"retryable", clientErr.Retryable(),
		"cause", cause)
}
